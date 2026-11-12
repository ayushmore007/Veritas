"""FastAPI application: the website's backend and the mobile app's API.

The same router is mounted at `/api` (what the website calls) and `/api/v1` (what the mobile app
and any other client should pin to), so there is one implementation and two stable paths.
Interactive docs: `/docs`.
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
import sqlite3
import sys
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from fastapi import APIRouter, Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from veritas import __version__
from veritas.api.history import ScanHistory
from veritas.api.security import (
    RateLimiter,
    check_target_allowed,
    client_id,
    configured_key,
    require_auth,
)
from veritas.api.validation import (
    MAX_PREVENTION_KEY_LEN,
    BadRequest,
    parse_port,
    parse_target,
)
from veritas.inference import (
    MAX_PCAP_BYTES,
    MAX_ROWS,
    FlowDetector,
    InputError,
    ModelNotAvailable,
)
from veritas.testbed.config import project_root

ROOT = project_root()
# The scanner lives beside the website (web/scanner.py); make `web` importable without installing it.
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from web import scanner as scanner_mod  # noqa: E402

WEB_DIR = ROOT / "web"
CONFIG_FILE = ROOT / "config" / "testbed.yaml"
TWIN_DB = ROOT / "data" / "processed" / "twin" / "twin.db"

#: Static files the website needs. An allow-list, not a directory mount: `web/` also holds
#: Python source that has no business being downloadable.
STATIC_FILES = {
    "app.js": "application/javascript",
    "api-client.js": "application/javascript",
    "ml.js": "application/javascript",
    "styles.css": "text/css",
    "manifest.webmanifest": "application/manifest+json",
}

logger = logging.getLogger("veritas.api")
MAX_CONCURRENT_SCANS = 3


# ---------------------------------------------------------------------------------------------
# request models
# ---------------------------------------------------------------------------------------------


class ScanRequest(BaseModel):
    target: str = Field(default="cdn-edge-3.internal.test", max_length=300)


class VerifyFixRequest(BaseModel):
    hostname: str = Field(max_length=300)
    test_id: str = Field(default="", max_length=64)
    port: int | None = None
    simulate: bool = False


class PreventionRequest(BaseModel):
    prevention_key: str = Field(max_length=MAX_PREVENTION_KEY_LEN)
    target_host: str = Field(default="all", max_length=300)


class PredictRequest(BaseModel):
    flows: list[dict[str, Any]] = Field(min_length=1, max_length=MAX_ROWS)
    explain: bool = True
    top_k: int = Field(default=5, ge=1, le=20)


# ---------------------------------------------------------------------------------------------
# state
# ---------------------------------------------------------------------------------------------


class AppState:
    def __init__(self) -> None:
        self.history = ScanHistory()
        self.active_preventions: set[str] = {"provenance_grounding_verifier"}
        self.scan_slots = asyncio.Semaphore(MAX_CONCURRENT_SCANS)
        self.scan_limiter = RateLimiter(per_minute=12)
        self.analyze_limiter = RateLimiter(per_minute=30)
        self._detector: FlowDetector | None = None
        self._detector_error: str | None = None

    def detector(self) -> FlowDetector:
        if self._detector is None:
            try:
                self._detector = FlowDetector.load()
                self._detector_error = None
            except ModelNotAvailable as exc:
                self._detector_error = str(exc)
                raise
        return self._detector

    def reload_detector(self) -> None:
        self._detector = None
        self.detector()


def _state(request: Request) -> AppState:
    return request.app.state.veritas


def _throttle(limiter_name: str):
    def dep(request: Request) -> None:
        limiter: RateLimiter = getattr(_state(request), limiter_name)
        wait = limiter.check(client_id(request))
        if wait is not None:
            raise HTTPException(
                status_code=429,
                detail=f"Too many requests; retry in {wait:.0f}s.",
                headers={"Retry-After": str(max(1, int(wait + 0.999)))},
            )

    return dep


def serialize_report(report: Any) -> dict[str, Any]:
    return dataclasses.asdict(report)


# ---------------------------------------------------------------------------------------------
# routes
# ---------------------------------------------------------------------------------------------

router = APIRouter()
protected = APIRouter(dependencies=[Depends(require_auth)])


@router.get("/health")
def health() -> dict[str, Any]:
    """Unauthenticated liveness probe; deliberately reveals nothing about the deployment."""
    return {"status": "ok"}


@protected.get("/status")
def status(request: Request) -> dict[str, Any]:
    state = _state(request)
    try:
        model_ready = state.detector() is not None
    except ModelNotAvailable:
        model_ready = False
    return {
        "status": "online",
        "engine": "Veritas Sentinel Live",
        "version": __version__,
        "twin_db_connected": TWIN_DB.is_file(),
        "testbed_config": CONFIG_FILE.is_file(),
        "model_ready": model_ready,
        "active_preventions": sorted(state.active_preventions),
        "persistent_scans_count": len(state.history.load()),
        "auth_required": configured_key() is not None,
    }


@protected.get("/topology")
def topology() -> dict[str, Any]:
    servers: list[dict[str, Any]] = []
    if CONFIG_FILE.is_file():
        try:
            import yaml

            data = yaml.safe_load(CONFIG_FILE.read_text(encoding="utf-8"))
            for host_id, info in (data.get("hosts") or {}).items():
                if info.get("role") == "server":
                    servers.append(
                        {
                            "id": host_id,
                            "host": info.get("sni", f"{host_id}.test"),
                            "ip": info.get("docker_ip", "172.28.0.10"),
                            "port": info.get("port", 4433),
                            "localhost_bind": info.get("localhost_bind", "127.0.0.1"),
                            "role": host_id,
                        }
                    )
        except Exception as exc:
            logger.warning("Failed to parse testbed.yaml: %s", exc)
    return {"servers": servers}


@protected.post("/scan", dependencies=[Depends(_throttle("scan_limiter"))])
async def scan(body: ScanRequest, request: Request) -> dict[str, Any]:
    try:
        target = parse_target(body.target)
    except BadRequest as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from exc
    await check_target_allowed(target)

    state = _state(request)
    logger.info("Scanning %s", target)
    async with state.scan_slots:
        try:
            report = await scanner_mod.LiveSecurityScanner(timeout=3.5).scan_target(target)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:
            logger.error("Scan error on %s: %s", target, exc, exc_info=True)
            raise HTTPException(status_code=500, detail="Scan failed.") from exc

    data = serialize_report(report)
    # Only engine-side controls are known to be active; server-side fixes need a probe.
    data["applied_preventions"] = sorted(
        k for k in state.active_preventions if k == "provenance_grounding_verifier"
    )
    await asyncio.to_thread(state.history.record, data)
    return {"success": True, "report": data}


@protected.get("/scans/history")
def scan_history(request: Request) -> dict[str, Any]:
    return {"history": _state(request).history.load()}


@protected.delete("/scans/history")
def clear_scan_history(request: Request) -> dict[str, Any]:
    _state(request).history.clear()
    return {"success": True, "message": "History cleared"}


@protected.post("/verify-fix", dependencies=[Depends(_throttle("scan_limiter"))])
async def verify_fix(body: VerifyFixRequest, request: Request) -> dict[str, Any]:
    """Probe the live host to check that a recommended fix is actually in place."""
    try:
        hostname = parse_target(body.hostname)
        port = parse_port(body.port, 443)
    except BadRequest as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from exc
    now = datetime.now(UTC).isoformat()

    # Lab hosts do not exist outside the testbed. Say so rather than presenting a simulation as a
    # verified deployment.
    if body.simulate or hostname.endswith(".internal.test"):
        return {
            "verified": True,
            "simulated": True,
            "hostname": hostname,
            "test_id": body.test_id,
            "message": f"Simulated: no live probe was sent for {body.test_id} on {hostname}.",
            "verified_at": now,
        }
    await check_target_allowed(hostname)
    state = _state(request)
    try:
        verified, message = await _probe(hostname, port, body.test_id, state)
    except Exception as exc:
        verified, message = False, f"Live probe failed: {exc}"
    return {
        "verified": verified,
        "simulated": False,
        "hostname": hostname,
        "test_id": body.test_id,
        "message": message,
        "verified_at": now,
    }


async def _probe(hostname: str, port: int, test_id: str, state: AppState) -> tuple[bool, str]:
    url = f"https://{hostname}" if port == 443 else f"http://{hostname}:{port}"
    try:
        # verify=False is deliberate: we are checking headers on hosts that may have bad certs, and
        # send nothing sensitive. follow_redirects stays off so a redirect cannot hop to a host the
        # target guard never saw.
        async with httpx.AsyncClient(timeout=3.0, verify=False, follow_redirects=False) as client:
            resp = await client.get(url)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            header_checks = {
                "TEST-HSTS": ("strict-transport-security", "Strict-Transport-Security"),
                "TEST-CSP": ("content-security-policy", "Content-Security-Policy"),
                "TEST-XFO": ("x-frame-options", "X-Frame-Options"),
            }
            if test_id in header_checks:
                key, label = header_checks[test_id]
                if key in headers:
                    return True, f"Verified: {label} is set ({headers[key][:120]})."
                return False, f"Verification failed: {label} header not returned by server."
            if test_id == "TEST-RECON-FUZZ":
                dot = await client.get(f"{url}/.env", follow_redirects=False)
                if dot.status_code in (403, 404):
                    return True, f"Verified: /.env returned HTTP {dot.status_code}."
                return False, f"Verification failed: /.env responded with HTTP {dot.status_code}."
            if test_id == "TEST-TLS-VER":
                if url.startswith("https://"):
                    return True, "Verified: server negotiates TLS."
                return False, "Verification failed: server only answered over plain HTTP."
            if test_id == "TEST-VERITAS-GROUNDING":
                if "provenance_grounding_verifier" in state.active_preventions:
                    return True, "Verified: provenance-grounding verifier is active in this engine."
                return False, "Verification failed: provenance-grounding verifier is not active."
            # Reporting success for a check we never ran would be a false "fixed".
            return False, f"No live verification probe exists for {test_id!r}."
    except Exception as exc:
        return False, f"Could not connect to {url} during verification: {exc}"


@protected.post("/prevention/apply")
def apply_prevention(body: PreventionRequest, request: Request) -> dict[str, Any]:
    if not body.prevention_key.strip():
        raise HTTPException(status_code=400, detail="Missing prevention_key")
    state = _state(request)
    state.active_preventions.add(body.prevention_key)
    logger.info("Registered prevention %s for %s", body.prevention_key, body.target_host)
    return {
        "success": True,
        "prevention_key": body.prevention_key,
        "target_host": body.target_host,
        "action_executed": True,
        "message": f"Prevention {body.prevention_key} registered for {body.target_host}.",
        "active_preventions": sorted(state.active_preventions),
    }


@protected.get("/twin/flows")
def twin_flows() -> dict[str, Any]:
    import json

    flows: list[dict[str, Any]] = []
    for source, db in (("testbed", TWIN_DB), ("live_scan", scanner_mod.LIVE_SCAN_DB_PATH)):
        if not db.is_file():
            continue
        try:
            conn = sqlite3.connect(db)
            try:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT flow_id, src_ip, dst_ip, src_port, dst_port, protocol, "
                    "measured_features, ground_truth FROM flows LIMIT 50"
                ).fetchall()
            finally:
                conn.close()
            for row in rows:
                flows.append(
                    {
                        "source": source,
                        "flow_id": row["flow_id"],
                        "src_ip": row["src_ip"],
                        "dst_ip": row["dst_ip"],
                        "dst_port": row["dst_port"],
                        "protocol": {17: "UDP/QUIC", 6: "TCP"}.get(row["protocol"], str(row["protocol"])),
                        "measured_features": json.loads(row["measured_features"]),
                        "ground_truth": json.loads(row["ground_truth"]),
                    }
                )
        except Exception as exc:
            logger.warning("Failed to read %s: %s", db, exc)
    return {"flows": flows, "count": len(flows)}


# -- ML model ---------------------------------------------------------------------------------


def _detector_or_503(request: Request) -> FlowDetector:
    try:
        return _state(request).detector()
    except ModelNotAvailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@protected.get("/model")
def model_info(request: Request) -> dict[str, Any]:
    return _detector_or_503(request).info()


@protected.post("/predict", dependencies=[Depends(_throttle("analyze_limiter"))])
async def predict(body: PredictRequest, request: Request) -> dict[str, Any]:
    """Score flows given as CICFlowMeter-style feature objects."""
    det = _detector_or_503(request)
    try:
        results = await asyncio.to_thread(det.predict, body.flows, explain=body.explain, top_k=body.top_k)
    except InputError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {
        "model_version": det.info()["version"],
        "results": results,
        "summary": {
            "flows": len(results),
            "malicious": sum(r["verdict"] == "malicious" for r in results),
        },
    }


@protected.post("/analyze/pcap", dependencies=[Depends(_throttle("analyze_limiter"))])
async def analyze_pcap(request: Request, file: UploadFile = File(...), explain: bool = True) -> dict[str, Any]:
    """Upload a PCAP/PCAPNG; every UDP/TCP flow in it is extracted and scored."""
    det = _detector_or_503(request)
    data = await file.read(MAX_PCAP_BYTES + 1)
    try:
        result = await asyncio.to_thread(det.analyze_pcap_bytes, data, explain=explain)
    except InputError as exc:
        raise HTTPException(status_code=413 if "too large" in str(exc) else 422, detail=str(exc)) from exc
    return {"model_version": det.info()["version"], "filename": file.filename, **result}


router.include_router(protected)


# ---------------------------------------------------------------------------------------------
# application factory
# ---------------------------------------------------------------------------------------------


def create_app() -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.veritas = AppState()
        yield

    app = FastAPI(
        title="Veritas Sentinel API",
        version=__version__,
        description="Security scanning, digital-twin telemetry and ML flow detection for QUIC traffic.",
        lifespan=lifespan,
    )

    # Same-origin by default. Native mobile clients do not need CORS; list origins only for
    # something like Expo web in development: VERITAS_CORS_ORIGINS=http://localhost:8081
    import os

    origins = [o.strip() for o in os.environ.get("VERITAS_CORS_ORIGINS", "").split(",") if o.strip()]
    if origins:
        from fastapi.middleware.cors import CORSMiddleware

        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_methods=["GET", "POST", "DELETE"],
            allow_headers=["X-API-Key", "Content-Type"],
        )

    @app.middleware("http")
    async def no_store(request: Request, call_next):
        response = await call_next(request)
        if request.url.path.startswith("/api"):
            response.headers["Cache-Control"] = "no-store"
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        return response

    @app.exception_handler(HTTPException)
    async def http_error(_: Request, exc: HTTPException) -> JSONResponse:
        # The website's existing client reads `error`; FastAPI's default is `detail`. Send both.
        return JSONResponse(
            {"success": False, "error": exc.detail, "detail": exc.detail},
            status_code=exc.status_code,
            headers=getattr(exc, "headers", None),
        )

    app.include_router(router, prefix="/api")
    app.include_router(router, prefix="/api/v1")

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(WEB_DIR / "index.html", media_type="text/html")

    @app.get("/{name}", include_in_schema=False)
    def static_file(name: str) -> FileResponse:
        media = STATIC_FILES.get(name)
        path = WEB_DIR / name
        if media is None or not path.is_file():
            raise HTTPException(status_code=404, detail="Not found")
        return FileResponse(path, media_type=media)

    return app


app = create_app()
