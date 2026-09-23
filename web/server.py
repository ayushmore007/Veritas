#!/usr/bin/env python3
"""
Veritas Sentinel Web Dashboard & Live Security Engine Server
Connects real backend security scanners, Digital Twin database, 
persistent scan history, and provenance defense systems to the frontend.

Usage:
    python web/server.py [--host 127.0.0.1] [--port 8000]

The scanner probes whatever host it is given, so the server listens on loopback by default and
refuses cross-origin API calls. Bind to another interface only on a network you control.
"""

from __future__ import annotations

import argparse
import asyncio
import http.server
import json
import logging
import sys
import threading
import urllib.parse
import webbrowser
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

# Project imports
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from web.scanner import LIVE_SCAN_DB_PATH, LiveSecurityScanner

WEB_DIR = ROOT / "web"
CONFIG_FILE = ROOT / "config" / "testbed.yaml"
TWIN_DB = ROOT / "data" / "processed" / "twin" / "twin.db"
HISTORY_FILE = ROOT / "data" / "processed" / "twin" / "scans_history.json"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("veritas.server")

# In-memory scan cache
SCAN_CACHE: dict[str, Any] = {}
ACTIVE_PREVENTIONS: set[str] = {"provenance_grounding_verifier"}

# Requests are served on worker threads; history is read-modify-written, so serialise it.
_HISTORY_LOCK = threading.Lock()
_STATE_LOCK = threading.Lock()

MAX_BODY_BYTES = 64 * 1024
MAX_TARGET_LEN = 253 + len("https://") + len(":65535/")
MAX_PREVENTION_KEY_LEN = 64


class BadRequest(ValueError):
    """Client sent something the API cannot act on (HTTP 4xx)."""

    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


def _parse_port(value: Any, default: int) -> int:
    if value is None or value == "":
        return default
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise BadRequest(f"invalid port: {value!r}") from exc
    if not 1 <= port <= 65535:
        raise BadRequest(f"port out of range: {port}")
    return port


def _parse_target(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BadRequest("target must be a non-empty string")
    value = value.strip()
    if len(value) > MAX_TARGET_LEN or any(ch.isspace() for ch in value):
        raise BadRequest("target is not a valid host or URL")
    return value


def load_persistent_history() -> list[dict[str, Any]]:
    if HISTORY_FILE.is_file():
        try:
            return json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("Could not read scans_history.json: %s", exc)
    return []


def save_persistent_history(history: list[dict[str, Any]]) -> None:
    try:
        HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
        # Keep last 50 scans. Write-then-rename so a crash never leaves a truncated file.
        trimmed = history[:50]
        tmp = HISTORY_FILE.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(trimmed, indent=2), encoding="utf-8")
        tmp.replace(HISTORY_FILE)
    except Exception as exc:
        logger.warning("Could not write scans_history.json: %s", exc)


def record_scan(report_dict: dict[str, Any]) -> None:
    """Insert a scan at the head of history, replacing any earlier scan of the same host."""
    hostname = str(report_dict.get("hostname", "")).lower()
    with _HISTORY_LOCK:
        history = [
            h for h in load_persistent_history() if str(h.get("hostname", "")).lower() != hostname
        ]
        history.insert(0, report_dict)
        save_persistent_history(history)


def clear_history() -> None:
    with _HISTORY_LOCK:
        save_persistent_history([])


class VeritasDashboardHandler(http.server.SimpleHTTPRequestHandler):
    """Handler supporting static UI delivery, scan persistence, and real live verification."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_DIR), **kwargs)

    # No CORS headers and no OPTIONS handler, on purpose: the dashboard is same-origin, and a
    # cross-origin page must not be able to drive the scanner from the user's machine.

    def do_GET(self) -> None:
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        if path == "/api/status":
            with _STATE_LOCK:
                active = sorted(ACTIVE_PREVENTIONS)
            self._send_json({
                "status": "online",
                "engine": "Veritas Sentinel Live",
                "twin_db_connected": TWIN_DB.is_file(),
                "testbed_config": CONFIG_FILE.is_file(),
                "active_preventions": active,
                "persistent_scans_count": len(load_persistent_history()),
            })
        elif path == "/api/topology":
            self._handle_get_topology()
        elif path == "/api/scans/history":
            self._send_json({"history": load_persistent_history()})
        elif path == "/api/twin/flows":
            self._handle_get_twin_flows()
        elif path.startswith("/api/"):
            # Scans are POST-only: a GET that scans an arbitrary host is triggerable by any page
            # the user visits (an <img> tag is enough).
            self._send_json({"success": False, "error": "Endpoint not found"}, status=404)
        else:
            super().do_GET()

    def _read_json_body(self) -> dict[str, Any]:
        content_type = self.headers.get("Content-Type", "").split(";")[0].strip().lower()
        if content_type != "application/json":
            # Forces a CORS preflight for cross-origin callers, which this server never approves.
            raise BadRequest("Content-Type must be application/json", status=415)
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError as exc:
            raise BadRequest("invalid Content-Length") from exc
        if length < 0 or length > MAX_BODY_BYTES:
            raise BadRequest("request body too large", status=413)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BadRequest("request body is not valid JSON") from exc
        if not isinstance(body, dict):
            raise BadRequest("request body must be a JSON object")
        return body

    def do_POST(self) -> None:
        path = urllib.parse.urlparse(self.path).path
        routes = {
            "/api/scan": lambda body: self._handle_run_scan(
                _parse_target(body.get("target", "cdn-edge-3.internal.test"))
            ),
            "/api/verify-fix": self._handle_verify_live_fix,
            "/api/prevention/apply": self._handle_apply_prevention,
        }
        handler = routes.get(path)
        if handler is None:
            self._send_json({"success": False, "error": "Endpoint not found"}, status=404)
            return
        try:
            handler(self._read_json_body())
        except BadRequest as exc:
            self._send_json({"success": False, "error": str(exc)}, status=exc.status)

    def do_DELETE(self) -> None:
        parsed_url = urllib.parse.urlparse(self.path)
        if parsed_url.path == "/api/scans/history":
            clear_history()
            self._send_json({"success": True, "message": "History cleared"})
        else:
            self._send_json({"success": False, "error": "Endpoint not found"}, status=404)

    def _handle_get_topology(self) -> None:
        servers = []
        if CONFIG_FILE.is_file():
            try:
                import yaml
                data = yaml.safe_load(CONFIG_FILE.read_text(encoding="utf-8"))
                for host_id, host_info in data.get("hosts", {}).items():
                    if host_info.get("role") == "server":
                        servers.append({
                            "id": host_id,
                            "host": host_info.get("sni", f"{host_id}.test"),
                            "ip": host_info.get("docker_ip", "172.28.0.10"),
                            "port": host_info.get("port", 4433),
                            "localhost_bind": host_info.get("localhost_bind", "127.0.0.1"),
                            "role": host_id,
                        })
            except Exception as exc:
                logger.warning("Failed to parse testbed.yaml: %s", exc)

        self._send_json({"servers": servers})

    def _handle_run_scan(self, target: str) -> None:
        logger.info("Executing live security scan on target: %s", target)
        scanner = LiveSecurityScanner(timeout=3.5)

        try:
            report = asyncio.run(scanner.scan_target(target))
        except ValueError as exc:
            self._send_json({"success": False, "error": str(exc)}, status=400)
            return
        except Exception as exc:
            logger.error("Scan error on %s: %s", target, exc, exc_info=True)
            self._send_json({"success": False, "error": str(exc)}, status=500)
            return

        report_dict = self._serialize_report(report)
        with _STATE_LOCK:
            SCAN_CACHE[target] = report_dict
        record_scan(report_dict)
        self._send_json({"success": True, "report": report_dict})

    def _handle_verify_live_fix(self, body: dict) -> None:
        """Sends a real probe over HTTP/TLS to check if a specific fix was actually applied on the live server."""
        hostname = body.get("hostname", "")
        test_id = body.get("test_id", "")
        if not isinstance(hostname, str) or not hostname.strip():
            raise BadRequest("hostname is required")
        hostname = _parse_target(hostname)
        if not isinstance(test_id, str):
            raise BadRequest("test_id must be a string")
        port = _parse_port(body.get("port"), 443)
        simulate = bool(body.get("simulate", False))
        now = datetime.now(timezone.utc).isoformat()

        logger.info("Verifying live fix for [%s] on host [%s] (Simulate: %s)", test_id, hostname, simulate)

        # Lab hosts (*.internal.test) do not exist outside the testbed, so there is nothing to
        # probe. Say so rather than presenting a simulation as a verified deployment.
        if simulate or hostname.endswith(".internal.test"):
            self._send_json({
                "verified": True,
                "simulated": True,
                "hostname": hostname,
                "test_id": test_id,
                "message": f"Simulated: no live probe was sent for {test_id} on {hostname}.",
                "verified_at": now,
            })
            return

        try:
            verified, message = asyncio.run(self._probe_live_verification(hostname, port, test_id))
        except Exception as exc:
            verified, message = False, f"Live probe failed: {exc}"
        self._send_json({
            "verified": verified,
            "simulated": False,
            "hostname": hostname,
            "test_id": test_id,
            "message": message,
            "verified_at": now,
        })

    async def _probe_live_verification(self, hostname: str, port: int, test_id: str) -> tuple[bool, str]:
        url = f"https://{hostname}" if port == 443 else f"http://{hostname}:{port}"
        try:
            async with httpx.AsyncClient(timeout=3.0, verify=False) as client:
                resp = await client.get(url)
                headers = {k.lower(): v for k, v in resp.headers.items()}

                if test_id == "TEST-HSTS":
                    if "strict-transport-security" in headers:
                        return True, f"Verified: Found Strict-Transport-Security: {headers['strict-transport-security']}"
                    return False, "Verification Failed: Strict-Transport-Security header not returned by server."

                elif test_id == "TEST-CSP":
                    if "content-security-policy" in headers:
                        return True, f"Verified: Content-Security-Policy is active ({len(headers['content-security-policy'])} chars)."
                    return False, "Verification Failed: Content-Security-Policy header not found."

                elif test_id == "TEST-XFO":
                    if "x-frame-options" in headers:
                        return True, f"Verified: X-Frame-Options set to {headers['x-frame-options']}."
                    return False, "Verification Failed: X-Frame-Options header not found."

                elif test_id == "TEST-RECON-FUZZ":
                    dot_resp = await client.get(f"{url}/.env", follow_redirects=False)
                    if dot_resp.status_code in (403, 404):
                        return True, "Verified: Public access to /.env returned 403/404 Forbidden."
                    return False, f"Verification Failed: /.env still responded with HTTP {dot_resp.status_code}."

                elif test_id == "TEST-TLS-VER":
                    if resp.url.scheme == "https":
                        return True, "Verified: Server successfully negotiates TLS/HTTPS connection."
                    return False, "Verification Failed: Server still connects over unencrypted HTTP."

                elif test_id == "TEST-VERITAS-GROUNDING":
                    # Engine-side control: it runs here, not on the remote server.
                    with _STATE_LOCK:
                        active = "provenance_grounding_verifier" in ACTIVE_PREVENTIONS
                    if active:
                        return True, "Verified: Provenance-grounding verifier is active in this engine."
                    return False, "Verification Failed: Provenance-grounding verifier is not active."

                # Reporting success for a check we never ran would be a false "fixed".
                return False, f"No live verification probe exists for {test_id!r}."
        except Exception as exc:
            return False, f"Could not connect to {url} during verification: {exc}"

    def _handle_apply_prevention(self, body: dict) -> None:
        prevention_key = body.get("prevention_key")
        target_host = body.get("target_host", "all")

        if not isinstance(prevention_key, str) or not prevention_key.strip():
            raise BadRequest("Missing prevention_key")
        if len(prevention_key) > MAX_PREVENTION_KEY_LEN:
            raise BadRequest("prevention_key too long")
        if not isinstance(target_host, str):
            raise BadRequest("target_host must be a string")

        with _STATE_LOCK:
            ACTIVE_PREVENTIONS.add(prevention_key)
            active = sorted(ACTIVE_PREVENTIONS)
        logger.info("Applying prevention [%s] for host [%s]", prevention_key, target_host)

        self._send_json({
            "success": True,
            "prevention_key": prevention_key,
            "target_host": target_host,
            "action_executed": True,
            "message": f"Prevention {prevention_key} successfully registered for {target_host}.",
            "active_preventions": active,
        })

    def _handle_get_twin_flows(self) -> None:
        flows = []
        for source, db_path in (("testbed", TWIN_DB), ("live_scan", LIVE_SCAN_DB_PATH)):
            if not db_path.is_file():
                continue
            try:
                import sqlite3
                conn = sqlite3.connect(db_path)
                try:
                    conn.row_factory = sqlite3.Row
                    rows = conn.execute(
                        "SELECT flow_id, src_ip, dst_ip, src_port, dst_port, protocol, "
                        "measured_features, ground_truth FROM flows LIMIT 50"
                    ).fetchall()
                finally:
                    conn.close()
                for row in rows:
                    flows.append({
                        "source": source,
                        "flow_id": row["flow_id"],
                        "src_ip": row["src_ip"],
                        "dst_ip": row["dst_ip"],
                        "dst_port": row["dst_port"],
                        # IP protocol 17 is UDP (QUIC in this testbed), 6 is TCP.
                        "protocol": {17: "UDP/QUIC", 6: "TCP"}.get(row["protocol"], str(row["protocol"])),
                        "measured_features": json.loads(row["measured_features"]),
                        "ground_truth": json.loads(row["ground_truth"]),
                    })
            except Exception as exc:
                logger.warning("Failed to read %s: %s", db_path, exc)

        self._send_json({"flows": flows, "count": len(flows)})

    def _serialize_report(self, report) -> dict[str, Any]:
        return {
            "target_input": report.target_input,
            "hostname": report.hostname,
            "ip_addresses": report.ip_addresses,
            "port": report.port,
            "protocol": report.protocol,
            "scan_timestamp": report.scan_timestamp,
            "scan_duration_ms": report.scan_duration_ms,
            "security_score": report.security_score,
            "posture_verdict": report.posture_verdict,
            "posture_class": report.posture_class,
            "open_ports": report.open_ports,
            "vulnerabilities_count": report.vulnerabilities_count,
            "twin_features": report.twin_features,
            "metadata_untrusted": report.metadata_untrusted,
            "recommended_preventions": report.recommended_preventions,
            "applied_preventions": report.applied_preventions,
            "tests": [
                {
                    "id": t.id,
                    "name": t.name,
                    "category": t.category,
                    "status": t.status,
                    "score_impact": t.score_impact,
                    "metric": t.metric,
                    "observed_value": t.observed_value,
                    "baseline": t.baseline,
                    "description": t.description,
                    "technical_details": t.technical_details,
                    "remediation": t.remediation,
                    "auto_fixable": t.auto_fixable,
                    "permission_required": t.permission_required,
                    "remediation_type": t.remediation_type,
                }
                for t in report.tests
            ],
        }

    def _send_json(self, data: dict, status: int = 200) -> None:
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


def run_server(host: str = "127.0.0.1", port: int = 8000, open_browser: bool = True) -> None:
    class DashboardServer(http.server.ThreadingHTTPServer):
        # A scan takes seconds; one slow scan must not freeze status polling and page loads.
        allow_reuse_address = True
        daemon_threads = True

    with DashboardServer((host, port), VeritasDashboardHandler) as httpd:
        url = f"http://{'localhost' if host in ('127.0.0.1', '::1', 'localhost') else host}:{port}"
        print("=" * 72)
        print("🛰️  VERITAS SENTINEL — PERSISTENT SECURITY SCANNER & DEFENSE ENGINE")
        print(f"    Live Web Interface:  {url}")
        print(f"    History Persistence: {HISTORY_FILE}")
        print(f"    Digital Twin Store:  {TWIN_DB}")
        print(f"    Live Scan Store:     {LIVE_SCAN_DB_PATH}")
        print("    Press Ctrl+C to terminate.")
        print("=" * 72)
        if host not in ("127.0.0.1", "::1", "localhost"):
            logger.warning(
                "Listening on %s: anyone who can reach this address can drive the scanner.", host
            )

        if open_browser:
            webbrowser.open(url)

        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down Veritas Server...")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Start Veritas Security Engine Web Server")
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Interface to bind (default: 127.0.0.1 — loopback only)",
    )
    parser.add_argument("--port", type=int, default=8000, help="Port to serve on (default: 8000)")
    parser.add_argument("--no-browser", action="store_true", help="Don't open browser automatically")
    args = parser.parse_args()
    run_server(host=args.host, port=args.port, open_browser=not args.no_browser)
