"""Backend API: auth, SSRF guard, rate limit, scan contract, and the ML endpoints."""

from __future__ import annotations

import random
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from scapy.all import IP, UDP, Ether, wrpcap

from tests.test_training import _rec  # synthetic corpus builder
from veritas.api import app as app_mod
from veritas.capture.records import EnrichedFlowRegistry
from veritas.training.pipeline import TrainingConfig, run_training
from web.scanner import ScanReport, SecurityTestResult


@pytest.fixture(scope="module")
def model_dir(tmp_path_factory) -> Path:
    base = tmp_path_factory.mktemp("model")
    rng = random.Random(5)
    recs, i = [], 0
    for run in range(30):
        for malicious in (False, False, True):
            recs.append(_rec(i, run, malicious, 0.0, None, rng)); i += 1
    feats = base / "f.jsonl"
    EnrichedFlowRegistry(feats).write_all(recs)
    run_training(
        TrainingConfig(
            features_file=feats, split_manifest=base / "s.json", out_dir=base / "m",
            families=("random_forest",), max_cv_folds=3, profiles=("clean",), deploy_profile="clean",
        )
    )
    return base / "m"


@pytest.fixture()
def env(monkeypatch, model_dir, tmp_path):
    monkeypatch.setenv("VERITAS_MODEL_DIR", str(model_dir))
    monkeypatch.delenv("VERITAS_API_KEY", raising=False)
    monkeypatch.delenv("VERITAS_ALLOW_PRIVATE_TARGETS", raising=False)
    monkeypatch.setattr("veritas.api.history.history_file", lambda: tmp_path / "hist.json")


@pytest.fixture()
def client(env):
    with TestClient(app_mod.create_app()) as c:
        yield c


def _fake_report(target: str) -> ScanReport:
    test = SecurityTestResult(
        id="TEST-X", name="x", category="c", status="passed", score_impact=0, metric="m",
        observed_value="o", baseline="b", description="d", technical_details="t", remediation="r",
        auto_fixable=False, permission_required=False, remediation_type="veritas_engine",
    )
    return ScanReport(
        target_input=target, hostname=target, ip_addresses=["93.184.216.34"], port=443,
        protocol="HTTPS", scan_timestamp="2026-01-01T00:00:00+00:00", scan_duration_ms=5.0,
        security_score=88, posture_verdict="GOOD", posture_class="health-good", tests=[test],
    )


MAL = {"tot_fwd_pkts": 60, "tot_bwd_pkts": 30, "flow_duration": 8.0, "flow_iat_std": 0.01}
BEN = {"tot_fwd_pkts": 12, "tot_bwd_pkts": 6, "flow_duration": 1.0, "flow_iat_std": 0.4}


# -- auth ----------------------------------------------------------------------------------------


def test_health_is_public_and_reveals_nothing(env):
    with TestClient(app_mod.create_app(), client=("203.0.113.9", 5)) as c:
        assert c.get("/api/health").json() == {"status": "ok"}


def test_without_a_key_only_loopback_is_served(env):
    with TestClient(app_mod.create_app(), client=("203.0.113.9", 5)) as c:
        assert c.get("/api/status").status_code == 403
    with TestClient(app_mod.create_app()) as c:
        assert c.get("/api/status").status_code == 200


def test_with_a_key_it_is_required_everywhere(env, monkeypatch):
    monkeypatch.setenv("VERITAS_API_KEY", "s3cret")
    with TestClient(app_mod.create_app(), client=("203.0.113.9", 5)) as c:
        assert c.get("/api/v1/status").status_code == 401
        assert c.get("/api/v1/status", headers={"X-API-Key": "wrong"}).status_code == 401
        ok = c.get("/api/v1/status", headers={"X-API-Key": "s3cret"})
        assert ok.status_code == 200 and ok.json()["auth_required"] is True


def test_both_mount_points_serve_the_same_api(client):
    assert client.get("/api/status").json().keys() == client.get("/api/v1/status").json().keys()


# -- scan guard / contract -----------------------------------------------------------------------


@pytest.mark.parametrize("target", ["127.0.0.1", "http://10.0.0.5:8080", "localhost", "169.254.169.254"])
def test_private_targets_are_refused_by_default(client, target):
    r = client.post("/api/v1/scan", json={"target": target})
    assert r.status_code == 403
    assert "non-public" in r.json()["error"]


def test_private_targets_allowed_with_explicit_opt_in(client, monkeypatch):
    monkeypatch.setenv("VERITAS_ALLOW_PRIVATE_TARGETS", "1")

    async def fake(self, target):  # noqa: ARG001
        return _fake_report(target)

    monkeypatch.setattr(app_mod.scanner_mod.LiveSecurityScanner, "scan_target", fake)
    r = client.post("/api/v1/scan", json={"target": "10.0.0.5"})
    assert r.status_code == 200 and r.json()["report"]["security_score"] == 88
    assert client.get("/api/v1/scans/history").json()["history"][0]["hostname"] == "10.0.0.5"
    assert client.delete("/api/v1/scans/history").json()["success"] is True
    assert client.get("/api/v1/scans/history").json()["history"] == []


def test_bad_scan_requests_are_rejected(client):
    assert client.post("/api/v1/scan", json={"target": "a b"}).status_code == 400
    assert client.post("/api/v1/scan", json={"target": "x" * 400}).status_code == 422


def test_scan_rate_limit_returns_429_with_retry_after(client, monkeypatch):
    monkeypatch.setenv("VERITAS_ALLOW_PRIVATE_TARGETS", "1")

    async def fake(self, target):  # noqa: ARG001
        return _fake_report(target)

    monkeypatch.setattr(app_mod.scanner_mod.LiveSecurityScanner, "scan_target", fake)
    codes = [client.post("/api/v1/scan", json={"target": "10.0.0.5"}).status_code for _ in range(14)]
    assert 429 in codes and codes[0] == 200
    limited = client.post("/api/v1/scan", json={"target": "10.0.0.5"})
    assert int(limited.headers["Retry-After"]) >= 1


def test_verify_fix_simulates_lab_hosts_and_says_so(client):
    r = client.post("/api/v1/verify-fix", json={"hostname": "cdn.internal.test", "test_id": "TEST-HSTS"})
    assert r.json()["simulated"] is True


def test_prevention_registers(client):
    r = client.post("/api/v1/prevention/apply", json={"prevention_key": "rate_limiter"})
    assert "rate_limiter" in r.json()["active_preventions"]


# -- static site -----------------------------------------------------------------------------


def test_website_is_served_but_source_files_are_not(client):
    assert client.get("/").status_code == 200
    assert client.get("/app.js").status_code == 200
    for hidden in ("scanner.py", "server.py", "../pyproject.toml"):
        assert client.get(f"/{hidden}").status_code == 404


# -- ML endpoints --------------------------------------------------------------------------------


def test_model_info(client):
    info = client.get("/api/v1/model").json()
    assert info["n_features"] > 0 and 0 < info["threshold"] < 1
    assert "limitations" in info and info["sklearn_mismatch"] is False


def test_predict_separates_the_synthetic_classes_and_explains(client):
    r = client.post("/api/v1/predict", json={"flows": [MAL, BEN], "top_k": 3})
    assert r.status_code == 200
    mal, ben = r.json()["results"]
    assert mal["verdict"] == "malicious" and ben["verdict"] == "benign"
    assert len(mal["top_features"]) == 3 and "contribution" in mal["top_features"][0]


def test_predict_ignores_identity_fields_it_must_not_use(client):
    # dst_port is the label in this lab; supplying it must not change the answer.
    a = client.post("/api/v1/predict", json={"flows": [MAL], "explain": False}).json()["results"][0]
    b = client.post(
        "/api/v1/predict", json={"flows": [{**MAL, "dst_port": 4433, "src_ip": "1.2.3.4"}], "explain": False}
    ).json()["results"][0]
    assert a["malicious_probability"] == b["malicious_probability"]


def test_predict_warns_when_features_are_missing(client):
    r = client.post("/api/v1/predict", json={"flows": [{"unrelated": 1}]}).json()["results"][0]
    assert "warning" in r and r["missing_features"] > 0


def test_predict_validation(client):
    assert client.post("/api/v1/predict", json={"flows": []}).status_code == 422
    assert client.post("/api/v1/predict", json={}).status_code == 422


def test_pcap_upload_is_analysed(client, tmp_path):
    pkts = []
    for i, t in enumerate((1000.0, 1000.5, 1001.0, 1001.5)):
        sp, dp = (40000, 4433) if i % 2 == 0 else (4433, 40000)
        p = Ether() / IP(src="127.0.0.1", dst="127.0.0.1") / UDP(sport=sp, dport=dp) / (b"x" * 200)
        p.time = t
        pkts.append(p)
    f = tmp_path / "t.pcap"
    wrpcap(str(f), pkts)
    r = client.post("/api/v1/analyze/pcap", files={"file": ("t.pcap", f.read_bytes())})
    assert r.status_code == 200
    body = r.json()
    assert body["summary"]["flows"] == 1 and body["flows"][0]["packets"] == 4
    assert body["flows"][0]["verdict"] in ("benign", "malicious")


def test_pcap_upload_rejects_garbage_and_empty(client):
    assert client.post("/api/v1/analyze/pcap", files={"file": ("x.pcap", b"")}).status_code == 422
    assert client.post("/api/v1/analyze/pcap", files={"file": ("x.pcap", b"not a pcap at all")}).status_code == 422


def test_model_endpoints_return_503_with_instructions_when_untrained(env, monkeypatch, tmp_path):
    monkeypatch.setenv("VERITAS_MODEL_DIR", str(tmp_path / "nothing"))
    with TestClient(app_mod.create_app()) as c:
        r = c.get("/api/v1/model")
        assert r.status_code == 503 and "veritas-train fit" in r.json()["error"]
        assert c.get("/api/v1/status").json()["model_ready"] is False
