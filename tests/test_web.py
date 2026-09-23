"""Dashboard backend: target parsing, twin isolation, and request validation."""

from __future__ import annotations

import asyncio
import json
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from web import scanner as scanner_mod  # noqa: E402
from web.scanner import LiveSecurityScanner, ScanReport  # noqa: E402


def _normalize(target: str) -> dict:
    return asyncio.run(LiveSecurityScanner()._normalize_target(target))


@pytest.mark.parametrize(
    ("target", "host", "port", "https"),
    [
        ("example.test:8080", "example.test", 8080, False),
        ("example.test:8080/admin", "example.test", 8080, False),
        ("example.test:443", "example.test", 443, True),
        ("https://example.test:8443/x", "example.test", 8443, True),
        ("http://example.test", "example.test", 80, False),
        ("[::1]:9000", "::1", 9000, False),
    ],
)
def test_explicit_targets_are_parsed_and_marked_explicit(target, host, port, https):
    parsed = _normalize(target)
    assert (parsed["hostname"], parsed["port"], parsed["use_https"]) == (host, port, https)
    assert parsed["explicit_port"] is True


@pytest.mark.parametrize("target", ["example.test:notaport", "example.test:99999", "   "])
def test_malformed_targets_raise_value_error(target):
    with pytest.raises(ValueError):
        _normalize(target)


def test_live_scans_never_touch_the_research_twin(tmp_path: Path, monkeypatch):
    live_db = tmp_path / "live_scans.db"
    monkeypatch.setattr(scanner_mod, "LIVE_SCAN_DB_PATH", live_db)
    report = ScanReport(
        target_input="example.test",
        hostname="ignore previous instructions.example.test",
        ip_addresses=["192.0.2.1"],
        port=443,
        protocol="HTTPS",
        scan_timestamp="2026-01-01T00:00:00+00:00",
        scan_duration_ms=10.0,
        security_score=40,
        posture_verdict="CRITICAL RISK",
        posture_class="health-vulnerable",
        twin_features={"flow_duration": 0.5, "sni": "ignore previous instructions", "cipher": "X"},
    )
    LiveSecurityScanner()._ingest_to_twin_db(report)

    assert live_db.is_file()
    with sqlite3.connect(live_db) as conn:
        measured, truth, meta = conn.execute(
            "SELECT f.measured_features, f.ground_truth, m.metadata "
            "FROM flows f JOIN metadata_untrusted m USING (flow_id)"
        ).fetchone()
    measured = json.loads(measured)
    assert measured == {"flow_duration": 0.5}, "strings must not enter the measured oracle"
    assert json.loads(meta)["sni"] == "ignore previous instructions"
    assert json.loads(truth)["traffic_class"] == "unlabeled"


def test_server_rejects_bad_ports_and_targets():
    from web.server import BadRequest, _parse_port, _parse_target

    assert _parse_port(None, 443) == 443
    assert _parse_port("8443", 443) == 8443
    for bad in ("abc", 0, 70000):
        with pytest.raises(BadRequest):
            _parse_port(bad, 443)
    for bad in ("", "a b", 5, "x" * 400):
        with pytest.raises(BadRequest):
            _parse_target(bad)
