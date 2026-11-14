"""Recorder backend selection: tshark that records nothing must not win silently."""

from __future__ import annotations

from pathlib import Path

import pytest

from veritas.capture import pcap_record
from veritas.capture.pcap_record import PcapRecorder


@pytest.fixture()
def calls(monkeypatch, tmp_path):
    seen: list[str] = []
    monkeypatch.setattr(pcap_record.shutil, "which", lambda name: "/usr/bin/tshark")
    monkeypatch.setattr(PcapRecorder, "_start_scapy", lambda self: seen.append("scapy"))
    return seen


def _rec(tmp_path: Path) -> PcapRecorder:
    return PcapRecorder(tmp_path / "x.pcapng", [4433])


def test_auto_falls_back_to_scapy_when_tshark_fails(calls, monkeypatch, tmp_path):
    monkeypatch.delenv("VERITAS_PCAP_BACKEND", raising=False)
    monkeypatch.setattr(PcapRecorder, "_start_tshark", lambda self: calls.append("tshark") or False)
    _rec(tmp_path).start()
    assert calls == ["tshark", "scapy"]


def test_auto_uses_tshark_when_it_works(calls, monkeypatch, tmp_path):
    monkeypatch.delenv("VERITAS_PCAP_BACKEND", raising=False)
    monkeypatch.setattr(PcapRecorder, "_start_tshark", lambda self: calls.append("tshark") or True)
    _rec(tmp_path).start()
    assert calls == ["tshark"]


def test_env_can_force_scapy_and_skip_tshark(calls, monkeypatch, tmp_path):
    monkeypatch.setenv("VERITAS_PCAP_BACKEND", "scapy")
    monkeypatch.setattr(PcapRecorder, "_start_tshark", lambda self: calls.append("tshark") or True)
    _rec(tmp_path).start()
    assert calls == ["scapy"]


def test_forced_tshark_does_not_fall_back(calls, monkeypatch, tmp_path):
    monkeypatch.setenv("VERITAS_PCAP_BACKEND", "tshark")
    monkeypatch.setattr(PcapRecorder, "_start_tshark", lambda self: calls.append("tshark") or False)
    _rec(tmp_path).start()
    assert calls == ["tshark"]


def test_unknown_backend_value_means_auto(calls, monkeypatch, tmp_path):
    monkeypatch.setenv("VERITAS_PCAP_BACKEND", "bogus")
    monkeypatch.setattr(PcapRecorder, "_start_tshark", lambda self: calls.append("tshark") or False)
    _rec(tmp_path).start()
    assert calls == ["tshark", "scapy"]
