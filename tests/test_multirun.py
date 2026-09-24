"""Multi-run generation, run-aware label handling, and Phase 8c entropy features."""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from veritas.capture.entropy import ENTROPY_FIELDS, add_entropy_features, entropy_features
from veritas.capture.join_labels import dedupe_labels
from veritas.testbed.audit import audit_label
from veritas.testbed.config import load_testbed_config
from veritas.testbed.labels import AttackType, FlowLabelRecord, TrafficClass
from veritas.testbed.orchestrator import vary_scenarios


def test_varied_scenarios_are_reproducible_and_differ_across_runs():
    base = load_testbed_config()["scenarios"]
    a = vary_scenarios(base, random.Random(7))
    b = vary_scenarios(base, random.Random(7))
    c = vary_scenarios(base, random.Random(8))
    assert a == b
    assert a != c
    assert base == load_testbed_config()["scenarios"], "the config itself must not be mutated"


@pytest.mark.parametrize("seed", range(20))
def test_varied_parameters_stay_inside_the_labelled_behaviour(seed):
    """A draw must not turn a beacon into something `audit` would reject."""
    params = vary_scenarios(load_testbed_config()["scenarios"], random.Random(seed))
    c2 = next(s for s in params["malicious"] if s["id"] == "c2_beacon")
    assert c2["interval_sec"] * c2["repetitions"] >= 5.0  # audit: min_duration_s
    assert c2["repetitions"] >= 3
    scan = next(s for s in params["malicious"] if s["id"] == "scan_probe")
    assert len(scan["paths"]) >= 3
    exfil = next(s for s in params["malicious"] if s["id"] == "data_exfil")
    assert exfil["upload_kb"] * 1024 >= 100_000


def _label(scenario: str, run_id: str | None, offset: int) -> FlowLabelRecord:
    t0 = datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=offset)
    return FlowLabelRecord(
        traffic_class=TrafficClass.BENIGN,
        scenario_id=scenario,
        dst_host="benign_server",
        dst_sni="benign.internal.test",
        dst_port=4433,
        started_at=t0,
        ended_at=t0 + timedelta(seconds=1),
        run_id=run_id,
    )


def test_latest_run_selection_uses_run_id_not_line_count():
    labels = [_label(s, "run-a", i) for i, s in enumerate(["browse", "stream", "x", "y", "z"])]
    labels += [_label(s, "run-b", 10 + i) for i, s in enumerate(["browse", "stream", "x"])]
    kept = dedupe_labels(labels, use_latest_run=True, latest_run_count=5)
    assert {label.run_id for label in kept} == {"run-b"}
    assert len(kept) == 3


def test_entropy_of_constant_sizes_is_zero_and_top_share_one():
    feats = entropy_features([100] * 8, [True] * 8, [float(i) for i in range(8)])
    assert feats["ent_size"] == 0.0
    assert feats["ent_top_size_share"] == 1.0
    assert feats["ent_distinct_sizes"] == 1.0
    assert feats["ent_iat"] == 0.0  # perfectly periodic


def test_entropy_of_distinct_sizes_is_maximal():
    feats = entropy_features([10, 20, 30, 40], [True, False, True, False], [0, 1, 2, 3])
    assert feats["ent_size"] == pytest.approx(2.0)
    assert feats["ent_size_norm"] == pytest.approx(1.0)
    assert feats["ent_size_fwd"] == pytest.approx(1.0)


def test_add_entropy_features_assigns_packets_by_five_tuple(tmp_path: Path):
    pytest.importorskip("scapy")
    from scapy.all import IP, UDP, Ether, wrpcap

    pkts = []
    for i, (sport, dport, payload) in enumerate(
        [(40000, 4433, b"a" * 10), (4433, 40000, b"b" * 500), (40000, 4433, b"c" * 10),
         (41000, 4434, b"d" * 50)]
    ):
        pkt = Ether() / IP(src="127.0.0.1", dst="127.0.0.1") / UDP(sport=sport, dport=dport) / payload
        pkt.time = 1_700_000_000 + i
        pkts.append(pkt)
    pcap = tmp_path / "e.pcap"
    wrpcap(str(pcap), pkts)

    ts = datetime.fromtimestamp(1_700_000_000).strftime("%Y-%m-%d %H:%M:%S")
    flows = [
        {"src_ip": "127.0.0.1", "dst_ip": "127.0.0.1", "src_port": 40000, "dst_port": 4433,
         "protocol": 17, "timestamp": ts},
        {"src_ip": "127.0.0.1", "dst_ip": "127.0.0.1", "src_port": 41000, "dst_port": 4434,
         "protocol": 17, "timestamp": ts},
    ]
    add_entropy_features(pcap, flows)

    assert set(ENTROPY_FIELDS) <= set(flows[0])
    assert flows[0]["ent_distinct_sizes"] == 2.0   # two small forward, one large backward
    assert flows[0]["ent_size_fwd"] == 0.0         # forward sizes identical
    assert flows[1]["ent_distinct_sizes"] == 1.0


def test_audit_accepts_a_generated_style_beacon():
    t0 = datetime(2026, 1, 1, tzinfo=UTC)
    label = FlowLabelRecord(
        traffic_class=TrafficClass.MALICIOUS,
        attack_type=AttackType.C2_BEACON,
        scenario_id="c2_beacon",
        dst_host="malicious_c2",
        dst_sni="c2.malicious.test",
        dst_port=4434,
        started_at=t0,
        ended_at=t0 + timedelta(seconds=12),
        bytes_sent=0,
        bytes_received=32,
        request_count=6,
    )
    assert not audit_label(label)["needs_review"]
