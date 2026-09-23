"""Regression tests for label↔flow assignment (Phase 2 ground-truth integrity)."""

from datetime import UTC, datetime, timedelta

from veritas.capture.join_labels import (
    match_labels_to_flows_scored,
    summarize_match_quality,
)
from veritas.testbed.labels import AttackType, FlowLabelRecord, TrafficClass

T0 = datetime(2026, 8, 1, 19, 40, 16, tzinfo=UTC)


def _label(scenario, attack, start_offset, duration, sent, received, port=4434):
    started = T0 + timedelta(seconds=start_offset)
    return FlowLabelRecord(
        traffic_class=TrafficClass.MALICIOUS if attack else TrafficClass.BENIGN,
        attack_type=attack,
        scenario_id=scenario,
        dst_host="h",
        dst_sni="s",
        dst_port=port,
        started_at=started,
        ended_at=started + timedelta(seconds=duration),
        bytes_sent=sent,
        bytes_received=received,
    )


def _flow(ts_offset, duration, fwd_bytes, bwd_bytes, port=4434):
    # Deliberately naive local-style timestamp string, as CICFlowMeter emits.
    ts = (T0 + timedelta(seconds=ts_offset)).strftime("%Y-%m-%d %H:%M:%S.%f")
    return {
        "src_ip": "127.0.0.1",
        "dst_ip": "127.0.0.1",
        "src_port": 50000 + int(ts_offset),
        "dst_port": port,
        "protocol": 17,
        "timestamp": ts,
        "flow_duration": duration,
        "totlen_fwd_pkts": fwd_bytes,
        "totlen_bwd_pkts": bwd_bytes,
    }


def test_beacon_and_scan_on_same_port_are_not_swapped():
    """
    The original matcher scored only on |wire_bytes - payload_bytes|. Both scenarios sit on port
    4434 and carry a few KB on the wire, so QUIC overhead dominated the payload term and the
    16 s beacon was labeled `scan_probe`. Duration must decide instead.
    """
    labels = [
        _label("c2_beacon", AttackType.C2_BEACON, 0, 16.08, 0, 32),
        _label("scan_probe", AttackType.SCAN_PROBE, 16.2, 0.31, 0, 57),
    ]
    flows = [
        _flow(0.0, 16.0986, 4505, 3188),   # the beacon
        _flow(16.2, 0.3332, 3913, 2859),   # the scan burst
    ]

    got = {label.scenario_id: round(row["flow_duration"], 2) for label, row, _ in
           match_labels_to_flows_scored(labels, flows)}
    assert got == {"c2_beacon": 16.10, "scan_probe": 0.33}


def test_assignment_is_global_not_first_come():
    """A locally cheap first pairing must not force a wrong second one."""
    labels = [
        _label("a", None, 0, 1.0, 0, 100, port=4433),
        _label("b", None, 2, 10.0, 0, 100, port=4433),
    ]
    flows = [_flow(0, 1.05, 500, 600, port=4433), _flow(2, 10.1, 500, 600, port=4433)]

    pairs = {label.scenario_id: round(row["flow_duration"], 1) for label, row, _ in
             match_labels_to_flows_scored(labels, flows)}
    assert pairs == {"a": 1.1, "b": 10.1}


def test_low_confidence_pair_is_reported():
    """A label with no plausible partner must surface, not be silently accepted."""
    labels = [_label("mystery", None, 0, 300.0, 0, 10, port=4435)]
    flows = [_flow(0, 0.02, 400, 400, port=4435)]

    scored = match_labels_to_flows_scored(labels, flows)
    quality = summarize_match_quality(scored)
    assert quality["low_confidence_pairs"], "an implausible pairing should be flagged"
    assert quality["low_confidence_pairs"][0]["scenario_id"] == "mystery"


def test_timezone_shift_in_capture_clock_does_not_break_matching():
    """
    CICFlowMeter timestamps are naive; the join must not depend on them agreeing with UTC labels.
    Shifting every flow timestamp by +5:30 must not change the assignment.
    """
    labels = [
        _label("c2_beacon", AttackType.C2_BEACON, 0, 16.08, 0, 32),
        _label("scan_probe", AttackType.SCAN_PROBE, 16.2, 0.31, 0, 57),
    ]
    shift = 5.5 * 3600
    flows = [
        _flow(shift, 16.0986, 4505, 3188),
        _flow(shift + 16.2, 0.3332, 3913, 2859),
    ]

    got = {label.scenario_id: round(row["flow_duration"], 2) for label, row, _ in
           match_labels_to_flows_scored(labels, flows)}
    assert got == {"c2_beacon": 16.10, "scan_probe": 0.33}
