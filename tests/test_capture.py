"""Phase 2 capture pipeline tests."""

from datetime import datetime, timezone
from pathlib import Path

from veritas.capture.join_labels import dedupe_labels, match_labels_to_flows
from veritas.capture.trust import tag_field_trust
from veritas.testbed.labels import AttackType, FlowLabelRecord, TrafficClass


def _label(scenario: str, port: int, sent: int, recv: int) -> FlowLabelRecord:
    return FlowLabelRecord(
        traffic_class=TrafficClass.MALICIOUS if port != 4433 else TrafficClass.BENIGN,
        attack_type=AttackType.C2_BEACON if scenario == "c2_beacon" else None,
        scenario_id=scenario,
        dst_host="h",
        dst_sni="sni.test",
        dst_port=port,
        started_at=datetime.now(timezone.utc),
    ).finalize(bytes_sent=sent, bytes_received=recv, request_count=1)


def test_dedupe_labels_keeps_latest_per_scenario_port():
    old = _label("browse", 4433, 1, 1)
    new = _label("browse", 4433, 99, 99)
    out = dedupe_labels([old, new], "last_per_scenario_port")
    assert len(out) == 1
    assert out[0].bytes_sent == 99


def test_match_labels_to_flows_by_bytes():
    label = _label("data_exfil", 4435, 500_000, 100)
    flow = {
        "src_port": 52000,
        "dst_port": 4435,
        "totlen_fwd_pkts": 510_000,
        "totlen_bwd_pkts": 90,
        "timestamp": 1.0,
    }
    pairs = match_labels_to_flows([label], [flow])
    assert len(pairs) == 1
    assert pairs[0][0].scenario_id == "data_exfil"


def test_metadata_fields_tagged_untrusted():
    tags = tag_field_trust(
        {"flow_duration": 1.2, "tot_fwd_pkts": 10},
        {"sni": "evil.test", "alpn": "h3"},
    )
    assert tags["flow_duration"] == "trusted"
    assert tags["sni"] == "untrusted"
    assert tags["alpn"] == "untrusted"


def test_extract_flows_from_minimal_pcap(tmp_path: Path):
    pytest = __import__("pytest")
    scapy = pytest.importorskip("scapy")
    from scapy.all import IP, UDP, Ether, wrpcap

    from veritas.capture.cicflowmeter_extract import extract_flows_from_pcap

    pcap = tmp_path / "mini.pcap"
    pkts = [
        Ether() / IP(src="127.0.0.1", dst="127.0.0.1") / UDP(sport=40000, dport=4433) / b"quic-test",
        Ether() / IP(src="127.0.0.1", dst="127.0.0.1") / UDP(sport=4433, dport=40000) / b"quic-reply",
    ]
    wrpcap(str(pcap), pkts)
    flows = extract_flows_from_pcap(pcap)
    assert len(flows) >= 1
    assert flows[0]["dst_port"] in (4433, 40000)


def test_extracted_time_fields_are_in_seconds(tmp_path: Path):
    """CICFlowMeter emits microseconds; the project reasons in seconds everywhere downstream."""
    pytest = __import__("pytest")
    pytest.importorskip("scapy")
    from scapy.all import IP, UDP, Ether, wrpcap

    from veritas.capture.cicflowmeter_extract import extract_flows_from_pcap

    pkts = []
    for i, t in enumerate((1000.0, 1001.5, 1003.0)):
        sport, dport = (40000, 4433) if i % 2 == 0 else (4433, 40000)
        pkt = Ether() / IP(src="127.0.0.1", dst="127.0.0.1") / UDP(sport=sport, dport=dport) / b"x"
        pkt.time = t
        pkts.append(pkt)
    pcap = tmp_path / "timed.pcap"
    wrpcap(str(pcap), pkts)

    flow = extract_flows_from_pcap(pcap)[0]
    assert abs(flow["flow_duration"] - 3.0) < 1e-6
    assert abs(flow["flow_iat_max"] - 1.5) < 1e-6
    assert flow["flow_pkts_s"] > 0.5  # rates stay per-second, not rescaled
