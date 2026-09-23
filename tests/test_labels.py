"""Phase 1 label registry tests."""

import json
from datetime import datetime, timezone
from pathlib import Path

from veritas.testbed.labels import AttackType, FlowLabelRecord, LabelRegistry, TrafficClass


def test_flow_label_roundtrip(tmp_path: Path):
    path = tmp_path / "flows.jsonl"
    registry = LabelRegistry(path)
    started = datetime(2026, 1, 1, tzinfo=timezone.utc)
    record = FlowLabelRecord(
        traffic_class=TrafficClass.MALICIOUS,
        attack_type=AttackType.C2_BEACON,
        scenario_id="c2_beacon",
        dst_host="malicious_c2",
        dst_sni="c2.malicious.test",
        dst_port=4434,
        started_at=started,
    ).finalize(bytes_sent=100, bytes_received=50, request_count=3)

    registry.append(record)
    loaded = registry.load_all()
    assert len(loaded) == 1
    assert loaded[0].traffic_class == TrafficClass.MALICIOUS
    assert loaded[0].attack_type == AttackType.C2_BEACON


def test_summary_counts(tmp_path: Path):
    path = tmp_path / "flows.jsonl"
    registry = LabelRegistry(path)
    registry.append(
        FlowLabelRecord(
            traffic_class=TrafficClass.BENIGN,
            scenario_id="browse",
            dst_host="benign_server",
            dst_sni="benign.internal.test",
            dst_port=4433,
            started_at=datetime.now(timezone.utc),
        ).finalize(bytes_sent=1, bytes_received=1, request_count=1)
    )
    summary = LabelRegistry.summarize(registry.load_all())
    assert summary["total"] == 1
    assert summary["by_class"]["benign"] == 1


def test_jsonl_is_one_object_per_line(tmp_path: Path):
    path = tmp_path / "flows.jsonl"
    registry = LabelRegistry(path)
    registry.append(
        FlowLabelRecord(
            traffic_class=TrafficClass.BENIGN,
            scenario_id="browse",
            dst_host="h",
            dst_sni="sni",
            dst_port=1,
            started_at=datetime.now(timezone.utc),
        ).finalize(bytes_sent=0, bytes_received=0, request_count=0)
    )
    line = path.read_text(encoding="utf-8").strip()
    parsed = json.loads(line)
    assert parsed["scenario_id"] == "browse"
