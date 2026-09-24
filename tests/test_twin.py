"""Digital twin Tier 1 tests."""

from pathlib import Path

from veritas.capture.records import EnrichedFlowRecord, EnrichedFlowRegistry
from veritas.twin.ingest import extract_measured_features, ingest_features_file
from veritas.twin.query import get_flow_stats, replay_flow_metadata_ablation
from veritas.twin.store import TwinStore


def _sample_record(flow_id: str = "test-flow-1") -> EnrichedFlowRecord:
    return EnrichedFlowRecord(
        flow_id=flow_id,
        capture_id="cap-1",
        pcap_source="test.pcap",
        cicflowmeter={"flow_duration": 1.5, "tot_fwd_pkts": 10, "totlen_fwd_pkts": 1000},
        metadata={"sni": "evil.test", "alpn": "h3"},
        field_trust={
            "flow_duration": "trusted",
            "tot_fwd_pkts": "trusted",
            "totlen_fwd_pkts": "trusted",
            "sni": "untrusted",
            "alpn": "untrusted",
        },
        ground_truth={"traffic_class": "malicious", "attack_type": "c2_beacon"},
        src_ip="127.0.0.1",
        dst_ip="127.0.0.1",
        src_port=40000,
        dst_port=4434,
        protocol=17,
    )


def test_measured_features_exclude_untrusted_metadata():
    rec = _sample_record()
    measured = extract_measured_features(rec)
    assert "flow_duration" in measured
    assert "sni" not in measured


def test_ingest_and_query(tmp_path: Path):
    features = tmp_path / "flows_features.jsonl"
    EnrichedFlowRegistry(features).write_all([_sample_record()])

    db = tmp_path / "twin.db"
    store = TwinStore(db)
    result = ingest_features_file(store, features)
    assert result["ingested"] == 1

    stats = get_flow_stats(store, "test-flow-1")
    assert stats["trust_level"] == "measured"
    assert stats["features"]["tot_fwd_pkts"] == 10


def test_metadata_ablation_replay(tmp_path: Path):
    features = tmp_path / "flows_features.jsonl"
    EnrichedFlowRegistry(features).write_all([_sample_record("flow-x")])

    store = TwinStore(tmp_path / "twin.db")
    ingest_features_file(store, features)

    replay = replay_flow_metadata_ablation(
        store,
        "flow-x",
        strip_fields=["sni", "alpn"],
    )
    assert replay["metadata_stripped"]["sni"] is None
    assert replay["measured_features"]["tot_fwd_pkts"] == 10


def test_ingest_real_features_if_present():
    path = Path("data/processed/features/flows_features.jsonl")
    if not path.is_file():
        return
    store = TwinStore(Path("data/processed/twin/test_twin.db"))
    store.clear()
    result = ingest_features_file(store, path)
    assert result["ingested"] >= 1
