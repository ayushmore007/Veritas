"""Label-leakage guards: the failure mode that produces a great number and no result."""

from __future__ import annotations

from pathlib import Path

import pytest

from veritas.agent.tools import AgentToolbox, IdentityLeak
from veritas.capture.records import EnrichedFlowRecord, EnrichedFlowRegistry
from veritas.capture.verify import MIN_PER_CLASS_FOR_STATS, check_leakage
from veritas.features import IDENTITY_FIELDS, behavioural_features, build_host_ref_index, host_ref
from veritas.twin.ingest import ingest_features_file
from veritas.twin.store import TwinStore


def _record(flow_id: str, *, port: int, traffic_class: str, duration: float) -> EnrichedFlowRecord:
    features = {
        "flow_duration": duration,
        "tot_fwd_pkts": 20,
        "totlen_fwd_pkts": 4000,
        "totlen_bwd_pkts": 3000,
        "down_up_ratio": 0.75,
        "src_ip": "127.0.0.1",
        "dst_ip": "127.0.0.2" if traffic_class == "malicious" else "127.0.0.3",
        "src_port": 50000,
        "dst_port": port,
        "protocol": 17,
    }
    metadata = {"sni": "cdn-edge-3.internal.test", "alpn": "h3"}
    trust = {k: "trusted" for k in features}
    trust.update({k: "untrusted" for k in metadata})
    return EnrichedFlowRecord(
        flow_id=flow_id,
        capture_id="cap-1",
        pcap_source="t.pcapng",
        cicflowmeter=features,
        metadata=metadata,
        field_trust=trust,
        ground_truth={"traffic_class": traffic_class, "attack_type": None,
                      "scenario_id": "s-" + flow_id},
        src_ip="127.0.0.1",
        dst_ip=features["dst_ip"],
        src_port=50000,
        dst_port=port,
        protocol=17,
    )


@pytest.fixture()
def features_file(tmp_path: Path) -> Path:
    records = [
        _record("f1", port=4433, traffic_class="benign", duration=0.02),
        _record("f2", port=4433, traffic_class="benign", duration=0.15),
        _record("f3", port=4434, traffic_class="malicious", duration=16.1),
        _record("f4", port=4435, traffic_class="malicious", duration=0.18),
    ]
    path = tmp_path / "flows_features.jsonl"
    EnrichedFlowRegistry(path).write_all(records)
    return path


def test_behavioural_view_drops_every_identity_field():
    measured = {"flow_duration": 1.0, "dst_port": 4434, "src_ip": "127.0.0.1", "timestamp": "x"}
    view = behavioural_features(measured)
    assert view == {"flow_duration": 1.0}
    assert IDENTITY_FIELDS.isdisjoint(view)


def test_leakage_screen_names_dst_port(features_file: Path):
    report = check_leakage(features_file)
    leaks = {c["feature"]: c for c in report["categorical_leaks"]}
    assert "dst_port" in leaks
    assert leaks["dst_port"]["verdict"] == "perfect_predictor"
    assert leaks["dst_port"]["value_to_class"]["4433"] == "benign"
    assert "dst_port" in report["identity_fields_in_feature_record"]


def test_leakage_screen_refuses_to_overclaim_on_small_samples(features_file: Path):
    """With 2 flows per class, perfect separation is the default, not evidence."""
    report = check_leakage(features_file)
    assert report["statistically_informative"] is False
    assert report["min_per_class_for_stats"] == MIN_PER_CLASS_FOR_STATS
    assert any("too small" in note for note in report["notes"])
    for finding in report["numeric_leaks"]:
        assert finding["informative"] is False


def test_agent_never_receives_ports_or_addresses(tmp_path: Path, features_file: Path):
    store = TwinStore(tmp_path / "twin.db")
    ingest_features_file(store, features_file)

    payload = AgentToolbox(store).get_flow_stats("f3")
    blob = str(payload)
    assert "4434" not in blob
    assert "127.0.0.2" not in blob
    assert "five_tuple" not in payload
    assert payload["peer_ref"].startswith("host-")


def test_widening_the_feature_list_cannot_reintroduce_identity(tmp_path: Path, features_file: Path):
    """Defence in depth: the behavioural filter runs before field selection, so asking for
    dst_port by name gets you nothing rather than the label."""
    store = TwinStore(tmp_path / "twin.db")
    ingest_features_file(store, features_file)

    toolbox = AgentToolbox(store, feature_fields=("flow_duration", "dst_port", "dst_ip"))
    payload = toolbox.get_flow_stats("f3")
    assert set(payload["features"]) == {"flow_duration"}


def test_identity_guard_raises_loudly(tmp_path: Path, features_file: Path):
    """The second layer: if a payload ever carries an identity field, fail rather than degrade."""
    store = TwinStore(tmp_path / "twin.db")
    ingest_features_file(store, features_file)
    toolbox = AgentToolbox(store)

    with pytest.raises(IdentityLeak) as exc:
        toolbox._assert_no_identity({"flow_duration": 1.0, "dst_port": 4434})
    assert "dst_port" in str(exc.value)


def test_peer_ref_is_stable_and_resolves_back(tmp_path: Path, features_file: Path):
    store = TwinStore(tmp_path / "twin.db")
    ingest_features_file(store, features_file)
    toolbox = AgentToolbox(store)

    ref = toolbox.get_flow_stats("f3")["peer_ref"]
    assert ref == host_ref("127.0.0.2")
    assert toolbox.resolve_peer_ref(ref) == "127.0.0.2"

    history = toolbox.get_host_history(ref)
    assert history["peer_ref"] == ref
    assert history["event_count"] >= 1
    assert "127.0.0.2" not in str(history)


def test_host_ref_index_is_injective():
    ips = ["127.0.0.1", "127.0.0.2", "10.0.0.1", "172.28.0.20"]
    index = build_host_ref_index(ips)
    assert len(index) == len(ips)
