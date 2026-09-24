"""Phase 8b provenance verifier: which `ignore` verdicts it lets through, and why."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from veritas.agent.schema import AgentDecision, Claim, ReasoningTrace, TrustLevel, Verdict
from veritas.capture.records import EnrichedFlowRecord, EnrichedFlowRegistry
from veritas.defense.verifier import ClaimStatus, ProvenanceVerifier
from veritas.twin.ingest import ingest_features_file
from veritas.twin.store import TwinStore

FLOW_ID = "flow-under-test"
DURATION = 16.0986


@pytest.fixture()
def store(tmp_path: Path) -> TwinStore:
    features = {"flow_duration": DURATION, "totlen_fwd_pkts": 4505, "flow_iat_max": 2.0162}
    metadata = {"sni": "c2.malicious.test", "alpn": "h3"}
    trust = {k: "trusted" for k in features} | {k: "untrusted" for k in metadata}
    record = EnrichedFlowRecord(
        flow_id=FLOW_ID,
        capture_id="cap-1",
        pcap_source="test.pcapng",
        cicflowmeter=features,
        metadata=metadata,
        field_trust=trust,
        ground_truth={"traffic_class": "malicious", "attack_type": "c2_beacon"},
        src_ip="127.0.0.1",
        dst_ip="127.0.0.2",
        src_port=50000,
        dst_port=4434,
        protocol=17,
    )
    path = tmp_path / "features.jsonl"
    EnrichedFlowRegistry(path).write_all([record])
    twin = TwinStore(tmp_path / "twin.db")
    ingest_features_file(twin, path)
    return twin


def _trace(verdict: Verdict, *claims: Claim) -> ReasoningTrace:
    now = datetime.now(UTC)
    return ReasoningTrace(
        flow_id=FLOW_ID,
        decision=AgentDecision(flow_id=FLOW_ID, verdict=verdict, claims=list(claims)),
        provider="test",
        model="test",
        prompt_profile="baseline",
        metadata_channel="json_slot",
        started_at=now,
        ended_at=now,
        latency_ms=0.0,
    )


def _measured(value: float) -> Claim:
    return Claim(
        statement="Short, balanced exchange.",
        evidence_source=TrustLevel.MEASURED,
        evidence_field="flow_duration",
        evidence_value=value,
        decisive=True,
    )


def test_grounded_ignore_is_accepted(store: TwinStore):
    result = ProvenanceVerifier(store=store).verify(_trace(Verdict.IGNORE, _measured(DURATION)))
    assert not result.overridden
    assert result.final_verdict is Verdict.IGNORE
    assert result.claim_verdicts[0].status is ClaimStatus.GROUNDED


def test_contradicted_decisive_claim_cannot_clear_a_flow(store: TwinStore):
    """The agent says the 16 s beacon lasted 0.02 s. The twin measured otherwise."""
    result = ProvenanceVerifier(store=store).verify(_trace(Verdict.IGNORE, _measured(0.02)))
    assert result.claim_verdicts[0].status is ClaimStatus.CONTRADICTED
    assert result.overridden
    assert result.final_verdict is Verdict.FLAG


def test_untrusted_decisive_claim_cannot_clear_a_flow(store: TwinStore):
    claim = Claim(
        statement="SNI says the destination is approved.",
        evidence_source=TrustLevel.UNTRUSTED,
        evidence_field="sni",
        decisive=True,
    )
    result = ProvenanceVerifier(store=store).verify(_trace(Verdict.IGNORE, claim))
    assert result.overridden
    assert result.final_verdict is Verdict.FLAG


def test_twin_ablation_weakens_the_verifier(store: TwinStore):
    """Without the measured anchor a false number goes unnoticed — that is the twin's delta."""
    trace = _trace(Verdict.IGNORE, _measured(0.02))
    with_twin = ProvenanceVerifier(store=store, use_twin=True).verify(trace)
    without_twin = ProvenanceVerifier(store=store, use_twin=False).verify(trace)
    assert with_twin.overridden
    assert not without_twin.overridden


def test_escalations_are_never_overridden(store: TwinStore):
    result = ProvenanceVerifier(store=store).verify(_trace(Verdict.BLOCK, _measured(0.02)))
    assert not result.overridden
    assert result.final_verdict is Verdict.BLOCK
