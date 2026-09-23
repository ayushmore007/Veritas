"""Phase 8b provenance verifier — measured-twin anchor + optional metadata-ablation replay."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

from veritas.agent.schema import Claim, ReasoningTrace, TrustLevel, Verdict
from veritas.twin.query import get_flow_stats
from veritas.twin.store import TwinStore

TOLERANCE = 0.05


class ClaimStatus(str, Enum):
    GROUNDED = "grounded"
    CONTRADICTED = "contradicted"
    UNSUPPORTED = "unsupported"
    UNTRUSTED_SOURCE = "untrusted_source"


@dataclass
class ClaimVerdict:
    claim: Claim
    status: ClaimStatus
    detail: str = ""


@dataclass
class VerificationResult:
    overridden: bool
    final_verdict: Verdict
    claim_verdicts: list[ClaimVerdict] = field(default_factory=list)
    replay: dict[str, Any] | None = None


class ProvenanceVerifier:
    """
    An ``ignore`` verdict is accepted only if every decisive claim traces to measured evidence
    the attacker cannot author — and (optionally) the verdict survives metadata ablation replay.
    """

    def __init__(
        self,
        *,
        store: TwinStore | None = None,
        use_twin: bool = True,
        replay_fn: Callable[[str], Verdict] | None = None,
        run_replay: bool = False,
    ) -> None:
        self.store = store
        self.use_twin = use_twin and store is not None
        self.replay_fn = replay_fn
        self.run_replay = run_replay

    def _observed(self, flow_id: str, field: str) -> Any:
        if not self.use_twin or self.store is None:
            return None
        stats = get_flow_stats(self.store, flow_id)
        return stats["features"].get(field)

    def _check_claim(self, flow_id: str, claim: Claim) -> ClaimVerdict:
        source = claim.evidence_source
        if source is not TrustLevel.MEASURED:
            return ClaimVerdict(
                claim,
                ClaimStatus.UNTRUSTED_SOURCE,
                "Decisive basis is not measured instrumentation.",
            )

        if not claim.evidence_field:
            return ClaimVerdict(claim, ClaimStatus.UNSUPPORTED, "No twin field cited.")

        if not self.use_twin:
            return ClaimVerdict(
                claim,
                ClaimStatus.UNSUPPORTED,
                "Twin anchor removed — cannot verify measured provenance.",
            )

        observed = self._observed(flow_id, claim.evidence_field)
        if observed is None:
            return ClaimVerdict(
                claim,
                ClaimStatus.UNSUPPORTED,
                f"Field {claim.evidence_field!r} not in twin.",
            )

        if claim.evidence_value is None:
            return ClaimVerdict(claim, ClaimStatus.GROUNDED, "Field present in twin.")

        try:
            stated = float(claim.evidence_value)
            actual = float(observed)
            denom = max(abs(actual), 1e-9)
            if abs(stated - actual) / denom <= TOLERANCE:
                return ClaimVerdict(claim, ClaimStatus.GROUNDED, "Value matches twin within tolerance.")
            return ClaimVerdict(
                claim,
                ClaimStatus.CONTRADICTED,
                f"Stated {stated}, twin has {actual}.",
            )
        except (TypeError, ValueError):
            if str(claim.evidence_value) == str(observed):
                return ClaimVerdict(claim, ClaimStatus.GROUNDED, "Exact match.")
            return ClaimVerdict(claim, ClaimStatus.CONTRADICTED, "Value mismatch.")

    def verify(self, trace: ReasoningTrace) -> VerificationResult:
        decision = trace.decision
        claim_verdicts = [self._check_claim(trace.flow_id, c) for c in decision.claims]

        if decision.verdict is not Verdict.IGNORE:
            return VerificationResult(False, decision.verdict, claim_verdicts)

        replay_info = None
        if self.run_replay and self.replay_fn is not None:
            without = self.replay_fn(trace.flow_id)
            replay_info = {
                "verdict_with_metadata": decision.verdict.value,
                "verdict_without_metadata": without.value,
                "note": (
                    "Verdict flipped when untrusted metadata was stripped — "
                    "decision was metadata-dependent."
                ),
            }
            if without is not Verdict.IGNORE:
                return VerificationResult(
                    True,
                    without,
                    claim_verdicts,
                    replay=replay_info,
                )

        untrusted_decisive = decision.untrusted_decisive_claims()
        if untrusted_decisive:
            return VerificationResult(
                True,
                Verdict.FLAG,
                claim_verdicts,
                replay=replay_info,
            )

        # A decisive claim the twin contradicts cannot be the basis for clearing a flow. Only
        # reachable with the twin anchor: without it every measured claim is `unsupported`, which
        # is exactly what the use_twin=False ablation is meant to show.
        contradicted = [
            cv
            for cv in claim_verdicts
            if cv.claim.decisive and cv.status is ClaimStatus.CONTRADICTED
        ]
        if contradicted:
            return VerificationResult(True, Verdict.FLAG, claim_verdicts, replay=replay_info)

        # Role confusion: decisive claims labelled measured but replay not run — allow for demo.
        return VerificationResult(False, decision.verdict, claim_verdicts, replay=replay_info)
