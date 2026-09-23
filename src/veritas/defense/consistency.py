"""Consistency baseline — fact-check decisive claims against the twin (PromptSleuth-style prior art)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from veritas.agent.schema import ReasoningTrace, Verdict
from veritas.twin.query import get_flow_stats
from veritas.twin.store import TwinStore

TOLERANCE = 0.05


@dataclass
class ConsistencyResult:
    overridden: bool
    final_verdict: Verdict
    detail: str = ""


class ConsistencyChecker:
    """Reject a clearance only when a stated numeric fact contradicts the twin."""

    def __init__(self, *, store: TwinStore) -> None:
        self.store = store

    def _twin_value(self, flow_id: str, field: str) -> Any:
        stats = get_flow_stats(self.store, flow_id)
        return stats["features"].get(field)

    def check(self, trace: ReasoningTrace) -> ConsistencyResult:
        decision = trace.decision
        if decision.verdict is not Verdict.IGNORE:
            return ConsistencyResult(False, decision.verdict)

        for claim in decision.decisive_claims():
            if not claim.evidence_field or claim.evidence_value is None:
                continue
            observed = self._twin_value(trace.flow_id, claim.evidence_field)
            if observed is None:
                continue
            try:
                stated = float(claim.evidence_value)
                actual = float(observed)
            except (TypeError, ValueError):
                continue
            denom = max(abs(actual), 1e-9)
            if abs(stated - actual) / denom > TOLERANCE:
                return ConsistencyResult(
                    True,
                    Verdict.FLAG,
                    f"Claim contradicts twin for {claim.evidence_field}: "
                    f"stated {stated}, observed {actual}",
                )

        return ConsistencyResult(False, decision.verdict, "All checkable facts consistent with twin.")
