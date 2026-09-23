"""Phase 4 smoke metrics: agent verdicts vs the twin's ground-truth oracle.

This is **not** the Phase 9 evaluation. It exists so a Phase 4 run can be sanity-checked on the
five Phase 1 scenarios. Five flows cannot support a detection-rate claim, and the deterministic
provider's thresholds were fitted on exactly these flows, so its score here is a tautology. Both
caveats are emitted in the result payload rather than left to the reader's memory.

Verdict → detection mapping: `block` and `flag` count as "detected as suspicious", `ignore` counts
as "cleared". That is the mapping the threat model uses — the attacker's goal is `ignore`.
"""

from __future__ import annotations

from typing import Any

from veritas.agent.schema import ReasoningTrace, Verdict
from veritas.eval.splits import assess_sufficiency
from veritas.twin.store import TwinStore


def _is_detected(verdict: Verdict) -> bool:
    return verdict in (Verdict.BLOCK, Verdict.FLAG)


def score_traces(
    store: TwinStore,
    traces: list[ReasoningTrace],
    *,
    split: str | None = None,
) -> dict[str, Any]:
    tp = fp = tn = fn = 0
    per_flow: list[dict[str, Any]] = []
    attack_type_correct = 0
    attack_total = 0
    ungrounded_ignores = 0

    for trace in traces:
        flow = store.get_flow(trace.flow_id)
        if flow is None:
            continue
        truth = flow["ground_truth"]
        is_malicious = truth.get("traffic_class") == "malicious"
        detected = _is_detected(trace.decision.verdict)

        if is_malicious and detected:
            tp += 1
        elif is_malicious and not detected:
            fn += 1
        elif not is_malicious and detected:
            fp += 1
        else:
            tn += 1

        if is_malicious:
            attack_total += 1
            if trace.decision.attack_type_guess == truth.get("attack_type"):
                attack_type_correct += 1

        # Provenance health: an `ignore` resting only on untrusted evidence is the exact failure
        # Phase 8b is built to catch. Counting it here gives a baseline before the verifier exists.
        if trace.decision.verdict is Verdict.IGNORE:
            decisive = trace.decision.decisive_claims()
            if decisive and not any(c.is_groundable() for c in decisive):
                ungrounded_ignores += 1

        per_flow.append(
            {
                "flow_id": trace.flow_id,
                "scenario_id": truth.get("scenario_id"),
                "truth": truth.get("traffic_class"),
                "attack_type": truth.get("attack_type"),
                "verdict": trace.decision.verdict.value,
                "attack_type_guess": trace.decision.attack_type_guess,
                "confidence": trace.decision.confidence,
                "decisive_untrusted_claims": len(trace.decision.untrusted_decisive_claims()),
                "parse_error": trace.parse_error,
            }
        )

    total = tp + fp + tn + fn
    benign_total = fp + tn
    malicious_total = tp + fn

    sufficiency = assess_sufficiency(
        {"benign": benign_total, "malicious": malicious_total},
        split=split or "scored set",
    )

    return {
        "split": split or "all recorded traces (NOT a held-out test set)",
        "sufficiency": sufficiency,
        "caveat": (
            "Phase 4 smoke check on a 5-flow testbed, not a detection result. "
            "Real numbers come from Phase 9 with a real model and a larger capture."
        ),
        "simulacrum_warning": (
            "If provider == 'deterministic', these thresholds were fitted on these same flows; "
            "the score is circular by construction."
        ),
        "reportable": sufficiency["supports_rates"] and split == "test",
        "flows_scored": total,
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        # Rates are withheld, not rounded, when the split cannot support them — a number on the
        # page gets quoted regardless of the caveat beside it.
        "detection_rate": (
            round(tp / malicious_total, 4)
            if malicious_total and sufficiency["supports_rates"]
            else None
        ),
        "false_positive_rate": (
            round(fp / benign_total, 4) if benign_total and sufficiency["supports_rates"] else None
        ),
        "attack_success_rate": (
            round(fn / malicious_total, 4)
            if malicious_total and sufficiency["supports_rates"]
            else None
        ),
        "attack_type_accuracy": (
            round(attack_type_correct / attack_total, 4) if attack_total else None
        ),
        "ungrounded_ignore_verdicts": ungrounded_ignores,
        "per_flow": per_flow,
    }
