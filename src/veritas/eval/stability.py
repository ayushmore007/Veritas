"""Decision-stability measurement for the LLM defender.

An LLM at temperature 0 is still not deterministic in practice — sampling, batching and server
state all move it. A defender that returns `block` on one run and `ignore` on the next is not a
detector with some accuracy; it is a coin flip, and any single-run metric computed from it is a
draw from a distribution nobody reported.

So: run each flow N times, report the verdict distribution, and treat instability as a finding in
its own right. Anything below `STABLE_AGREEMENT` on modal agreement means single-run numbers for
that flow should not be quoted.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

#: Modal-verdict agreement below this makes single-run metrics unreportable for that flow.
STABLE_AGREEMENT = 0.9


def measure_stability(
    agent: Any,
    flow_ids: list[str],
    *,
    repeats: int = 5,
) -> dict[str, Any]:
    """Triage each flow `repeats` times; report per-flow and overall verdict agreement."""
    if repeats < 2:
        raise ValueError("stability needs at least 2 repeats")

    per_flow: list[dict[str, Any]] = []
    for flow_id in flow_ids:
        verdicts: list[str] = []
        attack_guesses: list[str | None] = []
        latencies: list[float] = []
        parse_errors = 0

        for _ in range(repeats):
            trace = agent.triage(flow_id)
            verdicts.append(trace.decision.verdict.value)
            attack_guesses.append(trace.decision.attack_type_guess)
            latencies.append(trace.latency_ms)
            if trace.parse_error:
                parse_errors += 1

        counts = Counter(verdicts)
        modal, modal_n = counts.most_common(1)[0]
        agreement = modal_n / repeats
        per_flow.append(
            {
                "flow_id": flow_id,
                "repeats": repeats,
                "verdict_distribution": dict(counts),
                "modal_verdict": modal,
                "agreement": round(agreement, 4),
                "stable": agreement >= STABLE_AGREEMENT,
                "attack_type_distribution": dict(Counter(str(a) for a in attack_guesses)),
                "parse_errors": parse_errors,
                "latency_ms_mean": round(sum(latencies) / len(latencies), 2),
            }
        )

    unstable = [f for f in per_flow if not f["stable"]]
    mean_agreement = (
        round(sum(f["agreement"] for f in per_flow) / len(per_flow), 4) if per_flow else None
    )

    return {
        "flows": len(per_flow),
        "repeats": repeats,
        "mean_agreement": mean_agreement,
        "stable_threshold": STABLE_AGREEMENT,
        "unstable_flows": [f["flow_id"] for f in unstable],
        "verdict": (
            "Decisions are stable enough to quote single-run metrics."
            if not unstable
            else f"{len(unstable)} of {len(per_flow)} flows flip verdicts across runs. Report "
            "modal verdicts over N runs, or report the distribution — a single run is not a result."
        ),
        "note": (
            "A deterministic provider trivially scores 1.0 here; this measurement is only "
            "meaningful against a real model."
        ),
        "per_flow": per_flow,
    }
