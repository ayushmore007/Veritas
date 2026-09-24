"""Phase 8c ensemble — combine the ML baseline's probability with the agent's verdict.

The two detectors fail in different directions: the ML model never reads a justification, so
Phase 7 cannot touch it; the agent reasons over several features at once, so Phase 6 moves it
less. `or_flag` (the default) clears a flow only when *both* are fooled — the right asymmetry when
the attacker's goal is `ignore`. It buys attack resistance with false positives; Phase 9 reports
both numbers.
"""

from __future__ import annotations

from dataclasses import dataclass

from veritas.agent.schema import Verdict

STRATEGIES: tuple[str, ...] = ("or_flag", "and_flag", "ml_only", "agent_only")
DEFAULT_STRATEGY = "or_flag"
DEFAULT_THRESHOLD = 0.5


@dataclass(frozen=True)
class EnsembleDecision:
    detected: bool
    ml_detected: bool
    agent_detected: bool
    strategy: str


def combine(
    ml_malicious_probability: float,
    agent_verdict: Verdict,
    *,
    strategy: str = DEFAULT_STRATEGY,
    threshold: float = DEFAULT_THRESHOLD,
) -> EnsembleDecision:
    """Detected means "not cleared": ML above threshold and/or agent verdict block/flag."""
    if strategy not in STRATEGIES:
        raise ValueError(f"Unknown ensemble strategy {strategy!r}; expected one of {STRATEGIES}")
    ml = ml_malicious_probability >= threshold
    agent = agent_verdict is not Verdict.IGNORE
    detected = {
        "or_flag": ml or agent,
        "and_flag": ml and agent,
        "ml_only": ml,
        "agent_only": agent,
    }[strategy]
    return EnsembleDecision(detected, ml, agent, strategy)
