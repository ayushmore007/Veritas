"""Phase 4 agent data model: verdicts, provenance-tagged claims, and reasoning traces.

Design rule (from the threat model): a verdict is never trusted on its own. Every decisive
statement the agent makes must be an *atomic claim* carrying the trust level of the evidence it
rests on, so the Phase 8b verifier can re-check each claim against the twin oracle instead of
sentiment-matching free text. This is why the agent is required to emit `claims`, not prose.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class Verdict(str, Enum):
    """Defender actions, ordered by severity — see `SEVERITY`."""

    BLOCK = "block"
    FLAG = "flag"
    IGNORE = "ignore"


SEVERITY: dict[Verdict, int] = {Verdict.IGNORE: 0, Verdict.FLAG: 1, Verdict.BLOCK: 2}


class TrustLevel(str, Enum):
    """Where a piece of evidence came from, in the sense of `docs/threat-model.md`."""

    MEASURED = "measured"      # twin oracle, derived from instrumentation
    UNTRUSTED = "untrusted"    # attacker-controllable strings (SNI, ALPN)
    PRIOR = "prior"            # model background knowledge — verifiable by nothing in the twin


class Claim(BaseModel):
    """One atomic, checkable statement backing a verdict."""

    statement: str
    evidence_source: TrustLevel
    evidence_field: str | None = None
    evidence_value: Any = None
    decisive: bool = False

    def is_groundable(self) -> bool:
        """True when the claim names a field a verifier could look up in the twin."""
        return self.evidence_source is TrustLevel.MEASURED and bool(self.evidence_field)


class ToolCall(BaseModel):
    """One observation the agent made, with the trust level of what it received."""

    step: int
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    trust_level: TrustLevel
    result_keys: list[str] = Field(default_factory=list)
    error: str | None = None


class AgentDecision(BaseModel):
    flow_id: str
    verdict: Verdict
    confidence: float = 0.5
    attack_type_guess: str | None = None
    claims: list[Claim] = Field(default_factory=list)
    rationale: str = ""

    def decisive_claims(self) -> list[Claim]:
        return [c for c in self.claims if c.decisive]

    def untrusted_decisive_claims(self) -> list[Claim]:
        """Claims that drove the verdict but rest on attacker-controllable data.

        Phase 8b's provenance rule (`config/trust_labels.yaml`) refuses an `ignore` verdict when
        this list is non-empty.
        """
        return [c for c in self.decisive_claims() if c.evidence_source is not TrustLevel.MEASURED]


class ReasoningTrace(BaseModel):
    """Full record of one triage, sufficient to replay and audit the decision."""

    trace_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    flow_id: str
    decision: AgentDecision
    tool_calls: list[ToolCall] = Field(default_factory=list)

    provider: str
    model: str
    prompt_profile: str
    metadata_channel: str

    # What untrusted content actually reached the prompt this run. Phase 7 mutates exactly this;
    # Phase 8b's ablation replay strips exactly this.
    metadata_exposed: dict[str, Any] = Field(default_factory=dict)

    started_at: datetime
    ended_at: datetime
    latency_ms: float
    raw_response: str = ""
    parse_error: str | None = None

    def to_jsonl(self) -> str:
        return self.model_dump_json()


class TraceRegistry:
    """Append-only reasoning-trace store (`data/processed/agent/traces.jsonl`)."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, trace: ReasoningTrace) -> ReasoningTrace:
        with self.path.open("a", encoding="utf-8") as f:
            f.write(trace.to_jsonl() + "\n")
        return trace

    def load_all(self) -> list[ReasoningTrace]:
        if not self.path.is_file():
            return []
        out: list[ReasoningTrace] = []
        with self.path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    out.append(ReasoningTrace.model_validate_json(line))
        return out


def utcnow() -> datetime:
    return datetime.now(UTC)
