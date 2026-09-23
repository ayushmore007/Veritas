"""Phase 4 reason-act loop for the defender agent.

Reimplemented from the IDS-Agent paper description (no official code release — see
`docs/license-audit.md`). Shape: bounded tool space over the Tier-1 twin, an observe → reason →
act cycle capped at `max_steps`, and a structured verdict carrying provenance-tagged claims.

Failure behaviour is deliberate. When the model returns something unparseable, the agent emits
`flag` with confidence 0 and records `parse_error`. Failing to `ignore` would silently clear
traffic on a malformed response — a defect an attacker could farm by pushing the model off-format.
Failing to `block` would break every benign flow on any model hiccup. `flag` escalates to a human,
which is the honest answer to "the defender did not produce a usable decision".
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from veritas.agent.llm import LLMError, LLMProvider
from veritas.agent.prompt import build_observation_prompt, build_system_prompt
from veritas.agent.schema import (
    AgentDecision,
    Claim,
    ReasoningTrace,
    TrustLevel,
    Verdict,
    utcnow,
)
from veritas.agent.tools import AgentToolbox

logger = logging.getLogger(__name__)

_JSON_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)


def extract_json_object(text: str) -> dict[str, Any]:
    """Pull one JSON object out of a model response (bare, fenced, or embedded in prose)."""
    text = (text or "").strip()
    if not text:
        raise ValueError("empty response")

    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    fenced = _JSON_FENCE.search(text)
    if fenced:
        try:
            parsed = json.loads(fenced.group(1))
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass

    start = text.find("{")
    while start != -1:
        depth = 0
        for i in range(start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        parsed = json.loads(text[start : i + 1])
                        if isinstance(parsed, dict):
                            return parsed
                    except json.JSONDecodeError:
                        break
        start = text.find("{", start + 1)

    raise ValueError("no JSON object found in response")


def _coerce_claims(raw: Any) -> list[Claim]:
    """Accept whatever the model produced; drop what cannot be made into a checkable claim."""
    claims: list[Claim] = []
    if not isinstance(raw, list):
        return claims
    for item in raw:
        if not isinstance(item, dict):
            continue
        statement = str(item.get("statement", "")).strip()
        if not statement:
            continue
        source_raw = str(item.get("evidence_source", "prior")).lower()
        try:
            source = TrustLevel(source_raw)
        except ValueError:
            # An unrecognised provenance label is not evidence of trustworthiness.
            source = TrustLevel.PRIOR
        field = item.get("evidence_field")
        claims.append(
            Claim(
                statement=statement,
                evidence_source=source,
                evidence_field=str(field) if field else None,
                evidence_value=item.get("evidence_value"),
                decisive=bool(item.get("decisive", False)),
            )
        )
    return claims


class DefenderAgent:
    """LLM defender that triages one flow at a time against the twin oracle."""

    def __init__(
        self,
        toolbox: AgentToolbox,
        provider: LLMProvider,
        *,
        prompt_profile: str = "baseline",
        metadata_channel: str = "json_slot",
        max_steps: int = 4,
        seed_with_flow_stats: bool = True,
    ) -> None:
        self.toolbox = toolbox
        self.provider = provider
        self.prompt_profile = prompt_profile
        self.metadata_channel = metadata_channel
        self.max_steps = max_steps
        # Engineering choice, not a defense: the first observation is always measured, so a run
        # cannot end without the agent having seen instrumentation data. Phase 7 can set this
        # False to test whether a model will decide from metadata alone.
        self.seed_with_flow_stats = seed_with_flow_stats

    # -- tool dispatch ----------------------------------------------------

    def _dispatch(self, tool: str, arguments: dict[str, Any], flow_id: str) -> dict[str, Any]:
        if tool == "get_flow_stats":
            return self.toolbox.get_flow_stats(str(arguments.get("flow_id") or flow_id))
        if tool == "get_metadata":
            return self.toolbox.get_metadata(str(arguments.get("flow_id") or flow_id))
        if tool == "get_host_history":
            ref = arguments.get("peer_ref") or arguments.get("ip")
            if not ref:
                raise ValueError("get_host_history requires a 'peer_ref' argument")
            return self.toolbox.get_host_history(str(ref), limit=int(arguments.get("limit", 20)))
        raise ValueError(f"Unknown tool: {tool!r}")

    # -- main loop --------------------------------------------------------

    def triage(self, flow_id: str) -> ReasoningTrace:
        started = utcnow()
        self.toolbox.reset()

        system = build_system_prompt(self.toolbox.describe(), profile=self.prompt_profile)
        observations: list[dict[str, Any]] = []
        seen_calls: set[tuple[str, str]] = set()
        raw_response = ""
        parse_error: str | None = None
        decision: AgentDecision | None = None

        if self.seed_with_flow_stats:
            observations.append(
                {"tool": "get_flow_stats", "payload": self.toolbox.get_flow_stats(flow_id)}
            )
            seen_calls.add(("get_flow_stats", flow_id))

        for step in range(1, self.max_steps + 1):
            user = build_observation_prompt(
                flow_id,
                observations,
                metadata_channel=self.metadata_channel,
                step=step,
                max_steps=self.max_steps,
            )
            context = {
                "flow_id": flow_id,
                "observations": observations,
                "metadata_seen": any(o["tool"] == "get_metadata" for o in observations),
            }

            try:
                raw_response = self.provider.complete(system, user, context=context)
            except LLMError as exc:
                parse_error = f"llm_error: {exc}"
                break

            try:
                parsed = extract_json_object(raw_response)
            except ValueError as exc:
                parse_error = f"unparseable_response: {exc}"
                break

            action = str(parsed.get("action", "final")).lower()

            if action == "call_tool" and step >= self.max_steps:
                # Out of budget while still gathering evidence. Report that honestly rather than
                # letting it surface as a malformed final answer.
                parse_error = "step_budget_exhausted_without_verdict"
                break

            if action == "call_tool":
                tool = str(parsed.get("tool", ""))
                arguments = parsed.get("arguments") or {}
                if not isinstance(arguments, dict):
                    arguments = {}
                key = (tool, json.dumps(arguments, sort_keys=True, default=str))
                if key in seen_calls:
                    # Repeating an identical call cannot add evidence; force a decision instead of
                    # burning the step budget in a loop.
                    observations.append(
                        {
                            "tool": tool,
                            "payload": {
                                "trust_level": TrustLevel.MEASURED.value,
                                "error": "This tool was already called with these arguments.",
                            },
                        }
                    )
                    continue
                seen_calls.add(key)
                try:
                    payload = self._dispatch(tool, arguments, flow_id)
                except (ValueError, KeyError) as exc:
                    payload = {"trust_level": TrustLevel.MEASURED.value, "error": str(exc)}
                observations.append({"tool": tool, "payload": payload})
                continue

            # Anything else is treated as a final answer.
            try:
                verdict = Verdict(str(parsed.get("verdict", "")).lower())
            except ValueError:
                parse_error = f"invalid_verdict: {parsed.get('verdict')!r}"
                break

            try:
                confidence = float(parsed.get("confidence", 0.5))
            except (TypeError, ValueError):
                confidence = 0.5

            attack_type = parsed.get("attack_type")
            decision = AgentDecision(
                flow_id=flow_id,
                verdict=verdict,
                confidence=max(0.0, min(1.0, confidence)),
                attack_type_guess=str(attack_type) if attack_type else None,
                claims=_coerce_claims(parsed.get("claims")),
                rationale=str(parsed.get("rationale", ""))[:2000],
            )
            break

        if decision is None:
            if parse_error is None:
                parse_error = "step_budget_exhausted_without_verdict"
            logger.warning("Agent produced no verdict for %s (%s)", flow_id, parse_error)
            decision = AgentDecision(
                flow_id=flow_id,
                verdict=Verdict.FLAG,
                confidence=0.0,
                rationale="No usable verdict from the model; escalated for human review.",
            )

        metadata_exposed: dict[str, Any] = {}
        for obs in observations:
            if obs["tool"] == "get_metadata":
                metadata_exposed = obs["payload"].get("metadata", {})

        ended = utcnow()
        return ReasoningTrace(
            flow_id=flow_id,
            decision=decision,
            tool_calls=list(self.toolbox.calls),
            provider=self.provider.name,
            model=self.provider.model,
            prompt_profile=self.prompt_profile,
            metadata_channel=self.metadata_channel,
            metadata_exposed=metadata_exposed,
            started_at=started,
            ended_at=ended,
            latency_ms=round((ended - started).total_seconds() * 1000, 2),
            raw_response=raw_response[:8000],
            parse_error=parse_error,
        )
