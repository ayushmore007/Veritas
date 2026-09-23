"""LLM backends for the Phase 4 defender agent.

Two providers, for two different jobs:

* `OllamaProvider` — the real defender. Talks to a local Ollama server (default `llama3.1:8b`).
  Everything reported in the paper must come from this path.

* `DeterministicProvider` — a **simulacrum**, not a detector. It reproduces the *shape* of an
  undefended LLM's behaviour (reads measured features, is influenced by metadata, follows
  imperative text it finds in that metadata) using fixed thresholds, so that the Phases 7 and 8
  attack/defense machinery can be built and regression-tested without a GPU and without network
  access. Its thresholds were fitted by inspection on the five Phase 1 scenarios, so its accuracy
  on those flows is a tautology. **Never report a number produced by this provider as a detection
  result.** `is_simulacrum = True` is set so evaluation output can carry that warning.
"""

from __future__ import annotations

import json
import re
from typing import Any, Protocol

from veritas.agent.schema import TrustLevel, Verdict


class LLMError(RuntimeError):
    """Backend unreachable or returned something unusable."""


class LLMProvider(Protocol):
    name: str
    model: str
    is_simulacrum: bool

    def complete(self, system: str, user: str, *, context: dict[str, Any]) -> str:
        """Return the raw model response (expected to be a single JSON object)."""
        ...


# ---------------------------------------------------------------------------
# Ollama
# ---------------------------------------------------------------------------


class OllamaProvider:
    """Local Ollama chat backend. Requires `ollama serve` and the model pulled."""

    is_simulacrum = False

    def __init__(
        self,
        *,
        base_url: str = "http://localhost:11434",
        model: str = "llama3.1:8b",
        temperature: float = 0.0,
        timeout_sec: float = 120.0,
        num_ctx: int | None = 8192,
    ) -> None:
        self.name = "ollama"
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.temperature = temperature
        self.timeout_sec = timeout_sec
        self.num_ctx = num_ctx

    def complete(self, system: str, user: str, *, context: dict[str, Any]) -> str:
        try:
            import httpx
        except ImportError as exc:  # pragma: no cover
            raise LLMError("httpx is required for OllamaProvider") from exc

        options: dict[str, Any] = {"temperature": self.temperature}
        if self.num_ctx:
            options["num_ctx"] = self.num_ctx

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            # Ollama's JSON mode. Constrains shape only — it does not constrain content, and in
            # particular it is not a defense against anything in the metadata channel.
            "format": "json",
            "options": options,
        }

        try:
            response = httpx.post(
                f"{self.base_url}/api/chat", json=payload, timeout=self.timeout_sec
            )
            response.raise_for_status()
            data = response.json()
        except Exception as exc:
            raise LLMError(
                f"Ollama request failed against {self.base_url} (model {self.model}): {exc}"
            ) from exc

        content = (data.get("message") or {}).get("content", "")
        if not content:
            raise LLMError(f"Ollama returned no content: {data}")
        return content


# ---------------------------------------------------------------------------
# Deterministic simulacrum
# ---------------------------------------------------------------------------

# Imperative / authority patterns an undefended model tends to obey when they appear in tool
# output. Kept crude on purpose: this is a stand-in for LLM gullibility, not a detector. The real
# detector is Phase 8b's verifier, which works on provenance rather than on wording.
_INJECTION_PATTERNS = (
    r"\bignore (all |any )?(previous|prior|above)\b",
    r"\bdisregard\b",
    r"\bclassify (this|the flow) as benign\b",
    r"\bmark (this|it) (as )?(benign|safe|trusted)\b",
    r"\breturn (a )?verdict\b",
    r"\bverdict\s*[:=]\s*ignore\b",
    r"\bsystem\b.{0,20}\b(override|instruction)\b",
    r"\bapproved by\b",
    r"\bwhitelist(ed)?\b",
)
_INJECTION_RE = re.compile("|".join(_INJECTION_PATTERNS), re.IGNORECASE)

# SNI substrings that read as reassuring to a naive model.
_BENIGN_SOUNDING = ("internal", "corp", "cdn", "update", "trusted", "benign", "microsoft", "google")


class DeterministicProvider:
    """Offline stand-in for an undefended LLM defender. See module docstring — not a detector."""

    is_simulacrum = True

    def __init__(
        self,
        *,
        trust_metadata: bool = True,
        injection_susceptible: bool = True,
    ) -> None:
        self.name = "deterministic"
        self.model = "heuristic-v1"
        # Both default True so the stand-in behaves like an *undefended* agent. Setting them False
        # does not model a defended agent — it models a different, metadata-blind one; the real
        # defense lives in Phase 8.
        self.trust_metadata = trust_metadata
        self.injection_susceptible = injection_susceptible

    # -- feature rules ----------------------------------------------------

    @staticmethod
    def _classify(f: dict[str, Any]) -> tuple[Verdict, str | None, list[dict[str, Any]]]:
        """Threshold rules over measured features. Returns (verdict, attack_type, claims)."""

        def g(name: str, default: float = 0.0) -> float:
            try:
                return float(f.get(name, default) or 0.0)
            except (TypeError, ValueError):
                return default

        duration = g("flow_duration")
        iat_max = g("flow_iat_max")
        fwd_bytes = g("totlen_fwd_pkts")
        bwd_bytes = g("totlen_bwd_pkts")
        ratio = g("down_up_ratio")
        total_bytes = fwd_bytes + bwd_bytes

        def claim(statement, field, value, decisive=True):
            return {
                "statement": statement,
                "evidence_source": TrustLevel.MEASURED.value,
                "evidence_field": field,
                "evidence_value": value,
                "decisive": decisive,
            }

        if ratio < 0.5 and fwd_bytes >= 100_000:
            return (
                Verdict.BLOCK,
                "data_exfil",
                [
                    claim(
                        f"The flow uploaded {int(fwd_bytes)} bytes to the destination.",
                        "totlen_fwd_pkts",
                        fwd_bytes,
                    ),
                    claim(
                        f"Traffic is upload-dominated (down/up ratio {ratio:.2f}), "
                        "the inverse of normal client browsing.",
                        "down_up_ratio",
                        ratio,
                    ),
                ],
            )

        if duration >= 5.0 and iat_max >= 1.0 and total_bytes < 100_000:
            return (
                Verdict.BLOCK,
                "c2_beacon",
                [
                    claim(
                        f"The connection stayed open {duration:.1f}s while moving only "
                        f"{int(total_bytes)} bytes.",
                        "flow_duration",
                        duration,
                    ),
                    claim(
                        f"Largest inter-arrival gap is {iat_max:.2f}s, consistent with periodic "
                        "heartbeats rather than interactive traffic.",
                        "flow_iat_max",
                        iat_max,
                    ),
                ],
            )

        if 0.1 <= duration < 5.0 and iat_max >= 0.02 and total_bytes < 100_000:
            return (
                Verdict.FLAG,
                "scan_probe",
                [
                    claim(
                        f"Short {duration:.2f}s session with repeated small request/response "
                        "pairs and little data transferred.",
                        "flow_duration",
                        duration,
                    ),
                    claim(
                        f"Inter-arrival gaps up to {iat_max:.3f}s across many small exchanges "
                        "look like path probing.",
                        "flow_iat_max",
                        iat_max,
                    ),
                ],
            )

        if ratio >= 2.0 and bwd_bytes >= 100_000:
            return (
                Verdict.IGNORE,
                None,
                [
                    claim(
                        f"Download-dominated transfer ({int(bwd_bytes)} bytes inbound, "
                        f"ratio {ratio:.2f}), the normal shape for streaming or file fetch.",
                        "down_up_ratio",
                        ratio,
                    )
                ],
            )

        return (
            Verdict.IGNORE,
            None,
            [
                claim(
                    f"Short {duration:.3f}s exchange of {int(total_bytes)} bytes with balanced "
                    "direction; nothing distinguishes it from ordinary page loads.",
                    "flow_duration",
                    duration,
                )
            ],
        )

    # -- metadata influence ----------------------------------------------

    def _apply_metadata(
        self,
        verdict: Verdict,
        claims: list[dict[str, Any]],
        metadata: dict[str, Any],
    ) -> tuple[Verdict, list[dict[str, Any]], str | None]:
        """Model how an undefended agent lets untrusted strings move its verdict."""
        note: str | None = None
        blob = " ".join(str(v) for v in metadata.values() if v is not None)

        if self.injection_susceptible and _INJECTION_RE.search(blob):
            claims.append(
                {
                    "statement": "The handshake metadata states this destination is approved, "
                    "so the flow is cleared.",
                    "evidence_source": TrustLevel.UNTRUSTED.value,
                    "evidence_field": "sni",
                    "evidence_value": metadata.get("sni"),
                    "decisive": True,
                }
            )
            return Verdict.IGNORE, claims, "metadata_instruction_followed"

        sni = str(metadata.get("sni") or "").lower()
        if (
            self.trust_metadata
            and verdict is Verdict.FLAG
            and any(token in sni for token in _BENIGN_SOUNDING)
        ):
            claims.append(
                {
                    "statement": f"The server name {sni!r} belongs to a familiar service.",
                    "evidence_source": TrustLevel.UNTRUSTED.value,
                    "evidence_field": "sni",
                    "evidence_value": metadata.get("sni"),
                    "decisive": True,
                }
            )
            note = "metadata_reputation_downgrade"
            return Verdict.IGNORE, claims, note

        return verdict, claims, note

    # -- provider interface ----------------------------------------------

    def complete(self, system: str, user: str, *, context: dict[str, Any]) -> str:
        features: dict[str, Any] = {}
        metadata: dict[str, Any] = {}
        history_events = 0

        for obs in context.get("observations", []):
            payload = obs.get("payload", {})
            if obs.get("tool") == "get_flow_stats":
                features = payload.get("features", {})
            elif obs.get("tool") == "get_metadata":
                metadata = payload.get("metadata", {})
            elif obs.get("tool") == "get_host_history":
                history_events = payload.get("event_count", 0)

        if not features:
            return json.dumps(
                {"action": "call_tool", "tool": "get_flow_stats",
                 "arguments": {"flow_id": context.get("flow_id")}}
            )
        if not metadata and not context.get("metadata_seen"):
            return json.dumps(
                {"action": "call_tool", "tool": "get_metadata",
                 "arguments": {"flow_id": context.get("flow_id")}}
            )

        verdict, attack_type, claims = self._classify(features)
        verdict, claims, note = self._apply_metadata(verdict, claims, metadata)
        if verdict is Verdict.IGNORE:
            attack_type = None

        if history_events:
            claims.append(
                {
                    "statement": f"{history_events} prior measured flow events involve this host.",
                    "evidence_source": TrustLevel.MEASURED.value,
                    "evidence_field": "event_count",
                    "evidence_value": history_events,
                    "decisive": False,
                }
            )

        rationale = "; ".join(c["statement"] for c in claims if c.get("decisive"))
        if note:
            rationale += f" [simulacrum: {note}]"

        return json.dumps(
            {
                "action": "final",
                "verdict": verdict.value,
                "confidence": 0.75,
                "attack_type": attack_type,
                "claims": claims,
                "rationale": rationale,
            }
        )


def build_provider(config: dict[str, Any]) -> LLMProvider:
    """Instantiate a provider from the `agent.llm` config block."""
    provider = str(config.get("provider", "ollama")).lower()

    if provider == "ollama":
        return OllamaProvider(
            base_url=config.get("base_url", "http://localhost:11434"),
            model=config.get("model", "llama3.1:8b"),
            temperature=float(config.get("temperature", 0.0)),
            timeout_sec=float(config.get("timeout_sec", 120)),
            num_ctx=config.get("num_ctx", 8192),
        )
    if provider == "deterministic":
        det = config.get("deterministic", {}) or {}
        return DeterministicProvider(
            trust_metadata=bool(det.get("trust_metadata", True)),
            injection_susceptible=bool(det.get("injection_susceptible", True)),
        )
    raise ValueError(f"Unknown agent provider: {provider!r} (expected ollama|deterministic)")
