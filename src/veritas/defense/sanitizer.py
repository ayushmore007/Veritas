"""Phase 8a input sanitization — patterns from StruQ / Spotlighting (reimplemented; cite only)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from veritas.agent.tools import sanitize_metadata_value

# Hostname grammar: reject bracket annotations and obvious instruction carriers.
_INVALID_HOST = re.compile(r"[\[\]<>]|//|ignore\s+previous|SYSTEM:|VERIFIED|audit\s+mode", re.I)
_IMPERATIVE = re.compile(
    r"(ignore\s+previous|classify\s+this\s+flow\s+as|you\s+are\s+now|verdict\s*:|\{\s*\"tool\")",
    re.I,
)


@dataclass
class SanitizeResult:
    field: str
    original: Any
    cleaned: Any
    quarantined: bool
    reason: str | None = None


class Sanitizer:
    """Strip/quarantine untrusted metadata before it reaches the agent prompt."""

    def __init__(self, *, enabled: bool = True) -> None:
        self.enabled = enabled

    def apply(self, metadata: dict[str, Any]) -> tuple[dict[str, Any], list[SanitizeResult]]:
        if not self.enabled:
            return dict(metadata), []

        out: dict[str, Any] = {}
        results: list[SanitizeResult] = []

        for field, value in metadata.items():
            cleaned = sanitize_metadata_value(value)
            quarantined = False
            reason = None

            if field == "sni" and isinstance(cleaned, str):
                if _INVALID_HOST.search(cleaned) or _IMPERATIVE.search(cleaned):
                    quarantined = True
                    reason = "hostname_grammar_or_instruction_pattern"
                    cleaned = "[quarantined-by-sanitizer]"

            out[field] = cleaned
            results.append(
                SanitizeResult(
                    field=field,
                    original=value,
                    cleaned=cleaned,
                    quarantined=quarantined,
                    reason=reason,
                )
            )

        return out, results
