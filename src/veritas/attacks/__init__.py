"""Phases 6–7: statistical evasion and reasoning-manipulation attacks."""

from veritas.attacks.injection import (
    InjectionPayload,
    grammar_valid_payloads,
    grounding_aware_payloads,
    held_out_payloads,
    naive_payloads,
)

__all__ = [
    "InjectionPayload",
    "grammar_valid_payloads",
    "grounding_aware_payloads",
    "held_out_payloads",
    "naive_payloads",
]
