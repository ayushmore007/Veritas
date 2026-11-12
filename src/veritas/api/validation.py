"""Request validation shared by the API and the legacy `web/server.py` helpers."""

from __future__ import annotations

from typing import Any

MAX_TARGET_LEN = 253 + len("https://") + len(":65535/")
MAX_PREVENTION_KEY_LEN = 64


class BadRequest(ValueError):
    """Client sent something the API cannot act on (HTTP 4xx)."""

    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


def parse_port(value: Any, default: int) -> int:
    if value is None or value == "":
        return default
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise BadRequest(f"invalid port: {value!r}") from exc
    if not 1 <= port <= 65535:
        raise BadRequest(f"port out of range: {port}")
    return port


def parse_target(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BadRequest("target must be a non-empty string")
    value = value.strip()
    if len(value) > MAX_TARGET_LEN or any(ch.isspace() for ch in value):
        raise BadRequest("target is not a valid host or URL")
    return value
