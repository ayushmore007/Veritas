"""Authentication, rate limiting and the scan-target guard.

Why this exists: the scanner actively probes whatever host it is given. On loopback that is the
user's own business; once the API is reachable from a phone it becomes a service that anyone with
the URL could aim at third parties — or at the server's own private network (SSRF). So:

* **Auth.** With `VERITAS_API_KEY` set, every protected route needs `X-API-Key`. Without it, only
  loopback clients are served, so an accidentally exposed port is inert rather than open.
* **Target guard.** Targets that resolve to private, loopback, link-local or metadata addresses are
  refused unless `VERITAS_ALLOW_PRIVATE_TARGETS=1` (the lab/own-network opt-in).
* **Rate limit.** Per-client token bucket on expensive routes.
* **Residual risk** (documented, not solved): a DNS name can resolve differently between this check
  and the scanner's own lookup (DNS rebinding). Do not expose an unauthenticated instance.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import secrets
import socket
import threading
import time
import urllib.parse

from fastapi import HTTPException, Request

LOOPBACK_CLIENTS = {"127.0.0.1", "::1", "localhost", "testclient"}


def configured_key() -> str | None:
    key = os.environ.get("VERITAS_API_KEY", "").strip()
    return key or None


def allow_private_targets() -> bool:
    return os.environ.get("VERITAS_ALLOW_PRIVATE_TARGETS", "").strip().lower() in ("1", "true", "yes")


def require_auth(request: Request) -> None:
    key = configured_key()
    if key is None:
        host = request.client.host if request.client else ""
        if host not in LOOPBACK_CLIENTS:
            raise HTTPException(
                status_code=403,
                detail="This server has no VERITAS_API_KEY set, so it only serves loopback clients.",
            )
        return
    supplied = request.headers.get("x-api-key", "")
    if not secrets.compare_digest(supplied.encode(), key.encode()):
        raise HTTPException(status_code=401, detail="Missing or invalid X-API-Key.")


class RateLimiter:
    """Token bucket per client key. In-memory: one process, which is how this app is deployed."""

    def __init__(self, per_minute: int) -> None:
        self.capacity = float(per_minute)
        self.rate = per_minute / 60.0
        self._state: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def check(self, client: str) -> float | None:
        """None if allowed, else seconds until a token is available."""
        now = time.monotonic()
        with self._lock:
            tokens, last = self._state.get(client, (self.capacity, now))
            tokens = min(self.capacity, tokens + (now - last) * self.rate)
            if tokens >= 1.0:
                self._state[client] = (tokens - 1.0, now)
                return None
            self._state[client] = (tokens, now)
            return (1.0 - tokens) / self.rate


def client_id(request: Request) -> str:
    return request.headers.get("x-api-key") or (request.client.host if request.client else "unknown")


def _hostname_of(target: str) -> str | None:
    has_scheme = target.startswith(("http://", "https://"))
    return urllib.parse.urlparse(target if has_scheme else f"//{target}").hostname


def _is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip.split("%")[0]).is_global
    except ValueError:
        return False


async def check_target_allowed(target: str) -> None:
    """Raise 403 if `target` is (or resolves to) a non-public address and that is not opted in."""
    if allow_private_targets():
        return
    host = _hostname_of(target)
    if not host:
        return  # the scanner rejects unparseable targets with its own message
    try:
        ipaddress.ip_address(host)
        addresses = [host]
    except ValueError:
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except OSError:
            return  # unresolvable: nothing to reach; the scan reports the DNS failure itself
        addresses = sorted({info[4][0] for info in infos})
    blocked = [a for a in addresses if not _is_public(a)]
    if blocked:
        raise HTTPException(
            status_code=403,
            detail=(
                f"{host} resolves to a non-public address ({blocked[0]}). Scanning private networks "
                "from this server is disabled; set VERITAS_ALLOW_PRIVATE_TARGETS=1 on a lab network "
                "you are authorised to test."
            ),
        )
