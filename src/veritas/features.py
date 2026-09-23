"""Feature taxonomy: which measured fields may inform a decision, and which may not.

Every field CICFlowMeter produces is *measured* — the attacker cannot edit it by writing a string.
That makes it trustworthy in the sense of `docs/threat-model.md`, but trustworthy is not the same
as **admissible**. Some measured fields encode the ground truth by construction of the lab:

    dst_port 4433 → benign        (benign_server)
    dst_port 4434 → malicious     (malicious_c2)
    dst_port 4435 → malicious     (malicious_exfil)

A model or agent given `dst_port` scores ~100% while learning nothing about traffic behaviour, and
the number evaporates the moment anyone moves a service to a different port. This is the classic
label-leakage failure, and it is the single most common reason a security-ML result does not
survive review.

So there are three tiers, not two:

* **behavioural** — volume, direction, timing, burstiness. What a defender may actually reason
  from. This is the modelling and decision surface.
* **identity** — five-tuple and capture clock. Kept in the twin because replay, correlation and
  host history need them, and withheld from every decision view.
* **untrusted** — attacker-controllable strings (SNI, ALPN). Handled by
  `config/trust_labels.yaml`, not here.

The rule is enforced by `behavioural_features()`, which every decision or modelling path must call.
The twin itself stays faithful — it stores what was measured; the filtering happens at the view.
"""

from __future__ import annotations

import hashlib
from typing import Any

#: Measured, but a lab artifact rather than a generalisable signal — and in this testbed the
#: destination fields *are* the label. Never in a decision or modelling view.
IDENTITY_FIELDS: frozenset[str] = frozenset(
    {
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
        "timestamp",
    }
)

#: Bookkeeping handles. Not label-bearing, but not features either — they may appear in a view for
#: cross-referencing, and must never enter a feature vector.
PROVENANCE_FIELDS: frozenset[str] = frozenset({"flow_id", "capture_id", "pcap_source"})

NON_FEATURE_FIELDS: frozenset[str] = IDENTITY_FIELDS | PROVENANCE_FIELDS


def is_identity_field(name: str) -> bool:
    return name in IDENTITY_FIELDS


def behavioural_features(measured: dict[str, Any]) -> dict[str, Any]:
    """Drop identity and provenance fields. Call this before modelling or prompting."""
    return {k: v for k, v in measured.items() if k not in NON_FEATURE_FIELDS}


def host_ref(ip: str, *, salt: str = "veritas-lab") -> str:
    """
    Stable pseudonym for a host, so an agent can pivot on "the same peer" without being handed an
    address that names the destination service.

    Deterministic within a project, and intentionally not reversible from the agent's side. It is
    a *view* control, not a privacy mechanism — the twin still holds the real address.
    """
    digest = hashlib.sha256(f"{salt}:{ip}".encode()).hexdigest()
    return f"host-{digest[:10]}"


def build_host_ref_index(ips: list[str], *, salt: str = "veritas-lab") -> dict[str, str]:
    """Map pseudonym → real IP, for resolving an agent's `host_ref` back to the twin."""
    return {host_ref(ip, salt=salt): ip for ip in ips}
