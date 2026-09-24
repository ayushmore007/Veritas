"""Phase 6 statistical evasion — generator knobs that reshape real traffic.

The attack is real traffic, not edited numbers: an evaded flow is a genuine QUIC session that goes
through the same capture, extraction and trust tagging as clean traffic. These knobs change what
the malicious scenarios *do on the wire*; the features move because the traffic moved.

| Knob             | Traffic change                         | Feature it attacks                     |
|------------------|----------------------------------------|----------------------------------------|
| `cover_download` | fetch a large dummy object             | `totlen_bwd_pkts`, `down_up_ratio`     |
| `timing_jitter`  | randomise inter-request gaps           | `flow_iat_std`, `flow_iat_max`         |
| `chunk_uploads`  | split one upload into many             | burst size, packet count               |
| `cover_requests` | interleave ordinary page fetches       | request mix, duration                  |

`strength` in [0, 1] scales every enabled knob, so Phase 9 reports ASR as a curve. The held-out
variants enable exactly one knob each and are never used while designing a defense.

Benign traffic is never reshaped: it is the control arm.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

KNOBS: tuple[str, ...] = ("cover_download", "timing_jitter", "chunk_uploads", "cover_requests")

#: One knob each. Never used while designing Phase 8 — they exist to test generalisation.
HELD_OUT_VARIANTS: dict[str, frozenset[str]] = {
    "timing_only": frozenset({"timing_jitter"}),
    "volume_only": frozenset({"cover_download"}),
    "chunk_only": frozenset({"chunk_uploads"}),
    "cover_only": frozenset({"cover_requests"}),
}

#: Server-side cap on /stream/<kb> (see testbed/server.py).
MAX_STREAM_KB = 4096


def knobs_for_variant(variant: str | None) -> frozenset[str]:
    """`timing_only…` / `volume_only…` / … enable one knob; anything else (e.g. `baseline_0.75`) all."""
    if variant:
        for prefix, knobs in HELD_OUT_VARIANTS.items():
            if variant.startswith(prefix):
                return knobs
    return frozenset(KNOBS)


def is_held_out(variant: str | None) -> bool:
    return bool(variant) and any(variant.startswith(p) for p in HELD_OUT_VARIANTS)


@dataclass
class EvasionProfile:
    """How one run reshapes its malicious scenarios. `strength == 0` means clean traffic."""

    strength: float = 0.0
    variant: str | None = None
    seed: int | None = None
    knobs: frozenset[str] = field(init=False)
    rng: random.Random = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if not 0.0 <= self.strength <= 1.0:
            raise ValueError(f"evasion strength must be in [0, 1], got {self.strength}")
        self.knobs = knobs_for_variant(self.variant) if self.strength > 0 else frozenset()
        self.rng = random.Random(self.seed)

    @property
    def active(self) -> bool:
        return self.strength > 0 and bool(self.knobs)

    def on(self, knob: str) -> bool:
        if knob not in KNOBS:
            raise ValueError(f"unknown evasion knob: {knob}")
        return self.active and knob in self.knobs

    # -- knob arithmetic, kept here so scenarios stay readable ------------

    def jitter(self, base_sec: float) -> float:
        """A gap of `base_sec`, randomised by up to ±80% × strength when timing_jitter is on."""
        if not self.on("timing_jitter"):
            return base_sec
        return max(0.0, base_sec * (1.0 + self.rng.uniform(-0.8, 0.8) * self.strength))

    def chance(self, knob: str, scale: float = 1.0) -> bool:
        """True with probability strength × scale when `knob` is on."""
        return self.on(knob) and self.rng.random() < self.strength * scale

    def upload_chunks(self, total_kb: int) -> list[int]:
        """Split one upload into 1 + 15 × strength chunks (chunk_uploads), sizes in KB."""
        n = 1 + round(15 * self.strength) if self.on("chunk_uploads") else 1
        n = max(1, min(n, total_kb))
        base, extra = divmod(total_kb, n)
        return [base + (1 if i < extra else 0) for i in range(n)]

    def cover_download_kb(self, reference_kb: int) -> int:
        """Size of a dummy download that pulls down/up ratio toward browsing (cover_download)."""
        if not self.on("cover_download"):
            return 0
        return max(1, min(MAX_STREAM_KB, int(reference_kb * 2 * self.strength)))

    def cover_page_count(self, max_pages: int) -> int:
        """How many ordinary page fetches to interleave (cover_requests)."""
        return round(max_pages * self.strength) if self.on("cover_requests") else 0

    def cover_path(self) -> str:
        return f"/?page={self.rng.randint(0, 99)}"

    def describe(self) -> dict:
        return {
            "strength": self.strength,
            "variant": self.variant,
            "knobs": sorted(self.knobs),
            "held_out": is_held_out(self.variant),
        }
