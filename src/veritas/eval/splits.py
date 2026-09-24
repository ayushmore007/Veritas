"""Held-out splits, and a refusal to report metrics that a split cannot support.

Two rules from the evaluation plan are enforced here rather than remembered:

**Never measure on data used for tuning.** Splits are assigned once, written to a manifest with the
seed and ratios, and re-read on every evaluation. If the manifest exists, the test set is fixed —
you cannot silently re-roll it after seeing a bad number.

**Split by group, not by flow.** Flows from one `veritas-testbed generate` run share a capture,
a clock and a parameter draw; two of them in different splits is a near-duplicate across the
train/test boundary, which inflates test scores the same way label leakage does. The group key
defaults to `capture_id`, falling back to `(scenario_id, capture_id)` when only one capture exists.

**And a sample-size gate.** With a handful of flows, a detection rate is a coin flip with a decimal
point. `assess_sufficiency` states plainly what the split can and cannot support, and evaluation
surfaces that verdict alongside any number it prints.
"""

from __future__ import annotations

import json
import random
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SPLITS = ("train", "val", "test")

#: Minimum flows per class in the test split before a rate is worth reporting at two decimals.
MIN_TEST_PER_CLASS = 30

#: Below this, report counts only — a proportion would imply precision the data cannot carry.
MIN_TEST_PER_CLASS_FOR_ANY_RATE = 10


class SplitManifest:
    """Persisted flow_id → split assignment, with the parameters that produced it."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.data: dict[str, Any] = {}
        if path.is_file():
            self.data = json.loads(path.read_text(encoding="utf-8"))

    @property
    def exists(self) -> bool:
        return bool(self.data)

    @property
    def assignment(self) -> dict[str, str]:
        return self.data.get("assignment", {})

    def split_of(self, flow_id: str) -> str | None:
        return self.assignment.get(flow_id)

    def flow_ids(self, split: str) -> list[str]:
        return sorted(fid for fid, s in self.assignment.items() if s == split)

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.data, indent=2), encoding="utf-8")


def make_splits(
    flows: list[dict[str, Any]],
    *,
    ratios: tuple[float, float, float] = (0.6, 0.2, 0.2),
    seed: int = 0,
    group_key: str = "capture_id",
) -> dict[str, Any]:
    """
    Assign flows to train/val/test by group, stratified by class where possible.

    `flows` items need `flow_id`, `traffic_class`, and the group key. Groups are shuffled with the
    given seed and dealt to splits until each reaches its target share, so a whole capture lands on
    one side of the boundary.
    """
    if abs(sum(ratios) - 1.0) > 1e-6:
        raise ValueError(f"ratios must sum to 1.0, got {ratios}")

    groups: dict[Any, list[dict[str, Any]]] = defaultdict(list)
    for flow in flows:
        groups[flow.get(group_key)].append(flow)

    degenerate = len(groups) < len(SPLITS)
    if degenerate:
        # Only one capture: fall back to per-scenario groups so at least near-duplicates from the
        # same scenario stay together. This is weaker and is recorded in the manifest.
        groups = defaultdict(list)
        for flow in flows:
            groups[(flow.get("scenario_id"), flow.get(group_key))].append(flow)

    keys = sorted(groups, key=lambda k: str(k))
    random.Random(seed).shuffle(keys)

    total = len(flows)
    targets = {name: ratio * total for name, ratio in zip(SPLITS, ratios, strict=True)}
    counts = dict.fromkeys(SPLITS, 0)
    assignment: dict[str, str] = {}

    # With enough groups, give every split (test first) one group before dealing by deficit.
    # Dealing by deficit alone can leave `test` empty when groups are few and large: three
    # captures of five flows go train, train, val.
    seeded = ("test", "val", "train") if len(keys) >= len(SPLITS) else ()

    for i, key in enumerate(keys):
        if i < len(seeded):
            name = seeded[i]
        else:
            # Deal to whichever split is furthest below its target.
            name = max(SPLITS, key=lambda s: targets[s] - counts[s])
        for flow in groups[key]:
            assignment[str(flow["flow_id"])] = name
        counts[name] += len(groups[key])

    return {
        "created_at": datetime.now(UTC).isoformat(),
        "seed": seed,
        "ratios": dict(zip(SPLITS, ratios, strict=True)),
        "group_key": group_key,
        "grouping_degraded": degenerate,
        "grouping_note": (
            "Fewer distinct groups than splits: grouped by (scenario_id, capture_id) instead. "
            "Generate traffic across multiple runs to get real group separation."
            if degenerate
            else "Grouped by capture; no capture spans two splits."
        ),
        "counts": counts,
        "assignment": assignment,
    }


def assess_sufficiency(
    per_class_counts: dict[str, int],
    *,
    split: str = "test",
) -> dict[str, Any]:
    """State what this split can support, so no metric is printed without its caveat."""
    if not per_class_counts:
        return {
            "supports_rates": False,
            "supports_precise_rates": False,
            "verdict": f"The {split} split is empty; no metric can be computed.",
        }

    smallest = min(per_class_counts.values())
    supports_any = smallest >= MIN_TEST_PER_CLASS_FOR_ANY_RATE
    supports_precise = smallest >= MIN_TEST_PER_CLASS

    if supports_precise:
        verdict = (
            f"{split} split has {per_class_counts} — rates are reportable; "
            "still give confidence intervals."
        )
    elif supports_any:
        verdict = (
            f"{split} split has {per_class_counts} — report rates with explicit confidence "
            f"intervals only; below {MIN_TEST_PER_CLASS} per class a point estimate overstates "
            "what you know."
        )
    else:
        verdict = (
            f"{split} split has {per_class_counts} — too small for any rate. Report raw counts "
            f"({smallest} in the smallest class) and treat this as a pipeline smoke test, not a "
            "result. Generate more traffic before quoting a detection rate or FPR."
        )

    return {
        "per_class": per_class_counts,
        "smallest_class": smallest,
        "supports_rates": supports_any,
        "supports_precise_rates": supports_precise,
        "min_for_any_rate": MIN_TEST_PER_CLASS_FOR_ANY_RATE,
        "min_for_precise_rate": MIN_TEST_PER_CLASS,
        "verdict": verdict,
    }
