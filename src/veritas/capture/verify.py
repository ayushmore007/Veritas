"""Phase 2 sensor verification: is the feature pipeline reproducible, and is it leak-free?

Two checks, both aimed at defects that produce *good-looking* results rather than errors.

**Determinism.** Run the same PCAP through extraction twice and diff. A sensor that returns
different numbers on the same input makes every downstream measurement unrepeatable, and the
difference is usually invisible in aggregate metrics.

**Label leakage.** A feature that encodes the label gives a model a shortcut: high accuracy that
measures the lab topology rather than any ability to read traffic, and that collapses the moment a
service moves port. This screens every feature for that property and, separately, flags fields that
are label-bearing *by construction* here regardless of what the data says.

Honest-statistics note: with a handful of flows, almost any continuous feature separates the
classes perfectly by chance. The report therefore states the per-class sample size and marks the
statistical findings `informative: false` below `MIN_PER_CLASS_FOR_STATS`. Categorical/identity
findings do not depend on sample size and are always reported.
"""

from __future__ import annotations

from itertools import combinations
from pathlib import Path
from typing import Any

from veritas.capture.cicflowmeter_extract import extract_flows_from_pcap, filter_testbed_flows
from veritas.capture.records import EnrichedFlowRegistry
from veritas.features import IDENTITY_FIELDS

#: Below this, "this feature perfectly separates the classes" carries no evidential weight.
MIN_PER_CLASS_FOR_STATS = 30

#: Fields excluded from the determinism diff because they are expected to differ per run.
_VOLATILE_FIELDS = frozenset({"timestamp"})


def check_determinism(pcap: Path, ports: list[int]) -> dict[str, Any]:
    """Extract twice from the same PCAP; report any field that changed."""
    first = filter_testbed_flows(extract_flows_from_pcap(pcap, testbed_ports=ports), ports)
    second = filter_testbed_flows(extract_flows_from_pcap(pcap, testbed_ports=ports), ports)

    if len(first) != len(second):
        return {
            "deterministic": False,
            "reason": f"flow count differs between runs: {len(first)} vs {len(second)}",
            "flow_count": len(first),
            "differing_fields": [],
        }

    differing: dict[str, int] = {}
    for row_a, row_b in zip(first, second, strict=False):
        for key in set(row_a) | set(row_b):
            if key in _VOLATILE_FIELDS:
                continue
            if row_a.get(key) != row_b.get(key):
                differing[key] = differing.get(key, 0) + 1

    return {
        "deterministic": not differing,
        "flow_count": len(first),
        "differing_fields": sorted(differing.items(), key=lambda kv: -kv[1]),
    }


def _auc(positives: list[float], negatives: list[float]) -> float:
    """Rank-based AUC. 1.0 or 0.0 means a single threshold separates the classes perfectly."""
    if not positives or not negatives:
        return 0.5
    wins = ties = 0
    for p in positives:
        for n in negatives:
            if p > n:
                wins += 1
            elif p == n:
                ties += 1
    return (wins + 0.5 * ties) / (len(positives) * len(negatives))


def check_leakage(features_path: Path) -> dict[str, Any]:
    """Screen every feature in `flows_features.jsonl` for label leakage."""
    records = EnrichedFlowRegistry(features_path).load_all()
    if not records:
        raise FileNotFoundError(f"No enriched flow records in {features_path}")

    labels = [r.ground_truth.get("traffic_class") for r in records]
    classes = sorted({c for c in labels if c})
    per_class = {c: labels.count(c) for c in classes}
    informative = len(classes) >= 2 and min(per_class.values()) >= MIN_PER_CLASS_FOR_STATS

    identity_present = sorted(
        {k for r in records for k in r.cicflowmeter if k in IDENTITY_FIELDS}
    )

    categorical_leaks: list[dict[str, Any]] = []
    numeric_leaks: list[dict[str, Any]] = []

    keys = sorted({k for r in records for k in r.cicflowmeter})
    for key in keys:
        values = [r.cicflowmeter.get(key) for r in records]

        # Categorical view: does any single value occur under exactly one class?
        by_value: dict[Any, set[str]] = {}
        for value, label in zip(values, labels, strict=False):
            by_value.setdefault(value, set()).add(label)
        distinct = len(by_value)
        if distinct <= max(4, len(classes) + 1):
            pure = {v: next(iter(cs)) for v, cs in by_value.items() if len(cs) == 1}
            if pure and len(pure) == distinct:
                categorical_leaks.append(
                    {
                        "feature": key,
                        "kind": "identity" if key in IDENTITY_FIELDS else "categorical",
                        "distinct_values": distinct,
                        "value_to_class": {str(k): v for k, v in pure.items()},
                        "verdict": "perfect_predictor",
                    }
                )
                continue

        # Numeric view: does one threshold separate the classes?
        if len(classes) == 2 and all(isinstance(v, (int, float)) for v in values if v is not None):
            pos = [float(v) for v, lab in zip(values, labels, strict=False)
                   if lab == classes[1] and v is not None]
            neg = [float(v) for v, lab in zip(values, labels, strict=False)
                   if lab == classes[0] and v is not None]
            auc = _auc(pos, neg)
            if auc in (0.0, 1.0):
                numeric_leaks.append(
                    {
                        "feature": key,
                        "kind": "numeric",
                        "auc": auc,
                        "verdict": "separable_by_single_threshold",
                        "informative": informative,
                    }
                )

    return {
        "records": len(records),
        "classes": per_class,
        "statistically_informative": informative,
        "min_per_class_for_stats": MIN_PER_CLASS_FOR_STATS,
        "identity_fields_in_feature_record": identity_present,
        "categorical_leaks": categorical_leaks,
        "numeric_leaks": numeric_leaks,
        "notes": _leakage_notes(identity_present, categorical_leaks, informative),
    }


def _leakage_notes(
    identity_present: list[str],
    categorical_leaks: list[dict[str, Any]],
    informative: bool,
) -> list[str]:
    notes: list[str] = []
    if identity_present:
        notes.append(
            f"Identity fields present in the feature record: {identity_present}. These are kept "
            "for replay and correlation, and must be removed before modelling — call "
            "veritas.features.behavioural_features(). AgentToolbox already does."
        )
    hard = [c for c in categorical_leaks if c["kind"] != "identity"]
    if hard:
        notes.append(
            f"Non-identity perfect predictors found: {[c['feature'] for c in hard]}. Investigate — "
            "a behavioural feature that maps one-to-one onto the label usually means the scenarios "
            "differ in a way the generator, not the attack, controls."
        )
    if not informative:
        notes.append(
            "Sample size is too small for the numeric screen to mean anything: with few flows per "
            "class, perfect separation is the default, not a finding. Treat numeric_leaks as noise "
            "until you have "
            f"{MIN_PER_CLASS_FOR_STATS}+ flows per class."
        )
    return notes


def check_pairwise_scenario_overlap(features_path: Path) -> dict[str, Any]:
    """
    Are any two scenarios indistinguishable on behavioural features?

    The mirror image of leakage: if two classes overlap completely, no defender can separate them
    and a low detection rate is the dataset's fault rather than the model's. Worth knowing before
    blaming a model.
    """
    records = EnrichedFlowRegistry(features_path).load_all()
    by_scenario: dict[str, list[dict]] = {}
    for r in records:
        by_scenario.setdefault(str(r.ground_truth.get("scenario_id")), []).append(r.cicflowmeter)

    findings = []
    for a, b in combinations(sorted(by_scenario), 2):
        rows_a, rows_b = by_scenario[a], by_scenario[b]
        keys = set(rows_a[0]) & set(rows_b[0])
        separating = []
        for key in sorted(keys):
            if key in IDENTITY_FIELDS:
                continue
            try:
                va = [float(r[key]) for r in rows_a]
                vb = [float(r[key]) for r in rows_b]
            except (TypeError, ValueError, KeyError):
                continue
            if max(va) < min(vb) or max(vb) < min(va):
                separating.append(key)
        findings.append(
            {"scenarios": [a, b], "cleanly_separating_features": separating[:10],
             "separable": bool(separating)}
        )
    return {"pairs": findings}
