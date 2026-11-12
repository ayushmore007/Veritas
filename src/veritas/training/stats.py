"""Small statistics helpers: interval estimates and classification metrics with honest uncertainty."""

from __future__ import annotations

import math
from typing import Any

import numpy as np


def wilson_interval(hits: int, total: int, z: float = 1.96) -> tuple[float, float] | None:
    """95% Wilson score interval for a proportion; `None` when there is nothing to estimate."""
    if total <= 0:
        return None
    p = hits / total
    denom = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denom
    half = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denom
    return (round(max(0.0, centre - half), 4), round(min(1.0, centre + half), 4))


def rate(hits: int, total: int) -> dict[str, Any]:
    """A proportion with its count and interval — never a bare decimal."""
    return {
        "value": round(hits / total, 4) if total else None,
        "hits": int(hits),
        "total": int(total),
        "ci95": wilson_interval(hits, total),
    }


def classification_report(y_true: np.ndarray, proba: np.ndarray, threshold: float) -> dict[str, Any]:
    """Confusion-matrix metrics at `threshold` plus threshold-free AUCs when both classes exist."""
    from sklearn.metrics import average_precision_score, brier_score_loss, roc_auc_score

    y = np.asarray(y_true).astype(int)
    pred = (np.asarray(proba) >= threshold).astype(int)
    tp = int(((y == 1) & (pred == 1)).sum())
    fn = int(((y == 1) & (pred == 0)).sum())
    fp = int(((y == 0) & (pred == 1)).sum())
    tn = int(((y == 0) & (pred == 0)).sum())
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision and recall
        else (0.0 if precision is not None and recall is not None else None)
    )
    out: dict[str, Any] = {
        "n": int(len(y)),
        "threshold": round(float(threshold), 4),
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "recall": rate(tp, tp + fn),
        "false_positive_rate": rate(fp, fp + tn),
        "precision": rate(tp, tp + fp),
        "f1": round(f1, 4) if f1 is not None else None,
    }
    if len(set(y.tolist())) == 2:
        out["roc_auc"] = round(float(roc_auc_score(y, proba)), 4)
        out["pr_auc"] = round(float(average_precision_score(y, proba)), 4)
        out["brier"] = round(float(brier_score_loss(y, proba)), 4)
    return out


def threshold_for_fpr(
    y_true: np.ndarray, proba: np.ndarray, *, max_fpr: float, lo: float = 0.05, hi: float = 0.95
) -> float:
    """Decision threshold within a false-positive budget, taken from the middle of the best plateau.

    Candidates are thresholds in [lo, hi] whose false-positive rate on these (out-of-fold)
    predictions is <= max_fpr. Among them we keep those that reach the best recall, and return the
    *median* of that plateau. The lowest feasible threshold would also maximise recall, but on
    well-separated data it sits at the very edge of the benign score range and the first shift in
    traffic tips it into false alarms; the middle of the plateau has margin on both sides.
    Falls back to `hi` when no threshold meets the budget.
    """
    y = np.asarray(y_true).astype(int)
    p = np.asarray(proba)
    benign, attack = p[y == 0], p[y == 1]
    feasible: list[tuple[float, float]] = []
    for t in np.linspace(lo, hi, 91):
        t = float(round(t, 4))  # evaluate exactly the value we may return
        fpr = float((benign >= t).mean()) if len(benign) else 0.0
        if fpr <= max_fpr:
            recall = float((attack >= t).mean()) if len(attack) else 0.0
            feasible.append((t, recall))
    if not feasible:
        return hi
    best = max(r for _, r in feasible)
    plateau = [t for t, r in feasible if r >= best - 1e-9]
    return float(round(float(np.median(plateau)), 4))
