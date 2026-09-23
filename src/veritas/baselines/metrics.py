"""Classification metrics with sample-size gates (reuse eval/splits policy)."""

from __future__ import annotations

from typing import Any

from veritas.eval.splits import assess_sufficiency


def score_predictions(predictions: list[dict[str, Any]], *, split: str = "test") -> dict[str, Any]:
    tp = fp = tn = fn = 0
    for p in predictions:
        truth = int(p["truth_label"])
        pred = int(p["predicted_label"])
        if truth == 1 and pred == 1:
            tp += 1
        elif truth == 1 and pred == 0:
            fn += 1
        elif truth == 0 and pred == 1:
            fp += 1
        else:
            tn += 1

    benign_total = fp + tn
    malicious_total = tp + fn
    sufficiency = assess_sufficiency(
        {"benign": benign_total, "malicious": malicious_total},
        split=split,
    )

    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall and (precision + recall)
        else None
    )

    return {
        "split": split,
        "sufficiency": sufficiency,
        "reportable": sufficiency["supports_rates"] and split == "test",
        "caveat": (
            "Phase 5 smoke metrics on the lab testbed. NetMamba/ET-BERT comparison numbers "
            "require their repos (LICENSE-checked) and a larger capture."
        ),
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "precision": round(precision, 4) if precision is not None and sufficiency["supports_rates"] else None,
        "recall": round(recall, 4) if recall is not None and sufficiency["supports_rates"] else None,
        "f1": round(f1, 4) if f1 is not None and sufficiency["supports_rates"] else None,
        "flows_scored": len(predictions),
    }
