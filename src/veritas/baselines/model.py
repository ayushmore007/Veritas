"""Sklearn baseline classifier (Phase 5 primary — no external repo required)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


class BaselineClassifier:
    """Behavioural-feature classifier with persisted feature column order."""

    def __init__(self, pipeline: Pipeline, feature_cols: list[str], metadata: dict[str, Any]) -> None:
        self.pipeline = pipeline
        self.feature_cols = feature_cols
        self.metadata = metadata

    def predict(self, x: np.ndarray) -> np.ndarray:
        return self.pipeline.predict(x)

    def predict_proba(self, x: np.ndarray) -> np.ndarray:
        if hasattr(self.pipeline, "predict_proba"):
            return self.pipeline.predict_proba(x)
        # Fallback for pipelines without proba
        preds = self.predict(x)
        out = np.zeros((len(preds), 2))
        for i, p in enumerate(preds):
            out[i, int(p)] = 1.0
        return out

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {"pipeline": self.pipeline, "feature_cols": self.feature_cols, "metadata": self.metadata},
            path,
        )

    @classmethod
    def load(cls, path: Path) -> BaselineClassifier:
        blob = joblib.load(path)
        return cls(blob["pipeline"], blob["feature_cols"], blob["metadata"])


def build_sklearn_pipeline(cfg: dict[str, Any]) -> Pipeline:
    sk_cfg = cfg.get("sklearn", {})
    est = sk_cfg.get("estimator", "random_forest")
    rs = int(sk_cfg.get("random_state", 0))

    if est == "gradient_boosting":
        clf = GradientBoostingClassifier(random_state=rs)
    else:
        clf = RandomForestClassifier(
            n_estimators=int(sk_cfg.get("n_estimators", 100)),
            random_state=rs,
            class_weight=sk_cfg.get("class_weight", "balanced"),
        )

    return Pipeline([("scaler", StandardScaler()), ("clf", clf)])


def train_classifier(
    x: np.ndarray,
    y: np.ndarray,
    feature_cols: list[str],
    cfg: dict[str, Any],
) -> BaselineClassifier:
    pipeline = build_sklearn_pipeline(cfg)
    pipeline.fit(x, y)
    meta = {
        "backend": cfg.get("backend", "sklearn"),
        "estimator": cfg.get("sklearn", {}).get("estimator", "random_forest"),
        "n_samples": int(len(y)),
        "n_features": len(feature_cols),
        "class_counts": {"benign": int((y == 0).sum()), "malicious": int((y == 1).sum())},
        "references": cfg.get("references", {}),
    }
    return BaselineClassifier(pipeline, feature_cols, meta)


def predict_frame(model: BaselineClassifier, df, feature_cols: list[str]) -> list[dict[str, Any]]:
    x = df[feature_cols].fillna(0.0).astype(float).values
    preds = model.predict(x)
    probas = model.predict_proba(x)
    out: list[dict[str, Any]] = []
    # Positional index: `df` may be a filtered view whose index labels are not 0..n-1.
    for i, (_, row) in enumerate(df.iterrows()):
        mal_prob = float(probas[i, 1]) if probas.shape[1] > 1 else float(preds[i])
        out.append(
            {
                "flow_id": row["flow_id"],
                "scenario_id": row.get("scenario_id"),
                "truth_label": int(row["label"]),
                "predicted_label": int(preds[i]),
                "malicious_probability": round(mal_prob, 6),
                "predicted_class": "malicious" if preds[i] == 1 else "benign",
            }
        )
    return out
