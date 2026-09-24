"""SHAP and LIME attributions for the sklearn baseline."""

from __future__ import annotations

from typing import Any

import numpy as np


def explain_with_shap(
    model_pipeline,
    x: np.ndarray,
    feature_names: list[str],
    *,
    top_k: int = 8,
) -> list[dict[str, Any]]:
    """TreeExplainer for the classifier step inside the sklearn pipeline."""
    import shap

    clf = model_pipeline.named_steps["clf"]
    scaler = model_pipeline.named_steps["scaler"]
    x_scaled = scaler.transform(x)

    explainer = shap.TreeExplainer(clf)
    shap_values = explainer.shap_values(x_scaled)

    # Binary classifiers: older shap returns [class0, class1]; newer returns an
    # (n_samples, n_features, n_classes) array. Normalise to (n_samples, n_features) for class 1.
    if isinstance(shap_values, list):
        values = np.asarray(shap_values[1] if len(shap_values) > 1 else shap_values[0])
    else:
        values = np.asarray(shap_values)
        if values.ndim == 3:
            values = values[:, :, 1] if values.shape[2] > 1 else values[:, :, 0]

    explanations: list[dict[str, Any]] = []
    for i in range(len(x)):
        row_vals = values[i] if values.ndim > 1 else values
        pairs = sorted(
            zip(feature_names, row_vals, strict=False),
            key=lambda p: abs(float(p[1])),
            reverse=True,
        )[:top_k]
        explanations.append(
            {
                "method": "shap",
                "top_features": [
                    {"feature": name, "attribution": round(float(val), 6)} for name, val in pairs
                ],
            }
        )
    return explanations


def explain_with_lime(
    model_pipeline,
    x: np.ndarray,
    feature_names: list[str],
    *,
    top_k: int = 8,
) -> list[dict[str, Any]]:
    """LIME tabular explainer as a secondary attribution method."""
    from lime.lime_tabular import LimeTabularExplainer

    scaler = model_pipeline.named_steps["scaler"]
    clf = model_pipeline.named_steps["clf"]
    x_scaled = scaler.transform(x)

    def _predict_proba(data):
        return clf.predict_proba(data)

    explainer = LimeTabularExplainer(
        x_scaled,
        feature_names=feature_names,
        class_names=["benign", "malicious"],
        discretize_continuous=True,
        random_state=0,
    )

    out: list[dict[str, Any]] = []
    for i in range(len(x)):
        exp = explainer.explain_instance(x_scaled[i], _predict_proba, num_features=top_k)
        pairs = exp.as_list()
        out.append(
            {
                "method": "lime",
                "top_features": [
                    {"feature": name, "attribution": round(float(weight), 6)}
                    for name, weight in pairs
                ],
            }
        )
    return out
