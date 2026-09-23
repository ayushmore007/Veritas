"""Tests for Phase 5 ML baseline."""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from veritas.baselines.dataset import records_to_frame, xy_from_frame
from veritas.baselines.metrics import score_predictions
from veritas.baselines.model import BaselineClassifier, build_sklearn_pipeline, train_classifier
from veritas.capture.records import EnrichedFlowRecord


def _fake_record(flow_id: str, traffic_class: str, pkt: float) -> EnrichedFlowRecord:
    return EnrichedFlowRecord(
        flow_id=flow_id,
        capture_id="cap1",
        pcap_source="test.pcap",
        cicflowmeter={
            "dst_port": 4433 if traffic_class == "benign" else 4434,
            "total_fwd_packets": pkt,
            "total_bwd_packets": pkt / 2,
            "flow_duration": 1000.0,
        },
        ground_truth={
            "traffic_class": traffic_class,
            "attack_type": "benign_web" if traffic_class == "benign" else "c2_beacon",
            "scenario_id": f"s_{flow_id}",
        },
        metadata={"sni": "example.com", "alpn": "h3"},
    )


def test_behavioural_features_exclude_identity():
    recs = [
        _fake_record("f1", "benign", 10),
        _fake_record("f2", "malicious", 50),
        _fake_record("f3", "benign", 12),
        _fake_record("f4", "malicious", 80),
    ]
    df = records_to_frame(recs)
    assert "dst_port" not in df.columns
    assert "label" in df.columns
    feature_cols = [c for c in df.columns if c not in {"flow_id", "scenario_id", "traffic_class", "attack_type", "label"}]
    assert "total_fwd_packets" in feature_cols


def test_train_and_predict_smoke():
    df = pd.DataFrame(
        {
            "flow_id": [f"f{i}" for i in range(6)],
            "scenario_id": ["s"] * 6,
            "traffic_class": ["benign", "malicious"] * 3,
            "attack_type": ["a"] * 6,
            "label": [0, 1, 0, 1, 0, 1],
            "total_fwd_packets": [10, 100, 12, 90, 11, 95],
            "total_bwd_packets": [5, 50, 6, 45, 5, 48],
            "flow_duration": [1000.0] * 6,
        }
    )
    feature_cols = ["total_fwd_packets", "total_bwd_packets", "flow_duration"]
    x, y = xy_from_frame(df, feature_cols)
    cfg = {"backend": "sklearn", "sklearn": {"estimator": "random_forest", "n_estimators": 10}}
    model = train_classifier(x, y, feature_cols, cfg)
    preds = model.predict(x)
    assert set(preds.tolist()) <= {0, 1}


def test_score_predictions_with_sufficiency_gate():
    preds = [
        {"truth_label": 1, "predicted_label": 1},
        {"truth_label": 0, "predicted_label": 0},
    ]
    result = score_predictions(preds, split="test")
    assert result["confusion"]["tp"] == 1
    assert result["reportable"] is False  # too small for test split rates


def test_build_sklearn_pipeline():
    pipe = build_sklearn_pipeline({"sklearn": {"estimator": "gradient_boosting"}})
    assert "scaler" in pipe.named_steps
    assert "clf" in pipe.named_steps


@pytest.mark.slow
def test_shap_explain_smoke(tmp_path: Path):
    shap = pytest.importorskip("shap")
    from veritas.baselines.explain import explain_with_shap

    x = np.array([[1.0, 2.0], [3.0, 4.0], [2.0, 1.0], [4.0, 3.0]])
    y = np.array([0, 1, 0, 1])
    cfg = {"backend": "sklearn", "sklearn": {"estimator": "random_forest", "n_estimators": 10}}
    model = train_classifier(x, y, ["a", "b"], cfg)
    exps = explain_with_shap(model.pipeline, x[:1], ["a", "b"], top_k=2)
    assert exps[0]["method"] == "shap"
    assert len(exps[0]["top_features"]) <= 2
