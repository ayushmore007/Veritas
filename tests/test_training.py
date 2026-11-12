"""Training pipeline: selection, thresholding, leakage guards, artefacts (synthetic corpus)."""

from __future__ import annotations

import json
import random
from pathlib import Path

import numpy as np
import pytest

from veritas.baselines.model import BaselineClassifier
from veritas.capture.records import EnrichedFlowRecord, EnrichedFlowRegistry
from veritas.training.pipeline import TrainingConfig, run_training
from veritas.training.stats import classification_report, threshold_for_fpr, wilson_interval


def _rec(i: int, run: int, malicious: bool, strength: float, variant: str | None, rng: random.Random):
    # Malicious flows are chatty and regular; evasion pulls them toward benign (but not all the way).
    base_pkts = 60 if malicious else 12
    pkts = base_pkts * (1 - 0.5 * strength) + rng.uniform(-4, 4)
    return EnrichedFlowRecord(
        flow_id=f"f{i}",
        capture_id=f"run{run}",
        pcap_source="x.pcap",
        cicflowmeter={
            "tot_fwd_pkts": pkts,
            "tot_bwd_pkts": pkts / 2 + rng.uniform(-1, 1),
            "flow_duration": (8.0 if malicious else 1.0) + rng.uniform(-0.3, 0.3),
            "flow_iat_std": (0.01 if malicious else 0.4) + rng.uniform(0, 0.02),
            "constant_col": 7.0,
            "dst_port": 4434 if malicious else 4433,  # identity: must never be a feature
        },
        ground_truth={
            "traffic_class": "malicious" if malicious else "benign",
            "attack_type": "c2_beacon" if malicious else None,
            "scenario_id": "c2" if malicious else "browse",
            "evasion_strength": strength,
            "evasion_variant": variant,
        },
        metadata={},
        field_trust={},
        src_ip="127.0.0.1",
        dst_ip="127.0.0.1",
        src_port=50000 + i,
        dst_port=4434 if malicious else 4433,
        protocol=17,
    )


@pytest.fixture()
def corpus(tmp_path: Path) -> Path:
    rng = random.Random(3)
    recs, i = [], 0
    for run in range(30):
        for malicious in (False, False, True):
            recs.append(_rec(i, run, malicious, 0.0, None, rng)); i += 1
    for run in range(30, 38):
        recs.append(_rec(i, run, True, 0.5, None, rng)); i += 1
    for run in range(38, 44):
        recs.append(_rec(i, run, True, 0.75, "timing_only", rng)); i += 1
    path = tmp_path / "features.jsonl"
    EnrichedFlowRegistry(path).write_all(recs)
    return path


def _cfg(tmp_path: Path, corpus: Path, **kw) -> TrainingConfig:
    return TrainingConfig(
        features_file=corpus,
        split_manifest=tmp_path / "split.json",
        out_dir=tmp_path / "model",
        families=("random_forest",),
        max_cv_folds=3,
        **kw,
    )


def test_fit_writes_a_loadable_model_card_and_metrics(tmp_path, corpus):
    summary = run_training(_cfg(tmp_path, corpus))
    out = tmp_path / "model"
    assert {p.name for p in out.iterdir()} >= {"model.joblib", "metrics.json", "MODEL_CARD.md"}
    model = BaselineClassifier.load(out / "model.joblib")
    assert model.metadata["threshold"] == summary["profiles"]["robust"]["threshold"]
    assert summary["deployed_profile"] == "robust"
    assert "Limitations" in (out / "MODEL_CARD.md").read_text()
    assert json.loads((out / "metrics.json").read_text())["version"] == summary["version"]


def test_identity_and_constant_columns_never_reach_the_model(tmp_path, corpus):
    run_training(_cfg(tmp_path, corpus))
    cols = BaselineClassifier.load(tmp_path / "model" / "model.joblib").feature_cols
    assert "dst_port" not in cols and "constant_col" not in cols
    assert "tot_fwd_pkts" in cols


def test_held_out_variants_are_never_trained_on(tmp_path, corpus):
    summary = run_training(_cfg(tmp_path, corpus))
    corpus_info = summary["corpus"]
    assert corpus_info["held_out_variant_flows"] == 6
    for rep in summary["profiles"].values():
        pool = rep["training_pool"]
        # Pool is train+val of the 98 non-held-out flows (90 clean, 8 evaded); never the 6 held-out.
        assert pool["flows"] <= 98
        assert "timing_only" in rep["evaluation"]["held_out_variants"]


def test_clean_profile_excludes_evaded_flows_and_robust_includes_them(tmp_path, corpus):
    summary = run_training(_cfg(tmp_path, corpus))
    assert summary["profiles"]["clean"]["training_pool"]["evaded_malicious"] == 0
    assert summary["profiles"]["robust"]["training_pool"]["evaded_malicious"] > 0


def test_detects_the_separable_synthetic_attack(tmp_path, corpus):
    summary = run_training(_cfg(tmp_path, corpus))
    clean = summary["profiles"]["robust"]["evaluation"]["clean_test"]
    assert clean["recall"]["value"] >= 0.9
    assert clean["false_positive_rate"]["value"] <= 0.1
    assert clean["recall"]["ci95"] is not None


def test_leave_one_attack_out_is_reported_per_profile(tmp_path, corpus):
    summary = run_training(_cfg(tmp_path, corpus))
    for rep in summary["profiles"].values():
        assert "leave_one_attack_out" in rep  # {} here: the synthetic corpus has a single attack type


def test_too_few_captures_is_a_clear_error(tmp_path):
    rng = random.Random(0)
    path = tmp_path / "f.jsonl"
    EnrichedFlowRegistry(path).write_all(
        [_rec(i, 0, i % 2 == 0, 0.0, None, rng) for i in range(10)]
    )
    with pytest.raises(ValueError):
        run_training(_cfg(tmp_path, path))


def test_wilson_interval_and_threshold_helpers():
    lo, hi = wilson_interval(8, 10)
    assert lo < 0.8 < hi
    assert wilson_interval(0, 0) is None
    y = np.array([0] * 10 + [1] * 10)
    p = np.array([0.1] * 9 + [0.7] + [0.9] * 10)
    assert threshold_for_fpr(y, p, max_fpr=0.0) > 0.7
    assert classification_report(y, p, 0.5)["confusion"]["fp"] == 1
