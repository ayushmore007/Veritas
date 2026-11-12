"""Train, select, calibrate-by-threshold and honestly evaluate the flow detector.

The method, in the order it runs (each step exists to prevent a specific way of fooling yourself):

1. **Fixed split by capture** (`eval/splits.py`). The test split is assigned once and never used
   for any choice below.
2. **Pool = train + val, minus held-out evasion variants.** Held-out variants
   (`timing_only`, `volume_only`, ...) exist to measure generalisation to evasion the model never
   saw, so they are never trained on, in any profile.
3. **Model selection by grouped cross-validation** over the pool. Folds are grouped by capture, so
   two flows from one run never sit on both sides of a fold boundary (that would reward memorising
   a run, not detecting an attack).
4. **Decision threshold from out-of-fold predictions**, at a stated false-positive budget, rather
   than a default 0.5.
5. **One-shot evaluation** on the clean test split, on test-split evaded flows, and on the held-out
   variants, each with an interval, not a bare rate.

Two profiles are trained and reported side by side:

* `clean`  — trained only on unmodified traffic. This is what a naive deployment looks like.
* `robust` — also trained on evaded malicious traffic (adversarial augmentation). This is what we
  ship, and the gap between the two is itself a finding.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import platform
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import (
    ExtraTreesClassifier,
    GradientBoostingClassifier,
    RandomForestClassifier,
)
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from veritas.attacks.evasion import is_held_out
from veritas.baselines.dataset import NON_FEATURE_COLUMNS, records_to_frame
from veritas.baselines.model import BaselineClassifier
from veritas.capture.records import EnrichedFlowRegistry
from veritas.eval.splits import MIN_TEST_PER_CLASS, SplitManifest, make_splits
from veritas.training.stats import classification_report, rate, threshold_for_fpr

#: Models that `shap.TreeExplainer` can explain; only these may be deployed, because the API
#: returns per-flow attributions. Logistic regression is trained as a reference point only.
DEPLOYABLE = ("random_forest", "extra_trees", "gradient_boosting")

PROFILES = ("clean", "robust")


def candidate_grid(seed: int) -> list[tuple[str, dict[str, Any], Any]]:
    """(family, params, unfitted estimator). Small on purpose: the corpus is hundreds of flows."""
    out: list[tuple[str, dict[str, Any], Any]] = []
    for c in (0.1, 1.0, 10.0):
        out.append(
            (
                "logistic_regression",
                {"C": c},
                LogisticRegression(C=c, max_iter=2000, class_weight="balanced", random_state=seed),
            )
        )
    for n in (100, 300):
        for depth in (None, 8):
            for leaf in (1, 3):
                params = {"n_estimators": n, "max_depth": depth, "min_samples_leaf": leaf}
                out.append(
                    (
                        "random_forest",
                        params,
                        RandomForestClassifier(
                            class_weight="balanced", random_state=seed, n_jobs=-1, **params
                        ),
                    )
                )
    for leaf in (1, 3):
        params = {"n_estimators": 300, "max_depth": None, "min_samples_leaf": leaf}
        out.append(
            (
                "extra_trees",
                params,
                ExtraTreesClassifier(
                    class_weight="balanced", random_state=seed, n_jobs=-1, **params
                ),
            )
        )
    for n in (100, 200):
        for lr in (0.05, 0.1):
            for depth in (2, 3):
                params = {"n_estimators": n, "learning_rate": lr, "max_depth": depth}
                out.append(
                    (
                        "gradient_boosting",
                        params,
                        GradientBoostingClassifier(random_state=seed, **params),
                    )
                )
    return out


def _pipeline(estimator: Any) -> Pipeline:
    # Step names are load-bearing: baselines/explain.py reaches in for "scaler" and "clf".
    return Pipeline([("scaler", StandardScaler()), ("clf", estimator)])


@dataclass
class TrainingConfig:
    features_file: Path
    split_manifest: Path
    out_dir: Path
    seed: int = 0
    max_cv_folds: int = 5
    target_fpr: float = 0.01
    profiles: tuple[str, ...] = PROFILES
    deploy_profile: str = "robust"
    families: tuple[str, ...] | None = None  # restrict candidate families (tests, quick runs)
    notes: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------------------------
# data
# --------------------------------------------------------------------------------------------


def load_frame(features_file: Path) -> pd.DataFrame:
    records = EnrichedFlowRegistry(features_file).load_all()
    df = records_to_frame(records)
    if df.empty:
        raise ValueError(
            f"No flows in {features_file}. Build a corpus first (scripts/reproduce.py --quick "
            "--runs 60 --seed 1 --entropy ...). See docs/TRAINING.md."
        )
    df["held_out"] = df["evasion_variant"].map(lambda v: isinstance(v, str) and bool(is_held_out(v)))
    return df


def ensure_split(df: pd.DataFrame, manifest_path: Path, seed: int) -> SplitManifest:
    """Reuse the fixed split if it covers exactly these flows; otherwise (re)create it."""
    manifest = SplitManifest(manifest_path)
    current = set(df["flow_id"])
    if manifest.exists and set(manifest.assignment) == current:
        return manifest
    flows = [
        {
            "flow_id": r.flow_id,
            "traffic_class": "malicious" if r.label == 1 else "benign",
            "scenario_id": r.scenario_id,
            "capture_id": r.capture_id,
        }
        for r in df.itertuples()
    ]
    manifest.data = make_splits(flows, seed=seed)
    manifest.save()
    return manifest


def feature_columns(df: pd.DataFrame) -> list[str]:
    cols = [c for c in df.columns if c not in NON_FEATURE_COLUMNS and c != "held_out"]
    # Drop columns with no variation anywhere: no signal, and they break some explainers.
    return [c for c in cols if df[c].nunique(dropna=False) > 1]


def matrix(df: pd.DataFrame, cols: list[str]) -> np.ndarray:
    x = df.reindex(columns=cols).astype(float).replace([np.inf, -np.inf], np.nan).fillna(0.0)
    return x.values


# --------------------------------------------------------------------------------------------
# selection and evaluation
# --------------------------------------------------------------------------------------------


def _folds(y: np.ndarray, groups: np.ndarray, max_folds: int, seed: int) -> list[tuple]:
    n_groups = len(set(groups.tolist()))
    n_splits = min(max_folds, n_groups)
    if n_splits < 2:
        raise ValueError(
            f"Only {n_groups} distinct capture(s) in the training pool; grouped cross-validation "
            "needs at least 2. Generate more runs (--runs N)."
        )
    cv = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=seed)
    return list(cv.split(np.zeros(len(y)), y, groups))


def select_model(
    x: np.ndarray, y: np.ndarray, groups: np.ndarray, cfg: TrainingConfig
) -> tuple[dict[str, Any], list[dict[str, Any]], np.ndarray]:
    """Grouped-CV over the candidate grid. Returns (best candidate, leaderboard, OOF probabilities).

    Ranked by mean out-of-fold F1; ties broken by lower false-positive rate. Only deployable
    families are eligible to win, but every family is scored so the card can show the comparison.
    """
    from sklearn.base import clone

    folds = _folds(y, groups, cfg.max_cv_folds, cfg.seed)
    board: list[dict[str, Any]] = []
    oof_by_idx: dict[int, np.ndarray] = {}

    for family, params, est in candidate_grid(cfg.seed):
        if cfg.families and family not in cfg.families and family not in ("logistic_regression",):
            continue
        oof = np.zeros(len(y))
        for train_idx, test_idx in folds:
            if len(set(y[train_idx].tolist())) < 2:
                oof[test_idx] = 0.0
                continue
            pipe = _pipeline(clone(est))
            pipe.fit(x[train_idx], y[train_idx])
            oof[test_idx] = pipe.predict_proba(x[test_idx])[:, 1]
        rep = classification_report(y, oof, 0.5)
        entry = {
            "family": family,
            "params": params,
            "deployable": family in DEPLOYABLE,
            "cv_f1": rep["f1"],
            "cv_recall": rep["recall"]["value"],
            "cv_fpr": rep["false_positive_rate"]["value"],
            "cv_roc_auc": rep.get("roc_auc"),
            "cv_brier": rep.get("brier"),
        }
        board.append(entry)
        oof_by_idx[len(board) - 1] = oof

    eligible = [i for i, e in enumerate(board) if e["deployable"]]
    if not eligible:
        raise ValueError("No deployable candidate families were evaluated.")
    best_i = max(
        eligible,
        key=lambda i: (board[i]["cv_f1"] or 0.0, -(board[i]["cv_fpr"] or 0.0)),
    )
    best, best_oof = board[best_i], oof_by_idx[best_i]
    board.sort(key=lambda e: (e["cv_f1"] or 0.0), reverse=True)
    return best, board, best_oof


def fit_final(entry: dict[str, Any], x: np.ndarray, y: np.ndarray, seed: int) -> Pipeline:
    for family, params, est in candidate_grid(seed):
        if family == entry["family"] and params == entry["params"]:
            pipe = _pipeline(est)
            pipe.fit(x, y)
            return pipe
    raise ValueError(f"unknown candidate {entry['family']} {entry['params']}")


def _proba(model: Pipeline, x: np.ndarray) -> np.ndarray:
    return model.predict_proba(x)[:, 1]


def evaluate(
    model: Pipeline,
    cols: list[str],
    df: pd.DataFrame,
    manifest: SplitManifest,
    threshold: float,
    *,
    profile: str,
) -> dict[str, Any]:
    """Score once: clean test split, per-attack recall, evaded test flows, held-out variants."""
    test_ids = set(manifest.flow_ids("test"))
    in_test = df["flow_id"].isin(test_ids)
    clean = df[in_test & (df["evasion_strength"] == 0)]
    result: dict[str, Any] = {}

    if len(clean):
        y = clean["label"].astype(int).values
        p = _proba(model, matrix(clean, cols))
        result["clean_test"] = classification_report(y, p, threshold)
        per_attack = {}
        for attack, grp in clean[clean["label"] == 1].groupby("attack_type"):
            hits = int((_proba(model, matrix(grp, cols)) >= threshold).sum())
            per_attack[str(attack)] = rate(hits, len(grp))
        result["clean_test"]["recall_by_attack"] = per_attack
        counts = {"benign": int((y == 0).sum()), "malicious": int((y == 1).sum())}
        result["clean_test"]["class_counts"] = counts
        smallest = min(counts.values())
        result["clean_test"]["reportable"] = smallest >= MIN_TEST_PER_CLASS
        if smallest < MIN_TEST_PER_CLASS:
            result["clean_test"]["caveat"] = (
                f"Smallest test class has {smallest} flows (< {MIN_TEST_PER_CLASS}); treat rates as "
                "indicative and read the intervals, not the point estimates."
            )

    def evasion_block(frame: pd.DataFrame) -> dict[str, Any]:
        mal = frame[frame["label"] == 1]
        out: dict[str, Any] = {}
        for s, grp in mal.groupby("evasion_strength"):
            caught = int((_proba(model, matrix(grp, cols)) >= threshold).sum())
            out[f"{float(s):.2f}"] = {
                "detection": rate(caught, len(grp)),
                "attack_success_rate": rate(len(grp) - caught, len(grp)),
            }
        return out

    evaded_test = df[in_test & (df["evasion_strength"] > 0) & ~df["held_out"]]
    result["evaded_test_by_strength"] = evasion_block(evaded_test) if len(evaded_test) else {}
    if profile == "clean":
        # The clean model never saw any evaded flow, so *all* of them are unseen — more data.
        unseen = df[(df["evasion_strength"] > 0) & ~df["held_out"]]
        result["evaded_all_unseen_by_strength"] = evasion_block(unseen) if len(unseen) else {}

    held = df[df["held_out"] & (df["label"] == 1)]
    by_variant: dict[str, Any] = {}
    for variant, grp in held.groupby("evasion_variant"):
        caught = int((_proba(model, matrix(grp, cols)) >= threshold).sum())
        by_variant[str(variant)] = {
            "detection": rate(caught, len(grp)),
            "attack_success_rate": rate(len(grp) - caught, len(grp)),
        }
    result["held_out_variants"] = by_variant
    return result


def leave_one_attack_out(
    best: dict[str, Any],
    df: pd.DataFrame,
    manifest: SplitManifest,
    cols: list[str],
    threshold: float,
    seed: int,
    *,
    profile: str,
) -> dict[str, Any]:
    """Train without one attack type, then ask how many of its flows the model catches.

    In-distribution scores saturate on lab traffic (every candidate hits F1 = 1.0), so they cannot
    say whether the model learned something about *malicious behaviour* or merely memorised three
    scripted scenarios. This can: recall on an attack the model never saw, at the same threshold,
    with false alarms measured on the held-out test benign flows.
    """
    in_pool = df["flow_id"].isin(set(manifest.flow_ids("train")) | set(manifest.flow_ids("val")))
    pool = df[in_pool & ~df["held_out"]]
    if profile == "clean":
        pool = pool[pool["evasion_strength"] == 0]
    test_benign = df[df["flow_id"].isin(set(manifest.flow_ids("test"))) & (df["label"] == 0)]
    out: dict[str, Any] = {}
    attacks = sorted(a for a in df.loc[df["label"] == 1, "attack_type"].dropna().unique())
    for attack in attacks:
        train = pool[pool["attack_type"] != attack]
        if train["label"].nunique() < 2:
            continue
        model = fit_final(best, matrix(train, cols), train["label"].astype(int).values, seed)
        unseen = df[(df["attack_type"] == attack) & (df["label"] == 1) & (df["evasion_strength"] == 0)]
        caught = int((_proba(model, matrix(unseen, cols)) >= threshold).sum())
        false_alarms = int((_proba(model, matrix(test_benign, cols)) >= threshold).sum())
        out[str(attack)] = {
            "recall_on_unseen_attack": rate(caught, len(unseen)),
            "false_positive_rate": rate(false_alarms, len(test_benign)),
        }
    return out


def importances(model: Pipeline, cols: list[str], top: int = 15) -> list[dict[str, Any]]:
    clf = model.named_steps["clf"]
    vals = getattr(clf, "feature_importances_", None)
    if vals is None:
        return []
    order = np.argsort(vals)[::-1][:top]
    return [{"feature": cols[i], "importance": round(float(vals[i]), 5)} for i in order]


# --------------------------------------------------------------------------------------------
# orchestration
# --------------------------------------------------------------------------------------------


def train_profile(
    profile: str, df: pd.DataFrame, manifest: SplitManifest, cfg: TrainingConfig
) -> tuple[BaselineClassifier, dict[str, Any]]:
    cols = feature_columns(df)
    in_pool = df["flow_id"].isin(set(manifest.flow_ids("train")) | set(manifest.flow_ids("val")))
    pool = df[in_pool & ~df["held_out"]]
    if profile == "clean":
        pool = pool[pool["evasion_strength"] == 0]
    if pool["label"].nunique() < 2:
        raise ValueError(f"Profile {profile!r}: training pool lacks one of the classes.")

    x, y = matrix(pool, cols), pool["label"].astype(int).values
    groups = pool["capture_id"].astype(str).values
    best, board, oof = select_model(x, y, groups, cfg)
    threshold = threshold_for_fpr(y, oof, max_fpr=cfg.target_fpr)
    model = fit_final(best, x, y, cfg.seed)

    report = {
        "profile": profile,
        "training_pool": {
            "flows": int(len(pool)),
            "captures": int(pool["capture_id"].nunique()),
            "benign": int((y == 0).sum()),
            "malicious": int((y == 1).sum()),
            "evaded_malicious": int(((pool["evasion_strength"] > 0) & (pool["label"] == 1)).sum()),
        },
        "selected": best,
        "leaderboard": board,
        "threshold": threshold,
        "threshold_policy": f"lowest threshold with out-of-fold FPR <= {cfg.target_fpr}",
        "oof": classification_report(y, oof, threshold),
        "evaluation": evaluate(model, cols, df, manifest, threshold, profile=profile),
        "top_features": importances(model, cols),
        "leave_one_attack_out": leave_one_attack_out(
            best, df, manifest, cols, threshold, cfg.seed, profile=profile
        ),
    }
    meta = {
        "backend": "sklearn",
        "estimator": best["family"],
        "params": best["params"],
        "profile": profile,
        "threshold": threshold,
        "n_samples": int(len(y)),
        "n_features": len(cols),
        "class_counts": {"benign": int((y == 0).sum()), "malicious": int((y == 1).sum())},
    }
    return BaselineClassifier(model, cols, meta), report


def _pkg_version(name: str) -> str | None:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def _corpus_fingerprint(df: pd.DataFrame) -> str:
    return hashlib.sha256("\n".join(sorted(df["flow_id"])).encode()).hexdigest()[:16]


def run_training(cfg: TrainingConfig) -> dict[str, Any]:
    df = load_frame(cfg.features_file)
    manifest = ensure_split(df, cfg.split_manifest, cfg.seed)
    trained_at = datetime.now(UTC)
    version = trained_at.strftime("%Y%m%d-%H%M%S")

    summary: dict[str, Any] = {
        "version": version,
        "trained_at": trained_at.isoformat(),
        "environment": {
            "python": platform.python_version(),
            "sklearn": sklearn.__version__,
            "numpy": np.__version__,
            "pandas": pd.__version__,
            "cicflowmeter": _pkg_version("cicflowmeter"),
        },
        "corpus": {
            "fingerprint": _corpus_fingerprint(df),
            "flows": int(len(df)),
            "captures": int(df["capture_id"].nunique()),
            "benign": int((df["label"] == 0).sum()),
            "malicious": int((df["label"] == 1).sum()),
            "evaded_malicious": int(((df["evasion_strength"] > 0) & (df["label"] == 1)).sum()),
            "held_out_variant_flows": int(df["held_out"].sum()),
            "split_counts": manifest.data.get("counts"),
            "split_grouping": manifest.data.get("grouping_note"),
        },
        "config": {
            "seed": cfg.seed,
            "max_cv_folds": cfg.max_cv_folds,
            "target_fpr": cfg.target_fpr,
            "deploy_profile": cfg.deploy_profile,
        },
        "profiles": {},
    }

    models: dict[str, BaselineClassifier] = {}
    for profile in cfg.profiles:
        model, report = train_profile(profile, df, manifest, cfg)
        models[profile] = model
        summary["profiles"][profile] = report

    deploy = cfg.deploy_profile if cfg.deploy_profile in models else next(iter(models))
    summary["deployed_profile"] = deploy
    deployed = models[deploy]
    deployed.metadata.update(
        {
            "version": version,
            "trained_at": summary["trained_at"],
            "corpus_fingerprint": summary["corpus"]["fingerprint"],
            "sklearn_version": sklearn.__version__,
            "cicflowmeter_version": _pkg_version("cicflowmeter"),
            "feature_cols": list(deployed.feature_cols),
        }
    )

    cfg.out_dir.mkdir(parents=True, exist_ok=True)
    deployed.save(cfg.out_dir / "model.joblib")
    for profile, model in models.items():
        if profile != deploy:
            model.save(cfg.out_dir / f"model.{profile}.joblib")
    (cfg.out_dir / "metrics.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    from veritas.training.card import render_model_card

    (cfg.out_dir / "MODEL_CARD.md").write_text(render_model_card(summary), encoding="utf-8")
    return summary
