"""Load labelled feature matrices for ML baselines (Phase 5)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from veritas.capture.records import EnrichedFlowRecord, EnrichedFlowRegistry
from veritas.eval.splits import SplitManifest
from veritas.features import behavioural_features

#: Bookkeeping and label columns in the modelling frame. Everything else is a feature.
NON_FEATURE_COLUMNS: frozenset[str] = frozenset(
    {
        "flow_id",
        "capture_id",
        "scenario_id",
        "traffic_class",
        "attack_type",
        "label",
        # Phase 6 ground truth: how the generator reshaped the flow. A label, never a feature.
        "evasion_strength",
        "evasion_variant",
    }
)


def _label_binary(record: EnrichedFlowRecord) -> int:
    """1 = malicious, 0 = benign."""
    return 1 if record.ground_truth.get("traffic_class") == "malicious" else 0


def _label_attack_type(record: EnrichedFlowRecord) -> str:
    return str(record.ground_truth.get("attack_type") or "benign")


def records_to_frame(records: list[EnrichedFlowRecord]) -> pd.DataFrame:
    """Build a modelling dataframe from enriched flow records."""
    rows: list[dict[str, Any]] = []
    for rec in records:
        measured = behavioural_features(rec.cicflowmeter)
        row = {k: v for k, v in measured.items() if isinstance(v, (int, float))}
        row["flow_id"] = rec.flow_id
        row["capture_id"] = rec.capture_id
        row["scenario_id"] = rec.ground_truth.get("scenario_id")
        row["traffic_class"] = rec.ground_truth.get("traffic_class")
        row["attack_type"] = _label_attack_type(rec)
        row["label"] = _label_binary(rec)
        row["evasion_strength"] = float(rec.ground_truth.get("evasion_strength") or 0.0)
        row["evasion_variant"] = rec.ground_truth.get("evasion_variant")
        rows.append(row)
    if not rows:
        return pd.DataFrame()
    return pd.DataFrame(rows)


def load_dataset(
    features_path: Path,
    *,
    split_manifest: Path | None = None,
    split: str | None = None,
) -> tuple[pd.DataFrame, list[str]]:
    records = EnrichedFlowRegistry(features_path).load_all()
    df = records_to_frame(records)
    if df.empty:
        return df, []

    feature_cols = [c for c in df.columns if c not in NON_FEATURE_COLUMNS]

    if split:
        # Silently falling back to the full dataset would score the model on its training data.
        if split_manifest is None or not split_manifest.is_file():
            raise FileNotFoundError(
                f"Split {split!r} requested but no split manifest at {split_manifest}. "
                "Run `veritas-agent split` or `veritas-baseline ensure-split` first."
            )
        manifest = SplitManifest(split_manifest)
        allowed = set(manifest.flow_ids(split))
        df = df[df["flow_id"].isin(allowed)].reset_index(drop=True)

    return df, feature_cols


def xy_from_frame(df: pd.DataFrame, feature_cols: list[str]) -> tuple[np.ndarray, np.ndarray]:
    x = df[feature_cols].fillna(0.0).astype(float).values
    y = df["label"].astype(int).values
    return x, y
