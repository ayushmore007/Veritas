"""Phase 5 CLI — train, predict, explain, compare."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from veritas.baselines.compare import compare_agent_vs_ml
from veritas.baselines.config import load_baseline_config
from veritas.baselines.dataset import load_dataset, xy_from_frame
from veritas.baselines.explain import explain_with_lime, explain_with_shap
from veritas.baselines.metrics import score_predictions
from veritas.baselines.model import BaselineClassifier, predict_frame, train_classifier
from veritas.eval.splits import SplitManifest, make_splits


def _paths(cfg: dict) -> dict[str, Path]:
    out = cfg["output"]
    model_dir = Path(out["model_dir"])
    return {
        "features": Path(cfg["data"]["features_file"]),
        "split": Path(cfg["data"]["split_manifest"]),
        "model": model_dir / out["model_file"],
        "metrics": model_dir / out["metrics_file"],
        "explanations": model_dir / out["explanations_file"],
        "predictions": model_dir / out["predictions_file"],
        "traces": Path(cfg["comparison"]["agent_traces"]),
    }


def cmd_ensure_split(args: argparse.Namespace) -> int:
    cfg = load_baseline_config(Path(args.config) if args.config else None)
    paths = _paths(cfg)
    if paths["split"].is_file() and not args.force:
        print(f"Split manifest exists: {paths['split']}")
        return 0

    df, _ = load_dataset(paths["features"])
    flows = [
        {
            "flow_id": row["flow_id"],
            "traffic_class": "malicious" if row["label"] == 1 else "benign",
            "scenario_id": row.get("scenario_id"),
            "capture_id": "phase1",
        }
        for _, row in df.iterrows()
    ]
    manifest = make_splits(flows, seed=args.seed)
    SplitManifest(paths["split"]).data = manifest
    SplitManifest(paths["split"]).save()
    print(json.dumps(manifest, indent=2))
    return 0


def cmd_train(args: argparse.Namespace) -> int:
    cfg = load_baseline_config(Path(args.config) if args.config else None)
    paths = _paths(cfg)

    if not paths["split"].is_file():
        cmd_ensure_split(argparse.Namespace(config=args.config, force=False, seed=0))

    df, feature_cols = load_dataset(paths["features"], split_manifest=paths["split"], split="train")
    if len(df) < cfg["features"]["min_train_samples"]:
        print(
            f"ERROR: {len(df)} train flows — need at least {cfg['features']['min_train_samples']}. "
            "Run veritas-testbed generate --record-pcap and veritas-capture process.",
            file=sys.stderr,
        )
        return 1

    x, y = xy_from_frame(df, feature_cols)
    model = train_classifier(x, y, feature_cols, cfg["model"])
    model.save(paths["model"])
    print(f"Saved model -> {paths['model']} ({len(feature_cols)} features, {len(y)} samples)")
    return 0


def cmd_predict(args: argparse.Namespace) -> int:
    cfg = load_baseline_config(Path(args.config) if args.config else None)
    paths = _paths(cfg)

    if not paths["model"].is_file():
        print("ERROR: no trained model — run `veritas-baseline train` first.", file=sys.stderr)
        return 1

    split = args.split or "test"
    df, feature_cols = load_dataset(
        paths["features"], split_manifest=paths["split"], split=split
    )
    if df.empty:
        print(f"No flows in split '{split}'.", file=sys.stderr)
        return 1

    model = BaselineClassifier.load(paths["model"])
    preds = predict_frame(model, df, feature_cols)
    metrics = score_predictions(preds, split=split)

    paths["predictions"].parent.mkdir(parents=True, exist_ok=True)
    with paths["predictions"].open("w", encoding="utf-8") as fh:
        for p in preds:
            fh.write(json.dumps(p) + "\n")
    paths["metrics"].write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    print(json.dumps(metrics, indent=2))
    print(f"Predictions -> {paths['predictions']}")
    return 0


def cmd_explain(args: argparse.Namespace) -> int:
    cfg = load_baseline_config(Path(args.config) if args.config else None)
    paths = _paths(cfg)
    exp_cfg = cfg["explainability"]

    if not paths["model"].is_file():
        print("ERROR: no trained model.", file=sys.stderr)
        return 1

    split = args.split or "test"
    df, feature_cols = load_dataset(
        paths["features"], split_manifest=paths["split"], split=split
    )
    if args.flow_id:
        df = df[df["flow_id"] == args.flow_id]
    if df.empty:
        print("No flows to explain.", file=sys.stderr)
        return 1

    model = BaselineClassifier.load(paths["model"])
    x, _ = xy_from_frame(df, feature_cols)
    top_k = int(exp_cfg.get("top_k_features", 8))

    records: list[dict] = []
    shap_exps: list[dict] = []
    lime_exps: list[dict] = []

    if exp_cfg.get("shap", True):
        shap_exps = explain_with_shap(
            model.pipeline, x, feature_cols, top_k=top_k
        )
    if exp_cfg.get("lime", True):
        lime_exps = explain_with_lime(
            model.pipeline, x, feature_cols, top_k=top_k
        )

    for i, (_, row) in enumerate(df.iterrows()):
        rec = {
            "flow_id": row["flow_id"],
            "scenario_id": row.get("scenario_id"),
            "truth": "malicious" if row["label"] == 1 else "benign",
        }
        if shap_exps:
            rec["shap"] = shap_exps[i]
        if lime_exps:
            rec["lime"] = lime_exps[i]
        records.append(rec)

    paths["explanations"].parent.mkdir(parents=True, exist_ok=True)
    with paths["explanations"].open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec) + "\n")

    print(json.dumps(records, indent=2))
    print(f"Explanations -> {paths['explanations']}")
    return 0


def cmd_compare(args: argparse.Namespace) -> int:
    cfg = load_baseline_config(Path(args.config) if args.config else None)
    paths = _paths(cfg)

    if not paths["predictions"].is_file():
        cmd_predict(argparse.Namespace(config=args.config, split="test"))

    preds = [
        json.loads(line)
        for line in paths["predictions"].read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    result = compare_agent_vs_ml(preds, paths["traces"])
    print(json.dumps(result, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="veritas-baseline", description="Phase 5 ML baseline")
    parser.add_argument("--config", help="Path to baseline.yaml")
    sub = parser.add_subparsers(dest="command", required=True)

    p_split = sub.add_parser("ensure-split", help="Create split manifest from features")
    p_split.add_argument("--force", action="store_true")
    p_split.add_argument("--seed", type=int, default=0)

    sub.add_parser("train", help="Train sklearn baseline on train split")

    p_pred = sub.add_parser("predict", help="Predict on a split")
    p_pred.add_argument("--split", choices=["train", "val", "test"], default="test")

    p_exp = sub.add_parser("explain", help="SHAP/LIME attributions")
    p_exp.add_argument("--split", choices=["train", "val", "test"], default="test")
    p_exp.add_argument("--flow-id")

    sub.add_parser("compare", help="Compare ML vs agent traces")

    args = parser.parse_args(argv)
    handlers = {
        "ensure-split": cmd_ensure_split,
        "train": cmd_train,
        "predict": cmd_predict,
        "explain": cmd_explain,
        "compare": cmd_compare,
    }
    return handlers[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
