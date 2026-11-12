"""veritas-train — build, check and inspect the deployed flow-detector model."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from veritas.baselines.config import resolve_project_path
from veritas.training.pipeline import PROFILES, TrainingConfig, ensure_split, load_frame, run_training

DEFAULT_FEATURES = "data/processed/features/flows_features.jsonl"
DEFAULT_SPLIT = "data/processed/splits/split.json"
DEFAULT_OUT = "models/flow-detector"


def _cfg(args: argparse.Namespace) -> TrainingConfig:
    return TrainingConfig(
        features_file=resolve_project_path(args.features),
        split_manifest=resolve_project_path(args.split_manifest),
        out_dir=resolve_project_path(args.out),
        seed=args.seed,
        target_fpr=args.target_fpr,
        profiles=tuple(args.profiles),
        deploy_profile=args.deploy,
        max_cv_folds=args.folds,
    )


def cmd_check(args: argparse.Namespace) -> int:
    """Report whether the corpus is big and varied enough to train on, and say what to generate."""
    cfg = _cfg(args)
    try:
        df = load_frame(cfg.features_file)
    except (ValueError, FileNotFoundError) as exc:
        print(f"NOT READY: {exc}", file=sys.stderr)
        return 1
    benign, mal = int((df["label"] == 0).sum()), int((df["label"] == 1).sum())
    evaded = int(((df["evasion_strength"] > 0) & (df["label"] == 1)).sum())
    held = int(df["held_out"].sum())
    captures = int(df["capture_id"].nunique())
    problems = []
    if captures < 10:
        problems.append(f"only {captures} captures; want >= 60 (--runs 60)")
    if min(benign, mal) < 100:
        problems.append(f"smallest class has {min(benign, mal)} flows; want >= 100 per class")
    if evaded == 0:
        problems.append("no evaded flows; the robust profile needs --evasion-strengths 0.25,0.5,0.75,1")
    if held == 0:
        problems.append("no held-out variants; generalisation cannot be measured (--held-out-variants)")
    print(json.dumps({"flows": len(df), "captures": captures, "benign": benign, "malicious": mal,
                      "evaded_malicious": evaded, "held_out_variant_flows": held}, indent=2))
    for p in problems:
        print(f"WARNING: {p}")
    print("READY" if not problems else "USABLE, but see warnings")
    return 0


def cmd_fit(args: argparse.Namespace) -> int:
    cfg = _cfg(args)
    try:
        summary = run_training(cfg)
    except (ValueError, FileNotFoundError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    for name, rep in summary["profiles"].items():
        ct = rep["evaluation"].get("clean_test", {})
        sel = rep["selected"]
        print(
            f"[{name}] {sel['family']} thr={rep['threshold']} cvF1={sel['cv_f1']} "
            f"test recall={ct.get('recall', {}).get('value')} "
            f"fpr={ct.get('false_positive_rate', {}).get('value')}"
        )
    print(f"Deployed profile: {summary['deployed_profile']}")
    print(f"Wrote {cfg.out_dir}/ (model.joblib, metrics.json, MODEL_CARD.md)")
    return 0


def cmd_info(args: argparse.Namespace) -> int:
    path = resolve_project_path(args.out) / "metrics.json"
    if not path.is_file():
        print(f"No trained model at {path.parent}. Run `veritas-train fit`.", file=sys.stderr)
        return 1
    data = json.loads(path.read_text(encoding="utf-8"))
    print(json.dumps({k: data[k] for k in ("version", "trained_at", "deployed_profile", "corpus")}, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="veritas-train", description="Train the flow detector")
    parser.add_argument("--features", default=DEFAULT_FEATURES)
    parser.add_argument("--split-manifest", default=DEFAULT_SPLIT)
    parser.add_argument("--out", default=DEFAULT_OUT, help="model output directory")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--target-fpr", type=float, default=0.01)
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--profiles", nargs="+", default=list(PROFILES), choices=PROFILES)
    parser.add_argument("--deploy", default="robust", choices=PROFILES)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("check", help="Is the corpus big/varied enough?")
    sub.add_parser("fit", help="Select, train, evaluate and save the model")
    sub.add_parser("info", help="Show the saved model's summary")
    args = parser.parse_args(argv)
    return {"check": cmd_check, "fit": cmd_fit, "info": cmd_info}[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
