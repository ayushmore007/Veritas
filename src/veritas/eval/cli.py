"""Phase 9 CLI — run the evaluation, validate a saved report, render figures.

    veritas-eval run                          # every experiment, live
    veritas-eval run --only injection         # one (or a comma-separated few); merged into the report
    veritas-eval run --cached                 # validate an existing phase9_report.json only
    veritas-eval figures                      # render figures from the saved report
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from veritas.testbed.config import project_root

# Anchored at the project root so the CLI works from any working directory.
REPORT_PATH = project_root() / "data/processed/eval/phase9_report.json"
FIGURES_DIR = project_root() / "data/processed/eval/figures"
SPLIT_PATH = project_root() / "data/processed/splits/split.json"


def _validate_report(data: dict[str, Any]) -> list[str]:
    from veritas.eval.experiments import EXPERIMENTS

    errors: list[str] = []
    if "provider" not in data:
        errors.append("missing top-level key: provider")
    if not any(name in data for name in EXPERIMENTS):
        errors.append(f"no experiment results (expected any of {', '.join(EXPERIMENTS)})")
    if data.get("is_simulacrum") and not data.get("simulacrum_warning"):
        errors.append("simulacrum report must include simulacrum_warning")
    return errors


def _load_report() -> dict[str, Any] | None:
    if REPORT_PATH.is_file():
        return json.loads(REPORT_PATH.read_text(encoding="utf-8"))
    return None


def _build_context(args: argparse.Namespace):
    from veritas.agent.config import load_agent_config
    from veritas.agent.llm import build_provider
    from veritas.baselines.config import load_baseline_config, resolve_project_path
    from veritas.capture.records import EnrichedFlowRegistry
    from veritas.eval.experiments import ExperimentContext, honest_counterpart
    from veritas.eval.splits import SplitManifest
    from veritas.twin.config import load_twin_config
    from veritas.twin.store import TwinStore

    agent_cfg = load_agent_config()
    if args.provider:
        agent_cfg["llm"]["provider"] = args.provider
    provider = build_provider(agent_cfg["llm"])

    twin_cfg = load_twin_config()
    store = TwinStore(project_root() / twin_cfg["store"]["db_path"])
    baseline_cfg = load_baseline_config()
    records = EnrichedFlowRegistry(
        resolve_project_path(baseline_cfg["data"]["features_file"])
    ).load_all()
    manifest = SplitManifest(SPLIT_PATH)

    problems = []
    if store.count_flows() == 0:
        problems.append("the twin is empty — run `veritas-twin ingest`")
    if not records:
        problems.append("no enriched flows — run `veritas-capture process`")
    if not manifest.exists:
        problems.append("no split manifest — run `veritas-agent split`")
    if problems:
        raise RuntimeError("; ".join(problems))

    return ExperimentContext(
        store=store,
        records=records,
        manifest=manifest,
        provider=provider,
        agent_settings={
            "prompt_profile": agent_cfg["prompt"]["profile"],
            "metadata_channel": agent_cfg["prompt"]["metadata_channel"],
            "max_steps": agent_cfg["loop"]["max_steps"],
            "seed_with_flow_stats": agent_cfg["loop"].get("seed_with_flow_stats", True),
        },
        model_cfg=baseline_cfg["model"],
        replay_strip_fields=list(twin_cfg["replay"]["strip_fields"]),
        max_flows=args.max_flows,
        honest_provider=honest_counterpart(provider),
    )


def cmd_run(args: argparse.Namespace) -> int:
    from veritas.eval.experiments import EXPERIMENTS, run_experiments

    if args.cached:
        data = _load_report()
        if data is None:
            print(f"ERROR: no report at {REPORT_PATH}.", file=sys.stderr)
            return 1
        errors = _validate_report(data)
        if errors:
            print(f"ERROR: invalid report structure in {REPORT_PATH}:", file=sys.stderr)
            for err in errors:
                print(f"  - {err}", file=sys.stderr)
            return 1
        if args.provider and args.provider != data.get("provider"):
            print(
                f"WARNING: --provider {args.provider} differs from report provider "
                f"{data.get('provider')!r}.",
                file=sys.stderr,
            )
        print(json.dumps({k: data.get(k) for k in (
            "provider", "is_simulacrum", "dataset_flows", "test_flows", "experiments_run",
            "created_at")} | {"mode": "cached_report", "report": str(REPORT_PATH)}, indent=2))
        return 0

    only = None
    if args.only:
        only = [x.strip() for x in args.only.split(",") if x.strip()]
        unknown = set(only) - set(EXPERIMENTS)
        if unknown:
            print(f"ERROR: unknown experiment(s) {sorted(unknown)}; choose from {EXPERIMENTS}",
                  file=sys.stderr)
            return 2

    try:
        ctx = _build_context(args)
    except RuntimeError as exc:
        print(f"ERROR: cannot run Phase 9 — {exc}.", file=sys.stderr)
        return 1

    report = run_experiments(ctx, only)
    if only:
        # A partial run updates its experiments in the saved report and keeps the rest, so long
        # experiments can be run separately. Mixing providers would make the report incoherent.
        previous = _load_report() or {}
        if previous and previous.get("provider") != report["provider"]:
            print(
                f"NOTE: saved report used provider {previous.get('provider')!r}; starting a new "
                "report instead of merging.",
                file=sys.stderr,
            )
            previous = {}
        merged_runs = sorted(set(previous.get("experiments_run", [])) | set(report["experiments_run"]))
        report = {**previous, **report, "experiments_run": merged_runs}

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")

    summary = {
        "report": str(REPORT_PATH),
        "provider": report["provider"],
        "is_simulacrum": report["is_simulacrum"],
        "dataset_flows": report["dataset_flows"],
        "test_flows": report["test_flows"],
        "experiments_run": report["experiments_run"],
    }
    inj = report.get("injection")
    if inj:
        summary["injection_asr"] = {
            tier: {d: cells[d]["asr"] for d in inj["defenses"]}
            for tier, cells in inj["tiers"].items()
        }
        summary["injection_denominator"] = inj["denominator"]["caught_without_injection"]
    print(json.dumps(summary, indent=2))
    if report.get("simulacrum_warning"):
        print(f"\n{report['simulacrum_warning']}")
    return 0


def cmd_figures(args: argparse.Namespace) -> int:
    from veritas.eval.figures import render_all

    data = _load_report()
    if data is None:
        print(f"ERROR: run evaluation first — missing {REPORT_PATH}", file=sys.stderr)
        return 1
    made = render_all(data, FIGURES_DIR)
    print(json.dumps({"figures_dir": str(FIGURES_DIR), "figures": [p.name for p in made]}, indent=2))
    if not made:
        print("No figure had enough data; run more experiments first.", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="veritas-eval", description="Phase 9 evaluation")
    parser.add_argument(
        "--provider",
        choices=["deterministic", "ollama"],
        help="Agent backend for live runs (default: config/agent.yaml)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="Run Phase 9 experiments live (or validate with --cached)")
    run.add_argument("--only", help="Comma-separated subset: detection,evasion,injection,"
                     "false_alarms,generalization,latency,ensemble")
    run.add_argument("--max-flows", type=int, help="Cap flows per experiment (slow providers)")
    run.add_argument("--cached", action="store_true",
                     help="Only validate the saved phase9_report.json; run nothing")
    run.add_argument("--require-live", action="store_true",
                     help="Deprecated: runs are always live unless --cached")
    run.set_defaults(func=cmd_run)

    fig = sub.add_parser("figures", help="Render figures from the saved report")
    fig.set_defaults(func=cmd_figures)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
