"""CLI for Phase 4 — the AI defender agent."""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

from veritas.agent.config import load_agent_config, resolve_project_path
from veritas.agent.evaluate import score_traces
from veritas.agent.llm import build_provider
from veritas.agent.loop import DefenderAgent
from veritas.agent.schema import TraceRegistry
from veritas.agent.tools import AgentToolbox
from veritas.eval.splits import SplitManifest, assess_sufficiency, make_splits
from veritas.eval.stability import measure_stability
from veritas.twin.config import load_twin_config
from veritas.twin.store import TwinStore


def _build(args: argparse.Namespace) -> tuple[DefenderAgent, TwinStore, TraceRegistry, dict]:
    cfg = load_agent_config(Path(args.config) if args.config else None)

    if getattr(args, "provider", None):
        cfg["llm"]["provider"] = args.provider
    if getattr(args, "model", None):
        cfg["llm"]["model"] = args.model
    if getattr(args, "prompt_profile", None):
        cfg["prompt"]["profile"] = args.prompt_profile
    if getattr(args, "metadata_channel", None):
        cfg["prompt"]["metadata_channel"] = args.metadata_channel

    twin_cfg = load_twin_config()
    store = TwinStore(resolve_project_path(twin_cfg["store"]["db_path"]))

    toolbox = AgentToolbox(store)
    agent = DefenderAgent(
        toolbox,
        build_provider(cfg["llm"]),
        prompt_profile=cfg["prompt"]["profile"],
        metadata_channel=cfg["prompt"]["metadata_channel"],
        max_steps=int(cfg["loop"]["max_steps"]),
        seed_with_flow_stats=bool(cfg["loop"].get("seed_with_flow_stats", True)),
    )
    traces = TraceRegistry(resolve_project_path(cfg["output"]["traces_file"]))
    return agent, store, traces, cfg


def _cmd_triage(args: argparse.Namespace) -> int:
    agent, store, registry, cfg = _build(args)

    if args.all:
        flow_ids = [f["flow_id"] for f in store.list_flows(limit=args.limit)]
    elif args.flow_id:
        flow_ids = [args.flow_id]
    else:
        print("Provide a flow_id or --all")
        return 2

    if not flow_ids:
        print("No flows in the twin. Run `veritas-twin ingest` first.")
        return 1

    results = []
    for flow_id in flow_ids:
        trace = agent.triage(flow_id)
        registry.append(trace)
        results.append(
            {
                "flow_id": flow_id,
                "verdict": trace.decision.verdict.value,
                "attack_type_guess": trace.decision.attack_type_guess,
                "confidence": trace.decision.confidence,
                "decisive_claims": len(trace.decision.decisive_claims()),
                "decisive_untrusted_claims": len(trace.decision.untrusted_decisive_claims()),
                "tool_calls": [c.tool for c in trace.tool_calls],
                "latency_ms": trace.latency_ms,
                "parse_error": trace.parse_error,
                "rationale": trace.decision.rationale,
            }
        )

    print(json.dumps({"provider": cfg["llm"]["provider"], "results": results}, indent=2))
    print(f"\nTraces appended to: {cfg['output']['traces_file']}")
    if cfg["llm"]["provider"] == "deterministic":
        print("NOTE: deterministic provider is a simulacrum of an undefended LLM, not a detector.")
    return 0


def _split_manifest() -> SplitManifest:
    return SplitManifest(resolve_project_path("data/processed/splits/split.json"))


def _cmd_split(args: argparse.Namespace) -> int:
    _, store, _, _ = _build(args)
    manifest = _split_manifest()

    if manifest.exists and not args.force:
        print(json.dumps({k: v for k, v in manifest.data.items() if k != "assignment"}, indent=2))
        print(
            "\nA split already exists. Re-rolling it after seeing results invalidates every "
            "held-out number — pass --force only if you have a reason you can defend in the paper."
        )
        return 0

    flows = []
    for row in store.list_flows(limit=100_000):
        flow = store.get_flow(row["flow_id"])
        if not flow:
            continue
        flows.append(
            {
                "flow_id": flow["flow_id"],
                "capture_id": flow["capture_id"],
                "scenario_id": flow["ground_truth"].get("scenario_id"),
                "traffic_class": flow["ground_truth"].get("traffic_class"),
            }
        )
    if not flows:
        print("No flows in the twin. Run `veritas-twin ingest` first.")
        return 1

    manifest.data = make_splits(flows, seed=args.seed)
    manifest.save()

    by_class: dict[str, dict[str, int]] = {}
    for flow in flows:
        split = manifest.split_of(flow["flow_id"]) or "?"
        bucket = by_class.setdefault(split, {})
        cls = str(flow["traffic_class"])
        bucket[cls] = bucket.get(cls, 0) + 1

    summary = {k: v for k, v in manifest.data.items() if k != "assignment"}
    summary["per_split_class_counts"] = by_class
    summary["test_sufficiency"] = assess_sufficiency(by_class.get("test", {}), split="test")
    print(json.dumps(summary, indent=2))
    print(f"\nWritten to: {manifest.path}")
    return 0


def _cmd_evaluate(args: argparse.Namespace) -> int:
    _, store, registry, cfg = _build(args)
    traces = registry.load_all()
    if not traces:
        print("No traces yet. Run `veritas-agent triage --all` first.")
        return 1

    if args.latest_only:
        latest: dict[str, object] = {}
        for trace in traces:
            latest[trace.flow_id] = trace
        traces = list(latest.values())  # type: ignore[arg-type]

    manifest = _split_manifest()
    split = args.split
    if split:
        if not manifest.exists:
            print(
                f"No split manifest at {manifest.path}. Run `veritas-agent split` first — "
                "scoring without a fixed held-out set is how inflated numbers happen."
            )
            return 1
        traces = [t for t in traces if manifest.split_of(t.flow_id) == split]
        if not traces:
            print(f"No traces for split {split!r}. Triage those flows first.")
            return 1

    report = score_traces(store, traces, split=split)  # type: ignore[arg-type]
    print(json.dumps(report, indent=2))

    if not split:
        print(
            "\nWARNING: scored every recorded trace, which is not a held-out test set. "
            "Use --split test for any number that goes in the paper."
        )
    if not report["sufficiency"]["supports_rates"]:
        print(f"\nNOTE: {report['sufficiency']['verdict']}")
    return 0


def _cmd_stability(args: argparse.Namespace) -> int:
    agent, store, _, cfg = _build(args)
    if args.flow_id:
        flow_ids = [args.flow_id]
    else:
        flow_ids = [f["flow_id"] for f in store.list_flows(limit=args.limit)]
    if not flow_ids:
        print("No flows in the twin. Run `veritas-twin ingest` first.")
        return 1

    report = measure_stability(agent, flow_ids, repeats=args.repeats)
    print(json.dumps(report, indent=2))
    if cfg["llm"]["provider"] == "deterministic":
        print("\nNOTE: the deterministic provider scores 1.0 here by construction.")
    return 0 if not report["unstable_flows"] else 1


def _cmd_trace(args: argparse.Namespace) -> int:
    _, _, registry, _ = _build(args)
    traces = [t for t in registry.load_all() if t.flow_id == args.flow_id]
    if not traces:
        print(f"No trace for flow {args.flow_id}")
        return 1
    print(json.dumps(json.loads(traces[-1].to_jsonl()), indent=2))
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Veritas Phase 4 — LLM defender agent over the Tier-1 twin",
    )
    parser.add_argument("--config", default=str(resolve_project_path("config/agent.yaml")))
    parser.add_argument("--provider", choices=["ollama", "deterministic"])
    parser.add_argument("--model")
    parser.add_argument("--prompt-profile", choices=["baseline", "hardened"])
    parser.add_argument("--metadata-channel", choices=["json_slot", "inline_concat"])

    sub = parser.add_subparsers(dest="command", required=True)

    triage = sub.add_parser("triage", help="Produce a verdict for one flow or all flows")
    triage.add_argument("flow_id", nargs="?")
    triage.add_argument("--all", action="store_true", help="Triage every flow in the twin")
    triage.add_argument("--limit", type=int, default=100)
    triage.set_defaults(func=_cmd_triage)

    evaluate = sub.add_parser("evaluate", help="Score recorded traces against the twin oracle")
    evaluate.add_argument(
        "--latest-only",
        action="store_true",
        default=True,
        help="Score only the most recent trace per flow (default)",
    )
    evaluate.add_argument(
        "--all-traces", dest="latest_only", action="store_false", help="Score every recorded trace"
    )
    evaluate.add_argument(
        "--split",
        choices=["train", "val", "test"],
        help="Score only this split (required for any number you intend to publish)",
    )
    evaluate.set_defaults(func=_cmd_evaluate)

    split = sub.add_parser(
        "split", help="Create or show the fixed train/val/test assignment (grouped by capture)"
    )
    split.add_argument("--seed", type=int, default=0)
    split.add_argument(
        "--force", action="store_true", help="Overwrite an existing split (think first)"
    )
    split.set_defaults(func=_cmd_split)

    stability = sub.add_parser(
        "stability", help="Repeat triage N times per flow and report verdict agreement"
    )
    stability.add_argument("flow_id", nargs="?")
    stability.add_argument("--repeats", type=int, default=5)
    stability.add_argument("--limit", type=int, default=100)
    stability.set_defaults(func=_cmd_stability)

    trace = sub.add_parser("trace", help="Show the full reasoning trace for a flow")
    trace.add_argument("flow_id")
    trace.set_defaults(func=_cmd_trace)

    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    raise SystemExit(args.func(args))


if __name__ == "__main__":
    main()
