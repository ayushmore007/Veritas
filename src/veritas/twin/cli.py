"""CLI for Phase 3 digital twin Tier 1."""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

from veritas.twin.config import load_twin_config, resolve_project_path
from veritas.twin.ingest import ingest_features_file
from veritas.twin.query import (
    get_flow_stats,
    get_host_history,
    get_metadata,
    replay_flow_metadata_ablation,
)
from veritas.twin.store import TwinStore


def _store(args: argparse.Namespace) -> TwinStore:
    cfg = load_twin_config(Path(args.config) if args.config else None)
    db = resolve_project_path(cfg["store"]["db_path"])
    return TwinStore(db)


def _cmd_ingest(args: argparse.Namespace) -> int:
    cfg = load_twin_config(Path(args.config) if args.config else None)
    features = Path(args.features) if args.features else resolve_project_path(
        cfg["ingest"]["default_features"]
    )
    store = _store(args)
    result = ingest_features_file(store, features, replace=not args.append)
    print(json.dumps(result, indent=2))
    print(f"\nTwin oracle ready: {cfg['store']['db_path']}")
    print("Next: Phase 4 agent tools call get_flow_stats / get_host_history / get_metadata.")
    return 0


def _cmd_flow(args: argparse.Namespace) -> int:
    store = _store(args)
    print(json.dumps(get_flow_stats(store, args.flow_id), indent=2))
    return 0


def _cmd_metadata(args: argparse.Namespace) -> int:
    store = _store(args)
    print(json.dumps(get_metadata(store, args.flow_id), indent=2))
    return 0


def _cmd_host(args: argparse.Namespace) -> int:
    cfg = load_twin_config(Path(args.config) if args.config else None)
    store = _store(args)
    limit = args.limit or int(cfg["query"]["default_host_limit"])
    print(json.dumps(get_host_history(store, args.ip, limit=limit), indent=2))
    return 0


def _cmd_replay(args: argparse.Namespace) -> int:
    cfg = load_twin_config(Path(args.config) if args.config else None)
    store = _store(args)
    result = replay_flow_metadata_ablation(
        store,
        args.flow_id,
        strip_fields=cfg["replay"]["strip_fields"],
    )
    print(json.dumps(result, indent=2))
    return 0


def _cmd_summary(args: argparse.Namespace) -> int:
    store = _store(args)
    flows = store.list_flows(limit=100)
    print(
        json.dumps(
            {"total_flows": store.count_flows(), "flows": flows},
            indent=2,
        )
    )
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Veritas Phase 3 — Digital Twin Tier 1")
    parser.add_argument(
        "--config",
        default=str(resolve_project_path("config/twin.yaml")),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    ingest = sub.add_parser("ingest", help="Load flows_features.jsonl into twin oracle")
    ingest.add_argument("--features", help="Path to flows_features.jsonl")
    ingest.add_argument("--append", action="store_true", help="Append instead of replace")
    ingest.set_defaults(func=_cmd_ingest)

    flow = sub.add_parser("flow", help="Query measured flow stats (oracle)")
    flow.add_argument("flow_id")
    flow.set_defaults(func=_cmd_flow)

    meta = sub.add_parser("metadata", help="Query untrusted metadata side channel")
    meta.add_argument("flow_id")
    meta.set_defaults(func=_cmd_metadata)

    host = sub.add_parser("host", help="Query host history from measured events")
    host.add_argument("ip")
    host.add_argument("--limit", type=int)
    host.set_defaults(func=_cmd_host)

    replay = sub.add_parser("replay", help="Metadata-ablation replay view")
    replay.add_argument("flow_id")
    replay.set_defaults(func=_cmd_replay)

    summ = sub.add_parser("summary", help="Twin store summary")
    summ.set_defaults(func=_cmd_summary)

    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    raise SystemExit(args.func(args))


if __name__ == "__main__":
    main()
