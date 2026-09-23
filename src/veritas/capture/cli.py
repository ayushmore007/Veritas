"""CLI for Phase 2 capture and feature extraction."""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

from veritas.capture.config import load_capture_config, resolve_project_path
from veritas.capture.pipeline import CapturePipeline
from veritas.capture.records import EnrichedFlowRegistry


def _cmd_process(args: argparse.Namespace) -> int:
    pipeline = CapturePipeline(Path(args.config) if args.config else None)
    if args.use_tshark_sni:
        pipeline.config["metadata"]["use_tshark_sni"] = True
    if args.entropy:
        pipeline.config.setdefault("entropy", {})["enabled"] = True
    if args.manifest is not None and args.pcap:
        print("--manifest and --pcap are mutually exclusive")
        return 2

    if args.manifest is not None:
        result = pipeline.run_manifest(
            manifest_path=Path(args.manifest) if args.manifest else None,
            labels_path=Path(args.labels) if args.labels else None,
            output_path=Path(args.output) if args.output else None,
        )
    else:
        result = pipeline.run(
            pcap_path=Path(args.pcap) if args.pcap else None,
            labels_path=Path(args.labels) if args.labels else None,
            output_path=Path(args.output) if args.output else None,
        )
    print(json.dumps(result, indent=2))
    if result["matched_count"] == 0:
        print("\nWarning: no labels matched to flows. Check PCAP ports and label dedupe settings.")
        return 1
    low = result.get("match_quality", {}).get("low_confidence_pairs") or []
    if low:
        print(
            f"\nWarning: {len(low)} label/flow pair(s) matched with low confidence "
            "(durations disagree). Check them before trusting the ground truth:"
        )
        for pair in low:
            print(f"  - {pair['scenario_id']} ({pair['flow_id']})")
    print(f"\nEnriched features written to: {result['features_file']}")
    print("Next: Phase 3 digital twin ingests flows_features.jsonl (measured fields only).")
    return 0


def _cmd_summary(args: argparse.Namespace) -> int:
    path = Path(args.features)
    records = EnrichedFlowRegistry(path).load_all()
    by_class: dict[str, int] = {}
    untrusted_sni = 0
    for r in records:
        cls = r.ground_truth.get("traffic_class", "unknown")
        by_class[cls] = by_class.get(cls, 0) + 1
        if r.field_trust.get("sni") == "untrusted":
            untrusted_sni += 1
    print(
        json.dumps(
            {
                "total": len(records),
                "by_traffic_class": by_class,
                "records_with_untrusted_sni_tag": untrusted_sni,
                "cicflowmeter_keys_per_record": len(records[0].cicflowmeter) if records else 0,
            },
            indent=2,
        )
    )
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    from veritas.capture.verify import (
        check_determinism,
        check_leakage,
        check_pairwise_scenario_overlap,
    )

    cfg = load_capture_config(Path(args.config) if args.config else None)
    pcap = Path(args.pcap) if args.pcap else resolve_project_path(cfg["pcap"]["default_input"])
    features = Path(args.features)
    ports = [int(p) for p in cfg["pcap"]["filter_ports"]]

    report: dict = {}
    if pcap.is_file():
        report["determinism"] = check_determinism(pcap, ports)
    else:
        report["determinism"] = {"skipped": f"PCAP not found: {pcap}"}
    if features.is_file():
        report["leakage"] = check_leakage(features)
        report["scenario_overlap"] = check_pairwise_scenario_overlap(features)
    else:
        report["leakage"] = {"skipped": f"features file not found: {features}"}

    print(json.dumps(report, indent=2, default=str))
    if report["determinism"].get("deterministic") is False:
        return 1
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Veritas Phase 2 — PCAP to CICFlowMeter features + trust tags",
    )
    parser.add_argument(
        "--config",
        default=str(resolve_project_path("config/capture.yaml")),
        help="Path to capture.yaml",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    proc = sub.add_parser("process", help="Extract features and join ground-truth labels")
    proc.add_argument("--pcap", help="Input PCAP/PCAPNG path")
    proc.add_argument("--labels", help="Phase 1 flows.jsonl path")
    proc.add_argument("--output", help="Output flows_features.jsonl path")
    proc.add_argument(
        "--manifest",
        nargs="?",
        const="",
        help="Process every run in runs_manifest.json as its own capture "
        "(optional path; default from capture.yaml)",
    )
    proc.add_argument(
        "--entropy",
        action="store_true",
        help="Add Phase 8c packet-size / inter-arrival entropy features",
    )
    proc.add_argument(
        "--use-tshark-sni",
        action="store_true",
        help="Parse SNI via tshark (slower; default uses lab port map)",
    )
    proc.set_defaults(func=_cmd_process)

    summ = sub.add_parser("summary", help="Summarize enriched feature file")
    summ.add_argument(
        "--features",
        default=str(resolve_project_path("data/processed/features/flows_features.jsonl")),
    )
    summ.set_defaults(func=_cmd_summary)

    ver = sub.add_parser("verify", help="Check extraction determinism and label leakage")
    ver.add_argument("--pcap", help="PCAP to re-extract (default from capture.yaml)")
    ver.add_argument(
        "--features",
        default=str(resolve_project_path("data/processed/features/flows_features.jsonl")),
    )
    ver.set_defaults(func=_cmd_verify)

    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    raise SystemExit(args.func(args))


if __name__ == "__main__":
    main()
