"""CLI for Phase 1 testbed traffic generation."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from veritas.capture.pcap_record import PcapRecorder
from veritas.testbed.config import load_testbed_config, project_root, resolve_path
from veritas.testbed.labels import FlowLabelRecord, LabelRegistry
from veritas.testbed.orchestrator import LabOrchestrator
from veritas.testbed.server import run_server_process


#: Written next to the PCAPs; `veritas-capture process --manifest` reads it.
RUNS_MANIFEST_NAME = "runs_manifest.json"


def _cmd_generate(args: argparse.Namespace) -> int:
    orch = LabOrchestrator(Path(args.config) if args.config else None)
    cfg = load_testbed_config(Path(args.config) if args.config else None)
    ports = [h["port"] for h in cfg["hosts"].values() if h.get("role") == "server"]
    pcaps_dir = resolve_path(cfg["output"]["pcaps_dir"], cfg)

    if args.runs < 1:
        print("--runs must be at least 1", file=sys.stderr)
        return 2
    if args.pcap_out and args.runs > 1:
        print("--pcap-out names one file; it cannot be used with --runs > 1", file=sys.stderr)
        return 2

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    manifest_runs: list[dict] = []
    results: list[dict] = []

    for i in range(args.runs):
        run_id = f"{stamp}-r{i:03d}"
        # Distinct, reproducible draw per run; None keeps the configured values verbatim.
        run_seed = None if args.seed is None else args.seed * 100_003 + i

        recorder = None
        pcap_out: Path | None = None
        if args.record_pcap:
            if args.pcap_out:
                pcap_out = Path(args.pcap_out)
            elif args.runs == 1:
                pcap_out = pcaps_dir / "phase1.pcapng"
            else:
                pcap_out = pcaps_dir / f"run_{run_id}.pcapng"
            recorder = PcapRecorder(pcap_out, ports)
            recorder.start()
            time.sleep(1.5)  # let the capture attach before the first QUIC packets

        result: dict = {}
        try:
            result = asyncio.run(orch.run(run_id=run_id, seed=run_seed))
        finally:
            if recorder is not None and pcap_out is not None:
                result["pcap_file"] = str(pcap_out)
                result["pcap_packets"] = recorder.stop()

        results.append(result)
        manifest_runs.append(
            {
                "run_id": run_id,
                "seed": run_seed,
                "pcap": result.get("pcap_file"),
                "pcap_packets": result.get("pcap_packets"),
                "flow_ids": [r["flow_id"] for r in result.get("records", [])],
                "scenario_params": result.get("scenario_params"),
            }
        )
        print(
            f"[run {i + 1}/{args.runs}] {run_id}: {result['summary']['total']} flows"
            + (f", {result.get('pcap_packets', 0)} packets" if recorder else ""),
            file=sys.stderr,
        )

    manifest_path = pcaps_dir / RUNS_MANIFEST_NAME
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps(
            {
                "created_at": datetime.now(timezone.utc).isoformat(),
                "seed": args.seed,
                "runs": manifest_runs,
                "labels_file": results[-1]["labels_file"],
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    if args.runs == 1:
        print(json.dumps(results[0], indent=2))
    else:
        totals = LabelRegistry.summarize(
            [FlowLabelRecord.model_validate(r) for res in results for r in res["records"]]
        )
        print(json.dumps({"runs": args.runs, "seed": args.seed, "summary": totals}, indent=2))

    print(f"\nGround-truth labels written to: {results[-1]['labels_file']}")
    print(f"Run manifest: {manifest_path}")
    if args.record_pcap:
        empty = [r["run_id"] for r in manifest_runs if not r["pcap_packets"]]
        if empty:
            print(f"Hint: {len(empty)} run(s) captured 0 packets. Use tshark on loopback, or run "
                  "as a user allowed to capture (Npcap on Windows).")
        elif args.runs == 1:
            print("Next: veritas-capture process --pcap", results[0].get("pcap_file"))
        else:
            print("Next: veritas-capture process --manifest")
    else:
        print("Next: Phase 2 capture (tshark + CICFlowMeter) on these flows.")
    return 0


def _cmd_summary(args: argparse.Namespace) -> int:
    path = Path(args.labels)
    records = LabelRegistry(path).load_all()
    print(json.dumps(LabelRegistry.summarize(records), indent=2))
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    from veritas.testbed.certs import ensure_testbed_certs
    from veritas.testbed.config import load_testbed_config, resolve_path

    cfg = load_testbed_config(Path(args.config) if args.config else None)
    certs_dir = resolve_path(cfg["output"]["certs_dir"], cfg)
    snis = [h["sni"] for h in cfg["hosts"].values() if "sni" in h]
    cert, key = ensure_testbed_certs(certs_dir, snis)
    host_cfg = cfg["hosts"][args.host]
    logging.basicConfig(level=logging.INFO)
    asyncio.run(
        run_server_process(
            host_cfg["localhost_bind"],
            host_cfg["port"],
            cert,
            key,
        )
    )
    return 0


def _cmd_audit(args: argparse.Namespace) -> int:
    from veritas.testbed.audit import audit_labels

    cfg = load_testbed_config(Path(args.config) if args.config else None)
    labels_path = (
        Path(args.labels)
        if args.labels
        else resolve_path(cfg["output"]["labels_dir"], cfg) / "flows.jsonl"
    )
    labels = LabelRegistry(labels_path).load_all()
    if not labels:
        print(f"No labels in {labels_path}. Run `veritas-testbed generate` first.")
        return 1
    print(json.dumps(audit_labels(labels, sample=args.sample, seed=args.seed), indent=2, default=str))
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Veritas Phase 1 — QUIC testbed traffic generation (lab only)",
    )
    parser.add_argument(
        "--config",
        type=str,
        default=str(project_root() / "config" / "testbed.yaml"),
        help="Path to testbed.yaml",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("generate", help="Start servers, run all scenarios, write labels")
    gen.add_argument(
        "--record-pcap",
        action="store_true",
        help="Record UDP testbed traffic to PCAP during generation (requires Npcap)",
    )
    gen.add_argument(
        "--pcap-out",
        help="PCAP output path (with --record-pcap; single run only)",
    )
    gen.add_argument(
        "--runs",
        type=int,
        default=1,
        help="Independent generation runs; each gets its own PCAP and run_id (default: 1)",
    )
    gen.add_argument(
        "--seed",
        type=int,
        help="Vary scenario parameters per run, reproducibly (default: use config values as-is)",
    )
    gen.set_defaults(func=_cmd_generate)

    summ = sub.add_parser("summary", help="Summarize an existing flows.jsonl")
    summ.add_argument("--labels", required=True, help="Path to flows.jsonl")
    summ.set_defaults(func=_cmd_summary)

    audit = sub.add_parser("audit", help="Check that labels match the generated behaviour")
    audit.add_argument("--labels", help="Path to flows.jsonl (default from testbed.yaml)")
    audit.add_argument("--sample", type=int, help="Audit a random sample of N labels")
    audit.add_argument("--seed", type=int, default=0)
    audit.set_defaults(func=_cmd_audit)

    serve = sub.add_parser("serve", help="Run a single HTTP/3 server (debug)")
    serve.add_argument(
        "--host",
        choices=["benign_server", "malicious_c2", "malicious_exfil"],
        default="benign_server",
    )
    serve.set_defaults(func=_cmd_serve)

    args = parser.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if getattr(args, "verbose", False) else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )
    raise SystemExit(args.func(args))


if __name__ == "__main__":
    main()
