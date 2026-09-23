"""CLI for Phase 1 testbed traffic generation."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path

from veritas.capture.pcap_record import PcapRecorder
from veritas.testbed.config import load_testbed_config, project_root, resolve_path
from veritas.testbed.labels import LabelRegistry
from veritas.testbed.orchestrator import LabOrchestrator
from veritas.testbed.server import run_server_process


def _cmd_generate(args: argparse.Namespace) -> int:
    orch = LabOrchestrator(Path(args.config) if args.config else None)
    cfg = load_testbed_config(Path(args.config) if args.config else None)
    ports = [h["port"] for h in cfg["hosts"].values() if h.get("role") == "server"]

    recorder = None
    pcap_out: Path | None = Path(args.pcap_out) if args.pcap_out else None
    if args.record_pcap:
        pcap_out = pcap_out or resolve_path(cfg["output"]["pcaps_dir"], cfg) / "phase1.pcapng"
        recorder = PcapRecorder(pcap_out, ports)
        recorder.start()
        import time

        time.sleep(1.5)  # let tshark attach before first QUIC packets

    result: dict = {}
    try:
        result = asyncio.run(orch.run())
    finally:
        if recorder is not None and pcap_out is not None:
            result["pcap_file"] = str(pcap_out)
            result["pcap_packets"] = recorder.stop()

    print(json.dumps(result, indent=2))
    print(f"\nGround-truth labels written to: {result['labels_file']}")
    if recorder is not None:
        print(f"PCAP recording: {result.get('pcap_file')} ({result.get('pcap_packets', 0)} packets)")
        if result.get("pcap_packets", 0) == 0:
            print("Hint: If 0 packets, use tshark on loopback or install Npcap for scapy sniff.")
        else:
            print("Next: veritas-capture process --pcap", result.get("pcap_file"))
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
        help="PCAP output path (with --record-pcap)",
    )
    gen.set_defaults(func=_cmd_generate)

    summ = sub.add_parser("summary", help="Summarize an existing flows.jsonl")
    summ.add_argument("--labels", required=True, help="Path to flows.jsonl")
    summ.set_defaults(func=_cmd_summary)

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
