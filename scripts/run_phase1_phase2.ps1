"""Run Phase 1 traffic + PCAP record + Phase 2 feature extraction."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
from pathlib import Path

from veritas.capture.config import resolve_project_path
from veritas.capture.pcap_record import PcapRecorder
from veritas.capture.pipeline import CapturePipeline
from veritas.testbed.config import load_testbed_config, resolve_path
from veritas.testbed.orchestrator import LabOrchestrator


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate lab traffic, record PCAP, extract features")
    parser.add_argument(
        "--config",
        default=str(resolve_project_path("config/testbed.yaml")),
    )
    parser.add_argument(
        "--pcap-out",
        default=str(resolve_project_path("data/raw/pcap/phase1.pcapng")),
    )
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    cfg = load_testbed_config(Path(args.config))
    pcap_out = Path(args.pcap_out)
    ports = [h["port"] for h in cfg["hosts"].values() if h.get("role") == "server"]
    labels_path = resolve_path(cfg["output"]["labels_dir"], cfg) / "flows.jsonl"

    recorder = PcapRecorder(pcap_out, ports)
    recorder.start()
    orch = LabOrchestrator(Path(args.config))
    try:
        gen_result = asyncio.run(orch.run())
    finally:
        pkt_count = recorder.stop()

    capture_result = CapturePipeline().run(pcap_path=pcap_out, labels_path=labels_path)

    print(
        json.dumps(
            {
                "generate": gen_result.get("summary"),
                "pcap_packets": pkt_count,
                "capture": capture_result,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
