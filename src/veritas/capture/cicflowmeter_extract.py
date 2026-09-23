"""Extract CICFlowMeter features from PCAP (in-memory, no temp CSV required)."""

from __future__ import annotations

import os
from pathlib import Path

from scapy.utils import PcapReader

from cicflowmeter.flow_session import FlowSession


class _ListWriter:
    """Collect flow dicts from CICFlowMeter FlowSession."""

    def __init__(self) -> None:
        self.rows: list[dict] = []

    def write(self, data: dict) -> None:
        self.rows.append(dict(data))


def extract_flows_from_pcap(
    pcap_path: Path,
    *,
    testbed_ports: list[int] | None = None,
) -> list[dict]:
    """
    Run CICFlowMeter on an offline PCAP and return flow feature dicts.

    Streams packets via PcapReader (lower memory than rdpcap on large captures).
    """
    writer = _ListWriter()
    session = FlowSession(output_mode="csv", output=os.devnull)
    session.output_writer = writer  # type: ignore[assignment]

    port_set = set(testbed_ports) if testbed_ports else None
    processed = 0

    try:
        with PcapReader(str(pcap_path)) as reader:
            for pkt in reader:
                if "IP" not in pkt:
                    continue
                if "UDP" not in pkt and "TCP" not in pkt:
                    continue
                if port_set is not None and "UDP" in pkt:
                    sp = int(pkt["UDP"].sport)
                    dp = int(pkt["UDP"].dport)
                    if sp not in port_set and dp not in port_set:
                        continue
                session.process(pkt)
                processed += 1
    except Exception as exc:
        raise ValueError(f"Could not read PCAP: {pcap_path}") from exc

    session.flush_flows()
    return writer.rows


def filter_testbed_flows(flows: list[dict], ports: list[int]) -> list[dict]:
    """Keep UDP flows involving lab server ports."""
    port_set = set(ports)
    kept: list[dict] = []
    for row in flows:
        sp = int(row.get("src_port", 0) or 0)
        dp = int(row.get("dst_port", 0) or 0)
        if sp in port_set or dp in port_set:
            kept.append(row)
    return kept
