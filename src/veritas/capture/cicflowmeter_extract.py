"""Extract CICFlowMeter features from PCAP (in-memory, no temp CSV required)."""

from __future__ import annotations

import os
import re
from pathlib import Path

from scapy.utils import PcapReader

from cicflowmeter.flow_session import FlowSession


# CICFlowMeter (every published Python release) reports durations, inter-arrival times and
# active/idle periods in *microseconds*. Everything downstream — the agent's tool description,
# the label join, the simulacrum's thresholds, the injection payloads — reasons in seconds, so a
# 26 ms page load read raw looks like a seven-hour session. Rates (`*_s`) are already per second.
_MICROSECOND_FIELD = re.compile(r"^(flow_duration|(flow|fwd|bwd)_iat_\w+|(active|idle)_\w+)$")


def normalize_time_units(row: dict) -> dict:
    """Convert CICFlowMeter's microsecond time fields to seconds, in place, and return the row."""
    for key, value in row.items():
        if _MICROSECOND_FIELD.match(key) and isinstance(value, (int, float)):
            row[key] = float(value) / 1e6
    return row


class _ListWriter:
    """Collect flow dicts from CICFlowMeter FlowSession."""

    def __init__(self) -> None:
        self.rows: list[dict] = []

    def write(self, data: dict) -> None:
        self.rows.append(normalize_time_units(dict(data)))


class _OfflineFlowSession(FlowSession):
    """
    FlowSession driven packet-by-packet instead of by a live sniffer.

    CICFlowMeter reads its output settings from class attributes (0.1.9 uses `output_file`, 0.2.x
    uses `output`), and has no public "process one packet" / "flush" API. Setting both attribute
    names and calling `on_packet_received` / `garbage_collect(None)` works on either version.
    """

    output_mode = "csv"
    output = os.devnull
    output_file = os.devnull
    verbose = False
    fields = None


def extract_flows_from_pcap(
    pcap_path: Path,
    *,
    testbed_ports: list[int] | None = None,
) -> list[dict]:
    """
    Run CICFlowMeter on an offline PCAP and return flow feature dicts.

    Streams packets via PcapReader (lower memory than rdpcap on large captures). Time fields are
    returned in seconds (see `normalize_time_units`).
    """
    writer = _ListWriter()
    session = _OfflineFlowSession()
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
                session.on_packet_received(pkt)
                processed += 1
    except Exception as exc:
        raise ValueError(f"Could not read PCAP: {pcap_path}") from exc

    # Flush every flow still open at end of capture.
    session.garbage_collect(None)
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
