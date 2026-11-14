"""Extract CICFlowMeter features from PCAP (in-memory, no temp CSV required)."""

from __future__ import annotations

import math
import os
import re
from pathlib import Path

from scapy.utils import PcapReader

import cicflowmeter.flow_session as _cfm_session
from cicflowmeter.flow import Flow as _CfmFlow
from cicflowmeter.flow_session import FlowSession


# CICFlowMeter has not kept one time unit across releases: 0.1.x/0.2.x report durations,
# inter-arrival times and active/idle periods in *microseconds*, 0.5.x reports *seconds*. Everything
# downstream — the agent's tool description, the label join, the simulacrum's thresholds, the
# injection payloads — reasons in seconds, so a 26 ms page load read raw as microseconds looks like
# a seven-hour session, and the reverse error makes every flow look instantaneous. Rates (`*_s`)
# are per second in every release and so give an unit-free reference for the true duration.
_MICROSECOND_FIELD = re.compile(r"^(flow_duration|(flow|fwd|bwd)_iat_\w+|(active|idle)_\w+)$")


def _true_duration_seconds(row: dict) -> float | None:
    """Flow duration in seconds recovered from a per-second rate, whatever unit the tool used."""
    def num(key: str) -> float:
        value = row.get(key, 0)
        return float(value) if isinstance(value, (int, float)) else 0.0

    total_bytes = num("totlen_fwd_pkts") + num("totlen_bwd_pkts")
    if num("flow_byts_s") > 0 and total_bytes > 0:
        return total_bytes / num("flow_byts_s")
    total_pkts = num("tot_fwd_pkts") + num("tot_bwd_pkts")
    if num("flow_pkts_s") > 0 and total_pkts > 0:
        return total_pkts / num("flow_pkts_s")
    return None


def time_scale_divisor(row: dict) -> float:
    """
    Divisor that turns this row's time fields into seconds: 1 (already seconds), 1e3 or 1e6.

    Chosen by comparing the reported `flow_duration` with the duration implied by the flow's
    per-second rates, snapped to the nearest power of ten. When the row cannot say (a one-packet
    flow has zero duration, so every time field is 0 and the scale is moot) it returns 1.
    """
    reported = row.get("flow_duration")
    true_s = _true_duration_seconds(row)
    if not isinstance(reported, (int, float)) or reported <= 0 or not true_s:
        return 1.0
    ratio = float(reported) / true_s
    return min((1.0, 1e3, 1e6), key=lambda d: abs(math.log10(ratio) - math.log10(d)))


def normalize_time_units(row: dict) -> dict:
    """Convert CICFlowMeter time fields to seconds, whatever unit this release used, in place."""
    divisor = time_scale_divisor(row)
    if divisor == 1.0:
        return row
    for key, value in row.items():
        if _MICROSECOND_FIELD.match(key) and isinstance(value, (int, float)):
            row[key] = float(value) / divisor
    return row


class _SingleCountFlow(_CfmFlow):
    """
    `Flow` that counts its first packet once.

    cicflowmeter 0.5.x stores the first packet in `Flow.__init__` and `FlowSession.process` then
    calls `add_packet` with that same packet, so every flow counts its first packet twice: packet
    and byte totals are inflated and a spurious 0-second inter-arrival time makes `flow_iat_min`
    always 0. Older releases did not store it in `__init__`, so they are unaffected. Removing the
    stored copy first lets `add_packet` re-append it exactly once and still run its bulk/subflow
    bookkeeping for that packet.
    """

    def add_packet(self, packet, direction) -> None:  # type: ignore[override]
        if len(self.packets) == 1 and packet is self.packets[0][0]:
            self.packets.pop()
        super().add_packet(packet, direction)


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

    0.5.x additionally builds its writer inside `__init__` from `output_mode`/`output` arguments and
    raises when they are missing, so we hand it a throwaway devnull CSV writer; `_ListWriter`
    replaces it straight after construction.
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
    try:
        session = _OfflineFlowSession()
    except RuntimeError:  # cicflowmeter >= 0.5 requires an output mode at construction
        session = _OfflineFlowSession(output_mode="csv", output=os.devnull)
    session.output_writer = writer
    # FlowSession looks `Flow` up in its own module namespace; swap in the corrected class for the
    # duration of this extraction only.
    original_flow = _cfm_session.Flow
    _cfm_session.Flow = _SingleCountFlow  # type: ignore[assignment]

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
                # The per-packet entry point differs by release: cicflowmeter 0.2.x defines
                # `on_packet_received`; 0.5.x defines `process` instead. Order matters: scapy's
                # DefaultSession also has a no-op `process`, so testing for `process` first would
                # silently extract zero flows on 0.2.x (that is how CI on Python 3.11 caught it).
                feed = getattr(session, "on_packet_received", None) or session.process
                feed(pkt)
                processed += 1
    except Exception as exc:
        raise ValueError(f"Could not read PCAP: {pcap_path}") from exc
    finally:
        _cfm_session.Flow = original_flow

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
