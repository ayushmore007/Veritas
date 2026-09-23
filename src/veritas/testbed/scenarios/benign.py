"""Benign QUIC/HTTP-3 traffic patterns."""

from __future__ import annotations

from datetime import datetime, timezone

from veritas.testbed.client import HttpSession
from veritas.testbed.labels import FlowLabelRecord, LabelRegistry, TrafficClass


async def run_browse(
    session: HttpSession,
    *,
    dst_host: str,
    repetitions: int,
    registry: LabelRegistry,
) -> FlowLabelRecord:
    started = datetime.now(timezone.utc)
    for i in range(repetitions):
        await session.get(f"/?page={i}")

    record = FlowLabelRecord(
        traffic_class=TrafficClass.BENIGN,
        scenario_id="browse",
        description="HTTP/3 page fetches resembling normal browsing",
        dst_host=dst_host,
        dst_sni=session.sni,
        dst_port=session.port,
        started_at=started,
        capture_hint={"paths": ["/"]},
    )
    return registry.append(record.finalize(
        bytes_sent=session.stats.bytes_sent,
        bytes_received=session.stats.bytes_received,
        request_count=session.stats.request_count,
    ))


async def run_stream(
    session: HttpSession,
    *,
    dst_host: str,
    chunk_kb: int,
    repetitions: int,
    registry: LabelRegistry,
) -> FlowLabelRecord:
    started = datetime.now(timezone.utc)
    for _ in range(repetitions):
        await session.get(f"/stream/{chunk_kb}")

    record = FlowLabelRecord(
        traffic_class=TrafficClass.BENIGN,
        scenario_id="stream",
        description="Large HTTP/3 download resembling streaming",
        dst_host=dst_host,
        dst_sni=session.sni,
        dst_port=session.port,
        started_at=started,
        capture_hint={"paths": [f"/stream/{chunk_kb}"]},
    )
    return registry.append(record.finalize(
        bytes_sent=session.stats.bytes_sent,
        bytes_received=session.stats.bytes_received,
        request_count=session.stats.request_count,
    ))
