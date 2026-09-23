"""Malicious QUIC/HTTP-3 traffic patterns (lab-only, scripted behaviours)."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from veritas.testbed.client import HttpSession
from veritas.testbed.labels import AttackType, FlowLabelRecord, LabelRegistry, TrafficClass


async def run_c2_beacon(
    session: HttpSession,
    *,
    dst_host: str,
    interval_sec: float,
    repetitions: int,
    registry: LabelRegistry,
) -> FlowLabelRecord:
    started = datetime.now(timezone.utc)
    for _ in range(repetitions):
        await session.get("/beacon")
        await asyncio.sleep(interval_sec)

    record = FlowLabelRecord(
        traffic_class=TrafficClass.MALICIOUS,
        attack_type=AttackType.C2_BEACON,
        scenario_id="c2_beacon",
        description="Periodic low-volume heartbeat to controller",
        dst_host=dst_host,
        dst_sni=session.sni,
        dst_port=session.port,
        started_at=started,
        capture_hint={"pattern": "periodic_small_requests", "interval_sec": interval_sec},
    )
    return registry.append(record.finalize(
        bytes_sent=session.stats.bytes_sent,
        bytes_received=session.stats.bytes_received,
        request_count=session.stats.request_count,
    ))


async def run_data_exfil(
    session: HttpSession,
    *,
    dst_host: str,
    upload_kb: int,
    registry: LabelRegistry,
) -> FlowLabelRecord:
    started = datetime.now(timezone.utc)
    payload = b"E" * (upload_kb * 1024)
    await session.post("/upload", payload)

    record = FlowLabelRecord(
        traffic_class=TrafficClass.MALICIOUS,
        attack_type=AttackType.DATA_EXFIL,
        scenario_id="data_exfil",
        description="Sustained upload to unusual destination",
        dst_host=dst_host,
        dst_sni=session.sni,
        dst_port=session.port,
        started_at=started,
        capture_hint={"upload_kb": upload_kb, "path": "/upload"},
    )
    return registry.append(record.finalize(
        bytes_sent=session.stats.bytes_sent,
        bytes_received=session.stats.bytes_received,
        request_count=session.stats.request_count,
    ))


async def run_scan_probe(
    session: HttpSession,
    *,
    dst_host: str,
    paths: list[str],
    registry: LabelRegistry,
) -> FlowLabelRecord:
    started = datetime.now(timezone.utc)
    for path in paths:
        await session.get(path)
        await asyncio.sleep(0.05)

    record = FlowLabelRecord(
        traffic_class=TrafficClass.MALICIOUS,
        attack_type=AttackType.SCAN_PROBE,
        scenario_id="scan_probe",
        description="Rapid probing of multiple paths on destination",
        dst_host=dst_host,
        dst_sni=session.sni,
        dst_port=session.port,
        started_at=started,
        capture_hint={"paths": paths},
    )
    return registry.append(record.finalize(
        bytes_sent=session.stats.bytes_sent,
        bytes_received=session.stats.bytes_received,
        request_count=session.stats.request_count,
    ))
