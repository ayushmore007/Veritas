"""Malicious QUIC/HTTP-3 traffic patterns (lab-only, scripted behaviours)."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from veritas.attacks.evasion import EvasionProfile
from veritas.testbed.client import HttpSession
from veritas.testbed.labels import AttackType, FlowLabelRecord, LabelRegistry, TrafficClass


async def run_c2_beacon(
    session: HttpSession,
    *,
    dst_host: str,
    interval_sec: float,
    repetitions: int,
    registry: LabelRegistry,
    evasion: EvasionProfile | None = None,
) -> FlowLabelRecord:
    evasion = evasion or EvasionProfile()
    started = datetime.now(timezone.utc)
    for _ in range(repetitions):
        await session.get("/beacon")
        if evasion.chance("cover_requests"):
            await session.get(evasion.cover_path())
        if evasion.chance("cover_download", 0.5):
            await session.get(f"/stream/{evasion.cover_download_kb(32)}")
        await asyncio.sleep(evasion.jitter(interval_sec))

    record = FlowLabelRecord(
        traffic_class=TrafficClass.MALICIOUS,
        attack_type=AttackType.C2_BEACON,
        scenario_id="c2_beacon",
        description="Periodic low-volume heartbeat to controller",
        dst_host=dst_host,
        dst_sni=session.sni,
        dst_port=session.port,
        started_at=started,
        capture_hint={"pattern": "periodic_small_requests", "interval_sec": interval_sec,
                      "evasion": evasion.describe()},
        evasion_strength=evasion.strength if evasion.active else 0.0,
        evasion_variant=evasion.variant if evasion.active else None,
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
    evasion: EvasionProfile | None = None,
) -> FlowLabelRecord:
    evasion = evasion or EvasionProfile()
    started = datetime.now(timezone.utc)
    chunks = evasion.upload_chunks(upload_kb)
    cover_pages = evasion.cover_page_count(6)
    for i, chunk_kb in enumerate(chunks):
        await session.post("/upload", b"E" * (chunk_kb * 1024))
        if cover_pages and i < cover_pages:
            await session.get(evasion.cover_path())
        if len(chunks) > 1:
            await asyncio.sleep(evasion.jitter(0.05))
    for _ in range(max(0, cover_pages - len(chunks))):
        await session.get(evasion.cover_path())
    cover_kb = evasion.cover_download_kb(upload_kb)
    if cover_kb:
        await session.get(f"/stream/{cover_kb}")

    record = FlowLabelRecord(
        traffic_class=TrafficClass.MALICIOUS,
        attack_type=AttackType.DATA_EXFIL,
        scenario_id="data_exfil",
        description="Sustained upload to unusual destination",
        dst_host=dst_host,
        dst_sni=session.sni,
        dst_port=session.port,
        started_at=started,
        capture_hint={"upload_kb": upload_kb, "path": "/upload", "chunks": len(chunks),
                      "evasion": evasion.describe()},
        evasion_strength=evasion.strength if evasion.active else 0.0,
        evasion_variant=evasion.variant if evasion.active else None,
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
    evasion: EvasionProfile | None = None,
) -> FlowLabelRecord:
    evasion = evasion or EvasionProfile()
    started = datetime.now(timezone.utc)
    per_probe_cover = evasion.cover_page_count(3)
    for path in paths:
        await session.get(path)
        for _ in range(per_probe_cover):
            await session.get(evasion.cover_path())
        # Jitter alone barely moves a 50 ms gap; also stretch it so the burst stops looking like one.
        stretch = 0.5 * evasion.rng.random() * evasion.strength if evasion.on("timing_jitter") else 0.0
        await asyncio.sleep(evasion.jitter(0.05) + stretch)
    cover_kb = evasion.cover_download_kb(128)
    if cover_kb:
        await session.get(f"/stream/{cover_kb}")

    record = FlowLabelRecord(
        traffic_class=TrafficClass.MALICIOUS,
        attack_type=AttackType.SCAN_PROBE,
        scenario_id="scan_probe",
        description="Rapid probing of multiple paths on destination",
        dst_host=dst_host,
        dst_sni=session.sni,
        dst_port=session.port,
        started_at=started,
        capture_hint={"paths": paths, "evasion": evasion.describe()},
        evasion_strength=evasion.strength if evasion.active else 0.0,
        evasion_variant=evasion.variant if evasion.active else None,
    )
    return registry.append(record.finalize(
        bytes_sent=session.stats.bytes_sent,
        bytes_received=session.stats.bytes_received,
        request_count=session.stats.request_count,
    ))
