"""Ingest Phase 2 features into the Tier-1 twin oracle."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from veritas.capture.records import EnrichedFlowRecord, EnrichedFlowRegistry
from veritas.twin.store import TwinStore


def extract_measured_features(record: EnrichedFlowRecord) -> dict[str, Any]:
    """Keep only trusted (instrumented) fields in the oracle."""
    measured: dict[str, Any] = {}
    for key, value in record.cicflowmeter.items():
        if record.field_trust.get(key, "trusted") == "trusted":
            measured[key] = value
    # Five-tuple duplicates for query convenience
    measured["src_ip"] = record.src_ip
    measured["dst_ip"] = record.dst_ip
    measured["src_port"] = record.src_port
    measured["dst_port"] = record.dst_port
    measured["protocol"] = record.protocol
    return measured


def ingest_features_file(
    store: TwinStore,
    features_path: Path,
    *,
    replace: bool = True,
) -> dict[str, Any]:
    records = EnrichedFlowRegistry(features_path).load_all()
    if not records:
        raise FileNotFoundError(f"No enriched flow records in {features_path}")

    if replace:
        store.clear()

    for rec in records:
        store.upsert_flow(
            flow_id=rec.flow_id,
            capture_id=rec.capture_id,
            pcap_source=rec.pcap_source,
            src_ip=rec.src_ip,
            dst_ip=rec.dst_ip,
            src_port=rec.src_port,
            dst_port=rec.dst_port,
            protocol=rec.protocol,
            measured_features=extract_measured_features(rec),
            ground_truth=rec.ground_truth,
            metadata_untrusted=rec.metadata,
        )

    return {
        "ingested": len(records),
        "total_in_store": store.count_flows(),
        "features_source": str(features_path),
    }
