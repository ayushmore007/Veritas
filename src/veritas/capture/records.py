"""Phase 2 enriched flow record (features + metadata + trust tags + ground truth)."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel


class EnrichedFlowRecord(BaseModel):
    """One labeled flow ready for digital twin ingestion (Phase 3)."""

    flow_id: str
    capture_id: str
    pcap_source: str

    cicflowmeter: dict[str, Any]
    metadata: dict[str, Any]
    field_trust: dict[str, Literal["trusted", "untrusted"]]
    ground_truth: dict[str, Any]

    # Five-tuple from CICFlowMeter for replay/correlation
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int

    def to_jsonl(self) -> str:
        return self.model_dump_json()


class EnrichedFlowRegistry:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write_all(self, records: list[EnrichedFlowRecord]) -> None:
        with self.path.open("w", encoding="utf-8") as f:
            for rec in records:
                f.write(rec.to_jsonl() + "\n")

    def load_all(self) -> list[EnrichedFlowRecord]:
        if not self.path.is_file():
            return []
        out: list[EnrichedFlowRecord] = []
        with self.path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    out.append(EnrichedFlowRecord.model_validate_json(line))
        return out
