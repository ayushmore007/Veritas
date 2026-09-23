"""Ground-truth flow labels written at traffic creation time (Phase 1)."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field


class TrafficClass(str, Enum):
    BENIGN = "benign"
    MALICIOUS = "malicious"


class AttackType(str, Enum):
    C2_BEACON = "c2_beacon"
    DATA_EXFIL = "data_exfil"
    SCAN_PROBE = "scan_probe"


class FlowLabelRecord(BaseModel):
    """One logical QUIC flow session with ground-truth label."""

    flow_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    traffic_class: TrafficClass
    attack_type: AttackType | None = None
    scenario_id: str
    description: str = ""

    src_host: str = "client"
    dst_host: str
    dst_sni: str
    dst_port: int
    protocol: Literal["quic", "http3"] = "http3"

    started_at: datetime
    ended_at: datetime | None = None
    bytes_sent: int = 0
    bytes_received: int = 0
    request_count: int = 0

    # Phase 2+: maps to CICFlowMeter flow key once capture runs
    capture_hint: dict = Field(default_factory=dict)

    def finalize(
        self,
        *,
        bytes_sent: int,
        bytes_received: int,
        request_count: int,
        ended_at: datetime | None = None,
    ) -> FlowLabelRecord:
        self.bytes_sent = bytes_sent
        self.bytes_received = bytes_received
        self.request_count = request_count
        self.ended_at = ended_at or datetime.now(timezone.utc)
        return self

    def to_jsonl(self) -> str:
        return self.model_dump_json()


class LabelRegistry:
    """Append-only ground-truth store for generated flows."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, record: FlowLabelRecord) -> FlowLabelRecord:
        with self.path.open("a", encoding="utf-8") as f:
            f.write(record.to_jsonl() + "\n")
        return record

    def load_all(self) -> list[FlowLabelRecord]:
        if not self.path.is_file():
            return []
        records: list[FlowLabelRecord] = []
        with self.path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(FlowLabelRecord.model_validate_json(line))
        return records

    @staticmethod
    def summarize(records: list[FlowLabelRecord]) -> dict:
        by_class: dict[str, int] = {}
        by_attack: dict[str, int] = {}
        for r in records:
            by_class[r.traffic_class.value] = by_class.get(r.traffic_class.value, 0) + 1
            if r.attack_type:
                by_attack[r.attack_type.value] = by_attack.get(r.attack_type.value, 0) + 1
        return {"total": len(records), "by_class": by_class, "by_attack": by_attack}
