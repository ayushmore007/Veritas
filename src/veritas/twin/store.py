"""SQLite-backed Tier-1 digital twin store (measured features only in oracle)."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


SCHEMA = """
CREATE TABLE IF NOT EXISTS flows (
    flow_id TEXT PRIMARY KEY,
    capture_id TEXT NOT NULL,
    pcap_source TEXT,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    src_port INTEGER NOT NULL,
    dst_port INTEGER NOT NULL,
    protocol INTEGER NOT NULL,
    measured_features TEXT NOT NULL,
    ground_truth TEXT NOT NULL,
    ingested_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS metadata_untrusted (
    flow_id TEXT PRIMARY KEY,
    metadata TEXT NOT NULL,
    FOREIGN KEY (flow_id) REFERENCES flows(flow_id)
);

CREATE TABLE IF NOT EXISTS host_history (
    ip TEXT NOT NULL,
    flow_id TEXT NOT NULL,
    role TEXT NOT NULL,
    event_time TEXT,
    bytes_fwd INTEGER DEFAULT 0,
    bytes_bwd INTEGER DEFAULT 0,
    traffic_class TEXT,
    attack_type TEXT,
    PRIMARY KEY (ip, flow_id, role)
);

CREATE INDEX IF NOT EXISTS idx_host_ip ON host_history(ip);
CREATE INDEX IF NOT EXISTS idx_flows_dst_port ON flows(dst_port);
"""


class TwinStore:
    """Tamper-resistant oracle: measured features from instrumentation, not attacker strings."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def clear(self) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM host_history")
            conn.execute("DELETE FROM metadata_untrusted")
            conn.execute("DELETE FROM flows")

    def upsert_flow(
        self,
        *,
        flow_id: str,
        capture_id: str,
        pcap_source: str,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: int,
        measured_features: dict[str, Any],
        ground_truth: dict[str, Any],
        metadata_untrusted: dict[str, Any],
    ) -> None:
        ingested_at = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO flows
                (flow_id, capture_id, pcap_source, src_ip, dst_ip, src_port, dst_port,
                 protocol, measured_features, ground_truth, ingested_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    flow_id,
                    capture_id,
                    pcap_source,
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    protocol,
                    json.dumps(measured_features),
                    json.dumps(ground_truth),
                    ingested_at,
                ),
            )
            conn.execute(
                """
                INSERT OR REPLACE INTO metadata_untrusted (flow_id, metadata)
                VALUES (?, ?)
                """,
                (flow_id, json.dumps(metadata_untrusted)),
            )

            traffic_class = ground_truth.get("traffic_class")
            attack_type = ground_truth.get("attack_type")
            bytes_fwd = int(measured_features.get("totlen_fwd_pkts", 0) or 0)
            bytes_bwd = int(measured_features.get("totlen_bwd_pkts", 0) or 0)
            event_time = measured_features.get("timestamp")

            for ip, role in ((src_ip, "src"), (dst_ip, "dst")):
                conn.execute(
                    """
                    INSERT OR REPLACE INTO host_history
                    (ip, flow_id, role, event_time, bytes_fwd, bytes_bwd, traffic_class, attack_type)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (ip, flow_id, role, event_time, bytes_fwd, bytes_bwd, traffic_class, attack_type),
                )

    def get_flow(self, flow_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM flows WHERE flow_id = ?", (flow_id,)).fetchone()
            if not row:
                return None
            meta = conn.execute(
                "SELECT metadata FROM metadata_untrusted WHERE flow_id = ?", (flow_id,)
            ).fetchone()
        return {
            "flow_id": row["flow_id"],
            "capture_id": row["capture_id"],
            "pcap_source": row["pcap_source"],
            "src_ip": row["src_ip"],
            "dst_ip": row["dst_ip"],
            "src_port": row["src_port"],
            "dst_port": row["dst_port"],
            "protocol": row["protocol"],
            "measured_features": json.loads(row["measured_features"]),
            "ground_truth": json.loads(row["ground_truth"]),
            "metadata_untrusted": json.loads(meta["metadata"]) if meta else {},
            "ingested_at": row["ingested_at"],
        }

    def list_flows(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT flow_id, src_ip, dst_ip, dst_port, ingested_at FROM flows ORDER BY ingested_at LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_host_history(self, ip: str, limit: int = 50) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT h.*, f.measured_features
                FROM host_history h
                JOIN flows f ON f.flow_id = h.flow_id
                WHERE h.ip = ?
                ORDER BY h.event_time DESC
                LIMIT ?
                """,
                (ip, limit),
            ).fetchall()
        out = []
        for row in rows:
            item = dict(row)
            item["measured_features"] = json.loads(item.pop("measured_features"))
            out.append(item)
        return out

    def count_flows(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS c FROM flows").fetchone()
        return int(row["c"])
