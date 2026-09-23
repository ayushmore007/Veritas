"""Orchestrate Phase 1 servers and labeled traffic generation."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path

from veritas.testbed.certs import ensure_testbed_certs
from veritas.testbed.client import HttpSession
from veritas.testbed.config import load_testbed_config, project_root, resolve_path
from veritas.testbed.labels import FlowLabelRecord, LabelRegistry
from veritas.testbed.scenarios import benign, malicious
from veritas.testbed.server import TestbedServer

logger = logging.getLogger(__name__)


class LabOrchestrator:
    def __init__(self, config_path: Path | None = None) -> None:
        self.config = load_testbed_config(config_path)
        self.root = project_root()
        out = self.config["output"]
        self.labels_path = resolve_path(out["labels_dir"], self.config) / "flows.jsonl"
        self.pcaps_dir = resolve_path(out["pcaps_dir"], self.config)
        self.certs_dir = resolve_path(out["certs_dir"], self.config)
        self.registry = LabelRegistry(self.labels_path)
        self._ensure_output_dirs()

    def _ensure_output_dirs(self) -> None:
        self.labels_path.parent.mkdir(parents=True, exist_ok=True)
        self.pcaps_dir.mkdir(parents=True, exist_ok=True)
        self.certs_dir.mkdir(parents=True, exist_ok=True)

    def all_sni_names(self) -> list[str]:
        return [h["sni"] for h in self.config["hosts"].values() if "sni" in h]

    def ensure_certs(self) -> tuple[Path, Path]:
        cert, key = ensure_testbed_certs(self.certs_dir, self.all_sni_names())
        return cert, key

    async def start_servers(self, cert: Path, key: Path) -> list[TestbedServer]:
        servers: list[TestbedServer] = []
        for name, host_cfg in self.config["hosts"].items():
            if host_cfg.get("role") != "server":
                continue
            server = TestbedServer(
                host=host_cfg["localhost_bind"],
                port=host_cfg["port"],
                cert_path=cert,
                key_path=key,
            )
            await server.start()
            servers.append(server)
            logger.info("Started %s on %s:%s (SNI: %s)", name, host_cfg["localhost_bind"], host_cfg["port"], host_cfg["sni"])
        return servers

    async def stop_servers(self, servers: list[TestbedServer]) -> None:
        for s in servers:
            await s.stop()

    async def run_all_scenarios(self, *, ca_path: Path) -> list[FlowLabelRecord]:
        records: list[FlowLabelRecord] = []
        hosts = self.config["hosts"]
        scenario_cfg = self.config["scenarios"]

        benign_host = hosts["benign_server"]
        browse_cfg = scenario_cfg["benign"][0]
        async with HttpSession(
            host=benign_host["localhost_bind"],
            port=benign_host["port"],
            sni=benign_host["sni"],
            ca_path=str(ca_path),
        ) as session:
            records.append(
                await benign.run_browse(
                    session,
                    dst_host="benign_server",
                    repetitions=browse_cfg["repetitions"],
                    registry=self.registry,
                )
            )
        stream_cfg = scenario_cfg["benign"][1]
        async with HttpSession(
            host=benign_host["localhost_bind"],
            port=benign_host["port"],
            sni=benign_host["sni"],
            ca_path=str(ca_path),
        ) as session:
            records.append(
                await benign.run_stream(
                    session,
                    dst_host="benign_server",
                    chunk_kb=stream_cfg["chunk_kb"],
                    repetitions=stream_cfg["repetitions"],
                    registry=self.registry,
                )
            )

        c2_host = hosts["malicious_c2"]
        c2_cfg = next(s for s in scenario_cfg["malicious"] if s["id"] == "c2_beacon")
        async with HttpSession(
            host=c2_host["localhost_bind"],
            port=c2_host["port"],
            sni=c2_host["sni"],
            ca_path=str(ca_path),
        ) as session:
            records.append(
                await malicious.run_c2_beacon(
                    session,
                    dst_host="malicious_c2",
                    interval_sec=c2_cfg["interval_sec"],
                    repetitions=c2_cfg["repetitions"],
                    registry=self.registry,
                )
            )
        scan_cfg = next(s for s in scenario_cfg["malicious"] if s["id"] == "scan_probe")
        async with HttpSession(
            host=c2_host["localhost_bind"],
            port=c2_host["port"],
            sni=c2_host["sni"],
            ca_path=str(ca_path),
        ) as session:
            records.append(
                await malicious.run_scan_probe(
                    session,
                    dst_host="malicious_c2",
                    paths=scan_cfg["paths"],
                    registry=self.registry,
                )
            )

        exfil_host = hosts["malicious_exfil"]
        exfil_cfg = next(s for s in scenario_cfg["malicious"] if s["id"] == "data_exfil")
        async with HttpSession(
            host=exfil_host["localhost_bind"],
            port=exfil_host["port"],
            sni=exfil_host["sni"],
            ca_path=str(ca_path),
        ) as session:
            records.append(
                await malicious.run_data_exfil(
                    session,
                    dst_host="malicious_exfil",
                    upload_kb=exfil_cfg["upload_kb"],
                    registry=self.registry,
                )
            )

        return records

    async def run(self) -> dict:
        cert, key = self.ensure_certs()
        ca_path = self.certs_dir / "ca.crt"
        servers = await self.start_servers(cert, key)
        try:
            await asyncio.sleep(0.3)
            records = await self.run_all_scenarios(ca_path=ca_path)
        finally:
            await self.stop_servers(servers)

        summary = LabelRegistry.summarize(records)
        return {
            "labels_file": str(self.labels_path),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": summary,
            "records": [r.model_dump(mode="json") for r in records],
        }
