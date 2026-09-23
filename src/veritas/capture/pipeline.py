"""Phase 2 end-to-end capture pipeline."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from veritas.capture.cicflowmeter_extract import extract_flows_from_pcap, filter_testbed_flows
from veritas.capture.config import load_capture_config, resolve_project_path
from veritas.capture.join_labels import (
    dedupe_labels,
    label_to_ground_truth,
    match_labels_to_flows,
)
from veritas.capture.metadata import (
    build_port_sni_map,
    extract_sni_via_tshark,
    metadata_for_flow,
    tshark_available,
)
from veritas.capture.records import EnrichedFlowRecord, EnrichedFlowRegistry
from veritas.capture.trust import load_trust_config, tag_field_trust
from veritas.testbed.labels import LabelRegistry


class CapturePipeline:
    def __init__(self, config_path: Path | None = None) -> None:
        self.config = load_capture_config(config_path)
        self.trust_cfg = load_trust_config(
            resolve_project_path(self.config["trust"]["config"])
        )

    def run(
        self,
        *,
        pcap_path: Path | None = None,
        labels_path: Path | None = None,
        output_path: Path | None = None,
    ) -> dict:
        pcap = pcap_path or resolve_project_path(self.config["pcap"]["default_input"])
        labels_file = labels_path or resolve_project_path(self.config["labels"]["default_input"])
        out_file = output_path or resolve_project_path(
            self.config["output"]["features_dir"]
        ) / self.config["output"]["features_file"]

        if not pcap.is_file():
            raise FileNotFoundError(f"PCAP not found: {pcap}. Capture during `veritas-testbed generate` first.")

        capture_id = str(uuid.uuid4())
        ports = [int(p) for p in self.config["pcap"]["filter_ports"]]
        port_sni_map = build_port_sni_map(self.config["port_sni_map"])

        # 1) CICFlowMeter feature extraction
        raw_flows = extract_flows_from_pcap(pcap, testbed_ports=ports)
        flows = filter_testbed_flows(raw_flows, ports)

        # Optional CSV export for inspection / baseline tooling
        csv_dir = resolve_project_path(self.config["output"]["cicflowmeter_csv_dir"])
        csv_dir.mkdir(parents=True, exist_ok=True)
        csv_path = csv_dir / f"{pcap.stem}_cicflowmeter.csv"
        if flows:
            pd.DataFrame(flows).to_csv(csv_path, index=False)

        # 2) Metadata (tshark optional; lab port map is always untrusted fallback)
        tshark_sni: dict[int, str] = {}
        meta_cfg = self.config["metadata"]
        use_tshark = bool(meta_cfg.get("use_tshark_sni", False))
        if use_tshark and tshark_available():
            tshark_sni = extract_sni_via_tshark(
                pcap,
                meta_cfg["tshark_display_filter"],
                timeout_sec=int(meta_cfg.get("tshark_timeout_sec", 20)),
            )

        # 3) Join with Phase 1 ground-truth labels
        all_labels = LabelRegistry(labels_file).load_all()
        label_cfg = self.config["labels"]
        labels = dedupe_labels(
            all_labels,
            label_cfg["dedupe_strategy"],
            use_latest_run=bool(label_cfg.get("use_latest_run", False)),
            latest_run_count=int(label_cfg.get("latest_run_count", 5)),
        )
        pairs = match_labels_to_flows(labels, flows)

        # 4) Build enriched records with trust tags
        records: list[EnrichedFlowRecord] = []
        for label, row in pairs:
            sp = int(row["src_port"])
            dp = int(row["dst_port"])
            meta = metadata_for_flow(
                src_port=sp,
                dst_port=dp,
                port_sni_map=port_sni_map,
                tshark_sni_by_port=tshark_sni,
                default_alpn=self.config["metadata"]["default_alpn"],
            )
            metadata = {
                "sni": meta.sni,
                "alpn": meta.alpn,
                "quic_version": meta.quic_version,
                "connection_id": meta.connection_id,
                "metadata_source": meta.source,
            }
            trust = tag_field_trust(row, metadata, self.trust_cfg)
            records.append(
                EnrichedFlowRecord(
                    flow_id=label.flow_id,
                    capture_id=capture_id,
                    pcap_source=str(pcap),
                    cicflowmeter=row,
                    metadata=metadata,
                    field_trust=trust,
                    ground_truth=label_to_ground_truth(label),
                    src_ip=str(row["src_ip"]),
                    dst_ip=str(row["dst_ip"]),
                    src_port=sp,
                    dst_port=dp,
                    protocol=int(row.get("protocol", 17)),
                )
            )

        EnrichedFlowRegistry(out_file).write_all(records)

        unmatched_labels = len(labels) - len(pairs)
        unmatched_flows = len(flows) - len(pairs)

        return {
            "capture_id": capture_id,
            "processed_at": datetime.now(timezone.utc).isoformat(),
            "pcap": str(pcap),
            "labels_file": str(labels_file),
            "features_file": str(out_file),
            "cicflowmeter_csv": str(csv_path) if flows else None,
            "tshark_available": tshark_available(),
            "tshark_sni_ports": list(tshark_sni.keys()),
            "raw_flow_count": len(raw_flows),
            "testbed_flow_count": len(flows),
            "matched_count": len(records),
            "unmatched_labels": unmatched_labels,
            "unmatched_flows": unmatched_flows,
            "trust_summary": {
                "trusted_fields": sum(
                    1 for r in records for t in r.field_trust.values() if t == "trusted"
                ),
                "untrusted_fields": sum(
                    1 for r in records for t in r.field_trust.values() if t == "untrusted"
                ),
            },
        }
