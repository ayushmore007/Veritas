"""Phase 2 end-to-end capture pipeline."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from veritas.capture.cicflowmeter_extract import extract_flows_from_pcap, filter_testbed_flows
from veritas.capture.config import load_capture_config, resolve_project_path
from veritas.capture.entropy import add_entropy_features
from veritas.capture.join_labels import (
    dedupe_labels,
    label_to_ground_truth,
    match_labels_to_flows_scored,
    summarize_match_quality,
)
from veritas.capture.metadata import (
    build_port_sni_map,
    extract_sni_via_tshark,
    metadata_for_flow,
    tshark_available,
)
from veritas.capture.records import EnrichedFlowRecord, EnrichedFlowRegistry
from veritas.capture.trust import load_trust_config, tag_field_trust
from veritas.testbed.labels import FlowLabelRecord, LabelRegistry


class CapturePipeline:
    def __init__(self, config_path: Path | None = None) -> None:
        self.config = load_capture_config(config_path)
        self.trust_cfg = load_trust_config(
            resolve_project_path(self.config["trust"]["config"])
        )

    @property
    def entropy_enabled(self) -> bool:
        return bool((self.config.get("entropy") or {}).get("enabled", False))

    def _output_file(self, output_path: Path | None) -> Path:
        return output_path or resolve_project_path(
            self.config["output"]["features_dir"]
        ) / self.config["output"]["features_file"]

    def _process_pcap(
        self,
        pcap: Path,
        labels: list[FlowLabelRecord],
        capture_id: str,
    ) -> tuple[list[EnrichedFlowRecord], dict]:
        """Extract, enrich and label every testbed flow in one PCAP (= one capture)."""
        ports = [int(p) for p in self.config["pcap"]["filter_ports"]]
        port_sni_map = build_port_sni_map(self.config["port_sni_map"])

        # 1) CICFlowMeter feature extraction (+ optional packet-level shape features)
        raw_flows = extract_flows_from_pcap(pcap, testbed_ports=ports)
        flows = filter_testbed_flows(raw_flows, ports)
        if self.entropy_enabled and flows:
            add_entropy_features(pcap, flows)

        # Optional CSV export for inspection / baseline tooling
        csv_dir = resolve_project_path(self.config["output"]["cicflowmeter_csv_dir"])
        csv_dir.mkdir(parents=True, exist_ok=True)
        csv_path = csv_dir / f"{pcap.stem}_cicflowmeter.csv"
        if flows:
            pd.DataFrame(flows).to_csv(csv_path, index=False)

        # 2) Metadata (tshark optional; lab port map is always untrusted fallback)
        tshark_sni: dict[int, str] = {}
        meta_cfg = self.config["metadata"]
        if bool(meta_cfg.get("use_tshark_sni", False)) and tshark_available():
            tshark_sni = extract_sni_via_tshark(
                pcap,
                meta_cfg["tshark_display_filter"],
                timeout_sec=int(meta_cfg.get("tshark_timeout_sec", 20)),
            )

        # 3) Join with Phase 1 ground-truth labels
        scored_pairs = match_labels_to_flows_scored(labels, flows)

        # 4) Build enriched records with trust tags
        records: list[EnrichedFlowRecord] = []
        for label, row, _ in scored_pairs:
            sp = int(row["src_port"])
            dp = int(row["dst_port"])
            meta = metadata_for_flow(
                src_port=sp,
                dst_port=dp,
                port_sni_map=port_sni_map,
                tshark_sni_by_port=tshark_sni,
                default_alpn=meta_cfg["default_alpn"],
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

        stats = {
            "capture_id": capture_id,
            "pcap": str(pcap),
            "cicflowmeter_csv": str(csv_path) if flows else None,
            "tshark_sni_ports": list(tshark_sni.keys()),
            "raw_flow_count": len(raw_flows),
            "testbed_flow_count": len(flows),
            "labels": len(labels),
            "matched_count": len(records),
            "unmatched_labels": len(labels) - len(records),
            "unmatched_flows": len(flows) - len(records),
            "match_quality": summarize_match_quality(scored_pairs),
        }
        return records, stats

    @staticmethod
    def _trust_summary(records: list[EnrichedFlowRecord]) -> dict[str, int]:
        return {
            "trusted_fields": sum(
                1 for r in records for t in r.field_trust.values() if t == "trusted"
            ),
            "untrusted_fields": sum(
                1 for r in records for t in r.field_trust.values() if t == "untrusted"
            ),
        }

    def run(
        self,
        *,
        pcap_path: Path | None = None,
        labels_path: Path | None = None,
        output_path: Path | None = None,
    ) -> dict:
        """Single-capture mode: one PCAP, labels deduped per `config/capture.yaml`."""
        pcap = pcap_path or resolve_project_path(self.config["pcap"]["default_input"])
        labels_file = labels_path or resolve_project_path(self.config["labels"]["default_input"])
        out_file = self._output_file(output_path)

        if not pcap.is_file():
            raise FileNotFoundError(f"PCAP not found: {pcap}. Capture during `veritas-testbed generate` first.")

        label_cfg = self.config["labels"]
        labels = dedupe_labels(
            LabelRegistry(labels_file).load_all(),
            label_cfg["dedupe_strategy"],
            use_latest_run=bool(label_cfg.get("use_latest_run", False)),
            latest_run_count=int(label_cfg.get("latest_run_count", 5)),
        )
        # A run_id names the capture; older labels fall back to a fresh id.
        run_ids = {label.run_id for label in labels}
        capture_id = run_ids.pop() if len(run_ids) == 1 and None not in run_ids else str(uuid.uuid4())

        records, stats = self._process_pcap(pcap, labels, capture_id)
        EnrichedFlowRegistry(out_file).write_all(records)

        return {
            **stats,
            "processed_at": datetime.now(timezone.utc).isoformat(),
            "labels_file": str(labels_file),
            "features_file": str(out_file),
            "tshark_available": tshark_available(),
            "entropy_features": self.entropy_enabled,
            "trust_summary": self._trust_summary(records),
        }

    def run_manifest(
        self,
        *,
        manifest_path: Path | None = None,
        labels_path: Path | None = None,
        output_path: Path | None = None,
    ) -> dict:
        """
        Multi-run mode: every run in `runs_manifest.json` is its own capture.

        Each run's PCAP is joined only with that run's labels, and its `run_id` becomes the
        `capture_id` — the unit `veritas-agent split` keeps on one side of the train/test line.
        """
        manifest_file = manifest_path or resolve_project_path(
            self.config["pcap"]["runs_manifest"]
        )
        if not manifest_file.is_file():
            raise FileNotFoundError(
                f"Run manifest not found: {manifest_file}. "
                "Run `veritas-testbed generate --runs N --record-pcap` first."
            )
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        labels_file = labels_path or Path(
            manifest.get("labels_file") or resolve_project_path(self.config["labels"]["default_input"])
        )
        out_file = self._output_file(output_path)
        all_labels = {label.flow_id: label for label in LabelRegistry(labels_file).load_all()}

        records: list[EnrichedFlowRecord] = []
        per_run: list[dict] = []
        for run in manifest.get("runs", []):
            run_id = run["run_id"]
            pcap = Path(run["pcap"]) if run.get("pcap") else None
            if pcap is None or not pcap.is_file():
                per_run.append({"capture_id": run_id, "skipped": f"PCAP not found: {pcap}"})
                continue
            labels = [all_labels[fid] for fid in run.get("flow_ids", []) if fid in all_labels]
            run_records, stats = self._process_pcap(pcap, labels, run_id)
            records.extend(run_records)
            per_run.append(stats)

        EnrichedFlowRegistry(out_file).write_all(records)

        processed = [r for r in per_run if "skipped" not in r]
        low_conf = [
            pair for r in processed for pair in r["match_quality"]["low_confidence_pairs"]
        ]
        costs = [r["match_quality"]["mean_cost"] for r in processed if r["match_quality"]["mean_cost"] is not None]
        return {
            "processed_at": datetime.now(timezone.utc).isoformat(),
            "manifest": str(manifest_file),
            "labels_file": str(labels_file),
            "features_file": str(out_file),
            "runs_total": len(per_run),
            "runs_processed": len(processed),
            "runs_skipped": [r["capture_id"] for r in per_run if "skipped" in r],
            "tshark_available": tshark_available(),
            "entropy_features": self.entropy_enabled,
            "testbed_flow_count": sum(r["testbed_flow_count"] for r in processed),
            "matched_count": len(records),
            "unmatched_labels": sum(r["unmatched_labels"] for r in processed),
            "unmatched_flows": sum(r["unmatched_flows"] for r in processed),
            "match_quality": {
                "pairs": len(records),
                "mean_cost": round(sum(costs) / len(costs), 4) if costs else None,
                "low_confidence_pairs": low_conf,
            },
            "trust_summary": self._trust_summary(records),
            "per_run": per_run,
        }
