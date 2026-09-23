"""Join CICFlowMeter flows with Phase 1 ground-truth labels."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from veritas.testbed.labels import FlowLabelRecord


def dedupe_labels(
    labels: list[FlowLabelRecord],
    strategy: str = "last_per_scenario_port",
    *,
    use_latest_run: bool = False,
    latest_run_count: int = 5,
) -> list[FlowLabelRecord]:
    """Reduce duplicate labels from repeated `veritas-testbed generate` runs."""
    if use_latest_run and len(labels) > latest_run_count:
        labels = labels[-latest_run_count:]
    if strategy == "none":
        return labels
    if strategy != "last_per_scenario_port":
        raise ValueError(f"Unknown dedupe strategy: {strategy}")

    seen: dict[tuple[str, int], FlowLabelRecord] = {}
    for label in labels:
        key = (label.scenario_id, label.dst_port)
        seen[key] = label
    return sorted(seen.values(), key=lambda r: r.started_at)


def _server_port(row: dict) -> int:
    sp = int(row.get("src_port", 0) or 0)
    dp = int(row.get("dst_port", 0) or 0)
    testbed_ports = {4433, 4434, 4435}
    if dp in testbed_ports:
        return dp
    if sp in testbed_ports:
        return sp
    return dp


def _flow_timestamp(row: dict) -> float:
    ts = row.get("timestamp")
    if ts is None:
        return 0.0
    if isinstance(ts, (int, float)):
        return float(ts)
    from datetime import datetime

    text = str(ts).strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
        try:
            return datetime.strptime(text, fmt).timestamp()
        except ValueError:
            continue
    try:
        return float(text)
    except ValueError:
        return 0.0


def _match_score(label: FlowLabelRecord, row: dict) -> float:
    fwd = int(row.get("totlen_fwd_pkts", 0) or 0)
    bwd = int(row.get("totlen_bwd_pkts", 0) or 0)
    return abs(fwd - label.bytes_sent) + abs(bwd - label.bytes_received)


def match_labels_to_flows(
    labels: list[FlowLabelRecord],
    flows: list[dict],
) -> list[tuple[FlowLabelRecord, dict]]:
    """
    Greedy match: group by server port, pair by byte-count similarity.

    Works when Phase 1 scenarios use one QUIC connection each (our design).
    """
    by_port_labels: dict[int, list[FlowLabelRecord]] = {}
    for label in labels:
        by_port_labels.setdefault(label.dst_port, []).append(label)
    for port in by_port_labels:
        by_port_labels[port].sort(key=lambda r: r.started_at)

    by_port_flows: dict[int, list[dict]] = {}
    for row in flows:
        port = _server_port(row)
        by_port_flows.setdefault(port, []).append(row)
    for port in by_port_flows:
        by_port_flows[port].sort(key=_flow_timestamp)

    pairs: list[tuple[FlowLabelRecord, dict]] = []
    for port, port_labels in by_port_labels.items():
        port_flows = by_port_flows.get(port, [])
        used: set[int] = set()
        for label in port_labels:
            best_idx = None
            best_score = float("inf")
            for i, row in enumerate(port_flows):
                if i in used:
                    continue
                score = _match_score(label, row)
                if score < best_score:
                    best_score = score
                    best_idx = i
            if best_idx is not None:
                used.add(best_idx)
                pairs.append((label, port_flows[best_idx]))
    return pairs


def label_to_ground_truth(label: FlowLabelRecord) -> dict[str, Any]:
    return {
        "flow_id": label.flow_id,
        "traffic_class": label.traffic_class.value,
        "attack_type": label.attack_type.value if label.attack_type else None,
        "scenario_id": label.scenario_id,
        "description": label.description,
        "dst_host": label.dst_host,
        "dst_sni_expected": label.dst_sni,
        "label_started_at": label.started_at.astimezone(timezone.utc).isoformat(),
        "label_ended_at": label.ended_at.isoformat() if label.ended_at else None,
    }
