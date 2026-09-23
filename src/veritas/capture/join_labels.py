"""Join CICFlowMeter flows with Phase 1 ground-truth labels."""

from __future__ import annotations

import math
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
    if use_latest_run and labels:
        latest_run = labels[-1].run_id
        if latest_run is not None:
            labels = [label for label in labels if label.run_id == latest_run]
        elif len(labels) > latest_run_count:
            # Labels written before run_id existed: fall back to "the last N lines".
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


def flow_timestamp(row: dict) -> float:
    ts = row.get("timestamp")
    if ts is None:
        return 0.0
    if isinstance(ts, (int, float)):
        return float(ts)
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


#: A pair whose duration disagrees by more than this fraction *and* by more than
#: `LOW_CONFIDENCE_MIN_ABS_S` seconds is reported as low confidence rather than silently accepted.
LOW_CONFIDENCE_REL = 0.5
LOW_CONFIDENCE_MIN_ABS_S = 0.5

# Relative weight of each term in the assignment cost. Duration is the primary signal: it is the
# one quantity both sides measure in the same units. Start offset (relative to the first
# label/flow on the same port) breaks ties between similar-length sessions without depending on
# the capture clock agreeing with UTC. Bytes are only a weak tie-breaker, because labels count
# HTTP payload while CICFlowMeter counts wire bytes, and QUIC overhead dominates small sessions.
_W_DURATION = 1.0
_W_OFFSET = 0.25
_W_BYTES = 0.05


def _label_duration(label: FlowLabelRecord) -> float | None:
    if label.ended_at is None:
        return None
    return max(0.0, (label.ended_at - label.started_at).total_seconds())


def _flow_duration(row: dict) -> float:
    try:
        return max(0.0, float(row.get("flow_duration", 0.0) or 0.0))
    except (TypeError, ValueError):
        return 0.0


def _rel_diff(a: float, b: float, *, floor: float) -> float:
    return abs(a - b) / max(a, b, floor)


def _pair_cost(
    label: FlowLabelRecord,
    row: dict,
    *,
    label_offset: float,
    flow_offset: float,
    offset_scale: float,
) -> dict[str, float | None]:
    label_dur = _label_duration(label)
    flow_dur = _flow_duration(row)
    dur_term = 0.0 if label_dur is None else _rel_diff(label_dur, flow_dur, floor=0.05)

    offset_term = abs(label_offset - flow_offset) / offset_scale

    wire = int(row.get("totlen_fwd_pkts", 0) or 0) + int(row.get("totlen_bwd_pkts", 0) or 0)
    payload = label.bytes_sent + label.bytes_received
    bytes_term = abs(math.log1p(wire) - math.log1p(payload))

    return {
        "cost": _W_DURATION * dur_term + _W_OFFSET * offset_term + _W_BYTES * bytes_term,
        "label_duration": label_dur,
        "flow_duration": flow_dur,
        "duration_rel_diff": None if label_dur is None else round(dur_term, 4),
    }


def _is_low_confidence(info: dict[str, float | None]) -> bool:
    label_dur = info["label_duration"]
    if label_dur is None:
        return False
    flow_dur = float(info["flow_duration"] or 0.0)
    rel = float(info["duration_rel_diff"] or 0.0)
    return rel > LOW_CONFIDENCE_REL and abs(label_dur - flow_dur) > LOW_CONFIDENCE_MIN_ABS_S


def match_labels_to_flows_scored(
    labels: list[FlowLabelRecord],
    flows: list[dict],
) -> list[tuple[FlowLabelRecord, dict, dict[str, Any]]]:
    """
    Pair each label with at most one flow on the same server port, minimising total cost.

    The assignment is global (Hungarian algorithm) per port, so one locally cheap pairing cannot
    force a wrong one elsewhere. Timing uses offsets from the first label/flow on the port, so a
    naive CICFlowMeter timestamp in local time does not disturb the join. Each pair carries its
    cost breakdown and a `low_confidence` flag for `summarize_match_quality`.
    """
    from scipy.optimize import linear_sum_assignment

    by_port_labels: dict[int, list[FlowLabelRecord]] = {}
    for label in labels:
        by_port_labels.setdefault(label.dst_port, []).append(label)

    by_port_flows: dict[int, list[dict]] = {}
    for row in flows:
        by_port_flows.setdefault(_server_port(row), []).append(row)

    scored: list[tuple[FlowLabelRecord, dict, dict[str, Any]]] = []
    for port in sorted(by_port_labels):
        port_labels = sorted(by_port_labels[port], key=lambda r: r.started_at)
        port_flows = sorted(by_port_flows.get(port, []), key=flow_timestamp)
        if not port_flows:
            continue

        label_t0 = port_labels[0].started_at.timestamp()
        flow_t0 = flow_timestamp(port_flows[0])
        label_offsets = [lbl.started_at.timestamp() - label_t0 for lbl in port_labels]
        flow_offsets = [flow_timestamp(r) - flow_t0 for r in port_flows]
        offset_scale = max(1.0, *label_offsets, *flow_offsets)

        infos = [
            [
                _pair_cost(
                    lbl,
                    row,
                    label_offset=label_offsets[i],
                    flow_offset=flow_offsets[j],
                    offset_scale=offset_scale,
                )
                for j, row in enumerate(port_flows)
            ]
            for i, lbl in enumerate(port_labels)
        ]
        cost = [[float(info["cost"] or 0.0) for info in row] for row in infos]
        rows_idx, cols_idx = linear_sum_assignment(cost)

        for i, j in zip(rows_idx, cols_idx, strict=True):
            info = dict(infos[i][j])
            info["cost"] = round(float(info["cost"] or 0.0), 4)
            info["low_confidence"] = _is_low_confidence(info)
            scored.append((port_labels[i], port_flows[j], info))

    scored.sort(key=lambda item: item[0].started_at)
    return scored


def match_labels_to_flows(
    labels: list[FlowLabelRecord],
    flows: list[dict],
) -> list[tuple[FlowLabelRecord, dict]]:
    """Label/flow pairs without the score breakdown. See `match_labels_to_flows_scored`."""
    return [(label, row) for label, row, _ in match_labels_to_flows_scored(labels, flows)]


def summarize_match_quality(
    scored: list[tuple[FlowLabelRecord, dict, dict[str, Any]]],
) -> dict[str, Any]:
    """Report how trustworthy the join is, listing every pair that should be checked by hand."""
    low = [
        {
            "flow_id": label.flow_id,
            "scenario_id": label.scenario_id,
            "dst_port": label.dst_port,
            "label_duration_s": info["label_duration"],
            "flow_duration_s": info["flow_duration"],
            "cost": info["cost"],
        }
        for label, _, info in scored
        if info.get("low_confidence")
    ]
    costs = [float(info["cost"]) for _, _, info in scored]
    return {
        "pairs": len(scored),
        "mean_cost": round(sum(costs) / len(costs), 4) if costs else None,
        "max_cost": round(max(costs), 4) if costs else None,
        "low_confidence_pairs": low,
    }


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
