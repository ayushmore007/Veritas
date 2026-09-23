"""Phase 1 label sanity audit.

The Phase 1 label is asserted by the generator, not observed. If the generator says "this was a
C2 beacon" but the traffic it produced does not beacon, every downstream number is measuring the
wrong thing — and nothing will ever raise an error about it.

This renders, per sampled flow, the behavioural evidence a human needs to confirm the label by
eye: how long it ran, which way the bytes went, how the requests were spaced, how many there were.
It also applies a small set of expectation checks per scenario and marks disagreements, so an
auditor knows where to look first. The checks are a triage aid, **not** the audit — the audit is a
person reading the evidence column and, for a random subset, opening the PCAP in Wireshark.
"""

from __future__ import annotations

import random
from typing import Any

from veritas.testbed.labels import FlowLabelRecord

#: What each scenario should look like if the generator did what it claims.
EXPECTATIONS: dict[str, dict[str, Any]] = {
    "browse": {
        "description": "several small request/response pairs, download-leaning, sub-second",
        "max_duration_s": 5.0,
        "min_requests": 2,
        "direction": "download",
    },
    "stream": {
        "description": "one or few large downloads",
        "min_bytes_received": 100_000,
        "direction": "download",
    },
    "c2_beacon": {
        "description": "periodic small heartbeats over a long window",
        "min_duration_s": 5.0,
        "max_bytes_total": 100_000,
        "min_requests": 3,
    },
    "data_exfil": {
        "description": "sustained upload to an unusual destination",
        "min_bytes_sent": 100_000,
        "direction": "upload",
    },
    "scan_probe": {
        "description": "rapid burst of requests across several paths",
        "max_duration_s": 5.0,
        "min_requests": 3,
        "max_bytes_total": 100_000,
    },
}


def _duration(label: FlowLabelRecord) -> float:
    if label.ended_at is None:
        return 0.0
    return max(0.0, (label.ended_at - label.started_at).total_seconds())


def _direction(label: FlowLabelRecord) -> str:
    total = label.bytes_sent + label.bytes_received
    if total == 0:
        return "none"
    ratio = (label.bytes_sent - label.bytes_received) / total
    if ratio > 0.25:
        return "upload"
    if ratio < -0.25:
        return "download"
    return "balanced"


def audit_label(label: FlowLabelRecord) -> dict[str, Any]:
    """Evidence + expectation check for one labeled flow."""
    duration = _duration(label)
    direction = _direction(label)
    total_bytes = label.bytes_sent + label.bytes_received
    spec = EXPECTATIONS.get(label.scenario_id, {})

    disagreements: list[str] = []
    if "max_duration_s" in spec and duration > spec["max_duration_s"]:
        disagreements.append(
            f"duration {duration:.2f}s exceeds expected max {spec['max_duration_s']}s"
        )
    if "min_duration_s" in spec and duration < spec["min_duration_s"]:
        disagreements.append(
            f"duration {duration:.2f}s below expected min {spec['min_duration_s']}s"
        )
    if "min_requests" in spec and label.request_count < spec["min_requests"]:
        disagreements.append(
            f"{label.request_count} requests, expected at least {spec['min_requests']}"
        )
    if "min_bytes_sent" in spec and label.bytes_sent < spec["min_bytes_sent"]:
        disagreements.append(
            f"uploaded {label.bytes_sent} bytes, expected at least {spec['min_bytes_sent']}"
        )
    if "min_bytes_received" in spec and label.bytes_received < spec["min_bytes_received"]:
        disagreements.append(
            f"downloaded {label.bytes_received} bytes, expected at least "
            f"{spec['min_bytes_received']}"
        )
    if "max_bytes_total" in spec and total_bytes > spec["max_bytes_total"]:
        disagreements.append(
            f"{total_bytes} bytes total exceeds expected max {spec['max_bytes_total']}"
        )
    if "direction" in spec and direction != spec["direction"]:
        disagreements.append(f"traffic is {direction}, expected {spec['direction']}")

    return {
        "flow_id": label.flow_id,
        "scenario_id": label.scenario_id,
        "claimed_label": label.traffic_class.value,
        "claimed_attack": label.attack_type.value if label.attack_type else None,
        "expected_shape": spec.get("description", "(no expectation registered)"),
        "evidence": {
            "duration_s": round(duration, 4),
            "requests": label.request_count,
            "bytes_sent": label.bytes_sent,
            "bytes_received": label.bytes_received,
            "direction": direction,
            "dst_port": label.dst_port,
            "sni": label.dst_sni,
        },
        "disagreements": disagreements,
        "needs_review": bool(disagreements),
    }


def audit_labels(
    labels: list[FlowLabelRecord],
    *,
    sample: int | None = None,
    seed: int = 0,
) -> dict[str, Any]:
    """Audit a random sample (or all) of the label registry."""
    population = list(labels)
    if sample is not None and sample < len(population):
        population = random.Random(seed).sample(population, sample)

    findings = [audit_label(label) for label in population]
    flagged = [f for f in findings if f["needs_review"]]
    unregistered = sorted(
        {f["scenario_id"] for f in findings if f["scenario_id"] not in EXPECTATIONS}
    )

    return {
        "audited": len(findings),
        "population": len(labels),
        "sampled": sample is not None and sample < len(labels),
        "seed": seed,
        "flagged_for_review": len(flagged),
        "scenarios_without_expectations": unregistered,
        "instruction": (
            "Automated checks are triage only. Read the evidence column for every row and confirm "
            "the claimed label matches the behaviour; open a random subset in Wireshark and "
            "confirm the flow is really QUIC/HTTP-3 and really does the thing it claims."
        ),
        "findings": findings,
    }
