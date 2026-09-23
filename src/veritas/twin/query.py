"""Query and replay API for the Tier-1 digital twin (agent tool surface in Phase 4)."""

from __future__ import annotations

from typing import Any

from veritas.twin.store import TwinStore


def get_flow_stats(store: TwinStore, flow_id: str) -> dict[str, Any]:
    """Return measured features + ground truth for a flow (oracle view)."""
    flow = store.get_flow(flow_id)
    if flow is None:
        raise KeyError(f"Unknown flow_id: {flow_id}")
    return {
        "flow_id": flow_id,
        "trust_level": "measured",
        "features": flow["measured_features"],
        "ground_truth": flow["ground_truth"],
        "five_tuple": {
            "src_ip": flow["src_ip"],
            "dst_ip": flow["dst_ip"],
            "src_port": flow["src_port"],
            "dst_port": flow["dst_port"],
            "protocol": flow["protocol"],
        },
    }


def get_metadata(store: TwinStore, flow_id: str) -> dict[str, Any]:
    """Return untrusted metadata (attacker-controllable strings) in a side channel."""
    flow = store.get_flow(flow_id)
    if flow is None:
        raise KeyError(f"Unknown flow_id: {flow_id}")
    return {
        "flow_id": flow_id,
        "trust_level": "untrusted",
        "metadata": flow["metadata_untrusted"],
    }


def get_host_history(store: TwinStore, ip: str, limit: int = 50) -> dict[str, Any]:
    events = store.get_host_history(ip, limit=limit)
    return {
        "ip": ip,
        "trust_level": "measured",
        "event_count": len(events),
        "events": events,
    }


def replay_flow_metadata_ablation(
    store: TwinStore,
    flow_id: str,
    *,
    strip_fields: list[str],
) -> dict[str, Any]:
    """
    Metadata-ablation replay (Phase 8 fingerprint):
    return flow view with untrusted metadata stripped; if agent verdict would change,
    decision was metadata-dependent.
    """
    flow = store.get_flow(flow_id)
    if flow is None:
        raise KeyError(f"Unknown flow_id: {flow_id}")

    stripped = dict(flow["metadata_untrusted"])
    removed = []
    for field in strip_fields:
        if field in stripped:
            removed.append(field)
            stripped[field] = None

    return {
        "flow_id": flow_id,
        "replay_type": "metadata_ablation",
        "measured_features": flow["measured_features"],
        "metadata_original": flow["metadata_untrusted"],
        "metadata_stripped": stripped,
        "fields_removed": removed,
        "ground_truth": flow["ground_truth"],
    }
