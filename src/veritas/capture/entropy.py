"""Phase 8c distribution-shape features, computed per flow from the packets themselves.

CICFlowMeter summarises a flow as aggregates (totals, means, maxima). Phase 6 evasion moves
aggregates; moving the *shape* of the packet-size and timing distributions at the same time is much
harder. So these features describe shape:

* `ent_size`, `ent_size_fwd`, `ent_size_bwd` — Shannon entropy (bits) of the packet-size
  distribution, combined and per direction
* `ent_size_norm` — `ent_size` divided by its maximum for this packet count, in [0, 1]
* `ent_distinct_sizes` — number of distinct packet sizes
* `ent_top_size_share` — fraction of packets carrying the single most common size
* `ent_iat` — entropy of inter-arrival times quantised into log2 microsecond buckets

All are measured from packet timing and length, never from a string, so they are trusted and
admissible (see `veritas/features.py`). Forward means "sent by the flow's src endpoint".
"""

from __future__ import annotations

import math
from collections import Counter
from pathlib import Path
from typing import Any

from scapy.utils import PcapReader

from veritas.capture.join_labels import flow_timestamp

ENTROPY_FIELDS: tuple[str, ...] = (
    "ent_size",
    "ent_size_fwd",
    "ent_size_bwd",
    "ent_size_norm",
    "ent_distinct_sizes",
    "ent_top_size_share",
    "ent_iat",
)

# CICFlowMeter timestamps have one-second resolution, so a packet may precede its flow's
# recorded start by up to a second.
_START_SLACK_S = 1.0


def shannon_entropy(values: list[Any]) -> float:
    """Entropy in bits of the empirical distribution of `values`."""
    if not values:
        return 0.0
    n = len(values)
    return -sum((c / n) * math.log2(c / n) for c in Counter(values).values()) + 0.0


def _endpoint_key(proto: int, a: tuple[str, int], b: tuple[str, int]) -> tuple:
    return (proto, *sorted([a, b]))


def _row_key(row: dict) -> tuple:
    src = (str(row.get("src_ip")), int(row.get("src_port", 0) or 0))
    dst = (str(row.get("dst_ip")), int(row.get("dst_port", 0) or 0))
    return _endpoint_key(int(row.get("protocol", 17) or 17), src, dst)


def entropy_features(
    sizes: list[int],
    directions: list[bool],
    times: list[float],
) -> dict[str, float]:
    """Shape features for one flow. `directions[i]` is True for forward packets."""
    n = len(sizes)
    if n == 0:
        return dict.fromkeys(ENTROPY_FIELDS, 0.0)

    fwd = [s for s, d in zip(sizes, directions, strict=True) if d]
    bwd = [s for s, d in zip(sizes, directions, strict=True) if not d]
    ent = shannon_entropy(sizes)
    counts = Counter(sizes)

    ordered = sorted(times)
    iat_buckets = [
        int(math.log2((b - a) * 1e6 + 1)) for a, b in zip(ordered, ordered[1:], strict=False)
    ]

    return {
        "ent_size": round(ent, 6),
        "ent_size_fwd": round(shannon_entropy(fwd), 6),
        "ent_size_bwd": round(shannon_entropy(bwd), 6),
        "ent_size_norm": round(ent / math.log2(n), 6) if n > 1 else 0.0,
        "ent_distinct_sizes": float(len(counts)),
        "ent_top_size_share": round(counts.most_common(1)[0][1] / n, 6),
        "ent_iat": round(shannon_entropy(iat_buckets), 6),
    }


def add_entropy_features(pcap_path: Path, flows: list[dict]) -> list[dict]:
    """
    Add `ENTROPY_FIELDS` to each CICFlowMeter row, in place, from the packets in `pcap_path`.

    Packets are assigned by bidirectional five-tuple; when one five-tuple spans several rows
    (CICFlowMeter split it on a timeout), each packet goes to the latest row that had started.
    """
    rows_by_key: dict[tuple, list[tuple[float, int]]] = {}
    for idx, row in enumerate(flows):
        rows_by_key.setdefault(_row_key(row), []).append((flow_timestamp(row), idx))
    for starts in rows_by_key.values():
        starts.sort()

    collected: list[dict[str, list]] = [
        {"sizes": [], "dirs": [], "times": []} for _ in flows
    ]

    with PcapReader(str(pcap_path)) as reader:
        for pkt in reader:
            if "IP" not in pkt:
                continue
            ip = pkt["IP"]
            if "UDP" in pkt:
                l4, proto = pkt["UDP"], 17
            elif "TCP" in pkt:
                l4, proto = pkt["TCP"], 6
            else:
                continue
            src = (str(ip.src), int(l4.sport))
            dst = (str(ip.dst), int(l4.dport))
            starts = rows_by_key.get(_endpoint_key(proto, src, dst))
            if not starts:
                continue

            t = float(pkt.time)
            idx = starts[0][1]
            for start, candidate in starts:
                if start <= t + _START_SLACK_S:
                    idx = candidate
            row = flows[idx]
            forward = src == (str(row.get("src_ip")), int(row.get("src_port", 0) or 0))

            bucket = collected[idx]
            bucket["sizes"].append(len(ip))
            bucket["dirs"].append(forward)
            bucket["times"].append(t)

    for row, bucket in zip(flows, collected, strict=True):
        row.update(entropy_features(bucket["sizes"], bucket["dirs"], bucket["times"]))
    return flows
