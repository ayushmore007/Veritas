# Phase 2 — Capture & CICFlowMeter Features

## What Phase 2 does

Phase 1 produced **labeled traffic** and (optionally) a **PCAP**. Phase 2 turns raw packets into **structured feature records** the rest of the system can reason over:

```mermaid
flowchart LR
  A[PCAP] --> B[CICFlowMeter ~80 features]
  C[flows.jsonl labels] --> D[Join matcher]
  B --> D
  E[tshark SNI or port map] --> F[Metadata block]
  D --> G[flows_features.jsonl]
  F --> G
  H[trust_labels.yaml] --> G
```

| Step | Output | Trust |
|------|--------|-------|
| CICFlowMeter | `flow_duration`, `tot_fwd_pkts`, IAT stats, … | **trusted** (measured) |
| Metadata | `sni`, `alpn`, … | **untrusted** (attacker-controllable) |
| Join | `ground_truth.traffic_class`, `attack_type` | label oracle (Phase 1) |

**Why CICFlowMeter:** comparability with CIC-IDS2017/2018 baselines and published QUIC-IDS work (IEEE TNSM 2025). **Cite** the CICFlowMeter tool paper in methods.

**Why metadata separately:** SoK finding — encrypted payload alone is insufficient; header/metadata (SNI) matters, and in our threat model SNI is the injection surface for Phase 7.

## One-shot (recommended)

```powershell
veritas-testbed generate --record-pcap
veritas-capture process
veritas-capture summary
```

`--record-pcap` uses **tshark** on the loopback adapter when available (same as manual capture).

**Note:** tshark needs ~1.5s to attach; the CLI waits before sending traffic so benign flows on port 4433 are included.
Without tshark, scapy records the loopback interface (needs libpcap and capture permission).

## Multiple runs (the corpus)

```powershell
veritas-testbed generate --runs 60 --seed 1 --record-pcap
veritas-capture process --manifest --entropy
```

Each run writes its own `data/raw/pcap/run_<run_id>.pcapng` and is listed in
`data/raw/pcap/runs_manifest.json`. `--manifest` joins every run's PCAP with only that run's
labels and uses the `run_id` as `capture_id`, so a split never puts one capture on both sides.
`--seed` varies scenario parameters per run (reproducibly); omit it to use `config/testbed.yaml`
as-is. `--entropy` adds the Phase 8c packet-level shape features (`ent_*`).

## Units

CICFlowMeter reports durations, inter-arrival times and active/idle periods in microseconds.
Extraction converts them to **seconds**; rates (`*_s`) are already per second.

## Outputs

| File | Purpose |
|------|---------|
| `data/processed/features/flows_features.jsonl` | Twin/agent input (Phase 3+) |
| `data/processed/cicflowmeter/<pcap>_cicflowmeter.csv` | Raw CICFlowMeter export for baselines |

## Label deduplication

If you ran `veritas-testbed generate` multiple times, `flows.jsonl` has duplicate scenarios. In single-PCAP mode, `use_latest_run` keeps only the labels of the most recent run (by `run_id`), and `last_per_scenario_port` keeps the **latest** label per `(scenario_id, dst_port)`. `--manifest` mode needs neither: each run is joined with its own labels.

## Capture tip (Windows)

Terminal 1:
```powershell
tshark -i "Adapter for loopback traffic capture" -f "udp port 4433 or udp port 4434 or udp port 4435" -w data\raw\pcap\phase1.pcapng
```

Terminal 2:
```powershell
veritas-testbed generate
```

## Next: Phase 3

Digital twin Tier 1 ingests **measured** CICFlowMeter fields + host history — not metadata strings — as the tamper-resistant oracle.
