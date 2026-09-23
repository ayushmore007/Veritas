# Phase 1 — Testbed & Labeled Traffic

## What you built

Phase 1 is a **closed lab** that produces **ground-truth-labeled QUIC/HTTP-3 flows** before any AI or capture pipeline runs.

| Component | Purpose |
|-----------|---------|
| `config/testbed.yaml` | Topology, SNI names, scenario parameters |
| HTTP/3 servers | Benign + malicious endpoints (aioquic, reimplemented) |
| Scenario scripts | Benign browse/stream; malicious C2/exfil/scan |
| `flows.jsonl` | Label **at creation time** — scientific ground truth |
| Docker wrapper | Same orchestrator in an isolated container |

**Reference anchor:** QUIC-era ML-IDS (IEEE TNSM 2025, DOI [`10.1109/TNSM.2025.3540753`](https://doi.org/10.1109/TNSM.2025.3540753)) — cite in paper § testbed; your **primary data** is generated QUIC, not CIC-IDS2017.

## What you're doing (plain language)

1. Spin up fake internet inside your machine (localhost or Docker).
2. Run **normal** web traffic and **scripted attack-shaped** traffic over QUIC.
3. Stamp each session with a label **before** the defender sees it: `benign`, `c2_beacon`, `data_exfil`, or `scan_probe`.

That label file is what Phase 9 uses to measure detection accuracy and attack success — without it, you're guessing.

## Run locally (Windows / dev)

```powershell
cd d:\Veritas
.venv\Scripts\activate
pip install -e ".[dev]"
veritas-testbed generate
veritas-testbed summary --labels data\raw\labels\flows.jsonl
```

Expected output: **5 labeled flows** (2 benign + 3 malicious).

## Run in Docker (optional)

```powershell
docker compose -f docker/docker-compose.yml run --rm testbed
```

Labels appear under `data/raw/labels/flows.jsonl` on the host.

## Traffic scenarios

| ID | Class | Behaviour |
|----|-------|-----------|
| `browse` | benign | Repeated small GETs |
| `stream` | benign | Large `/stream/{kb}` download |
| `c2_beacon` | malicious | Periodic `/beacon` heartbeats |
| `data_exfil` | malicious | Large POST `/upload` |
| `scan_probe` | malicious | Rapid GETs across probe paths |

## SNI map (metadata surface for later phases)

| Host | SNI | Port |
|------|-----|------|
| benign_server | `benign.internal.test` | 4433 |
| malicious_c2 | `c2.malicious.test` | 4434 |
| malicious_exfil | `exfil.malicious.test` | 4435 |

SNI is **attacker-controllable** in the threat model (`config/trust_labels.yaml`); here we use fixed lab names.

## Compliance

- **Cite** QUIC-era IDS paper when describing testbed design.
- **Do not** download CIC datasets in Phase 1 — optional sanity data comes in Phase 5 with terms stored in `data/external/_terms/`.
- aioquic used as **library** (BSD-style); HTTP/3 handler **reimplemented**, not copied from examples.

## Next: Phase 2

Capture these flows with **tshark** → PCAP → **CICFlowMeter** features → tag `trusted`/`untrusted` fields.

```powershell
# Example (when tshark installed): capture during generate
tshark -i Loopback -f "udp port 4433 or udp port 4434 or udp port 4435" -w data/raw/pcap/phase1.pcapng
```
