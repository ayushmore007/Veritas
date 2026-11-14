# Training the Veritas flow detector

This is the full list of what you need and the exact steps. Everything here was run end to end in this
repository; the numbers in §6 come from that run.

## 1. What is being trained

| | |
|---|---|
| **Model** | scikit-learn tree ensemble (random forest / extra trees / gradient boosting are candidates; selection picks one) |
| **Input** | one network *flow*, as 55 behavioural statistics (constant columns are dropped): packet counts and sizes per direction, inter-arrival times, rates, flags, plus 7 packet-shape entropy features |
| **Output** | `malicious` / `benign`, a probability, and per-flow SHAP attributions ("which features pushed it") |
| **Never an input** | IP addresses, ports, timestamps, SNI/ALPN strings (`src/veritas/features.py`). In this lab the destination port *is* the label, so using it would score ~100% while learning nothing |
| **Not the same as the LLM agent** | The "defender agent" (Phase 4) is a separate LLM component. It is **not** needed to train or serve this model |

## 2. What you need

**Hardware / OS**
- Any x86-64 or ARM CPU, ~4 GB RAM, ~2 GB disk (the 258-capture corpus here is ~380 MB of PCAPs). **No GPU.** Training takes about a minute.
- **Linux, WSL2 or macOS** for generating traffic (loopback capture). Native Windows needs Npcap/tshark. Capturing needs root / `CAP_NET_RAW` (or tshark with capture rights).

**Software**
- Python 3.11+ (3.13 tested), `pip install -e ".[dev]"`.
- If `lime` fails to build (`install_layout` error): `pip install "setuptools<81" wheel && pip install --no-build-isolation lime`, then retry.
- Optional: `tshark` (nicer capture, SNI dissection). Without tshark *and* libpcap, the recorder falls back to filtering in Python (handled).
- Not needed for the ML model: Docker, Mininet, Ollama/GPU (only for the LLM agent).

**Data** — labelled flows. There is no public dataset to download for this: the lab *generates* its own.
- Per run, the testbed produces 5 flows: 2 benign (`browse`, `stream`) and 3 malicious (`c2_beacon`, `data_exfil`, `scan_probe`), each recorded to its own PCAP.
- Minimums that matter statistically (enforced as warnings by `veritas-train check` and the evaluation gates):
  - ≥ 10 flows in the smallest *test* class to quote any rate; **≥ 30 to quote one with a usable interval**.
  - ≥ ~60 separate captures so train/test splits (by capture) are meaningful.
- **Recommended corpus** (what produced the shipped model): 60 clean runs + 150 benign-only runs, plus evaded malicious runs at strengths 0.25/0.5/0.75/1.0 and four *held-out* evasion variants (never trained on, used to measure generalisation) → 744 flows, 258 captures.
- Time to build it: ~22 s per full run, ~3 s per benign-only run → about 45 minutes for the recommended corpus.

**Decisions only you can make**
1. **False-alarm budget** (`--target-fpr`, default 1%). It sets the decision threshold.
2. **Which attacks matter.** The model only recognises behaviours it was trained on (see §6, "Novel attacks"). New attack class → add a scenario in `src/veritas/testbed/scenarios/malicious.py` and retrain.
3. **Whether you have real traffic.** Everything below trains on *lab* traffic. To say anything about a real network you need labelled real QUIC flows and a feature mapping to the CICFlowMeter schema (§7).

## 3. Steps

```bash
# 0. install
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python scripts/setup_check.py

# 1. build the labelled corpus: traffic -> PCAP -> flow features -> labels -> digital twin
python scripts/reproduce.py --quick --runs 60 --seed 1 --entropy \
    --evasion-strengths 0.25,0.5,0.75,1 --evasion-runs 6 \
    --held-out-variants timing_only,volume_only,chunk_only,cover_only
#   cheap extra benign data (the benign class is otherwise the minority):
veritas-testbed generate --record-pcap --runs 150 --scenarios browse,stream --seed 77
veritas-capture process --manifest --entropy        # re-process every run
veritas-twin ingest

# 2. is the corpus good enough?
veritas-train check                                 # READY / warnings with what to generate

# 3. train, select, evaluate -> models/flow-detector/
veritas-train fit                                   # ~1 min
veritas-train info

# 4. use it
veritas-api                                         # website + REST API  (GET /api/v1/model)
```

What `veritas-train fit` does, and why each step is there:

1. **Fixed split by capture** (60/20/20, written to `data/processed/splits/split.json`). All flows of one run land on the same side, otherwise near-duplicates leak across the boundary and inflate the test score. The test split is never used for any choice.
2. **Pool = train + val**, minus held-out evasion variants (always).
3. **Model selection** — 21 candidates (logistic regression as a reference, random forest, extra trees, gradient boosting) scored by *grouped* stratified 5-fold cross-validation on the pool. Best **deployable** family (tree-based, so SHAP works) by out-of-fold F1, ties → lower false-positive rate.
4. **Threshold** from the out-of-fold predictions: the middle of the plateau that achieves the best recall within the false-alarm budget (not a default 0.5, and not the extreme edge of the feasible range, which is fragile).
5. **Two profiles** are trained: `clean` (only unmodified traffic — what a naive deployment looks like) and `robust` (also trained on evaded malicious flows). `robust` is deployed; `model.clean.joblib` is kept for comparison.
6. **One-shot evaluation**: clean test split; evaded test flows; held-out evasion variants; and **leave-one-attack-out** (train without one attack type, then test on it). Every rate carries a Wilson 95% interval and its raw counts.
7. **Artefacts**: `model.joblib`, `metrics.json` (everything), `MODEL_CARD.md` (readable summary + limitations). The model records the library versions it was trained with; `/model` warns on a mismatch.

Retrain whenever you add scenarios, change evasion profiles, or upgrade `cicflowmeter` (its feature semantics changed between releases — see §8).

## 4. Optional: the LLM agent (not needed for the model above)

```bash
ollama pull llama3.1:8b                      # ~5 GB; needs ~8 GB RAM (GPU optional but much faster)
python scripts/reproduce.py --provider ollama
```

Without Ollama the agent runs as a deterministic stand-in; its numbers demonstrate the mechanism and
are **not** measurements of a language model (the repo labels them so).

## 5. Verify

```bash
python -m pytest -q                          # 140+ tests, includes training + API
veritas-capture verify                       # extraction reproducible, no label leakage
veritas-baseline faithfulness --split test   # do SHAP attributions actually drive decisions?
```

## 6. What the shipped model measured (and how far to trust it)

From `models/flow-detector/MODEL_CARD.md` (744 flows, 258 captures, test split 86 benign / 30 malicious):

| | `clean` | `robust` (deployed) |
|---|---|---|
| Clean test recall | 30/30 | 30/30 |
| Clean test false positives | 0/86 | 1/86 (CI 0.2%–6.3%) |
| Evaded flows missed (test split) | 3/21 | 0/21 |
| Held-out evasion variants missed | `volume_only` 12/18 (67%) | 0/18 each |
| Attack never seen in training: `data_exfil` | **0/60 caught** | **0/60 caught** |

Read these carefully:
- **Saturated.** Every candidate, even logistic regression, reaches F1 = 1.0 in cross-validation. The lab attacks are very different from the lab benign traffic. That proves the pipeline works; it does **not** prove accuracy on real traffic, and it makes model *selection* a tie.
- **Novel attacks are missed.** With `data_exfil` withheld, none of its 60 flows is caught. This is a detector of known behaviours, not an anomaly detector.
- **Evasion.** Adversarial augmentation removed the measured evasion, including on variants it never saw, but each held-out variant has only 18 flows (a 0/18 result is consistent with a true miss rate up to ~18%).
- **README discrepancy, not reconciled.** The README quotes an earlier run where a clean-trained model was evaded 100%; this run measured 11–22% (67% for `volume_only`). Feature extraction changed in between (cicflowmeter units and a first-packet double-count, §8) and the corpus differs, so I can't say which explains it.

## 7. Making it credible on real traffic (not done here)

1. Obtain labelled **real QUIC** flows. The repo's reference list names CIC-IDS2017, CSE-CIC-IDS2018 and UNSW-NB15 (mostly TCP, so only a sanity check). A QUIC-specific public dataset (e.g. CESNET-QUIC22) is a candidate; I have **not** verified its current availability, licence or schema, and its features are packet sequences rather than CICFlowMeter rows, so a mapping layer would be required. Store dataset terms under `data/external/_terms/` per the project rules.
2. Add real benign diversity (video, downloads, API calls, DNS-over-QUIC) and real malicious families, keep split-by-capture, and re-run §3.
3. Re-check calibration and the false-alarm rate on a *different* network than the one used to train.

## 8. Things that went wrong (so you don't have to rediscover them)

| Symptom | Cause | Fix (already in the code) |
|---|---|---|
| 0 packets captured, run "succeeds" | No libpcap/tcpdump → scapy can't compile the BPF filter, sniffer thread dies silently | Recorder falls back to a Python-side filter |
| Durations 10⁶× too small | `cicflowmeter` ≥ 0.5 reports seconds; ≤ 0.2 reported microseconds | Scale inferred per flow from `bytes / flow_byts_s` |
| Packet/byte counts +1 packet, `flow_iat_min` always 0 | `cicflowmeter` 0.5.x counts each flow's first packet twice | Extractor counts it once |
| `RuntimeError: no output_mode provided` | 0.5.x API change | Extractor supports both APIs |
| `0 packets` recorded although `tshark` is installed (seen on WSL + sudo) | tshark started but wrote no file | Recorder now detects the missing file and falls back to scapy; `VERITAS_PCAP_BACKEND=scapy` forces scapy. Meanwhile `samples/sample-run.pcapng` needs no capture |
| 0 flows extracted on Python 3.11 (CI caught it) | pip installs `cicflowmeter` 0.2.0 there (0.5.0 needs a newer Python); its per-packet entry point is `on_packet_received`, 0.5.x's is `process`, and scapy's base class has a no-op `process` | Extractor picks the entry point the library actually defines; tested on both 0.2.0 and 0.5.0 |
| `pip install` fails on `lime` | `setuptools` ≥ 81 removed `install_layout` | see §2 |
