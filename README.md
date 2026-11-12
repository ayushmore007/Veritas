# Veritas — Explainable AI Defense for Encrypted QUIC Traffic

An explainable LLM-based network defender operating inside a **digital twin** testbed. We attack it via statistical evasion and metadata prompt-injection, then detect reasoning manipulation with a **provenance-grounding verifier** anchored on measured twin state.

> **Ethics:** All experiments run inside Mininet/Docker lab networks only. Never capture, generate, or analyze traffic on production or third-party networks without explicit authorization.

## Quick links

- [Phase 1 testbed guide](docs/phase1-testbed.md)
- [Phase 2 capture & features](docs/phase2-capture.md)
- [Phase 3 digital twin](docs/phase3-twin.md)
- [Phase 4 defender agent](docs/phase4-agent.md)
- [Phase 5 ML baseline & explainability](docs/phase5-baseline.md)
- [Phases 6-7 the two attacks](docs/phase6-7-attacks.md)
- [Phase 8 defense](docs/phase8-defense.md)
- [Phase 9 evaluation](docs/phase9-evaluation.md)
- [Paper draft](docs/paper/veritas-draft.md)
- [Phases (build plan)](docs/phases.md)
- [Test plan — what each phase must prove](docs/test-plan.md)
- [Reference map (prior art vs our delta)](docs/reference-map.md)
- [Threat model](docs/threat-model.md)
- [Licensing & citation policy](docs/licensing-and-citation.md)
- [License audit](docs/license-audit.md)
- [References checklist](references.md)

## Project rules

1. **Cite everything** — papers, datasets, tools, adapted methods (`docs/bibliography.md`).
2. **Check LICENSE** before copying code from any cloned repo (`scripts/check_repo_license.py`).
3. **Follow dataset terms** — research use + mandatory citation; store terms under `data/external/_terms/`.

## Stack

Python 3.11+, aioquic, tshark/Scapy, CICFlowMeter, Mininet/Docker, Ollama, scikit-learn, SHAP/LIME.

## Setup (Phase 0)

```bash
cd Veritas
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/WSL:  source .venv/bin/activate
pip install -e ".[dev]"
python scripts/setup_check.py
```

### Platform note (Windows)

Mininet is Linux-native. Use **WSL2 (Ubuntu)** or **Docker** for Phases 1+ testbed work. Phase 0 scaffolding runs on native Windows.

## The product: backend + website + mobile app + trained model

```
 mobile/ (Expo app) ──┐
                      ├──►  veritas-api (FastAPI, src/veritas/api)  ──►  trained flow detector (models/flow-detector)
 web/ (dashboard) ────┘            │                                    └─ SHAP per-flow explanations
                                   ├──►  live scanner (web/scanner.py) ─► digital twin DB
                                   └──►  scan history, prevention registry
```

### 1. Backend + website

```bash
pip install -e ".[dev]"
veritas-api                       # http://localhost:8000  (website)  ·  /docs (interactive API docs)
```

- Binds to loopback by default and serves loopback clients only. To reach it from a phone or Docker,
  set a key and bind wide — the server refuses to start otherwise:
  `export VERITAS_API_KEY="$(openssl rand -hex 24)"; veritas-api --host 0.0.0.0`
- **The scanner probes hosts you point it at.** Scan only systems you own or are authorised to test.
  As a guard against using the server as a pivot (SSRF), targets that resolve to private, loopback or
  link-local addresses are refused unless `VERITAS_ALLOW_PRIVATE_TARGETS=1` (lab networks only).
  Scans are rate-limited per client.
- The website (`web/`) has five tabs: security tests, prevention engine, digital-twin telemetry, the
  **ML Flow Detector**, and export. `python web/server.py` still works and just launches `veritas-api`.

| Endpoint (`/api/v1/…`, also at `/api/…`) | |
|---|---|
| `GET /health` | public liveness probe |
| `GET /status`, `GET /topology` | engine state, lab topology |
| `POST /scan` `{"target": "host[:port]"}` | live security scan → report (saved to history) |
| `GET/DELETE /scans/history` | persisted scans |
| `POST /verify-fix`, `POST /prevention/apply` | check a fix is live; register an engine-side control |
| `GET /twin/flows` | digital-twin flows |
| `GET /model` | trained model card: version, threshold, held-out metrics **with intervals**, limitations |
| `POST /predict` `{"flows":[{…}]}` | score CICFlowMeter-style flows → verdict, probability, top contributing features |
| `POST /analyze/pcap` (multipart `file`) | extract every flow from a PCAP/PCAPNG and score each |

Protected routes take `X-API-Key` when `VERITAS_API_KEY` is set. Config knobs are in `.env.example`.

### 2. Mobile app

`mobile/` is an Expo (React Native + TypeScript) app for iOS, Android and web: scan, history, ML
detector, settings. See [`mobile/README.md`](mobile/README.md).

### 3. The ML model

The deployed model is a scikit-learn tree ensemble over behavioural flow features. Rebuild it with the
steps in **[docs/TRAINING.md](docs/TRAINING.md)** — in short:

```bash
python scripts/reproduce.py --quick --runs 150 --seed 1 --entropy \
    --evasion-strengths 0.25,0.5,0.75,1 --evasion-runs 6 \
    --held-out-variants timing_only,volume_only,chunk_only,cover_only   # build the labelled corpus
veritas-train check          # is the corpus big/varied enough?
veritas-train fit            # select, train, evaluate -> models/flow-detector/{model.joblib,metrics.json,MODEL_CARD.md}
```

Docker: `export VERITAS_API_KEY=…; docker compose -f docker/docker-compose.yml up --build api`.

## Reproduce everything

```bash
python scripts/reproduce.py --quick              # smoke: Phases 1–5 + agent (~5 flows)
python scripts/reproduce.py --skip-generate      # reuse existing PCAP/labels
python scripts/reproduce.py --provider ollama    # real local model for agent steps
python scripts/reproduce.py --runs 60 --seed 1 --entropy   # multi-capture corpus
```

```bash
# Full evaluation corpus: clean runs, Phase 6 evaded runs per strength, held-out knob variants
python scripts/reproduce.py --runs 25 --seed 1 --entropy \
    --evasion-strengths 0.25,0.5,0.75,1 --held-out-variants timing_only,volume_only,chunk_only,cover_only
```

Each `--runs` run is its own capture (own PCAP and `run_id`), which is what the train/test split
groups on; `--seed` varies scenario parameters per run, reproducibly. Phase 9 runs live:
`veritas-eval run` executes every experiment (detection, evasion, injection with each defense
layer and the twin ablation, false alarms, generalization, latency, ensemble) and writes
`data/processed/eval/phase9_report.json`; `veritas-eval run --cached` only validates a saved one.

## Pipeline, stage by stage

```powershell
veritas-testbed generate --runs 60 --seed 1 --record-pcap   # Phase 1: labeled QUIC flows + PCAPs
veritas-capture process --manifest --entropy                # Phase 2 + 8c: every run, + entropy
veritas-twin ingest                                         # Phase 3: measured-feature oracle
veritas-agent split                                         # fix the held-out test set once
veritas-baseline train && veritas-baseline evaluate --split test   # Phase 5: ML baseline
veritas-testbed generate --runs 12 --record-pcap --scenarios c2_beacon,scan_probe,data_exfil \
    --evasion-strength 0.75                                 # Phase 6: evaded traffic (then re-capture)
veritas-agent triage --all                                  # Phase 4: agent verdicts + traces
veritas-eval run                                            # Phase 9: all experiments, live
veritas-eval run --only injection                           # one experiment, merged into the report
veritas-eval figures                                        # Phase 10: figures
```

## Headline results

*From the author's 620-flow run. Regenerate with the full-corpus command above and
`veritas-eval --provider ollama run` before quoting; agent-side numbers from the deterministic
stand-in demonstrate the mechanism and are not LLM measurements.*

620 flows (200 benign / 420 malicious) across 180 runs; 122-flow held-out test split.

| Attack | Undefended | Sanitizer (8a) | Consistency check (prior art) | Provenance verifier + replay (ours) | Twin ablated |
|---|---|---|---|---|---|
| 7a naive injection | 0.40 | **0.00** | 0.40 | **0.00** | 0.00 |
| 7b grounding-aware | 0.81 | **0.00** | 0.81 | **0.00** | 0.81 |
| 7b adaptive (valid hostname) | 0.75 | 0.75 | 0.75 | **0.00** | 0.75 |

False alarms on honest cleared flows: **0.00**. ML baseline on the test split: F1 0.988, FPR 0.00 —
but a clean-trained model is fully evaded by reshaped traffic (ASR 1.00), so evasion resistance is
supervised familiarity, not robustness. Agent-side numbers currently come from an offline stand-in;
see the [paper draft](docs/paper/veritas-draft.md) §8.

Verification at each stage (see [test plan](docs/test-plan.md)):

```powershell
veritas-testbed audit --sample 20        # Phase 1: do the labels match the behaviour?
veritas-capture verify                   # Phase 2: reproducible extraction, no label leakage
pytest tests/test_twin_integrity.py      # Phase 3: fidelity, tamper-resistance, replay
veritas-agent split                      # Phase 4: fix the held-out test set once
veritas-agent evaluate --split test      # Phase 4: the only numbers that belong in the paper
veritas-agent stability --repeats 5      # Phase 4: are decisions stable or coin flips?
```

## Repository layout

```
src/veritas/     Phase-aligned Python packages
  testbed/       Phase 1 — QUIC/HTTP-3 traffic generation + ground-truth labels
  capture/       Phase 2 — PCAP → CICFlowMeter features → trust tags
  twin/          Phase 3 — Tier-1 digital twin oracle (measured features only)
  agent/         Phase 4 — IDS-Agent-style reason-act defender
  attacks/       Phases 6-7 — evasion profiles + injection payloads and campaign runner
  defense/       Phase 8 — sanitizer, provenance verifier, consistency baseline, ensemble
                 (8c entropy features live in capture/entropy.py)
  baselines/     Phase 5 — ML baseline, SHAP, faithfulness test
  eval/          Phase 9 — splits, stability, live experiment runners, figures
  training/      `veritas-train` — grouped-CV model selection, thresholding, evaluation, model card
  api/           `veritas-api` — FastAPI backend for the website and the mobile app
  inference.py   loads the trained model; scores flows/PCAPs with explanations
web/             Website (dashboard UI) + the live scanner engine
mobile/          Expo mobile app
models/          Trained model + model card (rebuild with `veritas-train fit`)
config/          YAML configuration and trust labels
docs/            Plans, threat model, bibliography
scripts/         Setup and license checks
data/            Local datasets and captures (gitignored)
references/      Cloned paper repos (gitignored)
```

## License

Veritas project code: see `LICENSE` (to be set by author). Third-party code retains its original licenses — see `THIRD_PARTY_NOTICES.md` when populated.
