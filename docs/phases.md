# Build Phases (canonical workflow)

**Status: Phases 0-10 implemented.** See `docs/test-plan.md` for what each phase must prove and
`docs/paper/veritas-draft.md` for the measured results.

Each phase lists **prior art**, **our delta**, and **compliance hooks** (cite / LICENSE / dataset terms).

---

## Phase 0 — Foundation *(reference setup)*

Repo, config, testbed-only ethics README, reference map, licensing policy.

**Compliance:** Establish cite-everything, LICENSE-check, dataset-terms workflow.

**Stack:** Python, aioquic/HTTP-3, tshark/Scapy, CICFlowMeter, Ollama, scikit-learn, SHAP/LIME, Mininet/Docker.

---

## Phase 1 — Testbed + labeled traffic *(reference build)*

Mininet/container network generating labeled benign + malicious QUIC/HTTP-3 flows.

**Anchor:** QUIC-era IDS (IEEE TNSM 2025, DOI `10.1109/TNSM.2025.3540753`).

**Datasets (sanity only):** CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15 — cite + research terms; not QUIC-primary.

---

## Phase 2 — Capture + features + provenance tags *(reference build + seed of novelty)*

CICFlowMeter ~80-feature schema. Tag fields `trusted` vs `untrusted` (SNI = untrusted).

**Cite:** CICFlowMeter tool paper; SoK on encrypted-traffic features (header/metadata essential).

---

## Phase 3 — Digital twin Tier 1 *(differentiator)*

Mirror flows/host-history from **measured features only**. Tier 2 predictive = stretch.

**Delta vs CaMeL/dual-graph:** trust anchored in measured twin oracle, not static prompt-boundary labels.

---

## Phase 4 — AI defender agent *(reference build)*

IDS-Agent-style reason-act loop on Ollama. **Foundation, not contribution** — cite IDS-Agent; reimplement (no official repo).

---

## Phase 5 — Explainability + ML baseline *(reference build)*

NetMamba backbone (or reimplement if no LICENSE), ET-BERT + YaTC comparison. SHAP/LIME on ML. Full reasoning traces with claim provenance.

**LICENSE gate:** ET-BERT MIT OK; NetMamba/YaTC verify before copy.

---

## Phase 6 — Attack 1: statistical evasion *(reference build)*

Reshape flows so CICFlowMeter features look benign. Baseline ASR vs agent + ML.

---

## Phase 7 — Attack 2: reasoning manipulation

- **7a (reference):** Naive SNI injection; harness patterns from AgentDojo (MIT), InjecAgent, ASB (cite).
- **7b (NOVEL):** Grounding-aware adaptive injection citing real twin facts. Motivated by CoT-forgery / role confusion.

---

## Phase 8 — Defense (three layers)

- **8a (reference):** StruQ/Spotlighting-style sanitization — reimplement patterns; SecAlign cite-only if NC blocks copy.
- **8b (CORE):** Provenance-tracked verifier extending CaMeL, AgentArmor, dual-graph, Melon, Progent — **delta:** measured twin trust anchor + metadata-ablation replay test.
- **8c (reference):** Entropy features + ML ensemble (NetMamba/ET-BERT).

---

## Phase 9 — Evaluation + ablations *(paper spine)*

ASR (including adaptive 7b), verifier vs PromptSleuth/Counterfactual Eval, twin ablation, replay test, latency. Honest adaptive-attacker ASR — no false near-100% robustness claims.

---

## Phase 10 — Paper

Arms-race framing. Related work: IDS-Agent, CaMeL/AgentArmor/dual-graph, StruQ/SecAlign/Spotlighting, PromptSleuth/Counterfactual Eval.

**Compliance:** Every borrowed method and dataset cited; `THIRD_PARTY_NOTICES.md` for any copied code.
