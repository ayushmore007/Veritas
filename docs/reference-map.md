# Reference Map — Prior Art vs Veritas Delta

Use this when writing Related Work and when deciding **cite vs clone vs reimplement**.

| Phase | Prior art | What we reuse | Our delta | LICENSE status |
|-------|-----------|---------------|-----------|----------------|
| 1 | QUIC-era ML-IDS (TNSM 2025) | QUIC testbed design patterns | Own labeled QUIC/HTTP-3 flows | Cite only |
| 1 | CIC-IDS2017/2018, UNSW-NB15 | Baseline sanity, feature schema | Primary data = generated QUIC | Research + cite |
| 2 | CICFlowMeter | ~80-feature extraction pipeline | `trusted`/`untrusted` field tags | Tool cite |
| 3 | CaMeL, dual-graph provenance | IFC *ideas* for verifier | **Measured twin oracle** attacker cannot reach | Cite only |
| 4 | **IDS-Agent** | Agent loop, tool space, traces | QUIC + metadata injection surface | **No official repo — reimplement** |
| 5 | **NetMamba**, ET-BERT, YaTC | ML baseline comparison | Same schema on QUIC flows | ET-BERT MIT ✅; NetMamba/YaTC ⚠️ no LICENSE |
| 6 | Adversarial flow literature | Evasion techniques | Applied to QUIC CICFlowMeter features | Cite |
| 7a | **AgentDojo**, ASB, InjecAgent | Injection harness patterns | SNI/metadata channel (network NIDS) | AgentDojo MIT ✅ |
| 7b | CoT-forgery / role confusion | Attack motivation | **Grounding-aware adaptive injection** | Cite only |
| 8a | **StruQ**, Spotlighting, SecAlign | Structured delimiting | Flow metadata slots | StruQ ⚠️ Other; SecAlign ⚠️ NC code |
| 8b | CaMeL, AgentArmor, Melon, Progent | Provenance IFC prior art | Twin-anchored verifier + **metadata-ablation replay** | Cite only |
| 8b | PromptSleuth, Counterfactual Eval | Consistency baseline to beat | Show failure on 7b | Cite only |
| 9 | — | Metrics methodology | Adaptive-attacker honest ASR | — |

## Contribution summary (for paper abstract)

1. Reasoning-manipulation attack on AI QUIC NIDS agent (7a + novel 7b).
2. Provenance-grounding verifier with **digital-twin measured trust anchor** (8b).
3. Metadata-ablation replay test enabled by twin replay (8b).

## Before copying any repo

```bash
git clone <url> references/<name>
python scripts/check_repo_license.py references/<name>
# Update docs/license-audit.md with result
```
