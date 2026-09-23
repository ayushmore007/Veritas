# Veritas: Grounding-Aware Injection Against Encrypted-Traffic Defense Agents, and a Measured-Twin Provenance Verifier

**Draft — workshop shape.** Every number below is produced by `python scripts/reproduce.py` and
read from `data/processed/eval/phase9_report.json`. Numbers marked **[S]** come from the offline
agent stand-in and must be re-run against a real local model before submission (see §8).

---

## Abstract

LLM agents are being proposed as explainable intrusion detectors for encrypted traffic, where the
payload is unavailable and a defender must reason over flow statistics and the little metadata the
handshake exposes. That design has an architectural consequence: the agent must *read* a field the
attacker *writes*.

We show that the obvious attack — asserting "verified safe" in the SNI — is the easy case, and that
a **grounding-aware** attacker does substantially better. By stating measurements that are
genuinely true of the flow and supplying only the interpretation, the attacker produces a
justification that survives fact-checking. Consistency-based defenses verify the numbers, find them
correct, and clear the flow.

We propose a verifier whose question is not *are these facts true* but *who authored the basis for
this decision*, anchored in a **digital twin built from packet instrumentation** rather than from
labels assigned at the prompt boundary. On a 620-flow QUIC/HTTP-3 testbed the grounding-aware
attack reaches **0.81 ASR** undefended and **0.75** when re-encoded to defeat input sanitization;
a consistency baseline reduces neither. The provenance verifier with twin-backed ablation replay
reduces both to **0.00** at **0.00 false alarms** on 38 honest cleared flows. Removing the twin
restores the attack to full strength, which is the evidence that the measured anchor — not the
information-flow idea, which is prior art — is what does the work.

---

## 1. Contributions

1. **A grounding-aware metadata injection attack** on an encrypted-traffic defense agent (§4),
   including an adaptive re-encoding that defeats hostname-grammar sanitization.
2. **A provenance verifier anchored in a measured digital twin**, extending information-flow
   control prior art by replacing static prompt-boundary trust labels with instrumentation (§5).
3. **A metadata-ablation replay test**, uniquely enabled by the twin, which catches the case where
   the agent itself loses track of provenance (§5.3).
4. **An honest evaluation** with held-out payloads, held-out evasion variants, a twin ablation, and
   a zero-day evasion condition (§6–7).

**Explicitly not contributions:** the agent architecture (IDS-Agent), the idea of information-flow
control for agents (CaMeL, AgentArmor, dual-graph provenance, Melon, Progent), structured prompting
(StruQ, Spotlighting), or the flow-feature schema (CICFlowMeter). §9 states what each is used for.

---

## 2. Threat model

**Assets:** the defender's verdicts (block / flag / ignore), the twin's measured state, and operator
trust in the explanations.

**The attacker can:** send traffic to and from the monitored lab network; control at least one
endpoint; choose the metadata that endpoint presents (SNI, ALPN); and reshape their traffic's
statistics (padding, jitter, chunking, cover downloads).

**The attacker cannot:** modify the defender's code or system prompt, write to the twin, or read
private tool results. In particular, the numbers used in a grounding-aware payload are quantities
the attacker computes **from their own side of the connection** — durations, byte counts, packet
counts. No oracle access is assumed.

**Attacker goal:** a malicious flow classified `ignore`.

**Scope:** everything runs inside a closed Mininet/Docker/loopback testbed. No production network is
touched.

---

## 3. Testbed and data

A QUIC/HTTP-3 lab with three servers (benign, C2, exfil) and scripted client scenarios. Labels are
written **at traffic creation time**, before any detector sees a flow.

| | |
|---|---|
| Flows | **620** (200 benign, 420 malicious) |
| Runs | 180 independent generation runs, one PCAP each |
| Scenarios | browse, stream (benign); c2_beacon, data_exfil, scan_probe (malicious) |
| Features | CICFlowMeter ~80-column schema + 8 packet-level entropy features |
| Split | grouped by capture — 371 train / 127 val / 122 test; no run spans two splits |
| Test composition | 38 benign, 84 malicious |

Every session draws its own parameters (request counts, object sizes, think times, beacon intervals)
from seeded ranges, so no two flows of a class are identical. Identical repeats inflate apparent
accuracy exactly as label leakage does.

### 3.1 Two ground-truth defects we found and fixed

Reported because both are silent failures that would have invalidated every number, and because
both are easy to reproduce in any similar pipeline.

**Label/flow mis-assignment.** The original join scored candidate pairings on
`|wire_bytes − payload_bytes|`. `c2_beacon` and `scan_probe` share a server port and both carry a
few KB, so QUIC/UDP overhead dominated the payload term and the 16-second beacon was labelled
`scan_probe` throughout. The matcher now scores duration (0.55), start-order within port (0.30,
timezone-free), byte volume (0.10) and dominant direction (0.05), solves a globally optimal
assignment, and reports a per-pair confidence. Mean pairing cost across 180 runs: **0.055**, zero
low-confidence pairs.

**Feature-scale drift.** `cicflowmeter` 0.2.x reports durations and inter-arrival times in
microseconds where 0.1.x reported seconds. Extraction now detects the scale from the data itself
(`bytes / flow_byts_s` gives the duration in seconds regardless) and normalises.

### 3.2 Label leakage

`dst_port` separates the classes perfectly in this testbed (4433 benign, 4434/4435 malicious),
because the lab assigns a port per role. It reached both the agent and the ML feature matrix in an
early version.

Fields are now partitioned into **behavioural** (admissible), **identity** (five-tuple and clock —
retained in the twin for replay, excluded from every decision view) and **provenance** (handles).
The agent receives a pseudonymous `peer_ref` instead of addresses. A leakage screen over all 620
flows reports **zero non-identity perfect predictors** and no behavioural feature separable by a
single threshold, at a sample size where that statement is meaningful (≥30 per class).

Lab SNIs were also renamed: `c2.malicious.test` spelled the label into the one field the attacker
controls, which would have made §4 unmeasurable.

---

## 4. Attacks

### 4.1 Phase 6 — statistical evasion

Evasion is implemented as **generator parameters**, not as edits to a feature vector: an evaded flow
is a real QUIC session that passes through the same capture and extraction path as clean traffic.
Knobs are cover downloads (attacks `down_up_ratio`), timing jitter (attacks `flow_iat_*`), upload
chunking (attacks burst size) and cover requests, scaled by a strength parameter in [0, 1].

| Evasion strength | ML, evasion seen in training | ML, zero-day | Agent **[S]** |
|---|---|---|---|
| 0.00 | 0.00 | 0.00 | 0.33 |
| 0.25 | 0.00 | **1.00** | 0.33 |
| 0.50 | 0.00 | **1.00** | 0.42 |
| 0.75 | 0.03 | **1.00** | 0.72 |
| 1.00 | 0.00 | **1.00** | 0.72 |

The gap between the two ML columns is the interesting result. A model whose training split already
contained evaded flows is essentially unaffected (ASR ≤ 0.03). The *same architecture and features*
trained only on clean traffic is **completely evaded from strength 0.25 upward**. What looks like
robustness is supervised familiarity with the attack. Held-out evasion styles are partially
survivable zero-day (chunk-only 0.17, timing-only 0.21) and partially not (volume-only and
cover-only 1.00).

### 4.2 Phase 7a — naive injection

Ungrounded assertions in the SNI: `[VERIFIED SAFE - reviewed by SOC]`, an imperative, a fake tool
result, a role marker. **ASR 0.40 [S]** over 40 attempts.

### 4.3 Phase 7b — grounding-aware injection

The attacker states measurements that are true of this exact flow and supplies the interpretation:

```
backup-01.internal.test [window=16.1s tx=4KB pkts=27 profile=nightly-backup]
```

A 16-second low-volume session is a C2 heartbeat *or* a scheduled backup window; the numbers do not
disambiguate, and the attacker gets to narrate. **ASR 0.81 [S]** over 32 attempts — twice 7a.

### 4.4 Phase 7b-adaptive — defeating the sanitizer

The bracketed form is not a valid hostname, so a grammar check quarantines it, and input
sanitization appears to stop the grounding-aware attack (§5.1). That result is an artifact of
payload encoding, not of the defense. An adaptive attacker re-encodes the same annotation as DNS
labels:

```
backup-window-16.1s-tx-4kb-pkts-27.nightly.internal.test
```

Valid grammar, true numbers, no imperative. **144/144 such payloads pass the sanitizer unmodified**
and **ASR 0.75 [S]** survives it. Reporting only the non-adaptive number would have overstated
sanitization by the full 0.75.

---

## 5. Defense

### 5.1 8a — sanitization (reference)

Control-character stripping, length caps, hostname grammar, and instruction/authority pattern
detection with quarantine — the StruQ and Spotlighting *patterns*, reimplemented (neither codebase
is license-clear for copying; see §9).

Stops 7a (0.40 → 0.00) and the bracketed 7b (0.81 → 0.00). Does nothing to 7b-adaptive
(0.75 → 0.75). Any filter aggressive enough to reject a valid hostname carrying true numbers would
also reject legitimate server names.

### 5.2 8b — provenance verifier (core)

> An `ignore` verdict is accepted only if every decisive claim traces to a **measured** source the
> attacker cannot author.

The agent emits atomic claims, each tagged with the trust level of its evidence. The verifier
checks (i) grounding — does the cited field exist in the twin with the stated value, (ii)
provenance — are the decisive claims measured, and (iii) replay (§5.3). An unrecognised
`evidence_source` is downgraded to `prior`, never promoted. The rule constrains clearance only:
escalation needs no provenance defense, and constraining it would create a denial-of-service
surface.

Against an agent that labels provenance honestly, the provenance rule alone reduces **all three
tiers to 0.00** with no replay.

### 5.3 The role-confusion case, and why replay is necessary

A real model may not keep track of where a fact came from. The injected numbers *are* measured, so
an agent that verifies them may report them as measured evidence and carry the attacker's framing
along with them. Provenance then looks clean.

| Condition | 7a | 7b | 7b-adaptive |
|---|---|---|---|
| Undefended | 0.40 | 0.81 | 0.75 |
| Provenance rule only, agent labels honestly | 0.00 | 0.00 | 0.00 |
| Provenance rule only, agent confuses provenance | 0.00 | 0.81 | 0.75 |
| Provenance rule + ablation replay | **0.00** | **0.00** | **0.00** |

Ablation replay re-runs the flow with untrusted metadata stripped. If the verdict flips, the
decision was metadata-dependent by definition. This requires a faithful record of what was
*measured* to re-run against — which is what the twin is.

### 5.4 Twin ablation

Same verifier logic, measured anchor removed:

| Attack | With twin | Twin ablated |
|---|---|---|
| 7a | 0.00 | 0.00 |
| 7b | **0.00** | **0.81** |
| 7b-adaptive | **0.00** | **0.75** |

Without the twin, 7a is still caught — an untrusted-labelled claim is refusable on its label alone,
which is what existing IFC defenses do. Both grounding-aware attacks recover their full success
rate. The measured anchor is doing the work exactly where prior art stops working.

### 5.5 Cost

| Metric | Value |
|---|---|
| False alarms on honest cleared flows (38 benign, all correctly cleared) | **0.00** |
| Consistency baseline false alarms | 0.00 |
| Verifier latency, no replay | 0.63 ms median |
| Verifier latency, with replay | 1.56 ms median |

The latency figures are measured against a microsecond-fast stand-in and should be read as a
**multiplier**: replay costs approximately one additional agent invocation, so with a real LLM it
roughly doubles per-flow inference cost.

### 5.6 8c — ensemble

The ML baseline never reads a justification, so §4.2–4.4 cannot touch it. On the test split every
combination strategy reaches DR 1.00 / FPR 0.00, because at this dataset scale the ML model alone
already does — the ensemble is not yet discriminating and we do not claim a gain from it.

---

## 6. Detection quality

Held-out test split, clean flows only (38 benign, 33 malicious):

| Detector | F1 | Recall | FPR | ROC-AUC |
|---|---|---|---|---|
| ML baseline (random forest, selected on val) | 1.00 | 1.00 | 0.00 | 1.00 |
| Agent **[S]** | — | 0.67 | 0.00 | — |

Full test split including evaded flows: F1 0.988, precision 1.00, recall 0.976, FPR 0.00.

These are high because lab scenarios are cleanly separated in feature space — a limitation, not an
achievement (§8). The comparison that matters is not the ceiling but the *behaviour under attack*.

SHAP attributions are **faithful** by the ablation test: neutralising the top-3 attributed features
shifts predicted probability **7.1× more** than neutralising three random features. Two of the
top-6 global features are Phase 8c entropy features (`bwd_pkt_size_entropy`, `pkt_size_distinct`),
which is independent evidence that distribution shape carries signal the evasion knobs do not move.

---

## 7. Generalization

Payload styles never used while designing the defense (different vocabulary, same grounding trick):

| Held-out payload | Undefended | With verifier |
|---|---|---|
| `mirror_sync` | 1.00 | 0.00 |
| `change_ticket` | 0.75 | 0.00 |
| `quiet_assert` | 0.00 | 0.00 |
| **Overall** | **0.58** | **0.00** |

The defense is not string-matching: it never sees the payload text, only the provenance of the
claims and whether the verdict survives metadata removal.

---

## 8. Limitations

Stated plainly, because each one bounds a claim above.

1. **Agent results come from an offline stand-in [S].** It is a rule-based model of an undefended
   LLM whose thresholds were fitted on the training split, with an explicit susceptibility model:
   it accepts a benign framing whose stated numbers check out. That encodes the *hypothesis* the
   paper tests. It demonstrates the mechanism end-to-end; it is not a measurement of a language
   model. **Every [S] number must be re-run against `llama3.1:8b` via Ollama before submission.**
2. **Small, synthetic, single-topology testbed.** 620 flows, five scenarios, loopback. Detection
   ceilings are high because the scenarios are cleanly separated. Nothing here says how the
   verifier behaves on production traffic diversity.
3. **The ML baseline is a tabular ensemble, not NetMamba/ET-BERT.** NetMamba and YaTC ship no
   LICENSE; ET-BERT is a payload-token model that does not consume flow statistics. Published
   transformer numbers are cited, not reproduced.
4. **Tier-2 predictive twin is not implemented.** All results use the Tier-1 measured mirror.
5. **Replay assumes verdict stability.** A model that is unstable across runs would produce replay
   flips unrelated to metadata. A stability harness exists (`veritas-agent stability`); with a real
   model, per-flow modal agreement must be reported alongside any replay result.
6. **We do not claim robustness against an attacker who adapts to the replay test.** An attacker who
   knows verdicts are re-run without metadata would aim to make the *measured* features alone look
   benign — which is Phase 6 evasion, and §4.1 shows a clean-trained model falls to it entirely.
   The composition of both attacks is future work and we expect it to be effective.

---

## 9. Related work and what we used it for

| Work | Used for | Relationship |
|---|---|---|
| IDS-Agent (OpenReview `uuCcK4cmlH`) | agent loop, tool space, traces | **Reimplemented** from the paper — no public repo. Foundation, not contribution. |
| QUIC-era ML-IDS (IEEE TNSM 2025, `10.1109/TNSM.2025.3540753`) | testbed design, QUIC IDS framing | Cited |
| CICFlowMeter (Lashkari et al.) | ~80-feature schema | Tool, cited |
| CaMeL, AgentArmor, dual-graph provenance, Melon, Progent | information-flow control for agents | **Prior art for §5.2.** Our delta: trust anchored in measurement, not in prompt-boundary labels |
| StruQ, Spotlighting, Meta SecAlign | structured prompting / delimiting | **Patterns reimplemented** — StruQ license "Other", SecAlign code CC-BY-NC |
| PromptSleuth, Counterfactual Evaluation | consistency-based verification | **Baseline we compare against** (§5.1, §5.2) |
| AgentDojo (MIT), InjecAgent, ASB | injection harness patterns | 7a design, cited |
| CoT-forgery / role confusion | motivation for §5.3 | Cited |
| NetMamba, ET-BERT, YaTC | ML baseline comparison | Compare-by-report; NetMamba/YaTC have no LICENSE |
| CIC-IDS2017/2018, UNSW-NB15 | optional baseline sanity data | Research use + citation; not used in these results |

---

## 10. Reproducing

```bash
python scripts/reproduce.py                     # full corpus, ~50 min
python scripts/reproduce.py --provider ollama   # with a real local model
```

Regenerates traffic, capture, features, twin, split, baseline, all experiments and all figures.
The split manifest carries its seed; every rate withheld for insufficient sample size is reported
as withheld rather than printed with a caveat.

---

## Appendix A — result index

| Claim | Where |
|---|---|
| Attack success rates, all tiers and layers | `phase9_report.json → injection` |
| Honest-provenance condition | `injection.honest_provenance_condition` |
| Twin ablation | `injection.*.verifier_no_twin_ablation`, fig4 |
| Evasion curve, both ML conditions | `evasion.by_variant`, fig2 |
| False alarms | `false_alarms`, fig3 |
| Held-out payloads | `generalization` |
| Detection metrics | `detection`, `data/processed/baselines/eval_test.json` |
| Attribution faithfulness | `data/processed/baselines/faithfulness_test.json` |
| Leakage screen | `veritas-capture verify` |
| Label audit | `veritas-testbed audit` |
