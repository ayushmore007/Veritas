# Veritas: From Research Website to Security App

## 1. What Veritas is today (short)

Veritas is a research pipeline plus a web dashboard. An LLM "defender" triages encrypted QUIC flows inside a digital-twin lab. Two attacks are studied: statistical evasion and metadata prompt-injection (SNI and similar strings). The defense is a provenance-grounding verifier. It checks the agent's claims against measured twin state, with a sanitizer and an ML/entropy ensemble alongside.

Core idea worth keeping: **never trust what the data says about itself; trust only what was measured.** This is the product's identity.

Current gap: it is a research lab (CLI phases, a "scan a host" dashboard, a paper). It is not yet something a person installs and uses daily.

---

## 2. Reframe the ideation

| Now | Better |
|---|---|
| "Evaluate an AI defender against attacks" | "A trustworthy AI SOC analyst whose every claim is verified" |
| One-shot scans of a host | Continuous monitoring with a verdict feed |
| Benchmark numbers | Evidence the analyst can act on |
| Lab only | Lab mode (research) plus Sentinel mode (real, authorized networks) |

**Positioning:** *"The AI analyst that can't be talked into lying."* Every LLM security tool is vulnerable to prompt injection through attacker-controlled data. Veritas is built around that threat. This is the differentiator.

---

## 3. Product ideas (ranked by value for effort)

### Tier A: Core value (do first)

1. **Verified Verdict Cards**
   - *What:* Each alert shows verdict, the agent's claims, and a ✅/❌ per claim, each checked against twin measurements.
   - *Why:* Trust is the product. Analysts don't read paragraphs. They read "3 of 4 claims verified, 1 contradicted by measured data".
   - *How:* Reuse `defense/verifier.py` output. Render claim-level pass/fail in `web/` and the demo UI.

2. **Injection Tripwire (the cybersecurity hook)**
   - *What:* A prominent "Attack attempt detected" panel when the sanitizer quarantines imperative text in SNI, ALPN or other metadata. Treat the injection attempt itself as a threat indicator.
   - *Why:* An attacker who tries to manipulate the AI has just revealed themselves. This turns a defense into a detection signal.
   - *How:* Log sanitizer quarantine events as first-class alerts with a severity score and source host.

3. **Live Monitor Mode**
   - *What:* Tail a PCAP directory or interface, auto-run capture, twin ingest and agent triage, and stream results.
   - *Why:* A dashboard that must be clicked is a demo. A feed that updates is a tool.
   - *How:* Wrap the Phase 2 to 4 pipeline in a watcher with a small queue. Use SSE/WebSocket to the UI.

4. **Explain-Why Panel**
   - *What:* Combine SHAP features (Phase 5) with agent reasoning and show where they agree or disagree.
   - *Why:* A disagreement between the ML model and the LLM is itself an anomaly signal.
   - *How:* The ensemble already exists. Surface the disagreement score.

### Tier B: Makes it feel like an app

5. **Installable PWA / desktop shell:** manifest, service worker, offline cache of the last report. Later, optionally wrap it with Tauri/Electron. Cheap and a large perceived upgrade.
6. **Alert triage workflow:** statuses (new, investigating, confirmed, false positive), notes and assignee. A false-positive click feeds back into the false-alarm metric.
7. **Push notifications and webhooks:** Slack, Discord, email and a generic webhook for high-severity verified verdicts.
8. **Host profile pages:** per-host timeline from the twin (`host history`), with risk trend and past verdicts.
9. **Export:** one-click incident report (Markdown/PDF) with the evidence chain. Also STIX/JSON for SIEM import.

### Tier C: Cybersecurity depth

10. **Red-Team Arena mode:** a built-in game or lab where users craft evasion/injection payloads and see whether Veritas catches them. It is educational, great for demos, and generates new adversarial test cases (feed them back into Phase 9).
11. **Adaptive attacker loop:** an automated attacker LLM that mutates payloads against the defense, which is continuous hardening. The "7b adaptive" result already shows this is where defenses break.
12. **MITRE ATT&CK mapping:** tag verdicts (C2 beaconing → T1071, exfiltration → T1041, scan → T1046). It gives instant credibility and a common vocabulary.
13. **Threat-intel enrichment with provenance:** every enrichment source gets a trust label, so an untrusted feed can't override measured data (extends `config/trust_labels.yaml`).
14. **Model-agnostic adapters:** a plug-in interface for Ollama, hosted LLMs and the deterministic stand-in. Show the cost, latency and robustness of each side by side.
15. **Tamper-evident audit log:** hash-chain every verdict and trace so evidence can't be edited later (a forensics-grade feature).

### Tier D: Stretch

16. Twin Tier 2 (predictive "what would normal look like" simulation).
17. Federated or multi-site twins, where sites share only trust-labelled aggregates.
18. A public "Prompt-Injection-for-SOC" benchmark built from your attack suite, which is a research contribution and a community magnet.

---

## 4. Suggested architecture for the app

```
[Sensors: pcap/interface/agent]  →  [Ingest API]
        → Capture + trust tagging → Twin (measured oracle)
        → Sanitizer → Agent → Verifier → Ensemble
        → Alert store (SQLite → Postgres later)
        → API (FastAPI) → PWA / desktop UI + webhooks
```

- Keep research and product separated: `research mode` runs Phase 9 evals and `sentinel mode` runs live monitoring. They share the same engine.
- Single `docker compose up` to run everything. Lower friction means more users.
- Config-driven (YAML already in place), with an in-app settings page.

---

## 5. Roadmap

| Step | Deliverable | Effort |
|---|---|---|
| 1 | Verified Verdict Cards and Injection Tripwire | Small |
| 2 | Alert triage statuses, export, MITRE tags | Small–Medium |
| 3 | Live Monitor Mode (watcher and streaming UI) | Medium |
| 4 | PWA install, notifications and webhooks | Small |
| 5 | Red-Team Arena and adaptive attacker loop | Medium |
| 6 | Train and ship the ML model (section 5b), audit-log hash chain, model adapters | Medium |
| 7 | Desktop wrapper, Tier 2 twin, benchmark release | Large |

Do steps 1 to 2 first. They change the product feel the most for the least work.

---

## 5b. ML model training (your to-do)

You need to train the ML model yourself. The pipeline already supports it (`veritas-baseline`, Phase 5).

**Why:** the ML baseline is the fast, cheap detector. The LLM agent is the explainable one. The ensemble needs both, and the disagreement between them is a signal.

**How:**
1. Generate a larger corpus: `veritas-testbed generate --runs 60 --seed 1 --record-pcap`, then `veritas-capture process --manifest --entropy`.
2. Fix the held-out test split once: `veritas-agent split`.
3. Train and select: `veritas-baseline train`, then `veritas-baseline evaluate --split test`.
4. Retrain on evaded traffic (`--evasion-strength 0.25..1`) plus held-out variants (timing, volume, chunk, cover). Today's clean-trained model is fully evaded (ASR 1.00), so adversarial training is the biggest improvement.
5. Add entropy features (`capture/entropy.py`) and check SHAP faithfulness (`explain.py`).
6. For the app: save the model as a versioned artifact, add a retrain button or job, and show model version, F1, FPR and ASR in the UI.

**Watch out:** split by `run_id` to avoid leakage. Report FPR, not just F1. Don't give the model the five-tuple or capture clock.

---

## 6. Guardrails (keep these)

- Authorized networks only. Make the ethics notice an in-app first-run consent screen.
- Cite and license-check everything, as the repo already requires.
- Be honest in the UI. Label stand-in-model results as such, as the README already does.
- Never let untrusted text influence a verdict without verification. This is the product promise, so protect it above all.

---

## 7. One-line pitch

**Veritas: the AI security analyst that proves every claim against measured evidence, and treats attempts to fool it as attacks.**
