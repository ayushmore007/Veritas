# Project References Checklist

A working checklist for the QUIC AI-defense project. Tick each item as you install, download, clone, or read it. Grouped by **what you actually do with it** so you can work top-to-bottom.

**How to read the "Type" of each item:**
- **Install** — software you set up on your machine (Phase 0 setup day).
- **Download** — a dataset you fetch once and store locally.
- **Read + clone** — a paper whose code you'll reuse or compare against: read the method, then follow its "Code" link to the repo and `git clone` it.
- **Read + cite** — a paper you only need to understand and reference; no code to run.

> Note: links point to the authoritative arXiv / official page, not a guessed GitHub URL. Every arXiv abstract page has a **"Code"** link (via Papers-with-Code) that points to the correct repo — trust that over any typed-from-memory URL. For items marked *(search title)*, search the paper title rather than guessing the arXiv number. Expect normal research-code friction when cloning (dependency versions, missing dataset paths) — budget a little setup time per repo.

### About the "License" info below

- **Citing a paper never needs a license** — that's why the *read + cite* items have no license check. Copyright protects the exact text/figures, not the method or the idea, so referencing and building on a published method is always fine.
- **License only matters when you reuse someone's code or data.** Then you're bound by the repo's `LICENSE` file / the dataset's terms.
- **What the common licenses mean for you:** *MIT / Apache-2.0 / BSD* = use, modify, build on freely (keep the notice) — no problem. *GPL* = if you distribute your code, you may have to open-source it too. *CC-BY-NC* or "research/non-commercial only" = fine for a student paper, **not** fine for a product or anything commercial. *No LICENSE file* = no reuse rights are granted by default — treat as read-only until you ask the authors.
- **Where "verify" is written, open the repo's `LICENSE` file and confirm before reusing.** I've filled in the ones I could verify; the rest genuinely must be checked on the repo (I won't guess a license, because a wrong guess is exactly the risk you're avoiding).
- **Ties to the patent/commercial plan:** for a paper, reusing research code/data is fine. If you later commercialize or patent, non-commercial licenses (e.g. Meta SecAlign code) and dataset terms become blocking issues — raise them with your IP cell. (This is practical guidance, not legal advice.)

### Project rules (always)

1. **Cite everything** — papers, datasets, tools, and any adapted method. Maintain `docs/bibliography.md` and per-module `@cite` notes in code where prior art is implemented.
2. **Check LICENSE before copying code** — run `scripts/check_repo_license.py` after cloning; no copy-paste from repos without a clear permissive license or author permission. Reimplement from the paper when in doubt.
3. **Follow dataset terms** — CIC/UNSW datasets are research-use with mandatory citation; store acceptance emails/terms under `data/external/_terms/`.

See `docs/licensing-and-citation.md` for the full policy and `docs/license-audit.md` for current reuse status.

---

## 1. Tools to install (Phase 0 — do these first)

*All standard open-source software (permissive or GPL). You're **using** them, not redistributing them inside your product, so there's no licensing issue for a research project. No action needed beyond installing.*

- [ ] **Python 3.11** — `sudo apt install python3.11 python3-pip` (or python.org) — *phases: all*
- [ ] **Wireshark + tshark** — `sudo apt install wireshark tshark` — *phase 2*
- [ ] **Scapy** — `pip install scapy` — *phases 2, 6*
- [ ] **aioquic (QUIC / HTTP-3)** — `pip install aioquic` — *phase 1*
- [ ] **CICFlowMeter** — Java tool: clone and build from `github.com/ahlashkari/CICFlowMeter`; or Python port `pip install cicflowmeter` — *phase 2*
- [ ] **Mininet** — `sudo apt install mininet` (or mininet.org) — *phases 1, 3*
- [ ] **Docker** — install from docs.docker.com — *phases 1, 3*
- [ ] **Ollama + local model** — install from `ollama.com/download`, then `ollama pull llama3.1:8b` — *phase 4*
- [ ] **scikit-learn, pandas, numpy** — `pip install scikit-learn pandas numpy` — *phases 5, 6*
- [ ] **SHAP, LIME** — `pip install shap lime` — *phase 5*

---

## 2. Datasets to download (Phases 1, 5)

*Usage terms: all three are free **for research/academic use** and require you to **cite their source paper**. That's exactly your use case, so you're clear — just read the terms page and add the citation. (A commercial product on this data would be a separate question.)*

- [ ] **CIC-IDS2017** — `unb.ca/cic/datasets/ids-2017.html` (free, request form) — ~2.8M labeled flows, 80 CICFlowMeter features, 14 attack types, PCAP + CSV — *usage: research use, cite the ICISSP 2018 paper*
- [ ] **CSE-CIC-IDS2018** — `unb.ca/cic/datasets/ids-2018.html` — extension of 2017 with more attacks/larger topology — *usage: research use, cite CIC*
- [ ] **UNSW-NB15** — search "UNSW-NB15 dataset" (UNSW Canberra) — ~2.5M instances, 49 features, 9 attack types — *usage: research use, cite the source paper*

> Reminder: none of these are QUIC-specific and CIC-IDS2017 is aging. Use them for baseline/pre-training sanity, but your own generated QUIC/HTTP-3 flows stay primary — keep them in the CICFlowMeter feature schema for comparability.

---

## 3. Papers to read AND clone (reuse / compare against their code)

- [ ] **ET-BERT** (transformer baseline) — `arxiv.org/abs/2202.06335` → Code link on page — *phase 5* — **License: MIT ✅ (verified — free to reuse)**
- [ ] **AgentDojo** (injection attack benchmark) — `arxiv.org/abs/2406.13352` → Code link on page — *phase 7a* — **License: MIT ✅ (verified — free to reuse)**
- [ ] **Meta SecAlign** (open defended model) — `arxiv.org/abs/2507.02735` → model/code on page — *phase 8a* — **⚠️ Code license: CC-BY-NC (non-commercial only) — fine for your paper, NOT for a product/patent. The models themselves are under the Llama community license (commercial OK); the codebase is not.**
- [ ] **NetMamba** (ML baseline backbone) — `arxiv.org/abs/2405.11449` → `github.com/wangtz19/NetMamba` — *phase 5* — **⚠️ No LICENSE file in repo (checked Phase 0) — cite + compare metrics; reimplement or email authors before copying code**
- [ ] **YaTC** (traffic transformer, AAAI 2023) — `github.com/NSSL-SJTU/YaTC` — *phase 5* — **⚠️ No LICENSE file in repo (checked Phase 0) — cite + compare metrics; reimplement or contact authors before copying code**
- [ ] **IDS-Agent** (defender-agent template) — `openreview.net/forum?id=uuCcK4cmlH` — *phase 4* — **⚠️ No official public code repo found — cite paper (CC BY 4.0 on OpenReview); reimplement agent loop in Veritas; do not use unofficial forks without verifying LICENSE**
- [ ] **StruQ** (structured-query sanitization) — `github.com/Sizhe-Chen/StruQ` — *phase 8a* — **⚠️ GitHub lists license "Other" (no standard OSS license) — cite method; reimplement structured delimiters in Veritas; ask authors before copying training code**

---

## 4. Papers to read AND cite (understand + reference; no code to run)

*No license check needed for anything here — you're only citing them, and citing never requires a license.*

- [ ] **Spotlighting** (delimiting defense) — `arxiv.org/abs/2403.14720` — *phase 8a*
- [ ] **CaMeL — "Defeating prompt injections by design"** (prior art for your verifier) — `arxiv.org/abs/2503.18813` — *phase 8b*
- [ ] **AgentArmor** (runtime-trace program analysis; prior art) — `arxiv.org/abs/2508.01249` — *phase 8b*
- [ ] **Dual-Graph Provenance–Authorization defense** (prior art) — `arxiv.org/abs/2605.26497` — *phase 8b*
- [ ] **Melon** (provable indirect-PI defense; prior art) — `arxiv.org/abs/2502.05174` — *phase 8b*
- [ ] **Progent** (prior art) — *phase 8b* — add arXiv link when cloning
- [ ] **PromptSleuth** (consistency defense; your baseline to beat) — `arxiv.org/abs/2508.20890` — *phases 8b, 9*
- [ ] **Counterfactual Evaluation** (consistency defense; baseline) — `arxiv.org/abs/2507.23453` — *phases 8b, 9*
- [ ] **InjecAgent** (injection benchmark) — search title + verify arXiv/repo before cloning — *phase 7a* — **License: verify on repo before reuse**
- [ ] **ASB — Agent Security Bench** — `arxiv.org/abs/2410.02644` — *phase 7*
- [ ] **CoT-forgery / "Prompt Injection as Role Confusion"** (motivates attack 7b) — `arxiv.org/abs/2603.12277` — *phase 7b*
- [ ] **QUIC-era ML-IDS** (IEEE TNSM 2025; your QUIC anchor) — DOI `10.1109/TNSM.2025.3540753` — *phase 1*

---

## Quick status

- Tools installed: ___ / 10
- Datasets downloaded: ___ / 3
- Papers cloned: ___ / 7
- Papers read + cited: ___ / 10
