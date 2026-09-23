# License Audit (Phase 0 baseline)

Last reviewed: Phase 0 scaffold + Phase 5–10 doc import. Re-run `scripts/check_repo_license.py` after each clone.

## Clear to reuse code (verify notice retention)

| Item | License | Phase | Notes |
|------|---------|-------|-------|
| ET-BERT | MIT | 5 | Clone from arXiv Code link |
| AgentDojo | MIT | 7a | Injection benchmark harness |
| InjecAgent | Verify on clone | 7a | Cite harness patterns; run `check_repo_license.py` before reuse |

## OK for paper, blocked for commercial

| Item | License | Phase | Notes |
|------|---------|-------|-------|
| Meta SecAlign | CC-BY-NC (code) | 8a | Models: Llama community license. Use ideas + cite; do not ship NC code in a product |

## Cite + reimplement (do not copy code yet)

| Item | Status | Phase | Veritas plan |
|------|--------|-------|--------------|
| IDS-Agent | No official repo | 4 | Reimplement reason-act loop + tool space; cite OpenReview paper |
| NetMamba | No LICENSE file in repo | 5 | Wrapper/compare metrics; own sklearn baseline + optional author contact |
| YaTC | No LICENSE file in repo | 5 | Same as NetMamba |
| StruQ | GitHub "Other" | 8a | Reimplement structured prompt/data channels; cite USENIX Sec'25 |

## Cite only (no code expected)

All items in `references.md` §4 — CaMeL, AgentArmor, dual-graph, Melon, PromptSleuth, Spotlighting, ASB, CoT-forgery, QUIC-era IDS paper.

## Datasets — research use + mandatory citation

| Dataset | Commercial use | Action |
|---------|----------------|--------|
| CIC-IDS2017 | Not without separate agreement | Cite + store terms |
| CSE-CIC-IDS2018 | Not without separate agreement | Cite + store terms |
| UNSW-NB15 | Check UNSW terms | Cite + store terms |

## Head-ups before later phases

- **Phase 4:** No IDS-Agent code drop — budget time to build agent from paper description.
- **Phase 5:** NetMamba/YaTC may be comparison-by-number unless LICENSE clarified.
- **Phase 8a:** SecAlign NC code — use sanitization *patterns*, not a fork of their training pipeline, unless staying strictly academic.
- **Phase 8a:** StruQ — implement delimiter/template idea yourself.
