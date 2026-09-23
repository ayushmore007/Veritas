# Licensing and Citation Policy

These three rules apply to **every phase** of Veritas. They are non-negotiable project workflow requirements.

## 1. Cite everything

| What | Where to record | When |
|------|-----------------|------|
| Papers (methods, baselines, prior art) | `docs/bibliography.md` | Before writing related-work text or implementing an adapted method |
| Datasets | `data/external/_terms/` + bibliography | On download; cite in paper § datasets |
| Tools (CICFlowMeter, Ollama, etc.) | README or methods footnote | First use in experiments |
| Adapted code | File header + `THIRD_PARTY_NOTICES.md` if copied | Before merge |

**Rule:** If a design choice comes from a published source, the citation must exist before the code lands in `main`.

## 2. Check LICENSE before copying code

**Allowed without extra steps:** MIT, Apache-2.0, BSD — keep copyright notices.

**Restricted:**
- **CC-BY-NC** (Meta SecAlign **codebase**): OK for academic paper; **not OK** for commercial product or patent filing that embeds that code.
- **GPL**: Using as external tool is fine; **copying GPL code into Veritas** may require GPL on distribution — prefer subprocess/wrapper instead of paste.
- **No LICENSE / "Other"**: **Do not copy code.** Read the paper, cite it, reimplement. Optionally email authors.

**Workflow:**
1. Clone into `references/<repo-name>/` (gitignored).
2. Run `python scripts/check_repo_license.py references/<repo-name>`.
3. Log result in `docs/license-audit.md`.
4. Only then import, wrap, or port code.

## 3. Follow dataset cite-and-research-use terms

| Dataset | Terms summary | Action |
|---------|---------------|--------|
| CIC-IDS2017 | Free research use; cite ICISSP 2018 / CIC | Save request confirmation to `data/external/_terms/cic-ids2017.txt` |
| CSE-CIC-IDS2018 | Free research use; cite CIC | Same pattern |
| UNSW-NB15 | Research use; cite source paper | Same pattern |

**Rule:** Never commit raw PCAP/CSV blobs to git. Store under `data/external/` (gitignored). Your **primary** evaluation data is QUIC flows you generate (Phase 1); public datasets are for baseline sanity only.

## Default when blocked

If license or terms block reuse:

1. **Cite** the paper/dataset.
2. **Reimplement** the idea in Veritas (preferred for IDS-Agent, StruQ patterns, NetMamba/YaTC if no LICENSE).
3. **Compare** against their reported numbers where you cannot run their code.
4. **Flag** in `docs/license-audit.md` and tell the user before Phase N depends on it.
