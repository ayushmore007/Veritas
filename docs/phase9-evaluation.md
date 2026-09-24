# Phase 9 — Evaluation and Ablations

This phase does not test a model. It tests **the claim**, and it is what reviewers actually
scrutinise.

```powershell
veritas-eval run                      # everything
veritas-eval run --only injection     # one experiment
veritas-eval figures                  # render figures from the saved report
```

Output: `data/processed/eval/phase9_report.json` and `data/processed/eval/figures/`.

Implementation: `src/veritas/eval/experiments.py` (runners) and `src/veritas/eval/figures.py`.
`--only` accepts a comma-separated subset and merges it into the saved report; `--max-flows N`
caps flows per experiment for slow providers; `--cached` validates a saved report without running.
The evasion and generalization experiments need evaded runs in the corpus — generate them with
`--evasion-strength` / `--evasion-variant` (see Phase 6), or use `scripts/reproduce.py
--evasion-strengths … --held-out-variants …`.

## The eight experiments

| # | Experiment | Question it answers |
|---|------------|--------------------|
| 1 | `detection` | How well does each detector do on held-out clean traffic? |
| 2 | `evasion` | Does reshaping real traffic move each detector, and how fast? |
| 3–4 | `injection` | 7a and 7b ASR, undefended and behind each Phase 8 layer |
| 5 | `false_alarms` | What does the defense cost on honest, correctly-cleared flows? |
| 6 | twin ablation *(inside `injection`)* | Does the verifier still work without its measured anchor? |
| 7 | `generalization` | Do the defenses hold on payloads and evasion styles they never saw? |
| 8 | `latency` | What does each layer add per verdict? |
| — | `ensemble` | Does combining the detectors beat either alone, and at what FPR? |

## Measured results (620 flows, 122-flow test split, deterministic provider)

*The author's run; `veritas-eval run` regenerates every cell from your own corpus.*

| Attack | Undefended | 8a sanitizer | Consistency (prior art) | 8b provenance | 8b + replay | Twin ablated |
|---|---|---|---|---|---|---|
| 7a naive | 0.40 | **0.00** | 0.40 | **0.00** | **0.00** | 0.00 |
| 7b grounding-aware | 0.81 | **0.00** | 0.81 | 0.81 | **0.00** | 0.81 |
| 7b adaptive (valid hostname) | 0.75 | 0.75 | 0.75 | 0.75 | **0.00** | 0.75 |

False alarms on 38 honest cleared benign flows: **0.00** for every defense configuration.

Two rows deserve reading carefully.

**The consistency baseline reduces nothing — including 7a.** That is not a bug in the
reimplementation. A fact-checker fires only when the justification asserts a checkable value; the
naive payloads assert authority rather than numbers, so there is nothing to check, and the
grounding-aware payloads assert numbers that are correct. Consistency checking is the wrong
question for this attack surface, which is the point being made.

**8b without replay stops 7b only when the agent labels provenance honestly.** The default
condition models role confusion: the agent verifies the injected numbers, finds them genuine, and
reports them as measured evidence — carrying the attacker's framing with them. Provenance then looks
clean and only the ablation replay catches it. Both conditions are run and reported
(`injection.honest_provenance_condition`), which localises what each mechanism actually buys.

## The three results that carry the paper

**1. The contrast.** Both the consistency baseline and the provenance verifier should stop 7a. Only
the provenance verifier should stop 7b. If the consistency baseline also stops 7b, Phase 8b has no
contribution and the paper must say so.

**2. The twin ablation.** `verifier_no_twin_ablation` runs the same verifier logic with the measured
oracle removed. Measured: 7a unchanged at 0.00 (an untrusted-labelled claim is refusable on its
label alone — that is what existing IFC defenses do), but both grounding-aware attacks recover their
full success rate (0.81 and 0.75). The measured anchor is doing the work exactly where prior art
stops working. Without that gap the paper would be a reimplementation of CaMeL.

**3. The honest adaptive number.** The first 7b encoding was accidentally caught by 8a's hostname
grammar, which would have credited sanitization with a 0.81 reduction it had not earned. The
adaptive tier re-encodes the same framing as valid DNS labels; 144/144 payloads pass 8a untouched
and ASR stays at 0.75. Reporting only the non-adaptive number would have overstated that layer by
the full 0.75.

What we do **not** claim: robustness against an attacker who adapts to the replay test itself. Such
an attacker would aim to make the *measured* features alone look benign — which is Phase 6 evasion,
and a clean-trained model falls to that entirely (ASR 1.00). Composing both attacks is future work
and we expect it to be effective.

## Reporting rules enforced in code

- Rates are **withheld**, not caveated, when the split cannot support them
  (`veritas.eval.splits.assess_sufficiency`): 10 flows per class for any rate, 30 for two decimal
  places. A number on the page gets quoted regardless of the text beside it.
- The ASR denominator is "flows the undefended defender already caught", and it is printed.
- Every result carries the provider name, and `is_simulacrum` when the offline stand-in produced it.
- The test split is fixed once in a manifest with its seed; re-rolling requires `--force`.

## The simulacrum boundary

With `--provider deterministic`, agent-side numbers come from an offline stand-in that encodes
*assumptions* about how an LLM responds to metadata — specifically, that an undefended model accepts
a benign framing whose stated numbers check out. That demonstrates the **mechanism** end to end and
makes the whole pipeline testable without a GPU.

It is not a measurement of a language model. Everything agent-side in the paper must be re-run with:

```powershell
ollama serve && ollama pull llama3.1:8b
veritas-eval --provider ollama run
```

The ML-side results (detection, evasion, ensemble) are real measurements either way — that model is
trained and evaluated, not simulated.

## Ablations worth adding before submission

- **Prompt profile:** `baseline` vs `hardened` — how much does Phase 8a-style prompt hardening alone
  buy, separately from the sanitizer?
- **Metadata channel:** `json_slot` vs `inline_concat` — how much does structural separation alone
  buy?
- **Feature-count ablation:** the agent's 20-field view vs the full ~80 — does a smaller view help
  or hurt an 8B model?
- **Model size:** 8B vs a larger local model, to see whether 7b's success is a small-model artifact.

Each of these is a one-flag change; none needs new code.

## Next: Phase 10

Write it up, with every number traceable to a command in this repo.
