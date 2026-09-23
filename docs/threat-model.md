# Threat Model

Scope: lab testbed only (Mininet/Docker). See project brief §3.

## Assets

- Defender agent (verdicts: block / flag / ignore)
- Digital twin ground-truth store
- Tool outputs (threat intel, host history)
- Operator trust in explanations

## Attacker capabilities

- Send traffic to/from monitored lab network
- Control at least one endpoint (malicious server)
- Control observable **metadata** (e.g., SNI, ALPN on their server)
- Reshape traffic **statistics** (padding, jitter, chunking, dummy downloads)

## Attacker goals

- Malicious flows classified as **ignore** (benign)

## Out of scope

- Modifying defender code or system prompt
- Reading/modifying twin internal state
- Reading private tool results
- Production network attacks
- Supply-chain / physical / privileged insider attacks

## Attack surfaces

| Surface | Attack | Trusted? |
|---------|--------|----------|
| Volumetric/behavioural features | Evasion (Phase 6) | Measured — trusted after capture |
| SNI, string metadata | Manipulation (Phase 7) | **Untrusted** |
| Agent justification text | CoT forgery / grounding-aware 7b | Untrusted until verified |

## Trust boundaries

```
[Testbed traffic] → [Capture/measured features] → TRUSTED → [Twin Tier 1]
[Testbed metadata strings] ──────────────────────→ UNTRUSTED → [Sanitizer] → [Agent]
[Agent justification] ───────────────────────────→ UNTRUSTED → [Verifier + Twin] → [Final verdict]
```

## Compliance note

Document this model in the paper. Experiments must not extend beyond the testbed boundary.
