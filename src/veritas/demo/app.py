"""Veritas live demo — the attack and the defense, on real data, in front of an audience.

This is a presentation surface, not a new result. Everything here calls the same code paths the
CLI and the Phase 9 experiment suite call: the same twin, the same agent loop, the same injection
payloads, the same verifier. Nothing is mocked and no number is hardcoded — if the demo shows a
verdict flipping, that verdict really flipped.

Run:  streamlit run src/veritas/demo/app.py

Design intent, tab by tab:

1. **Pipeline** — makes the trust split visible. Two columns, measured and untrusted, side by side
   on a real flow. Everything else in the project follows from that one distinction.
2. **Attack** — shows a verdict flipping live. Pick a malicious flow the defender catches, pick a
   payload, watch `block` become `ignore`, and read the claim the agent used to justify it.
3. **Defense** — the same attack with layers switched on one at a time, so the audience sees which
   layer catches which attack and, crucially, which layer *fails* on the adaptive one.
4. **Results** — the measured Phase 9 table and figures.

The default backend is the offline stand-in so the demo always runs. If Ollama is up, the sidebar
lets you switch to the real model and everything below works identically.
"""

from __future__ import annotations

import json
from typing import Any

import streamlit as st

from veritas.agent.llm import DeterministicProvider, LLMError, OllamaProvider
from veritas.agent.loop import DefenderAgent
from veritas.agent.schema import Verdict
from veritas.agent.tools import AgentToolbox
from veritas.attacks.injection import (
    grammar_valid_payloads,
    grounding_aware_payloads,
    naive_payloads,
)
from veritas.defense.consistency import ConsistencyChecker
from veritas.defense.sanitizer import Sanitizer
from veritas.defense.verifier import ClaimStatus, ProvenanceVerifier
from veritas.testbed.config import project_root
from veritas.twin.query import get_flow_stats
from veritas.twin.store import TwinStore

ROOT = project_root()
TWIN_DB = ROOT / "data/processed/twin/twin.db"
REPORT = ROOT / "data/processed/eval/phase9_report.json"
FIGURES = ROOT / "data/processed/eval/figures"

VERDICT_STYLE = {
    Verdict.BLOCK: ("🛑", "#b3261e", "BLOCK"),
    Verdict.FLAG: ("⚠️", "#8a5a00", "FLAG"),
    Verdict.IGNORE: ("✅", "#1f5a4c", "IGNORE"),
}


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


@st.cache_resource
def load_store() -> TwinStore:
    return TwinStore(TWIN_DB)


@st.cache_data
def load_flow_index() -> list[dict[str, Any]]:
    """One row per flow, with the label attached. Cached so the picker is instant."""
    store = load_store()
    out = []
    for row in store.list_flows(limit=10_000):
        flow = store.get_flow(row["flow_id"])
        if not flow:
            continue
        gt = flow["ground_truth"]
        out.append(
            {
                "flow_id": flow["flow_id"],
                "scenario": gt.get("scenario_id"),
                "traffic_class": gt.get("traffic_class"),
                "attack_type": gt.get("attack_type"),
                "variant": (gt.get("evasion") or {}).get("variant", "none"),
                "duration": flow["measured_features"].get("flow_duration"),
            }
        )
    return out


@st.cache_data
def load_report() -> dict[str, Any] | None:
    if REPORT.is_file():
        return json.loads(REPORT.read_text(encoding="utf-8"))
    return None


def build_provider(name: str):
    if name == "ollama":
        return OllamaProvider()
    return DeterministicProvider()


def make_agent(provider, override: dict[str, dict[str, Any]] | None = None) -> DefenderAgent:
    toolbox = AgentToolbox(load_store(), metadata_override=override or {})
    return DefenderAgent(toolbox, provider)


def triage(provider, flow_id: str, override: dict | None = None):
    try:
        return make_agent(provider, override).triage(flow_id), None
    except LLMError as exc:
        return None, str(exc)


def verdict_badge(verdict: Verdict, caption: str = "") -> None:
    icon, colour, label = VERDICT_STYLE[verdict]
    st.markdown(
        f"<div style='border-left:4px solid {colour};padding:10px 14px;"
        f"background:rgba(128,128,128,.07);border-radius:3px'>"
        f"<span style='font-size:26px'>{icon}</span> "
        f"<span style='font-size:20px;font-weight:700;color:{colour}'>{label}</span>"
        f"<div style='color:#888;font-size:13px;margin-top:3px'>{caption}</div></div>",
        unsafe_allow_html=True,
    )


def claim_table(trace) -> None:
    """Show every claim with the trust level of its evidence — the thing the verifier reads."""
    rows = []
    for claim in trace.decision.claims:
        rows.append(
            {
                "decisive": "★" if claim.decisive else "",
                "source": claim.evidence_source.value,
                "field": claim.evidence_field or "—",
                "value": claim.evidence_value,
                "statement": claim.statement,
            }
        )
    if rows:
        st.dataframe(rows, use_container_width=True, hide_index=True)
    else:
        st.caption("No claims emitted.")


# ---------------------------------------------------------------------------
# Page
# ---------------------------------------------------------------------------

st.set_page_config(page_title="Veritas — live demo", page_icon="🛰️", layout="wide")

if not TWIN_DB.is_file():
    st.error(
        f"No twin database at {TWIN_DB}.\n\n"
        "Run the pipeline first:\n\n"
        "```\nveritas-testbed generate --runs 20 --seed 1 --record-pcap\n"
        "veritas-capture process --manifest --entropy\n"
        "veritas-twin ingest\n```"
    )
    st.stop()

st.sidebar.title("🛰️ Veritas")
st.sidebar.caption("Explainable AI defense for encrypted QUIC traffic")

provider_name = st.sidebar.radio(
    "Defender backend",
    ["deterministic", "ollama"],
    format_func=lambda v: "Offline stand-in" if v == "deterministic" else "Ollama (llama3.1:8b)",
    help=(
        "The stand-in is a rule-based model of an undefended LLM — it always runs and is fast "
        "enough to demo. Ollama is the real defender and needs `ollama serve` running."
    ),
)
provider = build_provider(provider_name)

if provider_name == "deterministic":
    st.sidebar.info(
        "**Stand-in active.** This models how an undefended LLM responds to metadata. "
        "It demonstrates the mechanism; it is not a measurement of a language model.",
        icon="ℹ️",
    )

flows = load_flow_index()
st.sidebar.metric("Flows in the twin", len(flows))
st.sidebar.metric(
    "Malicious", sum(1 for f in flows if f["traffic_class"] == "malicious")
)

tab_pipeline, tab_attack, tab_defense, tab_results = st.tabs(
    ["1 · The trust split", "2 · The attack", "3 · The defense", "4 · Measured results"]
)


# ---------------------------------------------------------------------------
# 1 — Pipeline / trust split
# ---------------------------------------------------------------------------

with tab_pipeline:
    st.header("Every field is either measured or attacker-written")
    st.markdown(
        "The defender cannot read encrypted payloads. It sees two very different things: "
        "**statistics our own instruments measured**, and **text the remote server chose to "
        "send**. Keeping those apart is what the whole project is built on."
    )

    options = {f"{f['scenario']} · {f['flow_id'][:8]}": f["flow_id"] for f in flows[:200]}
    picked = st.selectbox("Inspect a flow", list(options), key="pipeline_flow")
    flow_id = options[picked]

    store = load_store()
    flow = store.get_flow(flow_id)
    stats = get_flow_stats(store, flow_id)

    left, right = st.columns(2)

    with left:
        st.subheader("🟢 Measured — the twin")
        st.caption(
            "Derived from packet instrumentation. The attacker can only influence these by "
            "changing their actual traffic."
        )
        show = [
            "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts", "totlen_fwd_pkts",
            "totlen_bwd_pkts", "down_up_ratio", "flow_iat_max", "flow_iat_mean",
        ]
        st.dataframe(
            [
                {"field": k, "value": round(v, 4) if isinstance(v, float) else v}
                for k, v in stats["features"].items()
                if k in show
            ],
            use_container_width=True,
            hide_index=True,
        )

    with right:
        st.subheader("🟠 Untrusted — the attacker's channel")
        st.caption(
            "Chosen by the remote endpoint. This is the field the Phase 7 attack writes into."
        )
        st.dataframe(
            [{"field": k, "value": v} for k, v in flow["metadata_untrusted"].items()],
            use_container_width=True,
            hide_index=True,
        )
        st.info(
            "The server name is set by whoever owns the server — including an attacker. "
            "The defender still has to read it.",
            icon="⚠️",
        )

    with st.expander("Ground truth (never shown to the defender)"):
        st.caption(
            "Written when the traffic was generated, before any detector existed. The agent's "
            "tools strip this — there is a test that fails if a label ever reaches the prompt."
        )
        st.json(flow["ground_truth"])


# ---------------------------------------------------------------------------
# 2 — Attack
# ---------------------------------------------------------------------------

with tab_attack:
    st.header("Rewriting one field flips the verdict")

    malicious = [f for f in flows if f["traffic_class"] == "malicious" and f["variant"] == "none"]
    labels = {
        f"{f['attack_type']} · {f['duration']:.1f}s · {f['flow_id'][:8]}": f["flow_id"]
        for f in malicious[:120]
    }
    picked = st.selectbox("Pick a malicious flow", list(labels), key="attack_flow")
    flow_id = labels[picked]

    store = load_store()
    baseline_trace, err = triage(provider, flow_id)
    if err:
        st.error(f"Backend unreachable: {err}")
        st.stop()

    tier = st.radio(
        "Attack tier",
        ["none", "7a", "7b", "7b_adaptive"],
        horizontal=True,
        format_func=lambda t: {
            "none": "No attack",
            "7a": "7a — naive lie",
            "7b": "7b — true facts, false framing",
            "7b_adaptive": "7b adaptive — same, as a valid hostname",
        }[t],
        key="attack_tier",
    )

    payloads = {
        "7a": naive_payloads(),
        "7b": grounding_aware_payloads(store, flow_id),
        "7b_adaptive": grammar_valid_payloads(store, flow_id),
    }.get(tier, [])

    payload = None
    if payloads:
        names = {p.variant: p for p in payloads}
        chosen = st.selectbox("Payload", list(names), key="attack_payload")
        payload = names[chosen]
        st.code(payload.sni, language=None)
        st.caption(payload.notes)

    col_before, col_after = st.columns(2)

    with col_before:
        st.subheader("Before")
        verdict_badge(baseline_trace.decision.verdict, "no injection — the honest verdict")
        claim_table(baseline_trace)

    with col_after:
        st.subheader("After")
        if payload is None:
            st.caption("Choose an attack tier to see the injected run.")
        else:
            attacked, err = triage(provider, flow_id, {flow_id: payload.as_metadata()})
            if err:
                st.error(err)
            else:
                flipped = (
                    baseline_trace.decision.verdict in (Verdict.BLOCK, Verdict.FLAG)
                    and attacked.decision.verdict is Verdict.IGNORE
                )
                verdict_badge(
                    attacked.decision.verdict,
                    "attack succeeded — malicious flow cleared" if flipped
                    else "verdict held",
                )
                claim_table(attacked)

                untrusted = attacked.decision.untrusted_decisive_claims()
                if flipped:
                    if untrusted:
                        st.warning(
                            "The deciding reason is sourced **untrusted** — the trace records that "
                            "the attacker authored the basis for this clearance.",
                            icon="🔍",
                        )
                    else:
                        st.error(
                            "The deciding reason is labelled **measured**. The agent verified the "
                            "injected numbers, found them genuine, and lost track of the fact that "
                            "the *interpretation* came from the attacker. Provenance alone will "
                            "not catch this — see tab 3.",
                            icon="🔍",
                        )

    if tier == "7b":
        st.info(
            "Every number in that server name is **true** for this exact flow. Only the story "
            "wrapped around it is false. A defense that fact-checks the reasoning has nothing "
            "to reject.",
            icon="💡",
        )
    if tier == "7b_adaptive":
        st.info(
            "Same information, written as an ordinary hostname. This exists because the bracketed "
            "form was caught by a grammar check — not by understanding the attack. An attacker who "
            "reads the defense simply re-encodes.",
            icon="💡",
        )


# ---------------------------------------------------------------------------
# 3 — Defense
# ---------------------------------------------------------------------------

with tab_defense:
    st.header("Which layer stops it, and why")

    malicious = [f for f in flows if f["traffic_class"] == "malicious" and f["variant"] == "none"]
    labels = {
        f"{f['attack_type']} · {f['flow_id'][:8]}": f["flow_id"] for f in malicious[:120]
    }
    picked = st.selectbox("Flow", list(labels), key="defense_flow")
    flow_id = labels[picked]
    store = load_store()

    tier = st.radio(
        "Attack",
        ["7a", "7b", "7b_adaptive"],
        horizontal=True,
        format_func=lambda t: {
            "7a": "7a naive",
            "7b": "7b grounding-aware",
            "7b_adaptive": "7b adaptive",
        }[t],
        key="defense_tier",
    )
    payloads = {
        "7a": naive_payloads(),
        "7b": grounding_aware_payloads(store, flow_id),
        "7b_adaptive": grammar_valid_payloads(store, flow_id),
    }[tier]
    names = {p.variant: p for p in payloads}
    payload = names[st.selectbox("Payload", list(names), key="defense_payload")]

    st.markdown("**Defense layers**")
    c1, c2, c3, c4 = st.columns(4)
    use_sanitizer = c1.checkbox("8a Sanitizer", value=False)
    use_consistency = c2.checkbox("Consistency check", value=False,
                                  help="The prior-art baseline: fact-check the reasoning.")
    use_verifier = c3.checkbox("8b Provenance rule", value=False)
    use_replay = c4.checkbox("+ Ablation replay", value=False,
                             help="Re-run with metadata removed; a flipped verdict is the "
                                  "fingerprint of manipulation.")

    metadata = payload.as_metadata()
    sanitizer_note = None
    if use_sanitizer:
        cleaned, results = Sanitizer(enabled=True).apply(metadata)
        quarantined = [r.field for r in results if r.quarantined]
        metadata = cleaned
        sanitizer_note = (
            f"Quarantined: {', '.join(quarantined)}" if quarantined
            else "Nothing to reject — valid hostname, no instruction, no false statement."
        )

    trace, err = triage(provider, flow_id, {flow_id: metadata})
    if err:
        st.error(err)
        st.stop()

    final = trace.decision.verdict
    caught_by = None

    if use_consistency and final is Verdict.IGNORE:
        result = ConsistencyChecker(store=store).check(trace)
        if result.overridden:
            final = result.final_verdict
            caught_by = "consistency check"

    verification = None
    if use_verifier and final is Verdict.IGNORE:
        replay_fn = None
        if use_replay:
            def replay_fn(fid: str) -> Verdict:
                blank = {
                    fid: {
                        "sni": None,
                        "alpn": None,
                        "quic_version": None,
                        "connection_id": None,
                    }
                }
                return make_agent(provider, blank).triage(fid).decision.verdict

        verifier = ProvenanceVerifier(store=store, replay_fn=replay_fn, run_replay=use_replay)
        verification = verifier.verify(trace)
        if verification.overridden:
            final = verification.final_verdict
            caught_by = "provenance rule" if not use_replay else "provenance rule + replay"

    left, right = st.columns([1, 1])

    with left:
        st.subheader("Outcome")
        if final is Verdict.IGNORE:
            verdict_badge(final, "attack succeeded — the malicious flow was cleared")
        else:
            verdict_badge(final, f"attack stopped by the {caught_by}" if caught_by
                          else "verdict held")

        if sanitizer_note:
            st.caption(f"**8a —** {sanitizer_note}")

        if use_consistency and final is Verdict.IGNORE:
            st.caption(
                "**Consistency check —** every stated number matched observation, so it had "
                "nothing to reject."
            )

    with right:
        st.subheader("Why")
        if verification is not None:
            for cv in verification.claim_verdicts:
                icon = {
                    ClaimStatus.GROUNDED: "🟢",
                    ClaimStatus.CONTRADICTED: "🔴",
                    ClaimStatus.UNSUPPORTED: "🟠",
                    ClaimStatus.UNTRUSTED_SOURCE: "🟠",
                }[cv.status]
                star = " ★" if cv.claim.decisive else ""
                st.markdown(f"{icon} **{cv.status.value}**{star} — {cv.claim.statement[:150]}")
                if cv.detail:
                    st.caption(cv.detail)
            if verification.replay:
                r = verification.replay
                st.markdown(
                    f"**Replay:** with metadata → `{r['verdict_with_metadata']}`, "
                    f"without → `{r['verdict_without_metadata']}`"
                )
                st.caption(r["note"])
        else:
            st.caption("Switch on the provenance rule to see the per-claim verdict.")

    st.divider()
    st.caption(
        "Try this order: 7a with the sanitizer on → stopped. 7b with the sanitizer on → stopped, "
        "but only because of the brackets. 7b adaptive with the sanitizer on → straight through. "
        "Then add the provenance rule and the replay."
    )


# ---------------------------------------------------------------------------
# 4 — Results
# ---------------------------------------------------------------------------

with tab_results:
    st.header("Measured results")
    report = load_report()

    if report is None:
        st.warning("No Phase 9 report yet. Run `veritas-eval run`.")
    else:
        inj = report.get("injection", {})
        rows = []
        for tier, label in (
            ("7a", "7a naive"),
            ("7b", "7b grounding-aware"),
            ("7b_adaptive", "7b adaptive"),
        ):
            if tier not in inj:
                continue
            entry = inj[tier]
            rows.append(
                {
                    "attack": label,
                    "undefended": entry["undefended"]["asr"],
                    "sanitizer 8a": entry["sanitizer_8a"]["asr"],
                    "consistency check": entry["consistency_baseline"]["asr"],
                    "verifier + replay": entry["verifier_8b_with_replay"]["asr"],
                    "twin ablated": entry["verifier_no_twin_ablation"]["asr"],
                }
            )
        st.subheader("Attack success rate by defense")
        st.dataframe(rows, use_container_width=True, hide_index=True)

        fa = report.get("false_alarms", {})
        if fa.get("false_alarm_rates"):
            st.metric(
                "False alarms on honest cleared flows",
                fa["false_alarm_rates"].get("verifier_8b_with_replay"),
                help=f"Measured over {fa.get('correctly_cleared_by_agent')} benign flows the "
                     "agent had correctly cleared, with no injection.",
            )

        if report.get("is_simulacrum"):
            st.warning(report.get("simulacrum_warning", ""), icon="⚠️")

    st.subheader("Figures")
    if FIGURES.is_dir():
        for name in sorted(FIGURES.glob("*.png")):
            st.image(str(name), use_container_width=True)
    else:
        st.caption("No figures yet. Run `veritas-eval figures`.")