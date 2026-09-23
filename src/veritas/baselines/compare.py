"""Side-by-side comparison: ML baseline vs Phase 4 agent reasoning traces."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from veritas.agent.schema import ReasoningTrace


def _load_traces(path: Path) -> dict[str, ReasoningTrace]:
    traces: dict[str, ReasoningTrace] = {}
    if not path.is_file():
        return traces
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        trace = ReasoningTrace.model_validate_json(line)
        traces[trace.flow_id] = trace
    return traces


def compare_agent_vs_ml(
    predictions: list[dict[str, Any]],
    traces_path: Path,
) -> dict[str, Any]:
    """Join ML predictions with agent traces for explainability contrast."""
    traces = _load_traces(traces_path)
    rows: list[dict[str, Any]] = []
    agreement = 0

    for pred in predictions:
        fid = pred["flow_id"]
        trace = traces.get(fid)
        ml_mal = pred["predicted_label"] == 1
        agent_detected = False
        agent_verdict = None
        agent_claims: list[dict[str, Any]] = []

        if trace:
            agent_verdict = trace.decision.verdict.value
            agent_detected = agent_verdict in ("block", "flag")
            agent_claims = [
                {
                    "text": c.statement[:200],
                    "evidence_source": c.evidence_source.value,
                    "groundable": c.is_groundable(),
                }
                for c in trace.decision.decisive_claims()[:5]
            ]

        same = ml_mal == agent_detected
        if same:
            agreement += 1

        rows.append(
            {
                "flow_id": fid,
                "scenario_id": pred.get("scenario_id"),
                "truth": "malicious" if pred["truth_label"] == 1 else "benign",
                "ml_prediction": pred["predicted_class"],
                "ml_malicious_probability": pred.get("malicious_probability"),
                "agent_verdict": agent_verdict,
                "agents_agree_on_detection": same,
                "agent_decisive_claims": agent_claims,
            }
        )

    return {
        "flows_compared": len(rows),
        "detection_agreement": agreement,
        "detection_agreement_rate": round(agreement / len(rows), 4) if rows else None,
        "note": (
            "Agent traces carry claim-level provenance; ML carries SHAP/LIME feature attributions. "
            "Agreement on detection is not agreement on reasoning."
        ),
        "per_flow": rows,
    }
