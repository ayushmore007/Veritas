"""Held-out split machinery and the sample-size gate."""

from __future__ import annotations

from pathlib import Path

import pytest

from veritas.eval.splits import (
    MIN_TEST_PER_CLASS,
    SPLITS,
    SplitManifest,
    assess_sufficiency,
    make_splits,
)
from veritas.eval.stability import measure_stability


def _flows(n_captures: int = 6, per_capture: int = 5) -> list[dict]:
    out = []
    for c in range(n_captures):
        for i in range(per_capture):
            out.append(
                {
                    "flow_id": f"c{c}-f{i}",
                    "capture_id": f"cap-{c}",
                    "scenario_id": ["browse", "stream", "c2_beacon", "scan_probe", "data_exfil"][i],
                    "traffic_class": "benign" if i < 2 else "malicious",
                }
            )
    return out


def test_no_capture_spans_two_splits():
    """Flows from one generate run share a clock and parameter draw — splitting them leaks."""
    manifest = make_splits(_flows(), seed=7)
    by_capture: dict[str, set[str]] = {}
    for flow in _flows():
        by_capture.setdefault(flow["capture_id"], set()).add(
            manifest["assignment"][flow["flow_id"]]
        )
    for capture, splits in by_capture.items():
        assert len(splits) == 1, f"{capture} straddles {splits}"


def test_split_is_reproducible_for_a_seed():
    a = make_splits(_flows(), seed=3)["assignment"]
    b = make_splits(_flows(), seed=3)["assignment"]
    assert a == b
    c = make_splits(_flows(), seed=4)["assignment"]
    assert a != c, "different seeds should give different assignments"


def test_every_flow_lands_in_exactly_one_split():
    flows = _flows()
    assignment = make_splits(flows, seed=1)["assignment"]
    assert set(assignment) == {f["flow_id"] for f in flows}
    assert set(assignment.values()) <= set(SPLITS)


def test_single_capture_is_reported_as_degraded_grouping():
    """One capture means no real group separation — say so rather than pretend."""
    result = make_splits(_flows(n_captures=1), seed=0)
    assert result["grouping_degraded"] is True
    assert "multiple runs" in result["grouping_note"]


def test_ratios_must_sum_to_one():
    with pytest.raises(ValueError):
        make_splits(_flows(), ratios=(0.5, 0.3, 0.3))


def test_manifest_roundtrip(tmp_path: Path):
    path = tmp_path / "split.json"
    manifest = SplitManifest(path)
    assert not manifest.exists
    manifest.data = make_splits(_flows(), seed=0)
    manifest.save()

    reloaded = SplitManifest(path)
    assert reloaded.exists
    assert reloaded.assignment == manifest.assignment
    assert reloaded.flow_ids("test")


def test_sufficiency_refuses_rates_on_tiny_splits():
    tiny = assess_sufficiency({"benign": 2, "malicious": 3})
    assert tiny["supports_rates"] is False
    assert "too small" in tiny["verdict"]

    middling = assess_sufficiency({"benign": 12, "malicious": 15})
    assert middling["supports_rates"] is True
    assert middling["supports_precise_rates"] is False
    assert "confidence intervals" in middling["verdict"]

    ample = assess_sufficiency({"benign": MIN_TEST_PER_CLASS, "malicious": MIN_TEST_PER_CLASS})
    assert ample["supports_precise_rates"] is True


def test_sufficiency_handles_an_empty_split():
    empty = assess_sufficiency({})
    assert empty["supports_rates"] is False
    assert "empty" in empty["verdict"]


class _FlipFlopAgent:
    """Alternates verdicts, to prove the stability check can actually fail."""

    def __init__(self) -> None:
        self.n = 0

    def triage(self, flow_id: str):
        from veritas.agent.schema import AgentDecision, ReasoningTrace, Verdict, utcnow

        self.n += 1
        verdict = Verdict.BLOCK if self.n % 2 else Verdict.IGNORE
        now = utcnow()
        return ReasoningTrace(
            flow_id=flow_id,
            decision=AgentDecision(flow_id=flow_id, verdict=verdict),
            provider="test",
            model="flipflop",
            prompt_profile="baseline",
            metadata_channel="json_slot",
            started_at=now,
            ended_at=now,
            latency_ms=0.0,
        )


def test_stability_flags_a_coin_flip_agent():
    report = measure_stability(_FlipFlopAgent(), ["f1"], repeats=4)
    assert report["unstable_flows"] == ["f1"]
    assert report["mean_agreement"] == 0.5
    assert "flip verdicts" in report["verdict"]


def test_stability_requires_at_least_two_repeats():
    with pytest.raises(ValueError):
        measure_stability(_FlipFlopAgent(), ["f1"], repeats=1)
