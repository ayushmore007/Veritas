#!/usr/bin/env python3
"""End-to-end reproduction driver for Veritas.

Runs every pipeline stage in dependency order, ending with the live Phase 9 experiments
(``veritas-eval run``) and figures. Evasion experiments need evaded runs in the corpus — see
``--evasion-strengths`` / ``--held-out-variants``.

Examples::

    python scripts/reproduce.py --quick
    python scripts/reproduce.py --provider ollama
    python scripts/reproduce.py --skip-generate
    python scripts/reproduce.py --runs 60 --seed 1 --entropy   # multi-capture corpus
    python scripts/reproduce.py --runs 12 --seed 1 --evasion-strengths 0.25,0.5,0.75,1 \
        --held-out-variants timing_only,volume_only,chunk_only,cover_only
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPLIT_PATH = ROOT / "data/processed/splits/split.json"
FEATURES_PATH = ROOT / "data/processed/features/flows_features.jsonl"
REPORT_PATH = ROOT / "data/processed/eval/phase9_report.json"


def _current_flow_ids() -> set[str]:
    if not FEATURES_PATH.is_file():
        return set()
    ids: set[str] = set()
    for line in FEATURES_PATH.read_text(encoding="utf-8").splitlines():
        if line.strip():
            ids.add(json.loads(line)["flow_id"])
    return ids


def _split_is_stale() -> bool:
    if not SPLIT_PATH.is_file():
        return True
    assigned = set(json.loads(SPLIT_PATH.read_text(encoding="utf-8")).get("assignment", {}))
    current = _current_flow_ids()
    return not current or assigned != current


def _run(label: str, argv: list[str], *, cwd: Path = ROOT) -> None:
    cmd = [sys.executable, *argv]
    print(f"\n{'=' * 72}\n[{label}]\n  {' '.join(cmd)}\n{'=' * 72}")
    t0 = time.perf_counter()
    result = subprocess.run(cmd, cwd=cwd, check=False)
    elapsed = time.perf_counter() - t0
    if result.returncode != 0:
        raise SystemExit(f"{label} failed (exit {result.returncode}) after {elapsed:.1f}s")
    print(f"OK ({elapsed:.1f}s)")


def _agent_flags(provider: str) -> list[str]:
    return ["--provider", provider]


def run_pipeline(args: argparse.Namespace) -> int:
    provider = args.provider
    agent = _agent_flags(provider)

    if not args.skip_generate:
        gen_argv = [
            "-m", "veritas.testbed.cli", "generate", "--record-pcap", "--new-manifest",
            "--runs", str(args.runs),
        ]
        if args.seed is not None:
            gen_argv += ["--seed", str(args.seed)]
        _run("Phase 1 — testbed", gen_argv)

        # Phase 6: evaded runs of the malicious scenarios only (benign is the control arm).
        malicious = "c2_beacon,scan_probe,data_exfil"
        evasion_jobs = [(float(x), None) for x in args.evasion_strengths.split(",") if x.strip()]
        evasion_jobs += [(0.75, v) for v in args.held_out_variants.split(",") if v.strip()]
        for strength, variant in evasion_jobs:
            ev_argv = [
                "-m", "veritas.testbed.cli", "generate", "--record-pcap",
                "--runs", str(args.evasion_runs), "--scenarios", malicious,
                "--evasion-strength", str(strength),
            ]
            if variant:
                ev_argv += ["--evasion-variant", variant]
            if args.seed is not None:
                ev_argv += ["--seed", str(args.seed + int(strength * 1000) + len(variant or ""))]
            _run(f"Phase 6 — evasion {variant or 'baseline'} @ {strength}", ev_argv)
        # Re-capture assigns new flow_ids; split must be rebuilt before any held-out scoring.
        args.force_split = True
    else:
        print("\n[Phase 1] skipped (--skip-generate)")

    capture_argv = ["-m", "veritas.capture.cli", "process"]
    evading = bool(args.evasion_strengths or args.held_out_variants) and not args.skip_generate
    if args.runs > 1 or args.manifest or evading:
        capture_argv.append("--manifest")
    if args.entropy:
        capture_argv.append("--entropy")
    _run("Phase 2 — capture", capture_argv)

    _run("Phase 3 — twin ingest", ["-m", "veritas.twin.cli", "ingest"])

    split_argv = ["-m", "veritas.agent.cli", *agent, "split"]
    if args.force_split or _split_is_stale():
        if _split_is_stale() and not args.force_split:
            print("\n[Phase 4] split manifest stale (flow_ids changed) — re-creating split")
        split_argv.append("--force")
    _run("Phase 4 — fixed split", split_argv)

    _run("Phase 5 — baseline train", ["-m", "veritas.baselines.cli", "train"])
    _run(
        "Phase 5 — baseline predict (test)",
        ["-m", "veritas.baselines.cli", "predict", "--split", "test"],
    )

    if not args.quick:
        _run(
            "Phase 5 — baseline explain (test)",
            ["-m", "veritas.baselines.cli", "explain", "--split", "test"],
        )

    _run("Phase 4 — agent triage", ["-m", "veritas.agent.cli", *agent, "triage", "--all"])
    _run(
        "Phase 4 — agent evaluate (test)",
        ["-m", "veritas.agent.cli", *agent, "evaluate", "--split", "test"],
    )

    if not args.quick:
        _run("Phase 5 — agent vs ML compare", ["-m", "veritas.baselines.cli", "compare"])

    _run("Phase 9 — evaluation", ["-m", "veritas.eval.cli", "--provider", provider, "run"])
    if not args.quick:
        _run("Phase 10 — figures", ["-m", "veritas.eval.cli", "figures"])

    print("\nReproduction finished.")
    print(f"  Agent provider: {provider}")
    print(f"  Phase 9 report: {REPORT_PATH}")
    if args.quick:
        print(
            "\nNOTE: --quick is a smoke run. Paper numbers require the full corpus "
            "(e.g. --runs 60 --seed 1 --entropy) and a real LLM (--provider ollama)."
        )
    if provider == "deterministic":
        print(
            "\nNOTE: deterministic agent is a simulacrum — re-run with --provider ollama "
            "before citing agent-side numbers."
        )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the Veritas pipeline end-to-end (lab testbed only)",
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Smoke test: skip SHAP/LIME explain, compare, and figure generation",
    )
    parser.add_argument(
        "--provider",
        choices=["deterministic", "ollama"],
        default="deterministic",
        help="LLM backend for agent triage and eval (default: deterministic stand-in)",
    )
    parser.add_argument(
        "--skip-generate",
        action="store_true",
        help="Reuse existing Phase 1 labels/PCAP (run capture onward)",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=1,
        help="Testbed generation runs; each is its own capture (default: 1)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        help="Vary scenario parameters per run, reproducibly",
    )
    parser.add_argument(
        "--manifest",
        action="store_true",
        help="With --skip-generate: re-process every run in runs_manifest.json",
    )
    parser.add_argument(
        "--evasion-strengths",
        default="",
        help="Phase 6: comma-separated strengths to generate evaded runs at, e.g. 0.25,0.5,0.75,1",
    )
    parser.add_argument(
        "--evasion-runs",
        type=int,
        default=2,
        help="Evaded runs per strength / variant (default: 2)",
    )
    parser.add_argument(
        "--held-out-variants",
        default="",
        help="Held-out single-knob variants at strength 0.75, "
        "e.g. timing_only,volume_only,chunk_only,cover_only",
    )
    parser.add_argument(
        "--entropy",
        action="store_true",
        help="Add Phase 8c packet-level entropy features during capture",
    )
    parser.add_argument(
        "--force-split",
        action="store_true",
        help="Re-roll train/val/test split (invalidates held-out comparisons)",
    )
    args = parser.parse_args()
    return run_pipeline(args)


if __name__ == "__main__":
    raise SystemExit(main())
