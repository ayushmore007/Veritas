"""Phase 9 CLI — evaluation report and figures.

Live experiment runners for Phases 6–8 are not yet in the repository. Until they land, ``run``
validates an existing ``phase9_report.json`` (for example from a full corpus run) so
``scripts/reproduce.py`` and the paper draft have a stable artifact path.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPORT_PATH = Path("data/processed/eval/phase9_report.json")
FIGURES_DIR = Path("data/processed/eval/figures")


def _eval_modules_ready() -> bool:
    """True when attack/defense experiment code is importable (future phases 6–8)."""
    try:
        from veritas.attacks import injection  # noqa: F401
        from veritas.defense import verifier  # noqa: F401

        return True
    except ImportError:
        return False


def _validate_report(data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for key in ("detection", "injection", "false_alarms"):
        if key not in data:
            errors.append(f"missing top-level key: {key}")
    if "is_simulacrum" in data and data.get("provider") == "deterministic":
        if not data.get("simulacrum_warning"):
            errors.append("deterministic report should include simulacrum_warning")
    return errors


def cmd_run(args: argparse.Namespace) -> int:
    if args.require_live:
        if not _eval_modules_ready():
            print(
                "ERROR: --require-live set but Phases 6–8 modules are not implemented.",
                file=sys.stderr,
            )
            return 1
        print("Live Phase 9 experiments are not wired in this CLI yet.", file=sys.stderr)
        print("Implement veritas.eval.experiments and call from here.", file=sys.stderr)
        return 1

    if not REPORT_PATH.is_file():
        print(
            f"ERROR: no report at {REPORT_PATH}.",
            file=sys.stderr,
        )
        print(
            "Phases 6–8 (attacks, defense) are stubs in this repo — run the Phase 1–5 pipeline "
            "via scripts/reproduce.py, or place a full-corpus phase9_report.json under "
            "data/processed/eval/.",
            file=sys.stderr,
        )
        return 1

    data = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
    errors = _validate_report(data)
    if errors:
        print(f"ERROR: invalid report structure in {REPORT_PATH}:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    summary = {
        "report": str(REPORT_PATH),
        "provider": data.get("provider"),
        "is_simulacrum": data.get("is_simulacrum"),
        "dataset_flows": data.get("dataset_flows"),
        "test_flows": data.get("test_flows"),
        "mode": "cached_report",
        "note": (
            "Phases 6–8 experiment code is not in this repository yet. "
            "Using the saved Phase 9 report for paper/traceability."
        ),
    }
    if args.provider and args.provider != data.get("provider"):
        print(
            f"WARNING: CLI --provider {args.provider} differs from report provider "
            f"{data.get('provider')!r}. Re-run the full corpus with matching provider for paper numbers.",
            file=sys.stderr,
        )
    print(json.dumps(summary, indent=2))
    if data.get("simulacrum_warning"):
        print(f"\n{data['simulacrum_warning']}")
    return 0


def cmd_figures(args: argparse.Namespace) -> int:
    if not REPORT_PATH.is_file():
        print(f"ERROR: run evaluation first — missing {REPORT_PATH}", file=sys.stderr)
        return 1

    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    readme = FIGURES_DIR / "README.txt"
    readme.write_text(
        "Figure rendering from phase9_report.json is not implemented yet.\n"
        "See docs/phase9-evaluation.md for the experiment table and paper draft paths.\n",
        encoding="utf-8",
    )
    print(json.dumps({"figures_dir": str(FIGURES_DIR), "status": "placeholder"}, indent=2))
    print(f"Placeholder written -> {readme}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="veritas-eval",
        description="Phase 9 evaluation report (cached until Phases 6–8 land)",
    )
    parser.add_argument(
        "--provider",
        choices=["deterministic", "ollama"],
        help="Expected agent provider (warns if report used a different one)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="Validate or run Phase 9 experiments")
    run.add_argument(
        "--require-live",
        action="store_true",
        help="Fail unless live Phases 6–8 experiment code is available",
    )
    run.set_defaults(func=cmd_run)

    fig = sub.add_parser("figures", help="Render figures from the saved report")
    fig.set_defaults(func=cmd_figures)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
