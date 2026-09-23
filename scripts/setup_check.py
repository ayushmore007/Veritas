#!/usr/bin/env python3
"""Verify tools listed in references.md §1 (Phase 0 setup check)."""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
from dataclasses import dataclass


@dataclass
class CheckResult:
    name: str
    status: str  # ok | missing | optional_missing
    detail: str


def _has_module(name: str) -> bool:
    return importlib.util.find_spec(name) is not None


def _run_version(cmd: list[str]) -> str | None:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if out.returncode == 0:
            return (out.stdout or out.stderr).strip().splitlines()[0][:120]
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    return None


def main() -> int:
    results: list[CheckResult] = []

    py = sys.version.split()[0]
    results.append(
        CheckResult(
            "Python 3.11+",
            "ok" if sys.version_info >= (3, 11) else "missing",
            py,
        )
    )

    for mod, label in [
        ("pandas", "pandas"),
        ("numpy", "numpy"),
        ("sklearn", "scikit-learn"),
        ("yaml", "pyyaml"),
        ("scapy", "scapy"),
        ("aioquic", "aioquic"),
        ("shap", "shap"),
        ("lime", "lime"),
        ("httpx", "httpx"),
    ]:
        results.append(
            CheckResult(label, "ok" if _has_module(mod) else "missing", "import check")
        )

    # cicflowmeter package name may differ
    cic_ok = _has_module("cicflowmeter")
    results.append(
        CheckResult("cicflowmeter", "ok" if cic_ok else "missing", "pip install cicflowmeter")
    )

    for exe, label in [
        (["tshark", "-v"], "tshark"),
        (["docker", "--version"], "docker"),
        (["ollama", "--version"], "ollama"),
    ]:
        ver = _run_version(exe)
        results.append(
            CheckResult(label, "ok" if ver else "optional_missing", ver or "not on PATH")
        )

    mn = shutil.which("mn")
    results.append(
        CheckResult(
            "mininet (mn)",
            "ok" if mn else "optional_missing",
            mn or "Linux/WSL only — use Docker testbed on Windows",
        )
    )

    print("Veritas Phase 0 — setup check\n" + "=" * 40)
    missing = 0
    for r in results:
        icon = {"ok": "[OK]", "missing": "[!!]", "optional_missing": "[--]"}[r.status]
        print(f"{icon} {r.name}: {r.detail}")
        if r.status == "missing":
            missing += 1

    print("\nCompliance reminders:")
    print("  1. Cite everything (docs/bibliography.md)")
    print("  2. Check LICENSE before copying code (scripts/check_repo_license.py)")
    print("  3. Follow dataset terms (data/external/_terms/)")

    if missing:
        print(f"\n{missing} required item(s) missing. Run: pip install -e \".[dev]\"")
        return 1
    print("\nCore Python stack ready.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
