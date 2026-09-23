#!/usr/bin/env python3
"""Inspect LICENSE file(s) in a cloned reference repo before copying code."""

from __future__ import annotations

import re
import sys
from pathlib import Path

PERMISSIVE = {"mit", "apache", "bsd", "isc", "unlicense"}
RESTRICTED = {"cc-by-nc", "non-commercial", "noncommercial"}
COPYLEFT = {"gpl", "agpl", "lgpl"}


def classify(text: str) -> str:
    lower = text.lower()
    if any(x in lower for x in RESTRICTED):
        return "restricted_nc"
    if any(x in lower for x in COPYLEFT):
        return "copyleft"
    if any(x in lower for x in PERMISSIVE):
        return "permissive"
    return "unknown"


def find_license_files(root: Path) -> list[Path]:
    names = {"license", "license.md", "license.txt", "copying", "notice"}
    found = []
    for p in root.iterdir():
        if p.is_file() and p.name.lower() in names:
            found.append(p)
    return found


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python scripts/check_repo_license.py <path-to-cloned-repo>")
        return 2

    root = Path(sys.argv[1]).resolve()
    if not root.is_dir():
        print(f"Not a directory: {root}")
        return 2

    files = find_license_files(root)
    if not files:
        print("RESULT: NO_LICENSE_FILE")
        print("ACTION: Do NOT copy code. Cite paper and reimplement, or contact authors.")
        print("LOG: Update docs/license-audit.md")
        return 1

    for f in files:
        text = f.read_text(encoding="utf-8", errors="replace")
        kind = classify(text)
        print(f"FILE: {f.name}")
        print(f"CLASS: {kind}")
        first = text.strip().splitlines()[:8]
        print("PREVIEW:")
        print("\n".join(first))

        if kind == "permissive":
            print("ACTION: OK to reuse with attribution — add to THIRD_PARTY_NOTICES.md")
            return 0
        if kind == "restricted_nc":
            print("ACTION: OK for academic paper; NOT for commercial product/patent embedding")
            return 0
        if kind == "copyleft":
            print("ACTION: GPL-family — prefer wrapper/subprocess; legal review before embedding")
            return 0

    print("ACTION: Unknown license — treat as read-only until clarified")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
