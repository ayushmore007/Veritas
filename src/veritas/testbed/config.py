"""Load Phase 1 testbed configuration."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


def project_root() -> Path:
    return Path(__file__).resolve().parents[3]


def load_testbed_config(path: Path | None = None) -> dict[str, Any]:
    cfg_path = path or project_root() / "config" / "testbed.yaml"
    with cfg_path.open(encoding="utf-8") as f:
        return yaml.safe_load(f)


def resolve_path(relative: str, config: dict[str, Any]) -> Path:
    return project_root() / relative
