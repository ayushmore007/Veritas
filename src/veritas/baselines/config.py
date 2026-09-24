"""YAML config loader for Phase 5 baselines."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from veritas.testbed.config import project_root


def load_baseline_config(path: Path | None = None) -> dict[str, Any]:
    cfg_path = path or project_root() / "config" / "baseline.yaml"
    return yaml.safe_load(cfg_path.read_text(encoding="utf-8"))


def resolve_project_path(relative: str | Path) -> Path:
    """Config paths are relative to the project root, not the caller's working directory."""
    path = Path(relative)
    return path if path.is_absolute() else project_root() / path
