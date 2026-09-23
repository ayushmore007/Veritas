"""YAML config loader for Phase 5 baselines."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


def load_baseline_config(path: Path | None = None) -> dict[str, Any]:
    cfg_path = path or Path("config/baseline.yaml")
    return yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
