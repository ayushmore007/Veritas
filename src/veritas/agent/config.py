"""Agent configuration loader (Phase 4)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from veritas.testbed.config import project_root


def load_agent_config(path: Path | None = None) -> dict[str, Any]:
    cfg_path = path or project_root() / "config" / "agent.yaml"
    with cfg_path.open(encoding="utf-8") as f:
        return yaml.safe_load(f)


def resolve_project_path(relative: str) -> Path:
    return project_root() / relative
