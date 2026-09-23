"""Trusted vs untrusted field tagging for capture records."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from veritas.testbed.config import project_root


def load_trust_config(path: Path | None = None) -> dict[str, Any]:
    cfg_path = path or project_root() / "config" / "trust_labels.yaml"
    with cfg_path.open(encoding="utf-8") as f:
        return yaml.safe_load(f)


def tag_field_trust(
    cicflowmeter: dict[str, Any],
    metadata: dict[str, Any],
    trust_cfg: dict[str, Any] | None = None,
) -> dict[str, str]:
    """
    Tag every feature key as trusted or untrusted.

    Default rule: all CICFlowMeter numeric/stat columns = trusted;
    metadata strings (sni, alpn, ...) = untrusted (attacker-controllable in threat model).
    """
    cfg = trust_cfg or load_trust_config()
    untrusted_names = {f.lower() for f in cfg.get("untrusted", {}).get("fields", [])}

    tags: dict[str, str] = {}
    for key in cicflowmeter:
        tags[key] = "trusted"
    for key in metadata:
        tags[key] = "untrusted" if key.lower() in untrusted_names else "trusted"
    return tags
