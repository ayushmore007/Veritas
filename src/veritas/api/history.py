"""Persistent scan history (last 50 scans, one per host), safe under concurrent requests."""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Any

from veritas.testbed.config import project_root

logger = logging.getLogger("veritas.api.history")

MAX_SCANS = 50


def history_file() -> Path:
    return project_root() / "data" / "processed" / "twin" / "scans_history.json"


class ScanHistory:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or history_file()
        self._lock = threading.Lock()

    def load(self) -> list[dict[str, Any]]:
        if self.path.is_file():
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
                return data if isinstance(data, list) else []
            except Exception as exc:
                logger.warning("Could not read %s: %s", self.path, exc)
        return []

    def _save(self, history: list[dict[str, Any]]) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(history[:MAX_SCANS], indent=2), encoding="utf-8")
            tmp.replace(self.path)  # a crash never leaves a truncated file
        except Exception as exc:
            logger.warning("Could not write %s: %s", self.path, exc)

    def record(self, report: dict[str, Any]) -> None:
        """Insert at the head, replacing any earlier scan of the same host."""
        host = str(report.get("hostname", "")).lower()
        with self._lock:
            kept = [h for h in self.load() if str(h.get("hostname", "")).lower() != host]
            self._save([report, *kept])

    def clear(self) -> None:
        with self._lock:
            self._save([])
