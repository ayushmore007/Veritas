#!/usr/bin/env python3
"""
Veritas Sentinel dashboard launcher.

The backend is now the FastAPI app in `src/veritas/api/` (REST API for the website *and* the mobile
app, ML model endpoints, auth, rate limits). This file stays so `python web/server.py` keeps working.

Usage:
    python web/server.py [--host 127.0.0.1] [--port 8000] [--no-browser]

Equivalent to `veritas-api`. Binding beyond loopback requires VERITAS_API_KEY.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

# Re-exported for callers and tests that imported them from here.
from veritas.api.validation import BadRequest  # noqa: E402,F401
from veritas.api.validation import parse_port as _parse_port  # noqa: E402,F401
from veritas.api.validation import parse_target as _parse_target  # noqa: E402,F401

if __name__ == "__main__":
    from veritas.api.server import main

    raise SystemExit(main())
