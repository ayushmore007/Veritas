"""`veritas-api` — run the backend (website + REST API)."""

from __future__ import annotations

import argparse
import logging
import webbrowser

LOOPBACK = ("127.0.0.1", "::1", "localhost")


def main(argv: list[str] | None = None) -> int:
    import uvicorn

    from veritas.api.security import configured_key

    parser = argparse.ArgumentParser(prog="veritas-api", description="Run the Veritas backend")
    parser.add_argument("--host", default="127.0.0.1", help="interface to bind (default: loopback only)")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    log = logging.getLogger("veritas.api")

    exposed = args.host not in LOOPBACK
    if exposed and configured_key() is None:
        # Without a key the API only answers loopback clients, so binding wide would be pointless
        # and a phone could not use it. Fail loudly instead of starting something that looks up.
        parser.error(
            "Binding to a non-loopback address needs VERITAS_API_KEY set "
            '(e.g. export VERITAS_API_KEY="$(openssl rand -hex 24)").'
        )
    url = f"http://{'localhost' if not exposed else args.host}:{args.port}"
    print("=" * 72)
    print("  VERITAS SENTINEL — backend")
    print(f"  Website:   {url}")
    print(f"  API docs:  {url}/docs")
    print(f"  Auth:      {'X-API-Key required' if configured_key() else 'loopback clients only'}")
    print("=" * 72)
    if exposed:
        log.warning("Listening on %s: use HTTPS (reverse proxy) when the network is not trusted.", args.host)
    if not args.no_browser and not exposed:
        webbrowser.open(url)
    uvicorn.run("veritas.api.app:app", host=args.host, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
