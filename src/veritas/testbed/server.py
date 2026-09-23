"""Minimal HTTP/3 server for the Veritas lab testbed.

Pattern inspired by aioquic examples (MIT) — reimplemented here, not copied.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Callable

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, H3Event, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ProtocolNegotiated, QuicEvent

logger = logging.getLogger(__name__)

Handler = Callable[[str, str, bytes], tuple[int, bytes, str]]


def _default_handler(method: str, path: str, body: bytes) -> tuple[int, bytes, str]:
    if method == "GET" and path == "/":
        body_out = b"Veritas benign index\n"
        return 200, body_out, "text/plain"
    if method == "GET" and path.startswith("/stream/"):
        # Large payload for streaming-like downloads
        try:
            kb = int(path.split("/")[-1])
        except ValueError:
            kb = 64
        kb = min(max(kb, 1), 4096)
        return 200, b"X" * (kb * 1024), "application/octet-stream"
    if method == "POST" and path == "/upload":
        return 200, b"ok", "text/plain"
    if method == "GET" and path == "/beacon":
        return 200, b"pong", "text/plain"
    if method in ("GET", "HEAD") and path.startswith("/probe"):
        return 404, b"not-found", "text/plain"
    return 404, b"not found", "text/plain"


class TestbedH3Protocol(QuicConnectionProtocol):
    def __init__(self, *args, request_handler: Handler | None = None, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._http: H3Connection | None = None
        self._handler = request_handler or _default_handler
        self._streams: dict[int, dict] = {}

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, ProtocolNegotiated):
            self._http = H3Connection(self._quic)
        if self._http is None:
            return
        for http_event in self._http.handle_event(event):
            self._handle_http(http_event)

    def _handle_http(self, event: H3Event) -> None:
        if isinstance(event, HeadersReceived):
            method = path = ""
            for k, v in event.headers:
                if k == b":method":
                    method = v.decode()
                elif k == b":path":
                    path = v.decode()
            self._streams[event.stream_id] = {
                "method": method,
                "path": path,
                "body": b"",
            }
            if event.stream_ended:
                self._respond(event.stream_id)
        elif isinstance(event, DataReceived):
            state = self._streams.setdefault(event.stream_id, {"method": "", "path": "", "body": b""})
            state["body"] += event.data
            if event.stream_ended:
                self._respond(event.stream_id)

    def _respond(self, stream_id: int) -> None:
        assert self._http is not None
        state = self._streams.pop(stream_id, {"method": "GET", "path": "/", "body": b""})
        status, body, content_type = self._handler(state["method"], state["path"], state["body"])
        self._http.send_headers(
            stream_id=stream_id,
            headers=[
                (b":status", str(status).encode()),
                (b"content-type", content_type.encode()),
                (b"content-length", str(len(body)).encode()),
                (b"server", b"veritas-testbed"),
            ],
        )
        self._http.send_data(stream_id=stream_id, data=body, end_stream=True)


class TestbedServer:
    """Runs one HTTP/3 listener until stopped."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        cert_path: Path,
        key_path: Path,
        request_handler: Handler | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.cert_path = cert_path
        self.key_path = key_path
        self.request_handler = request_handler
        self._server = None
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        configuration = QuicConfiguration(alpn_protocols=H3_ALPN, is_client=False)
        configuration.load_cert_chain(str(self.cert_path), str(self.key_path))
        handler = self.request_handler

        def factory(*args, **kwargs):
            return TestbedH3Protocol(*args, request_handler=handler, **kwargs)

        self._server = await serve(
            self.host,
            self.port,
            configuration=configuration,
            create_protocol=factory,
        )
        logger.info("HTTP/3 testbed server listening on %s:%s", self.host, self.port)

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await asyncio.sleep(0.05)
            self._server = None


async def run_server_process(host: str, port: int, cert_path: Path, key_path: Path) -> None:
    server = TestbedServer(host=host, port=port, cert_path=cert_path, key_path=key_path)
    await server.start()
    await asyncio.Future()
