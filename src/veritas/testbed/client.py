"""HTTP/3 client wrapper for testbed traffic scenarios."""

from __future__ import annotations

import asyncio
import ssl
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import urlparse

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, H3Event, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent


@dataclass
class RequestStats:
    bytes_sent: int = 0
    bytes_received: int = 0
    request_count: int = 0


@dataclass
class HttpSession:
    host: str
    port: int
    sni: str
    ca_path: str
    stats: RequestStats = field(default_factory=RequestStats)
    _protocol: QuicClientProtocol | None = field(default=None, repr=False)
    _cm: object | None = field(default=None, repr=False)

    async def __aenter__(self) -> HttpSession:
        configuration = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
        configuration.load_verify_locations(self.ca_path)
        configuration.verify_mode = ssl.CERT_REQUIRED
        configuration.server_name = self.sni

        self._cm = connect(
            self.host,
            self.port,
            configuration=configuration,
            create_protocol=QuicClientProtocol,
        )
        self._protocol = await self._cm.__aenter__()
        assert isinstance(self._protocol, QuicClientProtocol)
        self._protocol.stats = self.stats
        return self

    async def __aexit__(self, *args) -> None:
        if self._cm is not None:
            await self._cm.__aexit__(*args)
        self._protocol = None
        self._cm = None

    async def get(self, path: str = "/") -> bytes:
        assert self._protocol is not None
        return await self._protocol.request("GET", path, b"")

    async def post(self, path: str, data: bytes) -> bytes:
        assert self._protocol is not None
        return await self._protocol.request("POST", path, data)


class QuicClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._http = H3Connection(self._quic)
        self._events: dict[int, deque[H3Event]] = {}
        self._waiters: dict[int, asyncio.Future] = {}
        self.stats = RequestStats()

    async def request(self, method: str, path: str, body: bytes) -> bytes:
        stream_id = self._quic.get_next_available_stream_id()
        headers = [
            (b":method", method.encode()),
            (b":scheme", b"https"),
            (b":authority", self._quic.configuration.server_name.encode()),
            (b":path", path.encode()),
        ]
        self._http.send_headers(stream_id=stream_id, headers=headers, end_stream=not body)
        sent = 0
        if body:
            self._http.send_data(stream_id=stream_id, data=body, end_stream=True)
            sent = len(body)
        else:
            sent = 0
        self.stats.bytes_sent += sent
        self.stats.request_count += 1

        loop = asyncio.get_running_loop()
        waiter: asyncio.Future = loop.create_future()
        self._events[stream_id] = deque()
        self._waiters[stream_id] = waiter
        self.transmit()

        events = await waiter
        received = b""
        for ev in events:
            if isinstance(ev, DataReceived):
                received += ev.data
        self.stats.bytes_received += len(received)
        return received

    def quic_event_received(self, event: QuicEvent) -> None:
        for http_event in self._http.handle_event(event):
            if isinstance(http_event, HeadersReceived):
                sid = http_event.stream_id
                if sid in self._events:
                    self._events[sid].append(http_event)
                    if http_event.stream_ended:
                        waiter = self._waiters.pop(sid)
                        waiter.set_result(self._events.pop(sid))
            elif isinstance(http_event, DataReceived):
                sid = http_event.stream_id
                if sid in self._events:
                    self._events[sid].append(http_event)
                    if http_event.stream_ended:
                        waiter = self._waiters.pop(sid)
                        waiter.set_result(self._events.pop(sid))


def build_url(host: str, port: int, path: str) -> str:
    return f"https://{host}:{port}{path}"
