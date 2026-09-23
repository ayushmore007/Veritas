"""QUIC/TLS metadata extraction from PCAP + lab port fallback."""

from __future__ import annotations

import csv
import io
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class FlowMetadata:
    sni: str
    alpn: str = "h3"
    quic_version: str | None = None
    connection_id: str | None = None
    source: str = "port_map"  # tshark | port_map


def tshark_available() -> bool:
    return shutil.which("tshark") is not None


def extract_sni_via_tshark(
    pcap_path: Path,
    display_filter: str,
    *,
    timeout_sec: int = 20,
) -> dict[int, str]:
    """Map server port -> SNI from ClientHello when Wireshark dissects QUIC/TLS."""
    cmd = [
        "tshark",
        "-n",
        "-q",
        "-r",
        str(pcap_path),
        "-Y",
        display_filter,
        "-T",
        "fields",
        "-e",
        "udp.dstport",
        "-e",
        "tls.handshake.extensions_server_name",
        "-E",
        "separator=,",
        "-E",
        "occurrence=f",
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return {}

    mapping: dict[int, str] = {}
    reader = csv.reader(io.StringIO(proc.stdout))
    for row in reader:
        if len(row) < 2 or not row[0] or not row[1]:
            continue
        try:
            port = int(row[0])
        except ValueError:
            continue
        mapping[port] = row[1].strip()
    return mapping


def metadata_for_flow(
    *,
    src_port: int,
    dst_port: int,
    port_sni_map: dict[int, str],
    tshark_sni_by_port: dict[int, str],
    default_alpn: str = "h3",
) -> FlowMetadata:
    """Attach metadata; prefer tshark SNI, else lab port map (untrusted either way)."""
    server_port = dst_port if dst_port in port_sni_map else src_port
    sni = tshark_sni_by_port.get(server_port) or port_sni_map.get(server_port, "unknown.internal.test")
    source = "tshark" if server_port in tshark_sni_by_port else "port_map"
    return FlowMetadata(sni=sni, alpn=default_alpn, source=source)


def build_port_sni_map(raw: dict) -> dict[int, str]:
    return {int(k): str(v) for k, v in raw.items()}
