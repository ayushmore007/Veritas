"""Record lab QUIC traffic to PCAP during testbed runs."""

from __future__ import annotations

import logging
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

logger = logging.getLogger(__name__)

# Common Windows loopback interface names (Npcap)
_LOOPBACK_IFACES = [
    "Adapter for loopback traffic capture",
    "\\Device\\NPF_Loopback",
    "Loopback Pseudo-Interface 1",
]


class PcapRecorder:
    """Record testbed UDP/QUIC traffic to PCAP (tshark preferred on Windows)."""

    def __init__(self, output_path: Path, ports: list[int], interface: str | None = None) -> None:
        self.output_path = output_path
        self.ports = ports
        self.interface = interface
        self._packets: list = []
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._tshark_proc: subprocess.Popen | None = None
        self._backend = "none"

    @property
    def bpf_filter(self) -> str:
        port_expr = " or ".join(f"port {p}" for p in self.ports)
        return f"udp and ({port_expr})"

    def start(self) -> None:
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        if shutil.which("tshark"):
            if self._start_tshark():
                return
        self._start_scapy()

    def _start_tshark(self) -> bool:
        iface = self.interface
        if not iface:
            # Npcap loopback names only exist on Windows; Linux/WSL/macOS loopback is lo / lo0.
            if sys.platform.startswith("win"):
                iface = _LOOPBACK_IFACES[0]
            elif sys.platform == "darwin":
                iface = "lo0"
            else:
                iface = "lo"
        cmd = [
            "tshark",
            "-i",
            iface,
            "-f",
            self.bpf_filter,
            "-w",
            str(self.output_path),
        ]
        try:
            self._tshark_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
        except OSError:
            self._tshark_proc = None
            return False

        # tshark exits almost immediately on a bad interface or missing capture permission;
        # Popen succeeding does not mean capture started.
        time.sleep(0.5)
        if self._tshark_proc.poll() is not None:
            err = (self._tshark_proc.stderr.read() if self._tshark_proc.stderr else b"") or b""
            logger.warning(
                "tshark exited on %s (%s); falling back to scapy",
                iface,
                err.decode(errors="replace").strip()[:300],
            )
            self._tshark_proc = None
            return False

        self._backend = "tshark"
        logger.info("Recording PCAP via tshark (%s) -> %s", iface, self.output_path)
        return True

    def _start_scapy(self) -> None:
        from scapy.all import conf, sniff

        self._stop.clear()
        # The testbed talks over 127.0.0.1. Without an explicit iface scapy sniffs the
        # default-route interface and records nothing.
        iface = self.interface or conf.loopback_name

        def _run() -> None:
            try:
                sniff(
                    iface=iface,
                    filter=self.bpf_filter,
                    prn=self._packets.append,
                    store=False,
                    stop_filter=lambda _: self._stop.is_set(),
                )
            except Exception:
                logger.exception("scapy sniff failed — try tshark or manual capture")

        self._thread = threading.Thread(target=_run, name="pcap-recorder", daemon=True)
        self._thread.start()
        self._backend = "scapy"
        logger.info("Recording PCAP via scapy on %s filter=%s", iface, self.bpf_filter)

    def stop(self) -> int:
        if self._backend == "tshark" and self._tshark_proc is not None:
            self._tshark_proc.terminate()
            try:
                self._tshark_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._tshark_proc.kill()
            if self.output_path.is_file():
                size = self.output_path.stat().st_size
                logger.info("tshark wrote %s (%d bytes)", self.output_path, size)
                return max(1, size // 500)  # rough packet estimate for display
            return 0

        if self._backend == "scapy":
            from scapy.all import wrpcap

            self._stop.set()
            if self._thread is not None:
                self._thread.join(timeout=8.0)
            count = len(self._packets)
            if count:
                wrpcap(str(self.output_path), self._packets)
                logger.info("Wrote %d packets to %s", count, self.output_path)
            else:
                logger.warning("No packets captured")
            return count

        return 0
