"""
Veritas Real-Time Server Security Scanner & Digital Twin Generator
Performs live DNS, TLS/SSL, QUIC/HTTP3, Header Audits, Sensitive Path Fuzzing,
Information Leakage, and Veritas Metadata Grounding tests on any URL/host.
Writes measured results directly to the Veritas Digital Twin database.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import math
import re
import socket
import ssl
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parent.parent
# Kept apart from the research twin (data/processed/twin/twin.db) — see _ingest_to_twin_db.
LIVE_SCAN_DB_PATH = ROOT / "data" / "processed" / "twin" / "live_scans.db"

logger = logging.getLogger("veritas.scanner")


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy in bits per byte."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts: dict[int, int] = {}
    for byte in data:
        counts[byte] = counts.get(byte, 0) + 1
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


class TrafficMeter:
    """
    Counts what the scanner actually put on and took off the wire at the HTTP layer.

    Attached to every scanner httpx client via event hooks, so the dashboard's "twin features"
    are measurements of this scan rather than placeholders. Byte counts cover the request line,
    headers and body (and the response headers and body); TLS and TCP overhead are not visible
    from here and are not estimated.
    """

    def __init__(self) -> None:
        self.requests = 0
        self.responses = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        self.request_times: list[float] = []
        self.first_request: float | None = None
        self.last_response: float | None = None

    @staticmethod
    def _header_bytes(headers: httpx.Headers) -> int:
        return sum(len(k) + len(v) + 4 for k, v in headers.raw)  # "k: v\r\n"

    async def on_request(self, request: httpx.Request) -> None:
        now = time.perf_counter()
        self.requests += 1
        self.request_times.append(now)
        if self.first_request is None:
            self.first_request = now
        try:
            body = len(request.content)
        except httpx.RequestNotRead:
            body = 0
        line = len(request.method) + len(request.url.raw_path) + len(" HTTP/1.1\r\n") + 1
        self.bytes_sent += line + self._header_bytes(request.headers) + 2 + body

    async def on_response(self, response: httpx.Response) -> None:
        await response.aread()
        self.responses += 1
        self.last_response = time.perf_counter()
        self.bytes_received += self._header_bytes(response.headers) + 2 + len(response.content)

    @property
    def hooks(self) -> dict[str, list]:
        return {"request": [self.on_request], "response": [self.on_response]}

    def features(self) -> dict[str, Any]:
        if self.first_request is None:
            return {"http_requests": 0, "http_responses": 0}
        end = self.last_response or self.first_request
        times = sorted(self.request_times)
        gaps = [b - a for a, b in zip(times, times[1:], strict=False)]
        return {
            "flow_duration": round(end - self.first_request, 4),
            "http_requests": self.requests,
            "http_responses": self.responses,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "down_up_ratio": round(self.bytes_received / self.bytes_sent, 2) if self.bytes_sent else None,
            "flow_iat_mean": round(sum(gaps) / len(gaps), 4) if gaps else None,
            "flow_iat_max": round(max(gaps), 4) if gaps else None,
        }


@dataclass
class SecurityTestResult:
    id: str
    name: str
    category: str
    status: str  # passed, failed, warning, info, defended
    score_impact: int
    metric: str
    observed_value: str
    baseline: str
    description: str
    technical_details: str
    remediation: str
    auto_fixable: bool
    permission_required: bool
    remediation_type: str  # veritas_engine, firewall_rule, web_server_config, dns_record


@dataclass
class ScanReport:
    target_input: str
    hostname: str
    ip_addresses: list[str]
    port: int
    protocol: str
    scan_timestamp: str
    scan_duration_ms: float
    security_score: int
    posture_verdict: str
    posture_class: str
    tests: list[SecurityTestResult] = field(default_factory=list)
    twin_features: dict[str, Any] = field(default_factory=dict)
    metadata_untrusted: dict[str, Any] = field(default_factory=dict)
    open_ports: list[int] = field(default_factory=list)
    vulnerabilities_count: dict[str, int] = field(default_factory=lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0, "passed": 0})
    recommended_preventions: list[dict[str, Any]] = field(default_factory=list)
    applied_preventions: list[str] = field(default_factory=list)


class LiveSecurityScanner:
    """Conducts comprehensive real-world security audits and creates digital twins."""

    COMMON_PORTS = [80, 443, 8080, 8443, 22, 21, 25, 3306, 5432, 6379, 27017]
    RECON_PATHS = [
        "/.env",
        "/.git/HEAD",
        "/robots.txt",
        "/.well-known/security.txt",
        "/admin",
        "/api",
        "/swagger.json",
        "/config.json",
        "/server-status",
        "/.dockerenv",
    ]

    def __init__(self, timeout: float = 4.0):
        self.timeout = timeout

    async def scan_target(self, target: str) -> ScanReport:
        t0 = time.perf_counter()
        parsed = await self._normalize_target(target)
        hostname = parsed["hostname"]
        port = parsed["port"]
        use_https = parsed["use_https"]

        tests: list[SecurityTestResult] = []
        open_ports: list[int] = []
        ip_addresses: list[str] = []
        twin_features: dict[str, Any] = {}
        metadata_untrusted: dict[str, Any] = {}

        # 1. DNS & Network Resolution
        dns_res = await self._test_dns(hostname)
        tests.append(dns_res["test"])
        ip_addresses = dns_res["ips"]
        primary_ip = ip_addresses[0] if ip_addresses else None

        # 2. Port & Transport Probing. Never fall back to scanning this machine when the target
        # does not resolve — that would report our own open ports as the target's.
        if primary_ip is not None:
            port_res = await self._test_ports(primary_ip, port)
            tests.append(port_res["test"])
            open_ports = port_res["open_ports"]

        # Pick the scheme/port only when the user did not name one.
        if not parsed["explicit_port"]:
            if 443 in open_ports:
                use_https = True
                port = 443
            elif 80 in open_ports:
                use_https = False
                port = 80

        # 3. SSL/TLS Certificate & Cipher Suite Audit
        tls_info = {}
        if use_https or 443 in open_ports:
            tls_res = await self._test_tls(hostname, port if port != 80 else 443)
            tests.extend(tls_res["tests"])
            tls_info = tls_res["info"]
        else:
            # Insecure Plaintext HTTP Detected
            tests.append(
                SecurityTestResult(
                    id="TEST-TLS-VER",
                    name="TLS Transport & Encryption",
                    category="Cryptographic Security",
                    status="failed",
                    score_impact=25,
                    metric="Transport Encryption",
                    observed_value="CLEARTEXT HTTP (Zero TLS / SSL Encryption)",
                    baseline="TLS 1.2 or TLS 1.3 Mandatory",
                    description="The server serves unencrypted cleartext HTTP. Passwords, session tokens, and traffic are vulnerable to eavesdropping and MITM tampering.",
                    technical_details=f"Port 443 unreachable on {hostname}; only unencrypted port {port} active.",
                    remediation="Install an SSL/TLS certificate (e.g. via Let's Encrypt / Certbot) and enforce HTTPS redirection.",
                    auto_fixable=True,
                    permission_required=True,
                    remediation_type="web_server_config",
                )
            )

        # 4. HTTP Headers, Security Directives & Server Leakage
        meter = TrafficMeter()
        http_res = await self._test_http_security(hostname, port, use_https, meter)
        tests.extend(http_res["tests"])
        raw_headers = http_res.get("headers", {})
        metadata_untrusted.update(http_res.get("untrusted_metadata", {}))

        # 5. Sensitive Path Fuzzing & Reconnaissance
        path_res = await self._test_sensitive_paths(hostname, port, use_https, meter)
        tests.append(path_res["test"])

        # 6. HTTP/3 & QUIC Protocol Support
        quic_res = await self._test_quic_support(hostname, port, raw_headers)
        tests.append(quic_res["test"])

        # 7. Metadata Prompt Injection & Grounding Resilience (Veritas Core)
        injection_res = await self._test_metadata_injection_resilience(hostname, raw_headers)
        tests.append(injection_res["test"])

        # 8. Compute Twin Features
        elapsed_total = (time.perf_counter() - t0)
        # Every value here was measured during this scan; nothing is estimated or defaulted.
        twin_features = {
            **meter.features(),
            "entropy": http_res.get("entropy"),
            "open_port_count": len(open_ports),
        }
        # Server-chosen strings belong in the untrusted channel, never with the measurements.
        metadata_untrusted["sni"] = hostname
        if tls_info:
            metadata_untrusted["tls_version"] = tls_info.get("version")
            metadata_untrusted["cipher"] = tls_info.get("cipher")

        # Calculate Score
        vuln_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "passed": 0}
        score = 100
        for t in tests:
            if t.status == "passed":
                vuln_counts["passed"] += 1
            elif t.status == "failed":
                if t.score_impact >= 20:
                    vuln_counts["critical"] += 1
                elif t.score_impact >= 10:
                    vuln_counts["high"] += 1
                else:
                    vuln_counts["medium"] += 1
                score -= t.score_impact
            elif t.status == "warning":
                vuln_counts["low"] += 1
                score -= max(3, t.score_impact // 2)

        score = max(5, min(100, score))

        if score >= 85:
            posture = "HARDENED DEFENSE"
            posture_class = "health-hardened"
        elif score >= 60:
            posture = "MODERATE PROTECTION"
            posture_class = "health-warning"
        else:
            posture = "CRITICAL RISK"
            posture_class = "health-vulnerable"

        # Generate Recommended Preventions
        preventions = self._generate_preventions(
            tests, hostname, primary_ip or hostname, port, use_https
        )

        report = ScanReport(
            target_input=target,
            hostname=hostname,
            ip_addresses=ip_addresses,
            port=port,
            protocol="QUIC/HTTP-3" if quic_res.get("supported") else ("HTTPS" if use_https else "HTTP"),
            scan_timestamp=datetime.now(timezone.utc).isoformat(),
            scan_duration_ms=round(elapsed_total * 1000, 2),
            security_score=score,
            posture_verdict=posture,
            posture_class=posture_class,
            tests=tests,
            twin_features=twin_features,
            metadata_untrusted=metadata_untrusted,
            open_ports=open_ports,
            vulnerabilities_count=vuln_counts,
            recommended_preventions=preventions,
            # Filled in by the server from what is actually active; a score is not a deployment.
            applied_preventions=[],
        )

        # Ingest into Twin Database
        self._ingest_to_twin_db(report)

        return report

    async def _normalize_target(self, target: str) -> dict[str, Any]:
        """
        Parse `host`, `host:port`, `host/path`, `[v6]:port` or a full URL.

        `explicit_port` records whether the user named a port or scheme; only when they did not
        may the scanner pick one for them.
        """
        target = target.strip()
        if not target:
            raise ValueError("empty scan target")

        has_scheme = target.startswith(("http://", "https://"))
        parsed = urllib.parse.urlparse(target if has_scheme else f"//{target}")
        hostname = parsed.hostname
        if not hostname:
            raise ValueError(f"could not parse a hostname from {target!r}")
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError(f"invalid port in {target!r}") from exc

        if has_scheme:
            use_https = parsed.scheme == "https"
            return {
                "hostname": hostname,
                "port": port or (443 if use_https else 80),
                "use_https": use_https,
                "explicit_port": True,
            }
        if port is not None:
            return {"hostname": hostname, "port": port, "use_https": port == 443, "explicit_port": True}

        # Test if port 443 is open before picking scheme
        if await self._is_port_open(hostname, 443, timeout=0.6):
            return {"hostname": hostname, "port": 443, "use_https": True, "explicit_port": False}
        return {"hostname": hostname, "port": 80, "use_https": False, "explicit_port": False}

    async def _is_port_open(self, host: str, port: int, timeout: float = 0.6) -> bool:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

    async def _test_dns(self, hostname: str) -> dict[str, Any]:
        ips = []
        try:
            loop = asyncio.get_running_loop()
            addrinfo = await loop.getaddrinfo(hostname, None)
            for item in addrinfo:
                ip = item[4][0]
                if ip not in ips:
                    ips.append(ip)

            test = SecurityTestResult(
                id="TEST-DNS",
                name="DNS Resolution & Topology Mapping",
                category="Network Topology",
                status="passed",
                score_impact=0,
                metric="Host Resolution",
                observed_value=f"{len(ips)} IP(s) [{', '.join(ips[:3])}]",
                baseline="Valid A/AAAA Records",
                description="Resolves target hostname to authoritative network addresses.",
                technical_details=f"Resolved addresses: {ips}",
                remediation="Ensure authoritative nameservers use DNSSEC to prevent spoofing.",
                auto_fixable=False,
                permission_required=False,
                remediation_type="dns_record",
            )
        except Exception as exc:
            test = SecurityTestResult(
                id="TEST-DNS",
                name="DNS Resolution & Topology Mapping",
                category="Network Topology",
                status="failed",
                score_impact=25,
                metric="Host Resolution",
                observed_value=f"Resolution Failed: {exc}",
                baseline="Valid A/AAAA Records",
                description="Failed to resolve target hostname.",
                technical_details=str(exc),
                remediation="Check DNS configuration and domain registrar status.",
                auto_fixable=False,
                permission_required=False,
                remediation_type="dns_record",
            )
        return {"test": test, "ips": ips}

    async def _test_ports(self, ip: str, primary_port: int) -> dict[str, Any]:
        open_ports = []
        ports_to_check = list(set([primary_port] + self.COMMON_PORTS))

        async def check_port(p: int) -> int | None:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, p), timeout=0.5
                )
                writer.close()
                await writer.wait_closed()
                return p
            except Exception:
                return None

        tasks = [check_port(p) for p in ports_to_check]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, int):
                open_ports.append(r)

        open_ports.sort()
        has_risky_ports = any(p in [21, 22, 25, 3306, 5432, 6379, 27017] for p in open_ports)

        if has_risky_ports:
            status = "warning"
            score_impact = 10
            observed = f"Open ports: {open_ports} (Internal databases/SSH exposed)"
            remediation = "Close internal ports (3306/5432/6379/27017) to public internet using firewall rules."
        else:
            status = "passed"
            score_impact = 0
            observed = f"Open ports: {open_ports}"
            remediation = "Standard web port posture maintained."

        test = SecurityTestResult(
            id="TEST-PORT",
            name="Network Port Exposure & Service Surface",
            category="Perimeter Security",
            status=status,
            score_impact=score_impact,
            metric="Exposed Ports",
            observed_value=observed,
            baseline="Only 80/443 exposed publicly",
            description="Scans common network service ports to detect accidental exposure of internal databases or management interfaces.",
            technical_details=f"Ports scanned: {ports_to_check}. Accessible: {open_ports}",
            remediation=remediation,
            auto_fixable=True,
            permission_required=True,
            remediation_type="firewall_rule",
        )
        return {"test": test, "open_ports": open_ports}

    async def _test_tls(self, hostname: str, port: int) -> dict[str, Any]:
        tests = []
        info = {}
        try:
            loop = asyncio.get_running_loop()
            ctx = ssl.create_default_context()

            def get_ssl_info():
                with socket.create_connection((hostname, port), timeout=2.5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        cipher = ssock.cipher()
                        version = ssock.version()
                        return {"cert": cert, "cipher": cipher, "version": version}

            res = await loop.run_in_executor(None, get_ssl_info)
            cert = res["cert"]
            cipher = res["cipher"]
            version = res["version"]
            info = {"version": version, "cipher": cipher[0] if cipher else "Unknown"}

            # TLS Version Check
            is_modern_tls = version in ("TLSv1.3", "TLSv1.2")
            tests.append(
                SecurityTestResult(
                    id="TEST-TLS-VER",
                    name="TLS Protocol Handshake & Version",
                    category="Cryptographic Security",
                    status="passed" if is_modern_tls else "failed",
                    score_impact=0 if is_modern_tls else 20,
                    metric="Negotiated Protocol",
                    observed_value=f"{version} ({cipher[0] if cipher else 'N/A'})",
                    baseline="TLS 1.2 or TLS 1.3 mandatory",
                    description="Verifies the cryptographic protocol version negotiated during client handshake.",
                    technical_details=f"Cipher: {cipher}, Version: {version}",
                    remediation="Disable legacy SSLv3/TLS 1.0/TLS 1.1 in web server SSL configuration.",
                    auto_fixable=True,
                    permission_required=True,
                    remediation_type="web_server_config",
                )
            )

            # Certificate Validity Check
            not_after = cert.get("notAfter", "")
            if not_after:
                expiry_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (expiry_dt - datetime.now(timezone.utc)).days
                cert_status = "passed" if days_left > 15 else ("warning" if days_left > 0 else "failed")
                cert_impact = 0 if days_left > 15 else (5 if days_left > 0 else 25)
                cert_obs = f"Valid ({days_left} days remaining, expires {not_after})"
            else:
                cert_status = "passed"
                cert_impact = 0
                cert_obs = "Certificate verified"

            tests.append(
                SecurityTestResult(
                    id="TEST-TLS-CERT",
                    name="X.509 Certificate Chain & Expiration",
                    category="Cryptographic Security",
                    status=cert_status,
                    score_impact=cert_impact,
                    metric="Cert Validity Period",
                    observed_value=cert_obs,
                    baseline="Active Certificate (> 15 days validity)",
                    description="Checks certificate expiration, subject alternative names (SAN), and authority trust.",
                    technical_details=f"Subject: {cert.get('subject')}, Issuer: {cert.get('issuer')}",
                    remediation="Renew TLS certificate via Let's Encrypt / Certbot automated pipeline.",
                    auto_fixable=False,
                    permission_required=False,
                    remediation_type="web_server_config",
                )
            )

        except Exception as exc:
            tests.append(
                SecurityTestResult(
                    id="TEST-TLS-VER",
                    name="TLS Protocol Handshake & Version",
                    category="Cryptographic Security",
                    status="warning",
                    score_impact=10,
                    metric="Negotiated Protocol",
                    observed_value=f"Handshake failed or self-signed: {exc}",
                    baseline="Valid TLS 1.3 / TLS 1.2",
                    description="Could not complete standard TLS handshake.",
                    technical_details=str(exc),
                    remediation="Install a valid SSL/TLS certificate issued by a trusted Certificate Authority.",
                    auto_fixable=False,
                    permission_required=False,
                    remediation_type="web_server_config",
                )
            )

        return {"tests": tests, "info": info}

    async def _test_http_security(
        self, hostname: str, port: int, use_https: bool, meter: TrafficMeter | None = None
    ) -> dict[str, Any]:
        tests = []
        headers_dict = {}
        untrusted_meta = {}
        entropy: float | None = None

        url = f"{'https' if use_https else 'http'}://{hostname}:{port}" if (port != 443 and port != 80) else f"{'https' if use_https else 'http'}://{hostname}"

        try:
            async with httpx.AsyncClient(
                timeout=2.5,
                follow_redirects=True,
                verify=False,
                event_hooks=meter.hooks if meter else None,
            ) as client:
                resp = await client.get(url)

                headers_dict = dict(resp.headers)
                body_bytes = resp.content
                entropy = calculate_entropy(body_bytes[:2048])

                untrusted_meta = {
                    "server_banner": headers_dict.get("server", "Hidden / Not Disclosed"),
                    "x_powered_by": headers_dict.get("x-powered-by", "Not Present"),
                    "content_type": headers_dict.get("content-type", "text/html"),
                    "http_status": str(resp.status_code),
                }

                # 1. HSTS Check
                hsts = headers_dict.get("strict-transport-security")
                if hsts:
                    hsts_status = "passed"
                    hsts_impact = 0
                    hsts_obs = f"Present: {hsts}"
                else:
                    hsts_status = "failed"
                    hsts_impact = 15
                    hsts_obs = "Missing Strict-Transport-Security (HSTS) header"

                tests.append(
                    SecurityTestResult(
                        id="TEST-HSTS",
                        name="HTTP Strict Transport Security (HSTS)",
                        category="HTTP Security Headers",
                        status=hsts_status,
                        score_impact=hsts_impact,
                        metric="HSTS Header",
                        observed_value=hsts_obs,
                        baseline="Strict-Transport-Security: max-age=31536000; includeSubDomains",
                        description="Forces browsers to communicate only over secure HTTPS, preventing SSL-stripping MITM attacks.",
                        technical_details=f"HSTS Header value: {hsts}",
                        remediation="Add header: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`.",
                        auto_fixable=True,
                        permission_required=True,
                        remediation_type="web_server_config",
                    )
                )

                # 2. Content Security Policy (CSP)
                csp = headers_dict.get("content-security-policy")
                if csp:
                    csp_status = "passed"
                    csp_impact = 0
                    csp_obs = f"Active ({len(csp)} chars)"
                else:
                    csp_status = "failed"
                    csp_impact = 15
                    csp_obs = "Missing Content-Security-Policy"

                tests.append(
                    SecurityTestResult(
                        id="TEST-CSP",
                        name="Content Security Policy (CSP)",
                        category="HTTP Security Headers",
                        status=csp_status,
                        score_impact=csp_impact,
                        metric="CSP Header",
                        observed_value=csp_obs,
                        baseline="Content-Security-Policy with strict script-src and default-src",
                        description="Mitigates Cross-Site Scripting (XSS), data injection, and clickjacking attacks.",
                        technical_details=f"CSP Header: {csp or 'None'}",
                        remediation="Define a strong Content-Security-Policy restricting script-src, object-src, and frame-ancestors.",
                        auto_fixable=True,
                        permission_required=True,
                        remediation_type="web_server_config",
                    )
                )

                # 3. Clickjacking / X-Frame-Options
                xfo = headers_dict.get("x-frame-options")
                if xfo and xfo.upper() in ("DENY", "SAMEORIGIN"):
                    xfo_status = "passed"
                    xfo_impact = 0
                    xfo_obs = f"Protected: {xfo}"
                else:
                    xfo_status = "failed"
                    xfo_impact = 10
                    xfo_obs = f"Missing or Weak ({xfo or 'None'})"

                tests.append(
                    SecurityTestResult(
                        id="TEST-XFO",
                        name="Clickjacking Defense (X-Frame-Options)",
                        category="HTTP Security Headers",
                        status=xfo_status,
                        score_impact=xfo_impact,
                        metric="Frame Options",
                        observed_value=xfo_obs,
                        baseline="X-Frame-Options: SAMEORIGIN or DENY",
                        description="Prevents malicious sites from embedding target website inside an invisible <iframe> to hijack user clicks.",
                        technical_details=f"X-Frame-Options: {xfo}",
                        remediation="Add header: `X-Frame-Options: SAMEORIGIN` or use CSP `frame-ancestors 'self'`.",
                        auto_fixable=True,
                        permission_required=True,
                        remediation_type="web_server_config",
                    )
                )

                # 4. MIME-Sniffing Defense
                xcto = headers_dict.get("x-content-type-options")
                is_xcto_valid = xcto and "nosniff" in xcto.lower()
                tests.append(
                    SecurityTestResult(
                        id="TEST-XCTO",
                        name="MIME-Type Sniffing Protection",
                        category="HTTP Security Headers",
                        status="passed" if is_xcto_valid else "warning",
                        score_impact=0 if is_xcto_valid else 5,
                        metric="Content Type Options",
                        observed_value="Protected (nosniff)" if is_xcto_valid else "Missing nosniff directive",
                        baseline="X-Content-Type-Options: nosniff",
                        description="Forces browsers to adhere to declared Content-Type, preventing drive-by executable execution.",
                        technical_details=f"Header value: {xcto}",
                        remediation="Add header: `X-Content-Type-Options: nosniff`.",
                        auto_fixable=True,
                        permission_required=True,
                        remediation_type="web_server_config",
                    )
                )

                # 5. Server Information Leakage
                srv_banner = headers_dict.get("server", "")
                powered_by = headers_dict.get("x-powered-by", "")
                has_leak = bool(re.search(r"\d+\.\d+", srv_banner)) or bool(powered_by)

                tests.append(
                    SecurityTestResult(
                        id="TEST-INFO-LEAK",
                        name="Server Technology & Version Disclosure",
                        category="Information Disclosure",
                        status="warning" if has_leak else "passed",
                        score_impact=8 if has_leak else 0,
                        metric="Version Leakage",
                        observed_value=f"Server: {srv_banner or 'Masked'} | Powered-By: {powered_by or 'None'}",
                        baseline="Server tokens and version numbers suppressed",
                        description="Checks if web server leaks specific software versions (e.g. Apache/2.4.41, PHP/5.6) that aid attacker reconnaissance.",
                        technical_details=f"Server: '{srv_banner}', X-Powered-By: '{powered_by}'",
                        remediation="Set `server_tokens off;` in NGINX or `ServerSignature Off` in Apache.",
                        auto_fixable=True,
                        permission_required=True,
                        remediation_type="web_server_config",
                    )
                )

        except Exception as exc:
            tests.append(
                SecurityTestResult(
                    id="TEST-HTTP",
                    name="HTTP Web Endpoint Connectivity",
                    category="Perimeter Security",
                    status="warning",
                    score_impact=10,
                    metric="HTTP Request",
                    observed_value=f"HTTP test warning: {exc}",
                    baseline="HTTP 200/301/302 Response",
                    description="Could not complete full HTTP header test.",
                    technical_details=str(exc),
                    remediation="Verify web server process is listening on target port.",
                    auto_fixable=False,
                    permission_required=False,
                    remediation_type="web_server_config",
                )
            )

        return {
            "tests": tests,
            "headers": headers_dict,
            "untrusted_metadata": untrusted_meta,
            "entropy": entropy,
        }

    async def _test_sensitive_paths(
        self, hostname: str, port: int, use_https: bool, meter: TrafficMeter | None = None
    ) -> dict[str, Any]:
        base_url = f"{'https' if use_https else 'http'}://{hostname}:{port}" if (port != 443 and port != 80) else f"{'https' if use_https else 'http'}://{hostname}"
        exposed_paths = []
        responded = 0

        try:
            async with httpx.AsyncClient(
                timeout=1.2, verify=False, event_hooks=meter.hooks if meter else None
            ) as client:
                async def check_path(path: str):
                    nonlocal responded
                    try:
                        resp = await client.get(f"{base_url}{path}", follow_redirects=False)
                        responded += 1
                        if resp.status_code in (200, 301, 302) and len(resp.content) > 0:
                            if "404" not in resp.text[:200].lower():
                                return path
                    except Exception:
                        pass
                    return None

                tasks = [check_path(p) for p in self.RECON_PATHS]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for r in results:
                    if isinstance(r, str):
                        exposed_paths.append(r)
        except Exception:
            pass

        has_critical_leaks = any(p in ["/.env", "/.git/HEAD", "/config.json"] for p in exposed_paths)
        if has_critical_leaks:
            status = "failed"
            impact = 25
            obs = f"CRITICAL LEAK DETECTED: {exposed_paths} publicly accessible!"
            remediation = "Instantly block web access to dotfiles (/.env, /.git) using web server access rules."
        elif responded == 0:
            # Nothing answered, so nothing was tested. That is not a pass.
            status = "info"
            impact = 0
            obs = f"Not tested: {base_url} did not respond to any of {len(self.RECON_PATHS)} probes"
            remediation = "Confirm the target is reachable, then re-run the scan."
        elif exposed_paths:
            status = "warning"
            impact = 8
            obs = f"Exposed reachable paths: {exposed_paths}"
            remediation = "Restrict access to sensitive admin or API discovery endpoints."
        else:
            status = "passed"
            impact = 0
            obs = (
                "Zero sensitive dotfiles or environment secrets exposed "
                f"(0/{len(self.RECON_PATHS)} probed)"
            )
            remediation = "Maintain strict directory traversal and hidden file access controls."

        test = SecurityTestResult(
            id="TEST-RECON-FUZZ",
            name="Sensitive File Exposure & Path Fuzzing",
            category="Penetration Testing",
            status=status,
            score_impact=impact,
            metric="Exposed Sensitive Paths",
            observed_value=obs,
            baseline="Zero sensitive configuration files accessible",
            description="Probes high-value targets including /.env, /.git repository indexes, and unauthenticated API endpoints.",
            technical_details=f"Tested paths: {self.RECON_PATHS}. Found exposed: {exposed_paths}",
            remediation=remediation,
            auto_fixable=True,
            permission_required=True,
            remediation_type="web_server_config",
        )
        return {"test": test, "exposed_paths": exposed_paths}

    async def _test_quic_support(self, hostname: str, port: int, headers: dict[str, str]) -> dict[str, Any]:
        alt_svc = headers.get("alt-svc", "")
        supports_h3 = "h3" in alt_svc or "h3-29" in alt_svc

        if supports_h3:
            status = "passed"
            obs = f"HTTP/3 & QUIC Enabled (`Alt-Svc: {alt_svc}`)"
        else:
            status = "info"
            obs = "Standard TCP Transport (No HTTP/3 Alt-Svc advertised)"

        test = SecurityTestResult(
            id="TEST-QUIC-H3",
            name="QUIC Protocol & HTTP/3 Transport Capability",
            category="Next-Gen Protocol",
            status=status,
            score_impact=0,
            metric="HTTP/3 Support",
            observed_value=obs,
            baseline="QUIC (RFC 9000) or HTTP/2",
            description="Checks if target endpoint supports next-generation encrypted QUIC/HTTP-3 protocol.",
            technical_details=f"Alt-Svc header: {alt_svc or 'None'}",
            remediation="Configure QUIC UDP listener in Caddy / NGINX / Cloudflare for 0-RTT encrypted transport.",
            auto_fixable=False,
            permission_required=False,
            remediation_type="web_server_config",
        )
        return {"test": test, "supported": supports_h3}

    async def _test_metadata_injection_resilience(self, hostname: str, headers: dict[str, str]) -> dict[str, Any]:
        """
        Does any server-controlled string carry instruction-like text?

        Uses the project's own patterns (Phase 8a sanitizer, Phase 4 simulacrum) over every value
        the server chooses: all response headers plus the host name. This detects *attempts* to
        address an AI triage agent; it cannot show that an agent would or would not obey them.
        """
        from veritas.agent.llm import _INJECTION_RE
        from veritas.defense.sanitizer import _IMPERATIVE, _INVALID_HOST

        candidates = {f"header:{k}": v for k, v in headers.items()}
        candidates["host"] = hostname
        hits = sorted(
            field
            for field, value in candidates.items()
            if _INJECTION_RE.search(str(value))
            or _IMPERATIVE.search(str(value))
            or (field == "host" and _INVALID_HOST.search(str(value)))
        )

        test = SecurityTestResult(
            id="TEST-VERITAS-GROUNDING",
            name="Metadata Prompt-Injection & AI Defender Grounding (Veritas)",
            category="AI Defense & Provenance",
            status="failed" if hits else "passed",
            score_impact=30 if hits else 0,
            metric="Instruction-like text in server-controlled metadata",
            observed_value=(
                f"Injection-style text found in: {', '.join(hits)}"
                if hits
                else f"None found in {len(candidates)} server-controlled fields"
            ),
            baseline="No instruction-like text in headers or host name",
            description="Screens every server-chosen string for text that addresses an AI triage agent (the Phase 7 attack surface). Detects attempts only; agent resilience is measured by the Phase 8 verifier, not by this scan.",
            technical_details=f"Fields screened: {sorted(candidates)}. Matches: {hits or 'none'}",
            remediation="Deploy Veritas Provenance-Grounding Verifier (Phase 8b) so decisions never rest on untrusted metadata.",
            auto_fixable=True,
            permission_required=False,
            remediation_type="veritas_engine",
        )
        return {"test": test, "fields_with_injection_text": hits}

    def _generate_preventions(self, tests: list[SecurityTestResult], hostname: str, ip: str, port: int, use_https: bool) -> list[dict[str, Any]]:
        preventions = []

        # 1. Veritas Provenance Verifier
        preventions.append({
            "key": "provenance_grounding_verifier",
            "title": "Deploy Veritas Provenance-Grounding Verifier",
            "category": "AI Defense Engine",
            "severity": "CRITICAL",
            "status": "ready_to_apply",
            "permission_required": False,
            "description": "Enforces strict provenance validation on all security triage decisions, anchoring verdicts solely on Digital Twin measured packet metrics.",
            "action_label": "Enable Veritas Grounding",
            "can_auto_execute": True,
            "remediation_type": "veritas_engine",
            "points_gain": 30,
        })

        # 2. Strict Security Headers Patch
        missing_headers = [t.name for t in tests if t.status in ("failed", "warning") and t.category == "HTTP Security Headers"]
        if missing_headers or not use_https:
            preventions.append({
                "key": "deploy_security_headers",
                "title": f"Deploy Hardened Security Headers ({len(missing_headers) or 4} Missing)",
                "category": "Web Server Hardening",
                "severity": "HIGH",
                "status": "permission_needed",
                "permission_required": True,
                "description": "Injects HSTS, CSP, X-Frame-Options, and X-Content-Type-Options into web server configuration.",
                "action_label": "Request Permission & Deploy Headers",
                "can_auto_execute": True,
                "remediation_type": "web_server_config",
                "points_gain": 25,
                "config_snippet": f"""# NGINX Configuration Patch for {hostname}
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none';" always;
server_tokens off;""",
            })

        # 3. Block Sensitive Dotfiles
        recon_test = next((t for t in tests if t.id == "TEST-RECON-FUZZ"), None)
        if recon_test and recon_test.status != "passed":
            preventions.append({
                "key": "block_dotfiles",
                "title": "Block Public Access to Sensitive Environment Files",
                "category": "Access Control",
                "severity": "CRITICAL",
                "status": "permission_needed",
                "permission_required": True,
                "description": "Installs web server block rules for /.env, /.git, and configuration directories.",
                "action_label": "Apply Dotfile Access Rules",
                "can_auto_execute": True,
                "remediation_type": "web_server_config",
                "points_gain": 20,
                "config_snippet": """# NGINX Dotfile Blocker
location ~ /\\.(env|git|svn|htaccess) {
    deny all;
    return 404;
}""",
            })

        # 4. Firewall & Rate Limiting Filter
        preventions.append({
            "key": "deploy_firewall_rules",
            "title": "Activate Adaptive QUIC & Service Firewall Rules",
            "category": "Perimeter Defense",
            "severity": "MEDIUM",
            "status": "permission_needed",
            "permission_required": True,
            "description": "Applies system iptables / Windows netsh rules to choke periodic heartbeat bursts and rate limit connection handshakes.",
            "action_label": "Deploy Firewall Drop Rules",
            "can_auto_execute": True,
            "remediation_type": "firewall_rule",
            "points_gain": 15,
            "config_snippet": f"""# IPTables Hardening for {ip}:{port}
iptables -A INPUT -p udp -d {ip} --dport {port} -m hashlimit --hashlimit-above 20/sec --hashlimit-burst 30 --hashlimit-mode srcip -j DROP
iptables -A INPUT -p tcp -d {ip} --dport {port} -m connlimit --connlimit-above 50 -j REJECT""",
        })

        return preventions

    def _ingest_to_twin_db(self, report: ScanReport) -> None:
        """
        Record the scan in the *live-scan* store, never in the research twin.

        The research twin (`twin.db`) is the ground-truth oracle for the agent, the split and the
        baselines; mixing in live scans would inject flows with invented labels into every
        experiment. Attacker-influenced strings (SNI, cipher and TLS version text) go in the
        untrusted side channel, keeping the measured oracle numeric.
        """
        try:
            from veritas.twin.store import TwinStore

            measured: dict[str, Any] = {}
            untrusted = dict(report.metadata_untrusted)
            for key, value in report.twin_features.items():
                if isinstance(value, (int, float)) and not isinstance(value, bool):
                    measured[key] = value
                else:
                    untrusted[key] = value

            store = TwinStore(LIVE_SCAN_DB_PATH)
            flow_id = hashlib.sha256(f"{report.hostname}:{report.scan_timestamp}".encode()).hexdigest()[:16]

            store.upsert_flow(
                flow_id=flow_id,
                capture_id=f"live_audit_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}",
                pcap_source="live_socket_instrumentation",
                src_ip="127.0.0.1",
                dst_ip=report.ip_addresses[0] if report.ip_addresses else report.hostname,
                src_port=0,
                dst_port=report.port,
                protocol=17 if "QUIC" in report.protocol else 6,
                measured_features=measured,
                # A live scan has no ground truth; the security score is not a traffic label.
                ground_truth={
                    "traffic_class": "unlabeled",
                    "scenario_id": "live_scan",
                    "attack_type": None,
                    "security_score": report.security_score,
                },
                metadata_untrusted=untrusted,
            )
            logger.info("Recorded live scan %s in %s", flow_id, LIVE_SCAN_DB_PATH)
        except Exception as exc:
            logger.warning("Could not record live scan: %s", exc)
