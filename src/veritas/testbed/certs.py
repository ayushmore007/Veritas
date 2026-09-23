"""Self-signed TLS material for the isolated lab testbed."""

from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def ensure_testbed_certs(
    cert_dir: Path,
    sni_names: list[str],
    *,
    force: bool = False,
) -> tuple[Path, Path]:
    """Create or reuse lab CA + server certificate covering all SNI names."""
    cert_dir.mkdir(parents=True, exist_ok=True)
    cert_path = cert_dir / "server.crt"
    key_path = cert_dir / "server.key"
    ca_cert_path = cert_dir / "ca.crt"

    if cert_path.is_file() and key_path.is_file() and ca_cert_path.is_file() and not force:
        return cert_path, key_path

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Veritas Lab"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Veritas Testbed CA"),
        ]
    )
    now = datetime.now(timezone.utc)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )

    san_entries: list[x509.GeneralName] = [x509.DNSName(n) for n in sni_names]
    san_entries.extend(
        [
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            x509.IPAddress(ipaddress.IPv4Address("172.28.0.10")),
            x509.IPAddress(ipaddress.IPv4Address("172.28.0.20")),
            x509.IPAddress(ipaddress.IPv4Address("172.28.0.21")),
        ]
    )

    server_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Veritas Lab"),
            x509.NameAttribute(NameOID.COMMON_NAME, sni_names[0]),
        ]
    )
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=825))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .sign(key, hashes.SHA256())
    )

    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
    ca_cert_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path
