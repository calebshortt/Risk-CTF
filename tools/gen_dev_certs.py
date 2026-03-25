#!/usr/bin/env python3
"""Generate self-signed TLS certificate and key for local Risk-CTF Mothership (development only).

Requires: pip install -e ".[dev]" (cryptography).
"""
from __future__ import annotations

import argparse
import ipaddress
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate dev cert.pem and key.pem for Mothership")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path.cwd(),
        help="Directory to write cert.pem and key.pem (default: current directory)",
    )
    args = parser.parse_args()
    out = args.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    cert_path = out / "cert.pem"
    key_path = out / "key.pem"

    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
        from cryptography.x509.oid import NameOID
    except ImportError:
        print(
            "cryptography is not installed. Install dev extras: pip install -e \".[dev]\"",
            file=sys.stderr,
        )
        return 1

    key = rsa.generate_private_key(65537, 2048, default_backend())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    san = x509.SubjectAlternativeName(
        [
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(san, False)
        .sign(key, hashes.SHA256(), default_backend())
    )

    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print(f"Wrote {cert_path}")
    print(f"Wrote {key_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
