"""The local TLS issuer must create a usable leaf without retaining its CA key."""

import hashlib
from pathlib import Path
import runpy
import subprocess


ROOT = Path(__file__).resolve().parents[1]
ISSUER = runpy.run_path(str(ROOT / "scripts/ensure-dev-integration-secret-tls.py"))


def test_development_secret_transport_identity_and_renewal(tmp_path):
    output = tmp_path / "tls"
    ensure_tls = ISSUER["ensure_tls"]
    valid = ISSUER["valid"]

    ensure_tls(output)
    assert valid(output)
    assert not (output / "ca.key").exists()
    certificate = (output / "tls.crt").read_bytes()
    details = subprocess.run(
        ["openssl", "x509", "-in", str(output / "tls.crt"), "-noout", "-text"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert "CA:FALSE" in details
    assert "DNS:signing-keys" in details
    assert "TLS Web Server Authentication" in details

    ensure_tls(output)
    assert (output / "tls.crt").read_bytes() == certificate

    (output / "tls.crt").write_text("invalid", encoding="ascii")
    ensure_tls(output)
    assert valid(output)
    assert hashlib.sha256((output / "tls.crt").read_bytes()).digest() != (
        hashlib.sha256(certificate).digest()
    )
    assert not (output / "ca.key").exists()


def test_loopback_probe_identity_is_ip_scoped(tmp_path):
    output = tmp_path / "loopback"
    ISSUER["ensure_tls"](output, "127.0.0.1")
    assert ISSUER["valid"](output, "127.0.0.1")
    assert not ISSUER["valid"](output, "signing-keys")
