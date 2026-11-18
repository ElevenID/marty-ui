"""Test-only loopback TLS material, trusted only by the owned child process."""

import os
import subprocess


def create_loopback_certificate(root):
    cert, key = root / "ca.pem", root / "server.key"
    # A test-only self-signed leaf with an IP SAN; trusted solely by the child.
    subprocess.run(
        [
            "openssl",
            "req",
            # The fixture supplies every required subject and extension. Avoid
            # inheriting a missing or host-specific OpenSSL configuration file.
            "-config",
            os.devnull,
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=synthetic-loopback-test",
            "-addext",
            "subjectAltName=IP:127.0.0.1",
            "-addext",
            "basicConstraints=critical,CA:FALSE",
            "-keyout",
            str(key),
            "-out",
            str(cert),
        ],
        check=True,
        capture_output=True,
        timeout=30,
    )
    return cert, key
