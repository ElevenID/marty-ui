#!/usr/bin/env python3
"""Verify remote-only passport TLS provisioning and an edge handshake."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import ssl
import subprocess
import tempfile

from probe_passport_keyless_edge import run as probe_edge
from passport_remote_tls import TLS_PREFIXES


def probe(bootstrap: Path, edge: Path) -> None:
    result = subprocess.run([str(bootstrap)], check=False, capture_output=True,
                            timeout=90)
    if result.returncode:
        raise RuntimeError("remote passport TLS bootstrap failed: "
                           + result.stderr.decode("utf-8", errors="replace")[:500])
    output = Path(os.environ["PASSPORT_TLS_OUTPUT_DIR"])
    expected = {"workload_identity_ca_cert"} | {
        f"{prefix}_{suffix}" for prefix in TLS_PREFIXES for suffix in ("cert", "kms_token")
    }
    if {path.name for path in output.iterdir()} != expected:
        raise RuntimeError("remote passport TLS bootstrap output differs")
    certs = [output / "workload_identity_ca_cert"]
    certs.extend(output / f"{prefix}_cert" for prefix in TLS_PREFIXES)
    tokens = [output / f"{prefix}_kms_token" for prefix in TLS_PREFIXES]
    for cert in certs:
        pem = cert.read_text(encoding="ascii")
        if "PRIVATE KEY" in pem:
            raise RuntimeError("remote passport TLS bootstrap exported a private key")
        ssl.PEM_cert_to_DER_cert(pem)
    values = [token.read_text(encoding="ascii") for token in tokens]
    if len(set(values)) != len(values) or any(len(value) < 20 for value in values):
        raise RuntimeError("remote passport TLS tokens are missing or shared")

    with tempfile.TemporaryDirectory(prefix="marty-passport-wrong-ca-") as temporary:
        wrong_ca_environment = os.environ.copy()
        wrong_ca_environment["BAO_CACERT"] = str(output / "workload_identity_ca_cert")
        wrong_ca_environment["PASSPORT_TLS_OUTPUT_DIR"] = temporary
        wrong_ca = subprocess.run([str(bootstrap)], env=wrong_ca_environment,
                                  check=False, capture_output=True, timeout=30)
        if wrong_ca.returncode == 0 or any(Path(temporary).iterdir()):
            raise RuntimeError("remote passport TLS bootstrap accepted the wrong CA")

    environment = {
        "PASSPORT_EDGE_TLS_CERT_FILE": str(output / "passport_edge_tls_cert"),
        "PASSPORT_EDGE_TLS_KMS_CA_CERT_FILE": os.environ["BAO_CACERT"],
        "PASSPORT_EDGE_TLS_KMS_TOKEN_FILE": str(output / "passport_edge_tls_kms_token"),
        "PASSPORT_EDGE_TLS_KMS_KEY_NAME": os.environ["PASSPORT_ACCEPTANCE_PROJECT"]
        + "-passport-edge",
        "PASSPORT_EDGE_TLS_KMS_KEY_VERSION": "1",
        "PASSPORT_EDGE_TLS_KMS_ADDR": os.environ["BAO_ADDR"],
        "MARTY_TEST_PASSPORT_EDGE_CA": str(output / "workload_identity_ca_cert"),
    }
    os.environ.update(environment)
    probe_edge(edge)
    print("Remote passport TLS bootstrap and edge handshake passed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bootstrap", type=Path, required=True)
    parser.add_argument("--edge", type=Path, required=True)
    args = parser.parse_args()
    probe(args.bootstrap.resolve(), args.edge.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
