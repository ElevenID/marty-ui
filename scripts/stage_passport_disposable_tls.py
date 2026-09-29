"""Issue short-lived, project-only TLS identities for disposable passport runs."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess


TLS_FILES = frozenset({
    "workload_identity_ca_cert",
    "passport_edge_tls_cert", "passport_edge_tls_key",
    "flow_workload_client_cert", "flow_workload_client_key",
    "flow_workload_server_cert", "flow_workload_server_key",
    "pp_workload_server_cert", "pp_workload_server_key",
})


class DisposableTlsError(ValueError):
    pass


def _openssl(root: Path, *args: str) -> None:
    try:
        result = subprocess.run(
            ["openssl", *args], cwd=root, capture_output=True, check=False,
            timeout=30, env={**os.environ, "OPENSSL_CONF": str(root / ".passport-openssl.cnf")},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise DisposableTlsError("Disposable TLS issuer is unavailable") from exc
    if result.returncode != 0:
        raise DisposableTlsError("Disposable TLS certificate creation failed")


def stage_tls(root: Path) -> None:
    """Create a private CA, then leave only short-lived service certs behind."""
    if not root.is_absolute() or not root.is_dir() or root.is_symlink():
        raise DisposableTlsError("Disposable TLS root is invalid")
    temporary = {".passport-ca-key", ".passport-openssl.cnf"}
    ca = "workload_identity_ca_cert"
    identities = (
        ("passport_edge_tls", "passport-https-edge", "serverAuth",
         "DNS:edge,DNS:passport-https-edge,DNS:localhost,IP:127.0.0.1"),
        ("flow_workload_client", "flow", "clientAuth",
         "URI:spiffe://marty.internal/service/flow"),
        ("flow_workload_server", "flow", "serverAuth", "DNS:flow"),
        ("pp_workload_server", "presentation-policy", "serverAuth",
         "DNS:presentation-policy"),
    )
    temporary.add(ca + ".srl")
    temporary.update({f".{prefix}.{suffix}" for prefix, *_ in identities
                      for suffix in ("csr", "ext")})
    if any((root / name).exists() or (root / name).is_symlink()
           for name in TLS_FILES | temporary):
        raise DisposableTlsError("Disposable TLS root contains an existing identity")
    try:
        (root / ".passport-openssl.cnf").write_text(
            "[req]\ndistinguished_name=req_distinguished_name\n"
            "[req_distinguished_name]\n", encoding="ascii",
        )
        _openssl(root, "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-sha256",
                 "-days", "2", "-subj", "/CN=Marty Disposable Passport CA",
                 "-addext", "basicConstraints=critical,CA:TRUE",
                 "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                 "-keyout", ".passport-ca-key", "-out", ca)
        for prefix, common_name, purpose, san in identities:
            csr = f".{prefix}.csr"
            ext = f".{prefix}.ext"
            temporary.update((csr, ext))
            (root / ext).write_text(
                "basicConstraints=critical,CA:FALSE\n"
                "keyUsage=critical,digitalSignature,keyEncipherment\n"
                f"extendedKeyUsage={purpose}\nsubjectAltName={san}\n",
                encoding="ascii",
            )
            _openssl(root, "req", "-new", "-newkey", "rsa:2048", "-nodes",
                     "-sha256", "-subj", f"/CN={common_name}",
                     "-keyout", f"{prefix}_key", "-out", csr)
            _openssl(root, "x509", "-req", "-in", csr, "-CA", ca,
                     "-CAkey", ".passport-ca-key", "-CAcreateserial", "-days", "2",
                     "-sha256", "-extfile", ext, "-out", f"{prefix}_cert")
        if {path.name for path in root.iterdir()} & TLS_FILES != TLS_FILES:
            raise DisposableTlsError("Disposable TLS certificate set is incomplete")
        if os.name == "posix":
            for name in TLS_FILES:
                os.chmod(root / name, 0o644)
    except BaseException:
        for name in TLS_FILES:
            (root / name).unlink(missing_ok=True)
        raise
    finally:
        for name in temporary:
            (root / name).unlink(missing_ok=True)
