"""Accept only public certificates and scoped tokens from Rust passport TLS bootstrap."""

from __future__ import annotations

import os
from pathlib import Path
import ssl
import stat


TLS_PREFIXES = (
    "passport_edge_tls", "signing_keys_workload_server",
    "gateway_workload_client", "auth_workload_client", "auth_workload_server",
    "compliance_profile_workload_client",
    "deployment_profile_workload_client", "org_workload_server",
    "es_workload_server", "rp_workload_server",
    "ct_workload_server", "issuance_workload_server",
    "flow_workload_client", "flow_workload_server", "pp_workload_server",
)
PUBLIC_TLS_FILES = frozenset({"workload_identity_ca_cert"}) | frozenset(
    f"{prefix}_{suffix}" for prefix in TLS_PREFIXES for suffix in ("cert", "kms_token")
)


def accept_remote_tls(output: Path, secret_dir: Path, root_token: str) -> None:
    """Move a complete, verified keyless bootstrap set into private Compose secrets."""
    if (not output.is_absolute() or not secret_dir.is_absolute()
        or output.is_symlink() or secret_dir.is_symlink()
        or not output.is_dir() or not secret_dir.is_dir()):
        raise ValueError("Disposable TLS output or secret directory is invalid")
    if os.name == "posix" and stat.S_IMODE(output.stat().st_mode) != 0o700:
        raise ValueError("Disposable TLS output directory is not private")
    entries = {path.name: path for path in output.iterdir()}
    if set(entries) != PUBLIC_TLS_FILES:
        raise ValueError("Disposable remote TLS output set is incomplete")
    certificates = {"workload_identity_ca_cert"} | {
        f"{prefix}_cert" for prefix in TLS_PREFIXES
    }
    tokens: list[str] = []
    for name, path in entries.items():
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024:
            raise ValueError("Disposable remote TLS output is invalid")
        value = path.read_text(encoding="ascii")
        if "PRIVATE KEY" in value or "\x00" in value:
            raise ValueError("Disposable remote TLS output contains private material")
        if name in certificates:
            if "BEGIN CERTIFICATE" not in value:
                raise ValueError("Disposable remote TLS certificate is invalid")
            ssl.PEM_cert_to_DER_cert(value)
        else:
            if len(value) < 20 or value == root_token or "\n" in value or "\r" in value:
                raise ValueError("Disposable remote TLS token is invalid")
            tokens.append(value)
        if (secret_dir / name).exists() or (secret_dir / name).is_symlink():
            raise ValueError("Disposable remote TLS destination already exists")
    if len(set(tokens)) != len(TLS_PREFIXES):
        raise ValueError("Disposable remote TLS tokens are shared")
    for name in sorted(PUBLIC_TLS_FILES):
        entries[name].rename(secret_dir / name)
        if os.name == "posix":
            os.chmod(secret_dir / name, 0o644)
