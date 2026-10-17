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
PASSPORT_CERT_FILES = frozenset({"workload_identity_ca_cert"}) | frozenset(
    f"{prefix}_cert" for prefix in TLS_PREFIXES
)

# The self-host Rust profile intentionally uses catalog token filenames rather
# than the passport producer's prefix-derived names. Keep this independent
# acceptor inventory aligned with the deployment catalog in a focused test.
SELFHOST_TOKEN_FILES = frozenset({
    "signing_keys_tls_kms_token", "gateway_tls_kms_token",
    "auth_tls_kms_token", "auth_server_tls_kms_token",
    "compliance_profile_tls_kms_token", "deployment_profile_tls_kms_token",
    "org_tls_kms_token", "es_tls_kms_token", "rp_tls_kms_token",
    "ct_tls_kms_token", "issuance_tls_kms_token",
    "notification_tls_kms_token",
    "flow_client_tls_kms_token", "flow_server_tls_kms_token",
    "pp_tls_kms_token", "verification_tls_kms_token",
})
SELFHOST_CERT_FILES = (PASSPORT_CERT_FILES - {"passport_edge_tls_cert"}) | {
    "verification_workload_client_cert", "notification_workload_server_cert"
}
SELFHOST_TLS_FILES = SELFHOST_CERT_FILES | SELFHOST_TOKEN_FILES


def accept_remote_tls(
    output: Path, secret_dir: Path, root_token: str, *,
    expected_files: frozenset[str] = PUBLIC_TLS_FILES,
    certificate_files: frozenset[str] = PASSPORT_CERT_FILES,
) -> None:
    """Move a complete, verified keyless bootstrap set into private Compose secrets."""
    if (not output.is_absolute() or not secret_dir.is_absolute()
        or output.is_symlink() or secret_dir.is_symlink()
        or not output.is_dir() or not secret_dir.is_dir()):
        raise ValueError("Disposable TLS output or secret directory is invalid")
    if os.name == "posix" and stat.S_IMODE(output.stat().st_mode) != 0o700:
        raise ValueError("Disposable TLS output directory is not private")
    entries = {path.name: path for path in output.iterdir()}
    if (not certificate_files <= expected_files
            or set(entries) != expected_files):
        raise ValueError("Disposable remote TLS output set is incomplete")
    tokens: list[str] = []
    for name, path in entries.items():
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024:
            raise ValueError("Disposable remote TLS output is invalid")
        value = path.read_text(encoding="ascii")
        if "PRIVATE KEY" in value or "\x00" in value:
            raise ValueError("Disposable remote TLS output contains private material")
        if name in certificate_files:
            if "BEGIN CERTIFICATE" not in value:
                raise ValueError("Disposable remote TLS certificate is invalid")
            ssl.PEM_cert_to_DER_cert(value)
        else:
            if len(value) < 20 or value == root_token or "\n" in value or "\r" in value:
                raise ValueError("Disposable remote TLS token is invalid")
            tokens.append(value)
        if (secret_dir / name).exists() or (secret_dir / name).is_symlink():
            raise ValueError("Disposable remote TLS destination already exists")
    if len(set(tokens)) != len(expected_files - certificate_files):
        raise ValueError("Disposable remote TLS tokens are shared")
    moved: list[str] = []
    try:
        for name in sorted(expected_files):
            entries[name].rename(secret_dir / name)
            moved.append(name)
            if os.name == "posix":
                os.chmod(secret_dir / name, 0o644)
    except OSError as error:
        rollback_failed = False
        for name in reversed(moved):
            try:
                (secret_dir / name).rename(output / name)
            except OSError:
                rollback_failed = True
        if rollback_failed:
            raise RuntimeError("Disposable remote TLS rollback is incomplete") from error
        raise
