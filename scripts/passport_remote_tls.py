"""Accept only public certificates and scoped tokens from Rust passport TLS bootstrap."""

from __future__ import annotations

import os
import json
from pathlib import Path
import ssl
import stat
from typing import Literal

if __package__:
    from .selfhost_native_operator import operator_bytes
else:
    from selfhost_native_operator import operator_bytes


TLS_PREFIXES = (
    "passport_edge_tls", "signing_keys_workload_server",
    "gateway_workload_client", "auth_workload_client", "auth_workload_server",
    "compliance_profile_workload_client",
    "deployment_profile_workload_client", "org_workload_server",
    "es_workload_server", "rp_workload_server",
    "ct_workload_server", "issuance_workload_server", "trust_profile_workload_server",
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
SELFHOST_CERT_FILES = (PASSPORT_CERT_FILES - {
    "passport_edge_tls_cert", "trust_profile_workload_server_cert"
}) | {
    "verification_workload_client_cert", "notification_workload_server_cert"
}
SELFHOST_TLS_FILES = SELFHOST_CERT_FILES | SELFHOST_TOKEN_FILES


def accept_remote_tls(
    output: Path, secret_dir: Path, root_token: str, *,
    expected_files: frozenset[str] = PUBLIC_TLS_FILES,
    certificate_files: frozenset[str] = PASSPORT_CERT_FILES,
    profile: Literal["passport", "passport-role-repair", "passport-role-renew"] = "passport",
    role: str | None = None,
    expected_workload_ca: Path | None = None,
) -> None:
    """Move an exact admitted output set through the existing custody owner."""
    repair = profile in {"passport-role-repair", "passport-role-renew"}
    if repair:
        if (role != "trust-profile-server" or expected_workload_ca is None
                or expected_files != PUBLIC_TLS_FILES or certificate_files != PASSPORT_CERT_FILES):
            raise ValueError("Selective remote TLS repair contract is invalid")
        expected_files = frozenset({"workload_identity_ca_cert",
                                    "trust_profile_workload_server_cert",
                                    "trust_profile_workload_server_kms_token"})
        certificate_files = expected_files - {"trust_profile_workload_server_kms_token"}
    elif profile != "passport" or role is not None or expected_workload_ca is not None:
        raise ValueError("Selective remote TLS repair requires its explicit profile")
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
    if repair:
        if (not expected_workload_ca.is_absolute() or expected_workload_ca.is_symlink()
                or not expected_workload_ca.is_file()
                or expected_workload_ca.stat().st_size > 64 * 1024):
            raise ValueError("Selective remote TLS expected CA is invalid")
        expected_ca = expected_workload_ca.read_text(encoding="ascii")
        produced_ca = entries["workload_identity_ca_cert"].read_text(encoding="ascii")
        if ssl.PEM_cert_to_DER_cert(expected_ca) != ssl.PEM_cert_to_DER_cert(produced_ca):
            raise ValueError("Selective remote TLS issuer certificate changed")
        root = Path(__file__).resolve().parents[1]
        try:
            expected_spki = operator_bytes(root, "operator", "certificate-spki", input=expected_ca.encode("ascii"))
            actual_spki = operator_bytes(root, "operator", "certificate-spki", input=produced_ca.encode("ascii"))
            if not expected_spki or expected_spki != actual_spki:
                raise ValueError("Selective remote TLS issuer public key changed")
            operator_bytes(root, "operator", "certificate-chain", input=json.dumps({
                "certificate": entries["trust_profile_workload_server_cert"].read_text(encoding="ascii"),
                "issuer": expected_ca,
            }).encode("ascii"))
        except RuntimeError as error:
            raise ValueError("Selective remote TLS issuer validation failed") from error
    moved: list[str] = []
    try:
        for name in sorted(expected_files):
            entries[name].rename(secret_dir / name)
            moved.append(name)
            if os.name == "posix":
                os.chmod(secret_dir / name, 0o600 if repair else 0o644)
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
