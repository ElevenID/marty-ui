#!/usr/bin/env python3
"""Provision a non-exportable OpenBao signer for disposable custody evidence."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys
from pathlib import Path
from urllib.error import HTTPError

from provision_selfhost_disposable_tls import read_protected_root_token, verified_openbao_owner
from provision_selfhost_evidence_identity import checked_login as evidence_login
from provision_selfhost_evidence_identity import mint as mint_evidence_token
from selfhost_native_operator import OperatorCleanupError, network_operation
from selfhost_operator_inputs import private_operator_directory, write_owned
from selfhost_operator_inputs import refresh_scoped_token as refresh_scoped_token
from selfhost_openbao_client import (
    CUSTODY_SIGNER,
    CUSTODY_SIGNER_LEAF_ACL,
    CUSTODY_SIGNER_POLICY,
    Bao,
    custody_signer_public,
)

SOURCE_ROOT = Path(__file__).resolve().parents[1]


def private_directory(path: Path) -> Path:
    return private_operator_directory(path, SOURCE_ROOT)


def provision(endpoint: str, state_root: Path, output_root: Path, project: str,
              *, refresh_token: bool = False,
              identity_root: Path | None = None) -> str:
    if os.name != "posix" or os.geteuid() != 0:
        raise ValueError("OpenBao signer provisioning requires root on Linux")
    if not re.fullmatch(r"https://127\.0\.0\.1:[0-9]{2,5}", endpoint):
        raise ValueError("OpenBao signer endpoint must be loopback HTTPS")
    state_root = private_directory(state_root)
    output_root = private_directory(output_root)
    private_root = state_root.parent
    if (state_root != private_root / "openbao-state"
            or output_root != private_root / "secrets"):
        raise ValueError("signer inputs must share the private install root")
    _, port_text = endpoint.rsplit(":", 1)
    port = int(port_text)
    verified_openbao_owner(
        project, state_root, private_root / "install" / "selfhost-prepared", port,
    )
    root_file = state_root / "root.token"
    ca_file = state_root / "tls" / "ca.crt"
    token_file = output_root / "selfhost_custody_signer_token"
    public_file = output_root / "selfhost_custody_signer.pub"
    pending_file = token_file.with_name(token_file.name + ".new")
    if refresh_token and identity_root is None:
        raise ValueError("evidence identity is required for custody token refresh")
    if ((identity_root is None and (root_file.is_symlink() or not root_file.is_file()))
            or ca_file.is_symlink()
            or not ca_file.is_file() or token_file.is_symlink()
            or public_file.is_symlink() or pending_file.is_symlink()):
        raise ValueError("OpenBao signer input or output is invalid")
    if identity_root is not None and not refresh_token:
        raise ValueError("evidence identity is only valid for rootless refresh")
    if refresh_token:
        if not token_file.is_file() or not public_file.is_file():
            raise ValueError("OpenBao custody signer outputs are absent for refresh")
        if pending_file.exists():
            raise ValueError("pending custody token refresh requires operator recovery")
    elif token_file.exists() or public_file.exists():
        raise ValueError("OpenBao custody signer outputs must be fresh")
    if not 0 < ca_file.stat().st_size <= 65536:
        raise ValueError("OpenBao signer CA is missing or invalid")
    if identity_root is None:
        root_token = read_protected_root_token(root_file)
        bao = Bao(endpoint, ca_file, root_token)
    else:
        identity_root = private_directory(identity_root)
        if (identity_root.parent != private_root
                or not re.fullmatch(r"evidence-identity(?:-[a-z0-9-]{1,80})?",
                                    identity_root.name)):
            raise ValueError("evidence identity must be separate from stack secrets")
        operator = evidence_login(Bao(endpoint, ca_file, ""), identity_root)
        bao = Bao(endpoint, ca_file, operator)
    exists = True
    try:
        bao.request("GET", f"transit/keys/{CUSTODY_SIGNER}")
    except HTTPError as error:
        if error.code != 404:
            raise ValueError("OpenBao custody key lookup failed") from None
        exists = False
    if not exists:
        if identity_root is not None:
            raise ValueError("rootless evidence refresh cannot create a signer")
        bao.request("POST", f"transit/keys/{CUSTODY_SIGNER}", {
            "type": "ed25519", "exportable": False, "allow_plaintext_backup": False,
        })
    metadata = bao.request("GET", f"transit/keys/{CUSTODY_SIGNER}").get("data", {})
    _, pem = custody_signer_public(metadata, version_one=True)
    if refresh_token and public_file.read_text(encoding="ascii") != pem:
        raise ValueError("OpenBao custody public key changed before token refresh")
    if identity_root is None:
        bao.request("PUT", f"sys/policies/acl/{CUSTODY_SIGNER_POLICY}",
                    {"policy": CUSTODY_SIGNER_LEAF_ACL})
    elif bao.request("GET", f"sys/policies/acl/{CUSTODY_SIGNER_POLICY}") \
            .get("data", {}).get("policy") != CUSTODY_SIGNER_LEAF_ACL:
        raise ValueError("rootless custody evidence policy drifted")
    owner = output_root.stat()

    def write(path: Path, value: str, mode: int) -> None:
        write_owned(path, value, mode, owner)

    if identity_root is None:
        created = bao.request("POST", "auth/token/create", {
            "policies": [CUSTODY_SIGNER_POLICY], "no_default_policy": True,
            "no_parent": True, "renewable": False, "ttl": "1h", "explicit_max_ttl": "1h",
        })
        token = created.get("auth", {}).get("client_token")
    else:
        token = mint_evidence_token(Bao(endpoint, ca_file, ""), identity_root)
    if not isinstance(token, str) or not token:
        raise ValueError("OpenBao scoped custody token is absent")
    try:
        scoped = Bao(endpoint, ca_file, token)
        network_operation(scoped, "leaf-check", kind="custody")
        if refresh_token:
            refresh_scoped_token(bao, token_file, token, write)
        else:
            write(public_file, pem, 0o444)
            write(token_file, token, 0o400)
    except Exception:
        # A failed refresh may have stored the new token in .new because the
        # old-token revocation response was ambiguous. Never discard that token.
        if not pending_file.exists() and not (token_file.is_file()
                                              and token_file.read_text(encoding="ascii").strip() == token):
            try:
                if identity_root is None:
                    bao.request("POST", "auth/token/revoke", {"token": token})
                else:
                    Bao(endpoint, ca_file, token).request("POST", "auth/token/revoke-self")
            except (OSError, RuntimeError, ValueError, HTTPError):
                try:
                    write(pending_file, token, 0o400)
                except (OSError, RuntimeError, ValueError, HTTPError) as recovery_error:
                    raise RuntimeError("new custody token could not be revoked or preserved") from recovery_error
        if not refresh_token:
            public_file.unlink(missing_ok=True)
        raise
    return hashlib.sha256(public_file.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--state-root", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--project-name", required=True)
    parser.add_argument("--refresh-token", action="store_true")
    parser.add_argument("--identity-root", type=Path)
    args = parser.parse_args()
    try:
        digest = provision(args.endpoint, args.state_root, args.output_root,
                           args.project_name,
                           refresh_token=args.refresh_token,
                           identity_root=args.identity_root)
    except OperatorCleanupError as error:
        print(str(error), file=sys.stderr)
        return 3
    except ValueError as error:
        print(f"OpenBao custody signer provisioning failed: {error}", file=sys.stderr)
        return 2
    except (OSError, RuntimeError, HTTPError) as error:
        print(f"OpenBao custody signer provisioning failed: {type(error).__name__}",
              file=sys.stderr)
        return 2
    print("OpenBao custody public-key SHA-256:", digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
