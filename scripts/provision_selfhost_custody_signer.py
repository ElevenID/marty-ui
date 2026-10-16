#!/usr/bin/env python3
"""Provision a non-exportable OpenBao signer for disposable custody evidence."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import sys
from pathlib import Path
from typing import Callable
from urllib.error import HTTPError

from selfhost_openbao_client import (
    CUSTODY_SIGNER,
    CUSTODY_SIGNER_POLICY,
    Bao,
    ed25519_public_pem,
)

SOURCE_ROOT = Path(__file__).resolve().parents[1]


def refresh_scoped_token(bao: Bao, token_file: Path, token: str,
                         write: Callable[[Path, str, int], None]) -> None:
    """Keep the previous credential recoverable until its revocation succeeds."""
    old_token = token_file.read_text(encoding="ascii").strip()
    temporary = token_file.with_name(token_file.name + ".new")
    if temporary.exists() or temporary.is_symlink():
        raise ValueError("pending custody token refresh requires operator recovery")
    write(temporary, token, 0o400)
    try:
        try:
            bao.request("POST", "auth/token/revoke", {"token": old_token})
        except HTTPError as error:
            if error.code != 400:  # Already-expired disposable token.
                raise
    except (OSError, RuntimeError, HTTPError):
        try:
            bao.request("POST", "auth/token/revoke", {"token": token})
        except (OSError, RuntimeError, HTTPError) as cleanup_error:
            # Preserve the new token so an operator can revoke it explicitly.
            raise RuntimeError("pending custody token refresh requires operator recovery") from cleanup_error
        temporary.unlink()
        raise
    # If replacement fails, the new token remains in .new for operator recovery.
    os.replace(temporary, token_file)


def private_directory(path: Path) -> Path:
    if (not path.is_absolute() or path.is_symlink() or not path.is_dir()
            or stat.S_IMODE(path.stat().st_mode) != 0o700):
        raise ValueError("operator directory must be an existing private directory")
    resolved = path.resolve()
    if resolved.is_relative_to(SOURCE_ROOT):
        raise ValueError("operator directory must be outside the source checkout")
    return resolved


def provision(endpoint: str, state_root: Path, output_root: Path,
              *, refresh_token: bool = False) -> str:
    if os.name != "posix" or os.geteuid() != 0:
        raise ValueError("OpenBao signer provisioning requires root on Linux")
    if not re.fullmatch(r"https://127\.0\.0\.1:[0-9]{2,5}", endpoint):
        raise ValueError("OpenBao signer endpoint must be loopback HTTPS")
    state_root = private_directory(state_root)
    output_root = private_directory(output_root)
    root_file = state_root / "root.token"
    ca_file = state_root / "tls" / "ca.crt"
    token_file = output_root / "selfhost_custody_signer_token"
    public_file = output_root / "selfhost_custody_signer.pub"
    pending_file = token_file.with_name(token_file.name + ".new")
    if (root_file.is_symlink() or not root_file.is_file() or ca_file.is_symlink()
            or not ca_file.is_file() or token_file.is_symlink()
            or public_file.is_symlink() or pending_file.is_symlink()):
        raise ValueError("OpenBao signer input or output is invalid")
    if refresh_token:
        if not token_file.is_file() or not public_file.is_file():
            raise ValueError("OpenBao custody signer outputs are absent for refresh")
        if pending_file.exists():
            raise ValueError("pending custody token refresh requires operator recovery")
    elif token_file.exists() or public_file.exists():
        raise ValueError("OpenBao custody signer outputs must be fresh")
    root_token = root_file.read_text(encoding="ascii").strip()
    if not 16 <= len(root_token) <= 2048 or not re.fullmatch(r"[A-Za-z0-9._-]+", root_token):
        raise ValueError("OpenBao root token is invalid")
    bao = Bao(endpoint, ca_file, root_token)
    exists = True
    try:
        bao.request("GET", f"transit/keys/{CUSTODY_SIGNER}")
    except HTTPError as error:
        if error.code != 404:
            raise ValueError("OpenBao custody key lookup failed") from None
        exists = False
    if not exists:
        bao.request("POST", f"transit/keys/{CUSTODY_SIGNER}", {
            "type": "ed25519", "exportable": False, "allow_plaintext_backup": False,
        })
    metadata = bao.request("GET", f"transit/keys/{CUSTODY_SIGNER}").get("data", {})
    if (metadata.get("type") != "ed25519" or metadata.get("exportable") is not False
            or metadata.get("allow_plaintext_backup") is not False
            or metadata.get("latest_version") != 1):
        raise ValueError("OpenBao custody key is not non-exportable Ed25519")
    pem = ed25519_public_pem(metadata.get("keys", {}).get("1", {}).get("public_key"))
    if refresh_token and public_file.read_text(encoding="ascii") != pem:
        raise ValueError("OpenBao custody public key changed before token refresh")
    policy = (
        f'path "transit/keys/{CUSTODY_SIGNER}" {{ capabilities = ["read"] }}\n'
        f'path "transit/sign/{CUSTODY_SIGNER}" {{ capabilities = ["update"] }}\n'
        'path "auth/token/lookup-self" { capabilities = ["read"] }\n'
    )
    bao.request("PUT", f"sys/policies/acl/{CUSTODY_SIGNER_POLICY}", {"policy": policy})
    created = bao.request("POST", "auth/token/create", {
        "policies": [CUSTODY_SIGNER_POLICY], "no_default_policy": True,
        "orphan": True, "renewable": False, "ttl": "1h", "explicit_max_ttl": "1h",
    })
    token = created.get("auth", {}).get("client_token")
    if not isinstance(token, str) or not token:
        raise ValueError("OpenBao scoped custody token is absent")
    scoped = Bao(endpoint, ca_file, token)
    lookup = scoped.request("GET", "auth/token/lookup-self").get("data", {})
    if (lookup.get("policies") != [CUSTODY_SIGNER_POLICY]
            or type(lookup.get("ttl")) is not int
            or not 0 < lookup["ttl"] <= 3600):
        raise ValueError("OpenBao custody signer token is not scoped or short-lived")
    scoped.request("GET", f"transit/keys/{CUSTODY_SIGNER}")
    try:
        scoped.request("GET", f"transit/export/signing-key/{CUSTODY_SIGNER}")
    except HTTPError as error:
        if error.code != 403:
            raise ValueError("OpenBao custody key export denial is invalid") from None
    else:
        raise ValueError("OpenBao custody key was exportable")
    owner = output_root.stat()

    def write(path: Path, value: str, mode: int) -> None:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600)
        try:
            with os.fdopen(descriptor, "w", encoding="ascii") as stream:
                stream.write(value)
                os.fchown(stream.fileno(), owner.st_uid, owner.st_gid)
                os.fchmod(stream.fileno(), mode)
        except Exception:
            path.unlink(missing_ok=True)
            raise

    if refresh_token:
        refresh_scoped_token(bao, token_file, token, write)
    else:
        try:
            write(public_file, pem, 0o444)
            write(token_file, token, 0o400)
        except Exception:
            public_file.unlink(missing_ok=True)
            try:
                bao.request("POST", "auth/token/revoke", {"token": token})
            except (OSError, RuntimeError, HTTPError):
                pass  # The scoped token expires within one hour.
            raise
    return hashlib.sha256(public_file.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--state-root", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--refresh-token", action="store_true")
    args = parser.parse_args()
    try:
        digest = provision(args.endpoint, args.state_root, args.output_root,
                           refresh_token=args.refresh_token)
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
