#!/usr/bin/env python3
"""Create a disposable, read-only OpenBao token for installed custody checks."""

from __future__ import annotations

import argparse
import os
import re
import stat
import sys
import uuid
from pathlib import Path
from urllib.error import HTTPError

from provision_selfhost_disposable_tls import read_protected_root_token, verified_openbao_owner
from provision_selfhost_custody_signer import refresh_scoped_token
from selfhost_native_operator import OperatorCleanupError
from selfhost_openbao_client import Bao
from selfhost_managed_reference import managed_reference


SOURCE_ROOT = Path(__file__).resolve().parents[1]
POLICY = "selfhost-qualification-audit"
SIGNER = "selfhost-qualification-custody-v1"


def private_directory(path: Path) -> Path:
    if (not path.is_absolute() or path.is_symlink() or not path.is_dir()
            or stat.S_IMODE(path.stat().st_mode) != 0o700):
        raise ValueError("operator directory must be an existing private directory")
    resolved = path.resolve()
    if resolved.is_relative_to(SOURCE_ROOT):
        raise ValueError("operator directory must be outside the source checkout")
    return resolved


def policy_for(org: str, slug: str, did: str) -> tuple[str, tuple[str, ...]]:
    try:
        canonical = str(uuid.UUID(org))
    except ValueError as error:
        raise ValueError("synthetic organization ID is invalid") from error
    if (org != canonical or not re.fullmatch(r"[a-zA-Z0-9._-]{1,128}", slug)
            or not re.fullmatch(r"did:web:[A-Za-z0-9.%-]+:orgs:" +
                                re.escape(slug), did)):
        raise ValueError("synthetic DID does not match organization slug")
    keys = tuple(managed_reference(org, purpose)
                 for purpose in ("vc_jwt_issuer", "oid4vp_request_signing"))
    paths = tuple(f"transit/keys/{name}" for name in (*keys, SIGNER))
    policy = "".join(f'path "{path}" {{ capabilities = ["read"] }}\n'
                     for path in paths)
    policy += 'path "auth/token/lookup-self" { capabilities = ["read"] }\n'
    policy += 'path "auth/token/revoke-self" { capabilities = ["update"] }\n'
    policy += 'path "sys/capabilities-self" { capabilities = ["update"] }\n'
    return policy, paths


def write_token(path: Path, value: str, owner: os.stat_result) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii") as stream:
            stream.write(value)
            os.fchown(stream.fileno(), owner.st_uid, owner.st_gid)
            os.fchmod(stream.fileno(), 0o400)
    except Exception:
        path.unlink(missing_ok=True)
        raise


def provision(endpoint: str, state_root: Path, output_root: Path,
              org: str, slug: str, did: str, project: str, *,
              refresh_token: bool = False, identity_root: Path | None = None) -> None:
    if os.name != "posix" or os.geteuid() != 0:
        raise ValueError("OpenBao audit provisioning requires root on Linux")
    if not re.fullmatch(r"https://127\.0\.0\.1:[0-9]{2,5}", endpoint):
        raise ValueError("OpenBao audit endpoint must be loopback HTTPS")
    state_root = private_directory(state_root)
    output_root = private_directory(output_root)
    private_root = state_root.parent
    if (state_root != private_root / "openbao-state"
            or output_root != private_root / "secrets"):
        raise ValueError("audit inputs must share the private install root")
    port = int(endpoint.rsplit(":", 1)[1])
    verified_openbao_owner(
        project, state_root, private_root / "install" / "selfhost-prepared", port,
    )
    root_file = state_root / "root.token"
    ca_file = state_root / "tls" / "ca.crt"
    token_file = output_root / "selfhost_audit_token"
    pending_file = token_file.with_name(token_file.name + ".new")
    if refresh_token and identity_root is None:
        raise ValueError("audit identity is required for token refresh")
    if identity_root is not None and not refresh_token:
        raise ValueError("audit identity is only valid for rootless refresh")
    if ((identity_root is None and (root_file.is_symlink() or not root_file.is_file()))
            or ca_file.is_symlink() or not ca_file.is_file()
            or token_file.is_symlink() or pending_file.is_symlink()):
        raise ValueError("OpenBao audit input or output is invalid")
    if refresh_token:
        if not token_file.is_file() or pending_file.exists():
            raise ValueError("pending or missing audit token requires operator recovery")
    elif token_file.exists() or pending_file.exists():
        raise ValueError("OpenBao audit input or output is invalid")
    if not 0 < ca_file.stat().st_size <= 65536:
        raise ValueError("OpenBao audit CA is missing or invalid")
    policy, paths = policy_for(org, slug, did)
    if identity_root is None:
        root_token = read_protected_root_token(root_file)
        bao = Bao(endpoint, ca_file, root_token)
        bao.request("PUT", f"sys/policies/acl/{POLICY}", {"policy": policy})
        created = bao.request("POST", "auth/token/create", {
            "policies": [POLICY], "no_default_policy": True, "no_parent": True,
            "renewable": False, "ttl": "1h", "explicit_max_ttl": "1h",
        })
        token = created.get("auth", {}).get("client_token")
    else:
        from provision_selfhost_audit_identity import checked_login, mint
        identity_root = private_directory(identity_root)
        if (identity_root.parent != private_root
                or not re.fullmatch(r"audit-identity(?:-[a-z0-9-]{1,80})?",
                                    identity_root.name)):
            raise ValueError("audit identity must be separate from stack secrets")
        operator = checked_login(Bao(endpoint, ca_file, ""), identity_root, policy)
        bao = Bao(endpoint, ca_file, operator)
        token = mint(Bao(endpoint, ca_file, ""), identity_root, policy, paths)
    if not isinstance(token, str) or not token:
        raise ValueError("OpenBao audit token is absent")
    try:
        scoped = Bao(endpoint, ca_file, token)
        metadata = scoped.request("GET", "auth/token/lookup-self").get("data", {})
        if (metadata.get("policies") != [POLICY] or metadata.get("orphan") is not True
                or type(metadata.get("ttl")) is not int
                or not 0 < metadata["ttl"] <= 3600):
            raise ValueError("OpenBao audit token is not orphaned, scoped or short-lived")
        forbidden = (f"transit/sign/{SIGNER}", f"transit/export/signing-key/{SIGNER}",
                     "auth/token/create", f"sys/policies/acl/{POLICY}")
        access = scoped.request("POST", "sys/capabilities-self", {
            "paths": [*paths, *forbidden],
        })
        if (any(access.get(path) != ["read"] for path in paths)
                or any(access.get(path) not in (["deny"], []) for path in forbidden)):
            raise ValueError("OpenBao audit token has excess or missing capabilities")
        if refresh_token:
            refresh_scoped_token(
                bao, token_file, token,
                lambda path, value, _mode: write_token(path, value, output_root.stat()),
            )
        else:
            write_token(token_file, token, output_root.stat())
    except Exception:
        if not pending_file.exists() and not (token_file.is_file()
                                              and token_file.read_text(encoding="ascii").strip() == token):
            try:
                if identity_root is None:
                    bao.request("POST", "auth/token/revoke", {"token": token})
                else:
                    Bao(endpoint, ca_file, token).request("POST", "auth/token/revoke-self")
            except (OSError, ValueError, RuntimeError, HTTPError) as error:
                recovery_file = pending_file if refresh_token else token_file
                if not recovery_file.exists():
                    write_token(recovery_file, token, output_root.stat())
                raise RuntimeError("audit token requires operator recovery") from error
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--state-root", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--org-id", required=True)
    parser.add_argument("--org-slug", required=True)
    parser.add_argument("--did", required=True)
    parser.add_argument("--project-name", required=True)
    parser.add_argument("--refresh-token", action="store_true")
    parser.add_argument("--identity-root", type=Path)
    args = parser.parse_args()
    try:
        provision(args.endpoint, args.state_root, args.output_root,
                  args.org_id, args.org_slug, args.did, args.project_name,
                  refresh_token=args.refresh_token, identity_root=args.identity_root)
    except OperatorCleanupError as error:
        print(str(error), file=sys.stderr)
        return 3
    except (OSError, ValueError, RuntimeError, HTTPError) as error:
        print(f"OpenBao audit provisioning failed: {type(error).__name__}", file=sys.stderr)
        return 2
    print("Created scoped disposable OpenBao audit token")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
