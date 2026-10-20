#!/usr/bin/env python3
"""Bootstrap or use a custody-evidence-only OpenBao AppRole.

The root is needed only to create this separate operator authority. Routine
logins can mint one-hour orphan tokens for the non-exportable evidence signer.
"""

from __future__ import annotations

import argparse
import base64
import os
from pathlib import Path
import re
import sys
from urllib.error import HTTPError

sys.dont_write_bytecode = True
from activate_selfhost_renewed_secrets import private_file  # noqa: E402
from provision_selfhost_renewal_identity import write_private  # noqa: E402
from provision_selfhost_snapshot_identity import snapshot_origin  # noqa: E402
from selfhost_openbao_client import (  # noqa: E402
    Bao, CUSTODY_SIGNER, CUSTODY_SIGNER_POLICY, CUSTODY_SIGNER_LEAF_ACL,
    custody_signer_public,
)
from stage_selfhost_renewed_secrets import private_empty_or_source  # noqa: E402


AUTH_MOUNT = "selfhost-evidence"
APPROLE = "custody-renewer"
OPERATOR_POLICY = "selfhost-evidence-operator"
LEAF_ROLE = "selfhost-evidence-leaf"
ROLE_ID_FILE = "evidence-role-id"
SECRET_ID_FILE = "evidence-secret-id"
TOKEN_FILE = "evidence-signer-token"
OPERATOR_ACL = "\n".join((
    f'path "auth/token/create/{LEAF_ROLE}" {{ capabilities = ["update"] }}',
    f'path "auth/token/roles/{LEAF_ROLE}" {{ capabilities = ["read"] }}',
    'path "auth/token/lookup" { capabilities = ["update"] }',
    f'path "sys/policies/acl/{CUSTODY_SIGNER_POLICY}" {{ capabilities = ["read"] }}',
    f'path "transit/keys/{CUSTODY_SIGNER}" {{ capabilities = ["read"] }}',
    f'path "auth/{AUTH_MOUNT}/role/{APPROLE}/secret-id" {{ capabilities = ["update"] }}',
    f'path "auth/{AUTH_MOUNT}/role/{APPROLE}/secret-id/destroy" {{ capabilities = ["update"] }}',
))


def bootstrap(bao: Bao, output: Path) -> None:
    output = private_empty_or_source(output, empty=True)
    metadata = bao.request("GET", f"transit/keys/{CUSTODY_SIGNER}").get("data", {})
    version, _ = custody_signer_public(metadata)
    if version != 1 or bao.request("GET", f"sys/policies/acl/{CUSTODY_SIGNER_POLICY}") \
            .get("data", {}).get("policy") != CUSTODY_SIGNER_LEAF_ACL:
        raise ValueError("custody evidence signer or leaf policy differs")
    auth = bao.request("GET", "sys/auth").get("data", {})
    if not isinstance(auth, dict) or f"{AUTH_MOUNT}/" in auth:
        raise ValueError("evidence AppRole mount already exists")
    for path in (f"sys/policies/acl/{OPERATOR_POLICY}",
                 f"auth/token/roles/{LEAF_ROLE}"):
        try:
            bao.request("GET", path)
        except HTTPError as error:
            if error.code != 404:
                raise
        else:
            raise ValueError("evidence authority already exists")
    bao.request("POST", f"sys/auth/{AUTH_MOUNT}", {"type": "approle"})
    try:
        bao.request("POST", f"auth/token/roles/{LEAF_ROLE}", {
            "allowed_policies": [CUSTODY_SIGNER_POLICY],
            "disallowed_policies": ["default", "root"], "orphan": True,
            "token_no_default_policy": True, "token_explicit_max_ttl": "1h",
            "token_type": "service",
        })
        bao.request("PUT", f"sys/policies/acl/{OPERATOR_POLICY}", {
            "policy": OPERATOR_ACL,
        })
        bao.request("POST", f"auth/{AUTH_MOUNT}/role/{APPROLE}", {
            "bind_secret_id": True, "secret_id_num_uses": 0, "secret_id_ttl": 0,
            "token_policies": [OPERATOR_POLICY], "token_no_default_policy": True,
            "token_ttl": "8h", "token_max_ttl": "24h", "token_type": "service",
        })
        role_id = bao.request("GET", f"auth/{AUTH_MOUNT}/role/{APPROLE}/role-id") \
            .get("data", {}).get("role_id")
        secret_id = bao.request("POST", f"auth/{AUTH_MOUNT}/role/{APPROLE}/secret-id", {}) \
            .get("data", {}).get("secret_id")
        if (not isinstance(role_id, str) or len(role_id) < 20
                or not isinstance(secret_id, str) or len(secret_id) < 20):
            raise ValueError("evidence AppRole credentials are absent")
        write_private(output / ROLE_ID_FILE, role_id)
        write_private(output / SECRET_ID_FILE, secret_id)
        checked_login(bao, output)
    except Exception as error:
        cleanup_failed = False
        for path in (f"auth/{AUTH_MOUNT}/role/{APPROLE}",
                     f"sys/policies/acl/{OPERATOR_POLICY}",
                     f"auth/token/roles/{LEAF_ROLE}", f"sys/auth/{AUTH_MOUNT}"):
            try:
                bao.request("DELETE", path)
            except HTTPError as cleanup_error:
                cleanup_failed |= cleanup_error.code != 404
            except Exception:
                cleanup_failed = True
        for name in (ROLE_ID_FILE, SECRET_ID_FILE):
            try:
                (output / name).unlink(missing_ok=True)
            except OSError:
                cleanup_failed = True
        if cleanup_failed:
            raise RuntimeError("evidence AppRole bootstrap cleanup is incomplete") from error
        raise


def checked_login(bao: Bao, identity: Path) -> str:
    identity = private_empty_or_source(identity, empty=False)
    role_id = private_file(identity / ROLE_ID_FILE).strip()
    secret_id = private_file(identity / SECRET_ID_FILE).strip()
    if len(role_id) < 20 or len(secret_id) < 20:
        raise ValueError("evidence AppRole credentials are invalid")
    response = bao.request("POST", f"auth/{AUTH_MOUNT}/login", {
        "role_id": role_id, "secret_id": secret_id,
    }, authenticate=False)
    auth = response.get("auth", {})
    token = auth.get("client_token")
    if (not isinstance(token, str) or len(token) < 20
            or auth.get("policies") != [OPERATOR_POLICY]
            or type(auth.get("lease_duration")) is not int
            or not 3600 <= auth["lease_duration"] <= 8 * 60 * 60):
        raise ValueError("evidence AppRole returned invalid scoped authority")
    role = bao.request("GET", f"auth/token/roles/{LEAF_ROLE}", token=token).get("data", {})
    if (not isinstance(role, dict)
            or role.get("allowed_policies") != [CUSTODY_SIGNER_POLICY]
            or set(role.get("disallowed_policies", [])) != {"default", "root"}
            or role.get("orphan") is not True
            or role.get("token_no_default_policy") is not True
            or role.get("token_explicit_max_ttl") != 3600
            or bao.request("GET", f"sys/policies/acl/{CUSTODY_SIGNER_POLICY}",
                           token=token).get("data", {}).get("policy") != CUSTODY_SIGNER_LEAF_ACL):
        raise ValueError("evidence leaf authority drifted")
    for method, path, body in (
        ("POST", f"transit/sign/{CUSTODY_SIGNER}", {"input": "YWJj"}),
        ("POST", "auth/token/create", {"ttl": "invalid"}),
        ("GET", "sys/storage/raft/snapshot", None),
    ):
        try:
            bao.request(method, path, body, token=token)
        except HTTPError as error:
            if error.code == 403:
                continue
        raise ValueError("evidence operator exceeded named leaf authority")
    return token


def mint(bao: Bao, identity: Path) -> str:
    operator = checked_login(bao, identity)
    created = bao.request("POST", f"auth/token/create/{LEAF_ROLE}", {
        "policies": [CUSTODY_SIGNER_POLICY], "no_default_policy": True,
        "renewable": False, "ttl": "1h", "explicit_max_ttl": "1h",
    }, token=operator)
    leaf = created.get("auth", {}).get("client_token")
    if not isinstance(leaf, str) or len(leaf) < 20:
        raise ValueError("evidence leaf token is absent")
    try:
        data = bao.request("POST", "auth/token/lookup", {"token": leaf},
                           token=operator).get("data", {})
        if (not isinstance(data, dict)
                or data.get("policies") != [CUSTODY_SIGNER_POLICY]
                or data.get("orphan") is not True
                or data.get("path") != f"auth/token/create/{LEAF_ROLE}"
                or type(data.get("ttl")) is not int
                or not 0 < data["ttl"] <= 3600):
            raise ValueError("evidence leaf has wrong scope, lineage or lifetime")
        signature = bao.request("POST", f"transit/sign/{CUSTODY_SIGNER}", {
            "input": base64.b64encode(b"evidence-custody-canary").decode("ascii"),
            "key_version": 1,
        }, token=leaf).get("data", {}).get("signature")
        if not isinstance(signature, str) or not signature.startswith("vault:v1:"):
            raise ValueError("evidence leaf cannot use version-one remote signer")
        try:
            bao.request("GET", f"transit/export/signing-key/{CUSTODY_SIGNER}",
                        token=leaf)
        except HTTPError as error:
            if error.code != 403:
                raise
        else:
            raise ValueError("evidence leaf could export signer")
    except Exception:
        try:
            bao.request("POST", "auth/token/revoke-self", token=leaf)
        except Exception as cleanup_error:
            raise RuntimeError("evidence leaf cleanup is unconfirmed") from cleanup_error
        raise
    return leaf


def require_revoked(bao: Bao, role_id: str, secret_id: str) -> None:
    try:
        bao.request("POST", f"auth/{AUTH_MOUNT}/login", {
            "role_id": role_id, "secret_id": secret_id,
        }, authenticate=False)
    except HTTPError as error:
        if error.code in (400, 403):
            return
        raise
    raise ValueError("retired evidence AppRole credential remains usable")


def rotate(bao: Bao, identity: Path, output: Path) -> None:
    identity = private_empty_or_source(identity, empty=False)
    output = private_empty_or_source(output, empty=True)
    if (identity == output or identity.parent != output.parent
            or not re.fullmatch(r"evidence-identity(?:-[a-z0-9-]{1,80})?",
                                identity.name)
            or not re.fullmatch(r"evidence-identity(?:-[a-z0-9-]{1,80})?",
                                output.name)):
        raise ValueError("replacement evidence identity must be separate")
    old_token = checked_login(bao, identity)
    role_id = private_file(identity / ROLE_ID_FILE).strip()
    old_secret = private_file(identity / SECRET_ID_FILE).strip()
    path = f"auth/{AUTH_MOUNT}/role/{APPROLE}/secret-id"
    fresh = bao.request("POST", path, {}, token=old_token).get("data", {})
    new_secret = fresh.get("secret_id")
    if not isinstance(new_secret, str) or len(new_secret) < 20 or new_secret == old_secret:
        raise ValueError("replacement evidence SecretID is invalid")
    staged = False
    try:
        write_private(output / ROLE_ID_FILE, role_id)
        write_private(output / SECRET_ID_FILE, new_secret)
        new_token = checked_login(bao, output)
        staged = True
    finally:
        if not staged:
            for name in (ROLE_ID_FILE, SECRET_ID_FILE):
                (output / name).unlink(missing_ok=True)
            bao.request("POST", path + "/destroy", {"secret_id": new_secret},
                        token=old_token)
    bao.request("POST", path + "/destroy", {"secret_id": old_secret},
                token=new_token)
    require_revoked(bao, role_id, old_secret)


def retire(bao: Bao, identity: Path, retired: Path) -> None:
    identity = private_empty_or_source(identity, empty=False)
    retired = private_empty_or_source(retired, empty=False)
    if identity == retired:
        raise ValueError("retired evidence identity must be separate")
    token = checked_login(bao, identity)
    role_id = private_file(identity / ROLE_ID_FILE).strip()
    secret_id = private_file(identity / SECRET_ID_FILE).strip()
    old_role = private_file(retired / ROLE_ID_FILE).strip()
    old_secret = private_file(retired / SECRET_ID_FILE).strip()
    if old_role != role_id or old_secret == secret_id:
        raise ValueError("retired evidence identity differs from active AppRole")
    bao.request("POST", f"auth/{AUTH_MOUNT}/role/{APPROLE}/secret-id/destroy",
                {"secret_id": old_secret}, token=token)
    require_revoked(bao, old_role, old_secret)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("bootstrap", "mint", "rotate", "retire"),
                        required=True)
    parser.add_argument("--bao-addr", required=True)
    parser.add_argument("--bao-ca", required=True, type=Path)
    parser.add_argument("--identity", type=Path)
    parser.add_argument("--retired-identity", type=Path)
    parser.add_argument("--root-token-file", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        if (os.name != "posix" or not args.bao_ca.is_absolute()
                or args.bao_ca.is_symlink() or not args.bao_ca.is_file()):
            raise ValueError("evidence OpenBao endpoint is invalid")
        snapshot_origin(args.bao_addr)
        if args.mode == "bootstrap":
            if (args.identity is not None or args.retired_identity is not None
                    or args.root_token_file is None or args.output is None):
                raise ValueError("evidence bootstrap inputs are incomplete")
            if (args.root_token_file.name != "root.token"
                    or args.root_token_file.parent.name != "openbao-state"
                    or args.output.parent != args.root_token_file.parent.parent
                    or not re.fullmatch(r"evidence-identity(?:-[a-z0-9-]{1,80})?",
                                        args.output.name)):
                raise ValueError("evidence identity must be outside stack secrets")
            root_token = private_file(args.root_token_file).strip()
            if len(root_token) < 20:
                raise ValueError("evidence bootstrap root token is invalid")
            bootstrap(Bao(args.bao_addr, args.bao_ca, root_token), args.output)
        elif args.mode == "mint":
            if (args.identity is None or args.output is None
                    or args.root_token_file is not None
                    or args.retired_identity is not None):
                raise ValueError("evidence mint inputs are incomplete")
            output = private_empty_or_source(args.output.parent, empty=False)
            if args.output.parent != output or args.output.exists() or args.output.is_symlink():
                raise ValueError("evidence token output must be a fresh private file")
            token = mint(Bao(args.bao_addr, args.bao_ca, ""), args.identity)
            try:
                write_private(args.output, token)
            except Exception:
                try:
                    Bao(args.bao_addr, args.bao_ca, token).request(
                        "POST", "auth/token/revoke-self")
                except Exception as cleanup_error:
                    raise RuntimeError("minted evidence token cleanup is unconfirmed") \
                        from cleanup_error
                raise
        elif args.mode == "rotate":
            if (args.identity is None or args.output is None
                    or args.root_token_file is not None
                    or args.retired_identity is not None):
                raise ValueError("evidence rotation inputs are incomplete")
            rotate(Bao(args.bao_addr, args.bao_ca, ""), args.identity, args.output)
        else:
            if (args.identity is None or args.retired_identity is None
                    or args.output is not None or args.root_token_file is not None):
                raise ValueError("evidence retirement inputs are incomplete")
            retire(Bao(args.bao_addr, args.bao_ca, ""), args.identity,
                   args.retired_identity)
    except (OSError, ValueError, RuntimeError, HTTPError) as error:
        print(f"self-host evidence identity failed: {type(error).__name__}", file=sys.stderr)
        return 2
    print("Scoped evidence identity is ready")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
