#!/usr/bin/env python3
"""Bootstrap and use the separate read-only custody-audit AppRole."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import sys
from urllib.error import HTTPError

sys.dont_write_bytecode = True
from selfhost_native_operator import OperatorCleanupError, approle_operation  # noqa: E402
from selfhost_operator_inputs import private_file, write_private, snapshot_origin, private_empty_or_source  # noqa: E402
from provision_selfhost_audit_token import POLICY, policy_for  # noqa: E402
from selfhost_approle_rotation import (  # noqa: E402
    RotationSpec, require_revoked as require_secret_revoked,
    retire as retire_secret_id, rotate as rotate_secret_id,
)
from selfhost_openbao_client import Bao  # noqa: E402


AUTH_MOUNT = "selfhost-audit"
APPROLE = "custody-auditor"
OPERATOR_POLICY = "selfhost-audit-operator"
LEAF_ROLE = "selfhost-audit-leaf"
ROLE_ID_FILE = "audit-role-id"
SECRET_ID_FILE = "audit-secret-id"
ROTATION = RotationSpec(AUTH_MOUNT, APPROLE, ROLE_ID_FILE, SECRET_ID_FILE,
                        "audit-identity", "audit")
OPERATOR_ACL = "\n".join((
    f'path "auth/token/create/{LEAF_ROLE}" {{ capabilities = ["update"] }}',
    f'path "auth/token/roles/{LEAF_ROLE}" {{ capabilities = ["read"] }}',
    'path "auth/token/lookup" { capabilities = ["update"] }',
    f'path "sys/policies/acl/{POLICY}" {{ capabilities = ["read"] }}',
    f'path "auth/{AUTH_MOUNT}/role/{APPROLE}/secret-id" {{ capabilities = ["update"] }}',
    f'path "auth/{AUTH_MOUNT}/role/{APPROLE}/secret-id/destroy" '
    '{ capabilities = ["update"] }',
))


def bootstrap(bao: Bao, output: Path, policy: str) -> None:
    approle_operation(bao, "bootstrap", "audit", output, policy=policy)


def checked_login(bao: Bao, identity: Path, policy: str) -> str:
    return approle_operation(bao, "login", "audit", identity, policy=policy)["token"]


def mint(bao: Bao, identity: Path, policy: str, paths: tuple[str, ...]) -> str:
    return approle_operation(bao, "mint", "audit", identity, policy=policy, paths=paths)


def require_revoked(bao: Bao, role_id: str, secret_id: str) -> None:
    require_secret_revoked(bao, role_id, secret_id, ROTATION)


def rotate(bao: Bao, identity: Path, output: Path, policy: str) -> None:
    rotate_secret_id(bao, identity, output, ROTATION,
                     lambda client, path: checked_login(client, path, policy),
                     private_empty_or_source, private_file, write_private)


def retire(bao: Bao, identity: Path, retired: Path, policy: str) -> None:
    retire_secret_id(bao, identity, retired, ROTATION,
                     lambda client, path: checked_login(client, path, policy),
                     private_empty_or_source, private_file)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("bootstrap", "rotate", "retire"),
                        required=True)
    parser.add_argument("--bao-addr", required=True)
    parser.add_argument("--bao-ca", required=True, type=Path)
    parser.add_argument("--root-token-file", type=Path)
    parser.add_argument("--identity", type=Path)
    parser.add_argument("--retired-identity", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--org-id", required=True)
    parser.add_argument("--org-slug", required=True)
    parser.add_argument("--did", required=True)
    args = parser.parse_args()
    try:
        if (os.name != "posix" or not args.bao_ca.is_absolute()
                or args.bao_ca.is_symlink() or not args.bao_ca.is_file()):
            raise ValueError("audit OpenBao endpoint is invalid")
        snapshot_origin(args.bao_addr)
        policy, _ = policy_for(args.org_id, args.org_slug, args.did)
        if args.mode == "bootstrap":
            if (args.root_token_file is None or args.output is None
                    or args.identity is not None or args.retired_identity is not None):
                raise ValueError("audit bootstrap inputs are incomplete")
            if (args.root_token_file.name != "root.token"
                    or args.root_token_file.parent.name != "openbao-state"
                    or args.output.parent != args.root_token_file.parent.parent
                    or not re.fullmatch(r"audit-identity(?:-[a-z0-9-]{1,80})?",
                                        args.output.name)):
                raise ValueError("audit identity must be outside stack secrets")
            root_token = private_file(args.root_token_file).strip()
            if len(root_token) < 20:
                raise ValueError("audit bootstrap root token is invalid")
            bootstrap(Bao(args.bao_addr, args.bao_ca, root_token), args.output,
                      policy)
        elif args.mode == "rotate":
            if (args.identity is None or args.output is None
                    or args.retired_identity is not None or args.root_token_file is not None):
                raise ValueError("audit rotation inputs are incomplete")
            rotate(Bao(args.bao_addr, args.bao_ca, ""), args.identity, args.output,
                   policy)
        else:
            if (args.identity is None or args.retired_identity is None
                    or args.output is not None or args.root_token_file is not None):
                raise ValueError("audit retirement inputs are incomplete")
            retire(Bao(args.bao_addr, args.bao_ca, ""), args.identity,
                   args.retired_identity, policy)
    except OperatorCleanupError as error:
        print(str(error), file=sys.stderr)
        return 3
    except (OSError, ValueError, RuntimeError, HTTPError) as error:
        print(f"self-host audit identity failed: {type(error).__name__}", file=sys.stderr)
        return 2
    print("Scoped audit identity is ready")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
