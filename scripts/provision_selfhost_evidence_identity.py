#!/usr/bin/env python3
"""Bootstrap or use a custody-evidence-only OpenBao AppRole.

The root is needed only to create this separate operator authority. Routine
logins can mint one-hour orphan tokens for the non-exportable evidence signer.
"""

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
from selfhost_approle_rotation import (  # noqa: E402
    RotationSpec, require_revoked as require_secret_revoked,
    retire as retire_secret_id, rotate as rotate_secret_id,
)
from selfhost_openbao_client import (  # noqa: E402
    Bao, CUSTODY_SIGNER, CUSTODY_SIGNER_POLICY,
)


AUTH_MOUNT = "selfhost-evidence"
APPROLE = "custody-renewer"
OPERATOR_POLICY = "selfhost-evidence-operator"
LEAF_ROLE = "selfhost-evidence-leaf"
ROLE_ID_FILE = "evidence-role-id"
SECRET_ID_FILE = "evidence-secret-id"
TOKEN_FILE = "evidence-signer-token"
ROTATION = RotationSpec(AUTH_MOUNT, APPROLE, ROLE_ID_FILE, SECRET_ID_FILE,
                        "evidence-identity", "evidence")
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
    approle_operation(bao, "bootstrap", "evidence", output)


def checked_login(bao: Bao, identity: Path) -> str:
    return approle_operation(bao, "login", "evidence", identity)["token"]


def mint(bao: Bao, identity: Path) -> str:
    return approle_operation(bao, "mint", "evidence", identity)


def require_revoked(bao: Bao, role_id: str, secret_id: str) -> None:
    require_secret_revoked(bao, role_id, secret_id, ROTATION)


def rotate(bao: Bao, identity: Path, output: Path) -> None:
    rotate_secret_id(bao, identity, output, ROTATION, checked_login,
                     private_empty_or_source, private_file, write_private)


def retire(bao: Bao, identity: Path, retired: Path) -> None:
    retire_secret_id(bao, identity, retired, ROTATION, checked_login,
                     private_empty_or_source, private_file)


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
    except OperatorCleanupError as error:
        print(str(error), file=sys.stderr)
        return 3
    except (OSError, ValueError, RuntimeError, HTTPError) as error:
        print(f"self-host evidence identity failed: {type(error).__name__}", file=sys.stderr)
        return 2
    print("Scoped evidence identity is ready")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
