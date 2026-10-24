#!/usr/bin/env python3
"""Bootstrap or log in to a scoped self-host OpenBao renewal AppRole.

Bootstrap is a one-time root operation after the initial KMS-only install.
Routine login uses only a private RoleID/SecretID pair and writes one short-lived
operator token for staging and activation. No key material is exported.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
from urllib.error import HTTPError

sys.dont_write_bytecode = True
from selfhost_native_operator import OperatorCleanupError, approle_operation, approle_policy, network_operation  # noqa: E402
from selfhost_operator_inputs import private_file, private_empty_or_source  # noqa: E402
from selfhost_operator_inputs import write_private as write_private  # noqa: E402
from selfhost_openbao_client import (Bao, RENEWAL_LEAF_ROLE, RENEWAL_OPERATOR_POLICY)  # noqa: E402


AUTH_MOUNT = "selfhost-renew"
APPROLE = "kms-renewer"
OPERATOR_POLICY = RENEWAL_OPERATOR_POLICY
LEAF_ROLE = RENEWAL_LEAF_ROLE
ROLE_ID_FILE = "renewal-role-id"
SECRET_ID_FILE = "renewal-secret-id"
TOKEN_FILE = "renewal-operator-token"
POLICY_NAMES_FILE = "renewal-leaf-policies.json"


def existing_policy_names(bao: Bao, current: Path) -> list[str]:
    return network_operation(bao, "renewal-inventory", current=str(current))


def operator_acl(policy_names: list[str], *, allow_secret_id_rotation: bool = True) -> str:
    return approle_policy("renewal", names=policy_names,
                          allow_secret_id_rotation=allow_secret_id_rotation)




def bootstrap(bao: Bao, current: Path, output: Path) -> None:
    current = private_empty_or_source(current, empty=False)
    output = private_empty_or_source(output, empty=True)
    if current == output:
        raise ValueError("renewal identity output must be separate")
    names = existing_policy_names(bao, current)
    approle_operation(bao, "bootstrap", "renewal", output, names=names)


def checked_login(bao: Bao, identity: Path) -> tuple[str, str, list[str], str]:
    result = approle_operation(bao, "login", "renewal", identity)
    return result["role_id"], result["secret_id"], result["names"], result["token"]


def login(bao: Bao, identity: Path, output: Path) -> None:
    output = private_empty_or_source(output, empty=True)
    _, _, _, token = checked_login(bao, identity)
    write_private(output / TOKEN_FILE, token)


def rotate(bao: Bao, identity: Path, output: Path) -> None:
    approle_operation(bao, "rotate", "renewal", identity, output=str(output))


def retire(bao: Bao, identity: Path, retired: Path) -> None:
    approle_operation(bao, "retire", "renewal", identity, retired=str(retired))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("bootstrap", "login", "rotate", "retire"),
                        required=True)
    parser.add_argument("--bao-addr", required=True)
    parser.add_argument("--bao-ca", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--root-token-file", type=Path)
    parser.add_argument("--current-secrets", type=Path)
    parser.add_argument("--identity", type=Path)
    parser.add_argument("--retired-identity", type=Path)
    args = parser.parse_args()
    try:
        if (os.name != "posix" or not args.bao_addr.startswith("https://")
                or not args.bao_ca.is_absolute() or args.bao_ca.is_symlink()
                or not args.bao_ca.is_file()):
            raise ValueError("renewal OpenBao endpoint is invalid")
        if args.mode == "bootstrap":
            if (args.output is None or args.root_token_file is None
                    or args.current_secrets is None or args.identity or args.retired_identity):
                raise ValueError("renewal bootstrap inputs are incomplete")
            root_token = private_file(args.root_token_file).strip()
            if len(root_token) < 20:
                raise ValueError("renewal bootstrap root token is invalid")
            bootstrap(Bao(args.bao_addr, args.bao_ca, root_token),
                      args.current_secrets, args.output)
        else:
            if args.identity is None or args.root_token_file or args.current_secrets:
                raise ValueError("renewal login inputs are incomplete")
            if args.mode == "login":
                if args.output is None or args.retired_identity:
                    raise ValueError("renewal login inputs are incomplete")
                login(Bao(args.bao_addr, args.bao_ca, ""), args.identity, args.output)
            elif args.mode == "rotate":
                if args.output is None or args.retired_identity:
                    raise ValueError("renewal rotation inputs are incomplete")
                rotate(Bao(args.bao_addr, args.bao_ca, ""), args.identity, args.output)
            else:
                if args.output is not None or args.retired_identity is None:
                    raise ValueError("renewal retirement inputs are incomplete")
                retire(Bao(args.bao_addr, args.bao_ca, ""),
                       args.identity, args.retired_identity)
    except OperatorCleanupError as error:
        print(str(error), file=sys.stderr)
        return 3
    except (OSError, ValueError, RuntimeError, HTTPError) as error:
        print(f"self-host renewal identity failed: {type(error).__name__}", file=sys.stderr)
        return 2
    print("Scoped self-host renewal identity is ready")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
