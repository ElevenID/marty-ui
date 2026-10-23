#!/usr/bin/env python3
"""Rotate the snapshot reader without granting it SecretID authority."""

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
from provision_selfhost_snapshot_identity import APPROLE as READER_ROLE, AUTH_MOUNT, POLICY as READER_POLICY, ROLE_ID_FILE as READER_ROLE_ID_FILE, SECRET_ID_FILE as READER_SECRET_ID_FILE, checked_login as reader_login  # noqa: E402
from selfhost_approle_rotation import (  # noqa: E402
    RotationSpec, retire as retire_secret_id, rotate as rotate_secret_id,
)
from selfhost_openbao_client import Bao  # noqa: E402


ROTATOR_ROLE = "raft-exporter-rotator"
ROTATOR_POLICY = "selfhost-raft-snapshot-rotation"
ROLE_ID_FILE = "snapshot-rotator-role-id"
SECRET_ID_FILE = "snapshot-rotator-secret-id"
READER_ROTATION = RotationSpec(AUTH_MOUNT, READER_ROLE, READER_ROLE_ID_FILE,
                               READER_SECRET_ID_FILE, "snapshot-identity", "snapshot")
ROTATOR_ROTATION = RotationSpec(AUTH_MOUNT, ROTATOR_ROLE, ROLE_ID_FILE,
                                SECRET_ID_FILE, "snapshot-rotator-identity",
                                "snapshot rotator")
ACL = "\n".join((
    f'path "{READER_ROTATION.secret_id_path}" {{ capabilities = ["update"] }}',
    f'path "{READER_ROTATION.secret_id_path}/destroy" '
    '{ capabilities = ["update"] }',
    f'path "{ROTATOR_ROTATION.secret_id_path}" {{ capabilities = ["update"] }}',
    f'path "{ROTATOR_ROTATION.secret_id_path}/destroy" '
    '{ capabilities = ["update"] }',
    f'path "auth/{AUTH_MOUNT}/role/{ROTATOR_ROLE}" '
    '{ capabilities = ["read"] }',
    f'path "sys/policies/acl/{READER_POLICY}" {{ capabilities = ["read"] }}',
    f'path "sys/policies/acl/{ROTATOR_POLICY}" {{ capabilities = ["read"] }}',
))


def bootstrap(bao: Bao, output: Path) -> None:
    approle_operation(bao, "bootstrap", "snapshot-rotator", output)


def checked_login(bao: Bao, identity: Path) -> str:
    return approle_operation(bao, "login", "snapshot-rotator", identity)["token"]


def rotate_reader(bao: Bao, identity: Path, output: Path,
                  rotator: Path) -> None:
    rotate_secret_id(bao, identity, output, READER_ROTATION, reader_login,
                     private_empty_or_source, private_file, write_private,
                     manager_login=lambda client: checked_login(client, rotator))


def retire_reader(bao: Bao, identity: Path, retired: Path,
                  rotator: Path) -> None:
    retire_secret_id(bao, identity, retired, READER_ROTATION, reader_login,
                     private_empty_or_source, private_file,
                     manager_login=lambda client: checked_login(client, rotator))


def rotate_rotator(bao: Bao, identity: Path, output: Path) -> None:
    rotate_secret_id(bao, identity, output, ROTATOR_ROTATION, checked_login,
                     private_empty_or_source, private_file, write_private)


def retire_rotator(bao: Bao, identity: Path, retired: Path) -> None:
    retire_secret_id(bao, identity, retired, ROTATOR_ROTATION, checked_login,
                     private_empty_or_source, private_file)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("bootstrap", "rotate-reader",
                                          "retire-reader", "rotate-rotator",
                                          "retire-rotator"), required=True)
    parser.add_argument("--bao-addr", required=True)
    parser.add_argument("--bao-ca", required=True, type=Path)
    parser.add_argument("--root-token-file", type=Path)
    parser.add_argument("--identity", type=Path)
    parser.add_argument("--rotator-identity", type=Path)
    parser.add_argument("--retired-identity", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        if (os.name != "posix" or not args.bao_ca.is_absolute()
                or args.bao_ca.is_symlink() or not args.bao_ca.is_file()):
            raise ValueError("snapshot rotator endpoint is invalid")
        snapshot_origin(args.bao_addr)
        if args.mode == "bootstrap":
            if (args.root_token_file is None or args.output is None
                    or args.identity is not None or args.rotator_identity is not None
                    or args.retired_identity is not None):
                raise ValueError("snapshot rotator bootstrap inputs are incomplete")
            if (args.root_token_file.name != "root.token"
                    or args.root_token_file.parent.name != "openbao-state"
                    or args.output.parent != args.root_token_file.parent.parent
                    or not re.fullmatch(r"snapshot-rotator-identity"
                                        r"(?:-[a-z0-9-]{1,80})?", args.output.name)):
                raise ValueError("snapshot rotator identity must be outside stack secrets")
            root_token = private_file(args.root_token_file).strip()
            if len(root_token) < 20:
                raise ValueError("snapshot rotator bootstrap root token is invalid")
            bootstrap(Bao(args.bao_addr, args.bao_ca, root_token), args.output)
        elif args.mode in ("rotate-reader", "rotate-rotator"):
            if (args.identity is None or args.output is None
                    or args.retired_identity is not None or args.root_token_file is not None
                    or (args.mode == "rotate-reader") !=
                    (args.rotator_identity is not None)):
                raise ValueError("snapshot rotation inputs are incomplete")
            client = Bao(args.bao_addr, args.bao_ca, "")
            if args.mode == "rotate-reader":
                rotate_reader(client, args.identity, args.output,
                              args.rotator_identity)
            else:
                rotate_rotator(client, args.identity, args.output)
        else:
            if (args.identity is None or args.retired_identity is None
                    or args.output is not None or args.root_token_file is not None
                    or (args.mode == "retire-reader") !=
                    (args.rotator_identity is not None)):
                raise ValueError("snapshot retirement inputs are incomplete")
            client = Bao(args.bao_addr, args.bao_ca, "")
            if args.mode == "retire-reader":
                retire_reader(client, args.identity, args.retired_identity,
                              args.rotator_identity)
            else:
                retire_rotator(client, args.identity, args.retired_identity)
    except OperatorCleanupError as error:
        print(str(error), file=sys.stderr)
        return 3
    except (OSError, ValueError, RuntimeError, HTTPError) as error:
        print(f"self-host snapshot rotation failed: {type(error).__name__}",
              file=sys.stderr)
        return 2
    print("Scoped snapshot rotation is ready")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
