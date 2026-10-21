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
from selfhost_operator_inputs import private_file, write_private, snapshot_origin, private_empty_or_source  # noqa: E402
from provision_selfhost_snapshot_identity import ACL as READER_ACL, APPROLE as READER_ROLE, AUTH_MOUNT, POLICY as READER_POLICY, ROLE_ID_FILE as READER_ROLE_ID_FILE, SECRET_ID_FILE as READER_SECRET_ID_FILE, checked_login as reader_login  # noqa: E402
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
    output = private_empty_or_source(output, empty=True)
    mounts = bao.request("GET", "sys/auth").get("data", {})
    if not isinstance(mounts, dict) or f"{AUTH_MOUNT}/" not in mounts:
        raise ValueError("snapshot reader AppRole mount is absent")
    if bao.request("GET", f"sys/policies/acl/{READER_POLICY}") \
            .get("data", {}).get("policy") != READER_ACL:
        raise ValueError("snapshot reader policy differs")
    for path in (f"sys/policies/acl/{ROTATOR_POLICY}",
                 f"auth/{AUTH_MOUNT}/role/{ROTATOR_ROLE}"):
        try:
            bao.request("GET", path)
        except HTTPError as error:
            if error.code != 404:
                raise
        else:
            raise ValueError("snapshot rotator authority already exists")
    try:
        bao.request("PUT", f"sys/policies/acl/{ROTATOR_POLICY}", {
            "policy": ACL,
        })
        bao.request("POST", f"auth/{AUTH_MOUNT}/role/{ROTATOR_ROLE}", {
            "bind_secret_id": True, "secret_id_num_uses": 0, "secret_id_ttl": 0,
            "token_policies": [ROTATOR_POLICY], "token_no_default_policy": True,
            "token_ttl": "1h", "token_max_ttl": "1h", "token_type": "service",
        })
        role_id = bao.request("GET", f"auth/{AUTH_MOUNT}/role/{ROTATOR_ROLE}/role-id") \
            .get("data", {}).get("role_id")
        secret_id = bao.request("POST", ROTATOR_ROTATION.secret_id_path, {}) \
            .get("data", {}).get("secret_id")
        if (not isinstance(role_id, str) or len(role_id) < 20
                or not isinstance(secret_id, str) or len(secret_id) < 20):
            raise ValueError("snapshot rotator AppRole credentials are absent")
        write_private(output / ROLE_ID_FILE, role_id)
        write_private(output / SECRET_ID_FILE, secret_id)
        checked_login(bao, output)
    except Exception as error:
        cleanup_failed = False
        for path in (f"auth/{AUTH_MOUNT}/role/{ROTATOR_ROLE}",
                     f"sys/policies/acl/{ROTATOR_POLICY}"):
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
            raise RuntimeError("snapshot rotator bootstrap cleanup is incomplete") from error
        raise


def checked_login(bao: Bao, identity: Path) -> str:
    identity = private_empty_or_source(identity, empty=False)
    role_id = private_file(identity / ROLE_ID_FILE).strip()
    secret_id = private_file(identity / SECRET_ID_FILE).strip()
    if len(role_id) < 20 or len(secret_id) < 20:
        raise ValueError("snapshot rotator credentials are invalid")
    response = bao.request("POST", f"auth/{AUTH_MOUNT}/login", {
        "role_id": role_id, "secret_id": secret_id,
    }, authenticate=False)
    auth = response.get("auth", {})
    token = auth.get("client_token")
    if (not isinstance(token, str) or len(token) < 20
            or auth.get("policies") != [ROTATOR_POLICY]
            or type(auth.get("lease_duration")) is not int
            or not 0 < auth["lease_duration"] <= 3600):
        raise ValueError("snapshot rotator AppRole returned invalid scoped authority")
    role = bao.request("GET", f"auth/{AUTH_MOUNT}/role/{ROTATOR_ROLE}", token=token) \
        .get("data", {})
    if (not isinstance(role, dict)
            or role.get("token_policies") != [ROTATOR_POLICY]
            or role.get("token_no_default_policy") is not True
            or bao.request("GET", f"sys/policies/acl/{ROTATOR_POLICY}",
                           token=token).get("data", {}).get("policy") != ACL
            or bao.request("GET", f"sys/policies/acl/{READER_POLICY}",
                           token=token).get("data", {}).get("policy") != READER_ACL):
        raise ValueError("snapshot rotator authority drifted")
    for method, path, body in (
        ("GET", "sys/storage/raft/snapshot", None),
        ("GET", "transit/keys/foreign-snapshot-probe", None),
        ("POST", "auth/token/create", {"ttl": "1h"}),
    ):
        try:
            bao.request(method, path, body, token=token)
        except HTTPError as error:
            if error.code == 403:
                continue
        raise ValueError("snapshot rotator exceeded SecretID-only authority")
    return token


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
    except (OSError, ValueError, RuntimeError, HTTPError) as error:
        print(f"self-host snapshot rotation failed: {type(error).__name__}",
              file=sys.stderr)
        return 2
    print("Scoped snapshot rotation is ready")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
