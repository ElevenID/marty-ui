#!/usr/bin/env python3
"""Create and use a separate, snapshot-read-only self-host OpenBao AppRole."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
from urllib.error import HTTPError

sys.dont_write_bytecode = True
from selfhost_operator_inputs import private_file, write_private, private_empty_or_source  # noqa: E402
from selfhost_operator_inputs import snapshot_origin as snapshot_origin  # noqa: E402
from selfhost_openbao_client import Bao  # noqa: E402


AUTH_MOUNT = "selfhost-snapshot"
APPROLE = "raft-exporter"
POLICY = "selfhost-raft-snapshot-read"
ROLE_ID_FILE = "snapshot-role-id"
SECRET_ID_FILE = "snapshot-secret-id"
ACL = 'path "sys/storage/raft/snapshot" { capabilities = ["read"] }'




def bootstrap(bao: Bao, output: Path) -> None:
    output = private_empty_or_source(output, empty=True)
    auth = bao.request("GET", "sys/auth").get("data", {})
    if not isinstance(auth, dict) or f"{AUTH_MOUNT}/" in auth:
        raise ValueError("snapshot AppRole mount already exists")
    try:
        bao.request("GET", f"sys/policies/acl/{POLICY}")
    except HTTPError as error:
        if error.code != 404:
            raise
    else:
        raise ValueError("snapshot policy already exists")
    bao.request("POST", f"sys/auth/{AUTH_MOUNT}", {"type": "approle"})
    try:
        bao.request("PUT", f"sys/policies/acl/{POLICY}", {"policy": ACL})
        bao.request("POST", f"auth/{AUTH_MOUNT}/role/{APPROLE}", {
            "bind_secret_id": True, "secret_id_num_uses": 0, "secret_id_ttl": 0,
            "token_policies": [POLICY], "token_no_default_policy": True,
            "token_ttl": "1h", "token_max_ttl": "1h", "token_type": "service",
        })
        role_id = bao.request("GET", f"auth/{AUTH_MOUNT}/role/{APPROLE}/role-id") \
            .get("data", {}).get("role_id")
        secret_id = bao.request("POST", f"auth/{AUTH_MOUNT}/role/{APPROLE}/secret-id", {}) \
            .get("data", {}).get("secret_id")
        if (not isinstance(role_id, str) or len(role_id) < 20
                or not isinstance(secret_id, str) or len(secret_id) < 20):
            raise ValueError("snapshot AppRole credentials are absent")
        write_private(output / ROLE_ID_FILE, role_id)
        write_private(output / SECRET_ID_FILE, secret_id)
        checked_login(bao, output)
    except Exception as error:
        cleanup_failed = False
        for path in (f"auth/{AUTH_MOUNT}/role/{APPROLE}",
                     f"sys/policies/acl/{POLICY}", f"sys/auth/{AUTH_MOUNT}"):
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
            raise RuntimeError("snapshot AppRole bootstrap cleanup is incomplete") from error
        raise


def checked_login(bao: Bao, identity: Path) -> str:
    identity = private_empty_or_source(identity, empty=False)
    role_id = private_file(identity / ROLE_ID_FILE).strip()
    secret_id = private_file(identity / SECRET_ID_FILE).strip()
    if len(role_id) < 20 or len(secret_id) < 20:
        raise ValueError("snapshot AppRole credentials are invalid")
    response = bao.request("POST", f"auth/{AUTH_MOUNT}/login", {
        "role_id": role_id, "secret_id": secret_id,
    }, authenticate=False)
    auth = response.get("auth", {})
    token = auth.get("client_token")
    if (not isinstance(token, str) or len(token) < 20
            or auth.get("policies") != [POLICY]
            or type(auth.get("lease_duration")) is not int
            or not 0 < auth["lease_duration"] <= 3600):
        raise ValueError("snapshot AppRole returned an invalid scoped token")
    for method, path, body in (
        ("GET", "transit/keys/foreign-snapshot-probe", None),
        ("POST", "auth/token/create", {"ttl": "invalid"}),
        ("GET", f"sys/policies/acl/{POLICY}", None),
    ):
        try:
            bao.request(method, path, body, token=token)
        except HTTPError as error:
            if error.code == 403:
                continue
        raise ValueError("snapshot AppRole exceeded read-only snapshot authority")
    return token


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bao-addr", required=True)
    parser.add_argument("--bao-ca", required=True, type=Path)
    parser.add_argument("--root-token-file", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        if (os.name != "posix"
                or not args.bao_ca.is_absolute() or args.bao_ca.is_symlink()
                or not args.bao_ca.is_file()):
            raise ValueError("snapshot OpenBao endpoint is invalid")
        snapshot_origin(args.bao_addr)
        root_token = private_file(args.root_token_file).strip()
        if len(root_token) < 20:
            raise ValueError("snapshot bootstrap root token is invalid")
        bootstrap(Bao(args.bao_addr, args.bao_ca, root_token), args.output)
    except (OSError, ValueError, RuntimeError, HTTPError) as error:
        print(f"self-host snapshot identity failed: {type(error).__name__}", file=sys.stderr)
        return 2
    print("Scoped self-host snapshot identity is ready")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
