#!/usr/bin/env python3
"""Bootstrap or log in to a scoped self-host OpenBao renewal AppRole.

Bootstrap is a one-time root operation after the initial KMS-only install.
Routine login uses only a private RoleID/SecretID pair and writes one short-lived
operator token for staging and activation. No key material is exported.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys
from urllib.error import HTTPError

sys.dont_write_bytecode = True
from selfhost_native_operator import approle_operation, approle_policy  # noqa: E402
from selfhost_operator_inputs import private_file, private_empty_or_source  # noqa: E402
from selfhost_operator_inputs import write_private as write_private  # noqa: E402
from activate_selfhost_renewed_secrets import checked_certificates, checked_tokens  # noqa: E402
from selfhost_openbao_client import (Bao, RENEWAL_LEAF_ROLE, RENEWAL_OPERATOR_POLICY)  # noqa: E402
from stage_selfhost_renewed_secrets import RENEWED_TOKEN_FILES, entries  # noqa: E402
from selfhost_approle_rotation import (  # noqa: E402
    RotationSpec, rotate_credentials, retire_credentials,
)


AUTH_MOUNT = "selfhost-renew"
APPROLE = "kms-renewer"
OPERATOR_POLICY = RENEWAL_OPERATOR_POLICY
LEAF_ROLE = RENEWAL_LEAF_ROLE
ROLE_ID_FILE = "renewal-role-id"
SECRET_ID_FILE = "renewal-secret-id"
TOKEN_FILE = "renewal-operator-token"
POLICY_NAMES_FILE = "renewal-leaf-policies.json"
ROTATION = RotationSpec(AUTH_MOUNT, APPROLE, ROLE_ID_FILE, SECRET_ID_FILE,
                        "", "renewal")
NAME = re.compile(r"[a-z0-9-]{1,160}\Z")


def existing_policy_names(bao: Bao, current: Path) -> list[str]:
    if not RENEWED_TOKEN_FILES <= entries(current).keys():
        raise ValueError("current generation lacks a renewed token input")
    checked_tokens(bao, current, current, 3600, require_orphan_new=False)
    checked_certificates(bao, current, current, 3600)
    names = []
    for file_name in sorted(RENEWED_TOKEN_FILES):
        token = (current / file_name).read_text(encoding="ascii").strip()
        data = bao.request("POST", "auth/token/lookup", {"token": token}).get("data", {})
        policies = data.get("policies")
        if (not isinstance(policies, list) or len(policies) != 1
                or not isinstance(policies[0], str) or not NAME.fullmatch(policies[0])):
            raise ValueError("existing remote signer policy is invalid")
        names.append(policies[0])
    if len(names) != 21 or len(set(names)) != len(names):
        raise ValueError("existing scoped policy inventory is incomplete")
    return names


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


def verify_denials(bao: Bao, token: str) -> None:
    probes = (
        ("GET", "transit/keys/foreign-keycloak-selfhost", None),
        ("POST", "auth/token/create", {"ttl": "invalid"}),
        ("PUT", "sys/policies/acl/selfhost-renewal-forbidden-probe",
         {"policy": "invalid policy"}),
        ("POST", "sys/mounts/selfhost-renewal-forbidden-probe",
         {"type": "not-an-engine"}),
    )
    for method, path, body in probes:
        try:
            bao.request(method, path, body, token=token)
        except HTTPError as error:
            if error.code == 403:
                continue
        raise ValueError("renewal operator exceeded its reviewed authority")


def verified_operator_policy(bao: Bao, token: str, names: list[str]) -> None:
    actual = bao.request("GET", f"sys/policies/acl/{OPERATOR_POLICY}",
                         token=token).get("data", {}).get("policy")
    if actual != operator_acl(names):
        raise ValueError("renewal operator policy drifted from reviewed authority")


def checked_login(bao: Bao, identity: Path) -> tuple[str, str, list[str], str]:
    result = approle_operation(bao, "login", "renewal", identity)
    return result["role_id"], result["secret_id"], result["names"], result["token"]


def login(bao: Bao, identity: Path, output: Path) -> None:
    output = private_empty_or_source(output, empty=True)
    _, _, _, token = checked_login(bao, identity)
    write_private(output / TOKEN_FILE, token)


def rotate(bao: Bao, identity: Path, output: Path) -> None:
    """Stage a validated replacement, then revoke the old SecretID."""
    identity = private_empty_or_source(identity, empty=False)
    output = private_empty_or_source(output, empty=True)
    if identity == output:
        raise ValueError("replacement identity must be separate")
    role_id, old_secret, names, old_token = checked_login(bao, identity)

    def stage(new_secret: str) -> str:
        response = bao.request("POST", f"auth/{AUTH_MOUNT}/login", {
            "role_id": role_id, "secret_id": new_secret,
        }, authenticate=False)
        auth = response.get("auth", {})
        new_token = auth.get("client_token")
        if (not isinstance(new_token, str) or len(new_token) < 20
                or auth.get("policies") != [OPERATOR_POLICY]
                or type(auth.get("lease_duration")) is not int
                or not 3600 <= auth["lease_duration"] <= 8 * 60 * 60):
            raise ValueError("replacement AppRole login is invalid")
        verify_denials(bao, new_token)
        write_private(output / ROLE_ID_FILE, role_id)
        write_private(output / SECRET_ID_FILE, new_secret)
        write_private(output / POLICY_NAMES_FILE,
                      json.dumps(names, separators=(",", ":")), max_bytes=4096)
        return new_token

    def cleanup() -> None:
        for name in (ROLE_ID_FILE, SECRET_ID_FILE, POLICY_NAMES_FILE):
            (output / name).unlink(missing_ok=True)

    rotate_credentials(bao, ROTATION, role_id, old_secret, old_token, stage, cleanup)


def retire(bao: Bao, identity: Path, retired: Path) -> None:
    """Finish an interrupted rotation using the validated replacement identity."""
    identity = private_empty_or_source(identity, empty=False)
    retired = private_empty_or_source(retired, empty=False)
    if identity == retired:
        raise ValueError("retired identity must be separate")
    role_id, new_secret, _, token = checked_login(bao, identity)
    old_role = private_file(retired / ROLE_ID_FILE).strip()
    old_secret = private_file(retired / SECRET_ID_FILE).strip()
    retire_credentials(bao, ROTATION, role_id, new_secret, old_role, old_secret, token)


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
    except (OSError, ValueError, RuntimeError, HTTPError) as error:
        print(f"self-host renewal identity failed: {type(error).__name__}", file=sys.stderr)
        return 2
    print("Scoped self-host renewal identity is ready")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
