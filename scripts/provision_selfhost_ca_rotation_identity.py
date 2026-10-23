#!/usr/bin/env python3
"""Bootstrap or log in to a bounded, rootless self-host CA-rotation AppRole.

Only the initial installation root may create this identity. Routine CA
rotation uses the separate RoleID/SecretID pair and exact versioned PKI paths.
The operator can issue public certificates but cannot export Transit keys,
change policies or operate an unrelated mount.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from urllib.error import HTTPError

sys.dont_write_bytecode = True
from selfhost_operator_inputs import private_file, write_private, snapshot_origin, private_empty_or_source  # noqa: E402
from provision_selfhost_renewal_identity import NAME, existing_policy_names, operator_acl  # noqa: E402
from provision_selfhost_disposable_tls import KEY_NAMES  # noqa: E402
from selfhost_openbao_client import Bao  # noqa: E402


AUTH_MOUNT = "selfhost-ca-rotation"
APPROLE = "kms-ca-rotator"
POLICY = "selfhost-kms-ca-rotation"
ROLE_ID_FILE = "ca-rotation-role-id"
SECRET_ID_FILE = "ca-rotation-secret-id"
TOKEN_FILE = "ca-rotation-operator-token"
POLICY_NAMES_FILE = "ca-rotation-leaf-policies.json"
# Pre-authorized exact mount names; a mid-path `*` is not an OpenBao ACL glob.
VERSIONS = range(2, 9)


def checked_issuer_certificate(certificate: str, kind: str, version: int) -> None:
    """Verify the public CA response with OpenSSL before accepting its issuer."""
    encoded = certificate.encode("ascii")
    if not re.fullmatch(
            r"-----BEGIN CERTIFICATE-----\n(?:[A-Za-z0-9+/=]+\n)+"
            r"-----END CERTIFICATE-----\n?", certificate):
        raise RuntimeError("CA replacement certificate is not one PEM certificate")

    def openssl(*arguments: str, input_bytes: bytes | None = encoded) -> str:
        result = subprocess.run(
            ["openssl", *arguments], input=input_bytes, capture_output=True,
            timeout=10, check=False,
        )
        if result.returncode:
            raise RuntimeError("CA replacement certificate failed OpenSSL validation")
        return result.stdout.decode("ascii")

    name = f"CN=Marty self-host {kind} CA v{version}"
    names = openssl("x509", "-noout", "-subject", "-issuer", "-nameopt", "RFC2253")
    if names.splitlines() != [f"subject={name}", f"issuer={name}"]:
        raise RuntimeError("CA replacement certificate differs from reviewed issuer")
    constraints = openssl("x509", "-noout", "-ext", "basicConstraints")
    if [line.strip() for line in constraints.splitlines()] != [
            "X509v3 Basic Constraints: critical", "CA:TRUE"]:
        raise RuntimeError("CA replacement lacks CA basic constraints")
    public = openssl("x509", "-pubkey", "-noout")
    key = openssl("pkey", "-pubin", "-text", "-noout", input_bytes=public.encode("ascii"))
    if "Public-Key: (256 bit)" not in key or "ASN1 OID: prime256v1" not in key:
        raise RuntimeError("CA replacement certificate has an unexpected public key")
    with tempfile.TemporaryDirectory(prefix="selfhost-ca-verify-") as directory:
        path = Path(directory) / "issuer.pem"
        path.write_bytes(encoded)
        openssl("verify", "-x509_strict", "-check_ss_sig", "-no_check_time",
                "-purpose", "any",
                "-CAfile", str(path), str(path), input_bytes=None)


def rotation_acl(names: list[str]) -> str:
    """Add bounded CA provisioning paths to the reviewed renewal authority."""
    base = operator_acl(names, allow_secret_id_rotation=False)
    paths: dict[str, tuple[str, ...]] = {
        f"sys/policies/acl/{POLICY}": ("read",),
    }
    for version in VERSIONS:
        for prefix, roles in (("workload-pki", tuple(sorted(KEY_NAMES))),
                              ("keycloak-pki", ("rs256",))):
            mount = f"{prefix}-v{version}"
            paths[f"sys/mounts/{mount}"] = ("create", "read", "update")
            paths[f"{mount}/root/generate/internal"] = ("create", "update")
            paths[f"{mount}/cert/ca"] = ("read",)
            for role in roles:
                paths[f"{mount}/roles/{role}"] = ("create", "read", "update")
                paths[f"{mount}/sign/{role}"] = ("update",)
    return base + "\n" + "\n".join(
        f'path "{path}" {{ capabilities = {json.dumps(list(caps))} }}'
        for path, caps in sorted(paths.items())
    )


def checked_login(bao: Bao, identity: Path) -> str:
    identity = private_empty_or_source(identity, empty=False)
    if identity.stat().st_uid != os.getuid():
        raise ValueError("CA-rotation identity has an unexpected owner")
    role_id = private_file(identity / ROLE_ID_FILE).strip()
    secret_id = private_file(identity / SECRET_ID_FILE).strip()
    names = json.loads(private_file(identity / POLICY_NAMES_FILE))
    if (not isinstance(names, list) or len(names) != 21
            or not all(isinstance(name, str) and NAME.fullmatch(name) for name in names)
            or len(set(names)) != 21):
        raise ValueError("CA-rotation policy receipt is invalid")
    if len(role_id) < 20 or len(secret_id) < 20:
        raise ValueError("CA-rotation AppRole credentials are invalid")
    response = bao.request("POST", f"auth/{AUTH_MOUNT}/login", {
        "role_id": role_id, "secret_id": secret_id,
    }, authenticate=False)
    auth = response.get("auth", {})
    token = auth.get("client_token")
    if (not isinstance(token, str) or len(token) < 20
            or auth.get("policies") != [POLICY]
            or type(auth.get("lease_duration")) is not int
            or not 3600 <= auth["lease_duration"] <= 8 * 60 * 60):
        raise ValueError("CA-rotation AppRole returned an invalid scoped token")
    actual = bao.request("GET", f"sys/policies/acl/{POLICY}", token=token) \
        .get("data", {}).get("policy")
    if actual != rotation_acl(names):
        raise ValueError("CA-rotation ACL drifted from exact reviewed paths")
    for method, path, body in (
        ("POST", "sys/mounts/unrelated-ca-probe", {"type": "pki"}),
        ("GET", "transit/export/signing-key/workload-tls-organization-server", None),
        ("PUT", "sys/policies/acl/ca-escalation-probe", {"policy": "invalid"}),
        ("POST", "auth/selfhost-renew/role/kms-renewer/secret-id", {}),
        ("POST", "sys/mounts/workload-pki-v9", {"type": "pki"}),
    ):
        try:
            bao.request(method, path, body, token=token)
        except HTTPError as error:
            if error.code == 403:
                continue
        raise ValueError("CA-rotation operator exceeded exact reviewed authority")
    return token


def bootstrap(bao: Bao, current: Path, output: Path) -> None:
    output = private_empty_or_source(output, empty=True)
    if output.stat().st_uid != os.getuid():
        raise ValueError("CA-rotation identity output has an unexpected owner")
    names = existing_policy_names(bao, current)
    auth = bao.request("GET", "sys/auth").get("data", {})
    if not isinstance(auth, dict) or f"{AUTH_MOUNT}/" in auth:
        raise ValueError("CA-rotation AppRole mount already exists")
    try:
        bao.request("GET", f"sys/policies/acl/{POLICY}")
    except HTTPError as error:
        if error.code != 404:
            raise
    else:
        raise ValueError("CA-rotation policy already exists")
    bao.request("POST", f"sys/auth/{AUTH_MOUNT}", {"type": "approle"})
    try:
        bao.request("PUT", f"sys/policies/acl/{POLICY}", {
            "policy": rotation_acl(names),
        })
        bao.request("POST", f"auth/{AUTH_MOUNT}/role/{APPROLE}", {
            "bind_secret_id": True, "secret_id_num_uses": 0, "secret_id_ttl": 0,
            "token_policies": [POLICY], "token_no_default_policy": True,
            "token_ttl": "8h", "token_max_ttl": "24h", "token_type": "service",
        })
        role_id = bao.request("GET", f"auth/{AUTH_MOUNT}/role/{APPROLE}/role-id") \
            .get("data", {}).get("role_id")
        secret_id = bao.request("POST", f"auth/{AUTH_MOUNT}/role/{APPROLE}/secret-id", {}) \
            .get("data", {}).get("secret_id")
        if (not isinstance(role_id, str) or len(role_id) < 20
                or not isinstance(secret_id, str) or len(secret_id) < 20):
            raise ValueError("CA-rotation AppRole credentials are absent")
        write_private(output / ROLE_ID_FILE, role_id)
        write_private(output / SECRET_ID_FILE, secret_id)
        write_private(output / POLICY_NAMES_FILE,
                      json.dumps(sorted(names), separators=(",", ":")), max_bytes=4096)
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
        for name in (ROLE_ID_FILE, SECRET_ID_FILE, POLICY_NAMES_FILE):
            try:
                (output / name).unlink(missing_ok=True)
            except OSError:
                cleanup_failed = True
        if cleanup_failed:
            raise RuntimeError("CA-rotation bootstrap cleanup is incomplete") from error
        raise


def stage_issuer(bao: Bao, identity: Path, output: Path,
                 kind: str, version: int) -> str:
    """Create or resume one non-exportable CA; leave leaf production to its owner."""
    output = private_empty_or_source(output, empty=True)
    if output.stat().st_uid != os.getuid():
        raise ValueError("CA replacement output has an unexpected owner")
    if kind not in ("workload", "keycloak") or type(version) is not int or version not in VERSIONS:
        raise ValueError("CA replacement mount is outside reviewed versions")
    mount = f"{kind}-pki-v{version}"
    token = checked_login(bao, identity)
    mounts = bao.request("GET", "sys/mounts", token=token).get("data", {})
    if not isinstance(mounts, dict):
        raise ValueError("CA replacement mount inventory is invalid")
    if f"{mount}/" not in mounts:
        bao.request("POST", f"sys/mounts/{mount}", {
            "type": "pki", "config": {"max_lease_ttl": "8760h"},
        }, token=token)
    configured = bao.request("GET", f"sys/mounts/{mount}", token=token).get("data", {})
    if (not isinstance(configured, dict) or configured.get("type") != "pki"
            or not isinstance(configured.get("config"), dict)
            or configured["config"].get("max_lease_ttl") != 365 * 24 * 60 * 60):
        raise RuntimeError("CA replacement mount differs from reviewed lifetime")
    try:
        data = bao.request("GET", f"{mount}/cert/ca", token=token).get("data", {})
    except HTTPError as error:
        if error.code not in (400, 404):
            raise
        data = {}
    if not data.get("certificate"):
        data = bao.request("POST", f"{mount}/root/generate/internal", {
            "common_name": f"Marty self-host {kind} CA v{version}",
            "ttl": "8760h", "key_type": "ec", "key_bits": 256,
        }, token=token).get("data", {})
    certificate = data.get("certificate")
    if ("private_key" in data or not isinstance(certificate, str)
            or not certificate.startswith("-----BEGIN CERTIFICATE-----\n")
            or "PRIVATE KEY" in certificate or len(certificate) > 64 * 1024):
        raise RuntimeError("CA replacement exported or omitted key material")
    checked_issuer_certificate(certificate, kind, version)
    live = bao.request("GET", f"{mount}/cert/ca", token=token).get("data", {})
    if live.get("certificate") != certificate:
        raise RuntimeError("CA replacement differs from its mounted issuer")
    validity = subprocess.run(
        ["openssl", "x509", "-checkend", str(300 * 24 * 60 * 60), "-noout"],
        input=certificate.encode("ascii"), capture_output=True, timeout=10, check=False,
    )
    if validity.returncode:
        raise RuntimeError("CA replacement expires before the overlap window")
    destination = output / f"{kind}-ca-v{version}.crt"
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as stream:
        stream.write(certificate)
        stream.flush()
        os.fsync(stream.fileno())
    return mount


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("bootstrap", "login", "stage-issuer"), required=True)
    parser.add_argument("--bao-addr", required=True)
    parser.add_argument("--bao-ca", required=True, type=Path)
    parser.add_argument("--token-file", type=Path)
    parser.add_argument("--current-secrets", type=Path)
    parser.add_argument("--identity", type=Path)
    parser.add_argument("--kind", choices=("workload", "keycloak"))
    parser.add_argument("--version", type=int)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        if (os.name != "posix" or not args.bao_ca.is_absolute()
                or args.bao_ca.is_symlink() or not args.bao_ca.is_file()):
            raise ValueError("CA-rotation OpenBao endpoint is invalid")
        snapshot_origin(args.bao_addr)
        if args.mode == "bootstrap":
            if (args.identity is not None or args.token_file is None
                    or args.current_secrets is None or args.kind is not None
                    or args.version is not None):
                raise ValueError("bootstrap requires the root token and current generation")
            token = private_file(args.token_file).strip()
            if len(token) < 20:
                raise ValueError("CA-rotation bootstrap root token is invalid")
            bootstrap(Bao(args.bao_addr, args.bao_ca, token),
                      args.current_secrets, args.output)
        elif args.mode == "login":
            if (args.identity is None or args.token_file is not None
                    or args.current_secrets is not None or args.kind is not None
                    or args.version is not None):
                raise ValueError("login requires only the existing CA identity")
            output = private_empty_or_source(args.output, empty=True)
            if output.stat().st_uid != os.getuid():
                raise ValueError("CA-rotation login output has an unexpected owner")
            bao = Bao(args.bao_addr, args.bao_ca, "")
            write_private(output / TOKEN_FILE, checked_login(bao, args.identity))
        else:
            if (args.identity is None or args.token_file is not None
                    or args.current_secrets is not None or args.kind is None
                    or args.version is None):
                raise ValueError("issuer staging requires one kind, version and CA identity")
            bao = Bao(args.bao_addr, args.bao_ca, "")
            stage_issuer(bao, args.identity, args.output, args.kind, args.version)
    except (OSError, ValueError, RuntimeError, HTTPError,
            subprocess.SubprocessError) as error:
        print(f"self-host CA-rotation identity failed: {type(error).__name__}", file=sys.stderr)
        return 2
    print("Scoped self-host CA-rotation identity is ready")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
