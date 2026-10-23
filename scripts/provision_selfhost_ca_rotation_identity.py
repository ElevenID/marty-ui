#!/usr/bin/env python3
"""Bootstrap or log in to a bounded, rootless self-host CA-rotation AppRole.

Only the initial installation root may create this identity. Routine CA
rotation uses the separate RoleID/SecretID pair and exact versioned PKI paths.
The operator can issue public certificates but cannot export Transit keys,
change policies or operate an unrelated mount.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from urllib.error import HTTPError

sys.dont_write_bytecode = True
from selfhost_native_operator import OperatorCleanupError, approle_operation, approle_policy  # noqa: E402
from selfhost_operator_inputs import private_file, write_private, snapshot_origin, private_empty_or_source  # noqa: E402
from provision_selfhost_renewal_identity import existing_policy_names  # noqa: E402
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
    return approle_policy("ca-rotation", names=names)


def checked_login(bao: Bao, identity: Path) -> str:
    return approle_operation(bao, "login", "ca-rotation", identity)["token"]


def bootstrap(bao: Bao, current: Path, output: Path) -> None:
    output = private_empty_or_source(output, empty=True)
    if output.stat().st_uid != os.getuid():
        raise ValueError("CA-rotation identity output has an unexpected owner")
    names = existing_policy_names(bao, current)
    approle_operation(bao, "bootstrap", "ca-rotation", output, names=names)


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
    except OperatorCleanupError as error:
        print(str(error), file=sys.stderr)
        return 3
    except (OSError, ValueError, RuntimeError, HTTPError,
            subprocess.SubprocessError) as error:
        print(f"self-host CA-rotation identity failed: {type(error).__name__}", file=sys.stderr)
        return 2
    print("Scoped self-host CA-rotation identity is ready")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
