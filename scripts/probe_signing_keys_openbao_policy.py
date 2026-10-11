"""Qualify the shipped signing-keys ACL against disposable pinned OpenBao.

Creates only a labeled dev container, synthetic Transit keys and short-lived
tokens. It never contacts an existing OpenBao deployment or reads host secrets.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "deploy-config/passport-supported-disposable-infra-images.json"
OPENBAO = json.loads(CATALOG.read_text(encoding="utf-8"))["images"]["openbao"]
IMAGE = OPENBAO["reference"]
REDIS_IMAGE = json.loads(CATALOG.read_text(encoding="utf-8"))["images"]["redis"][
    "reference"
]
POSTGRES_IMAGE = json.loads(CATALOG.read_text(encoding="utf-8"))["images"][
    "postgres"
]["reference"]


def docker(*args: str, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=timeout, check=False
    )


def require_docker(*args: str, timeout: int = 120) -> str:
    result = docker(*args, timeout=timeout)
    if result.returncode:
        # Provider/bootstrap output may contain credentials; keep errors generic.
        raise RuntimeError(f"Disposable Docker operation failed: {args[0]}")
    return result.stdout.strip()


def ensure(condition: bool, operation: str) -> None:
    if not condition:
        raise RuntimeError(f"Scoped signing-keys policy failed: {operation}")


def qualify(*, rust_adapter: bool = False, grant_verifier: bool = False) -> None:
    ensure(not (rust_adapter and grant_verifier), "select one Rust adapter mode")
    version = require_docker("run", "--rm", IMAGE, "version")
    ensure(
        f"OpenBao v{OPENBAO['version']}" in version
        and OPENBAO["source_revision"] in version,
        "pinned image metadata",
    )
    name = f"kms-signing-policy-{uuid.uuid4().hex[:12]}"
    redis_name = f"kms-signing-redis-{uuid.uuid4().hex[:12]}"
    postgres_name = f"kms-holder-postgres-{uuid.uuid4().hex[:12]}"
    root_token = f"disposable-root-{uuid.uuid4().hex}"
    postgres_password = f"disposable-holder-{uuid.uuid4().hex}"
    started = False
    redis_started = False
    postgres_started = False
    try:
        require_docker(
            "run",
            "--rm",
            "-d",
            "--name",
            name,
            "--label",
            "marty.disposable=kms-signing-policy",
            "-e",
            f"BAO_DEV_ROOT_TOKEN_ID={root_token}",
            "-p",
            "127.0.0.1::8200",
            IMAGE,
            "server",
            "-dev",
        )
        started = True
        mapping = require_docker("port", name, "8200/tcp")
        port = int(mapping.splitlines()[0].rsplit(":", 1)[1])
        endpoint = f"http://127.0.0.1:{port}/v1"

        def call(
            method: str, path: str, token: str, body: dict | None = None
        ) -> tuple[int, dict]:
            payload = None if body is None else json.dumps(body).encode()
            request = urllib.request.Request(
                f"{endpoint}/{path}",
                data=payload,
                method=method,
                headers={"X-Vault-Token": token, "Content-Type": "application/json"},
            )
            try:
                with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310 - disposable loopback only
                    raw = response.read()
                    return response.status, json.loads(raw) if raw else {}
            except urllib.error.HTTPError as error:
                error.read()
                return error.code, {}

        for _ in range(40):
            try:
                status, _ = call("GET", "sys/health", root_token)
                if status == 200:
                    break
            except OSError:
                pass
            time.sleep(0.25)
        else:
            raise RuntimeError("Disposable OpenBao did not become healthy")

        init_script = ROOT / "docker/openbao-init.sh"
        require_docker(
            "run",
            "--rm",
            "--network",
            f"container:{name}",
            "-e",
            "BAO_ADDR=http://127.0.0.1:8200",
            "-e",
            f"BAO_TOKEN={root_token}",
            "-v",
            f"{init_script}:/scripts/openbao-init.sh:ro",
            IMAGE,
            "/bin/sh",
            "/scripts/openbao-init.sh",
        )

        def issue(policies: list[str]) -> str:
            status, response = call(
                "POST",
                "auth/token/create",
                root_token,
                {"policies": policies, "no_default_policy": True},
            )
            ensure(status == 200, "issue token")
            return response["auth"]["client_token"]

        managed = issue(["credential-service", "signing-keys-managed"])
        plain = issue(["credential-service"])
        status, lookup = call(
            "POST", "auth/token/lookup", root_token, {"token": managed}
        )
        ensure(status == 200, "look up managed token")
        ensure(
            set(lookup["data"]["policies"])
            == {"credential-service", "signing-keys-managed"},
            "managed token policy isolation",
        )

        cases = (
            ("cred-issuer-probe", "ecdsa-p256"),
            ("cred-dsc-probe", "ecdsa-p521"),
            ("cred-holder-probe", "ed25519"),
            ("cred-presenter-probe", "ecdsa-p256"),
            ("lti-tool-probe", "rsa-2048"),
            ("oid4vp-verifier-probe", "ecdsa-p256"),
        )
        for reference, algorithm in cases:
            path = f"transit/keys/{reference}"
            ensure(
                call("POST", path, managed, {"type": algorithm})[0] == 200,
                f"create {reference}",
            )
            ensure(
                call("POST", f"{path}/rotate", managed, {})[0] == 200,
                f"rotate {reference}",
            )
            status, metadata = call("GET", path, managed)
            ensure(status == 200, f"read {reference}")
            data = metadata["data"]
            ensure(
                data["latest_version"] == 2 and data["type"] == algorithm,
                f"metadata {reference}",
            )
            for flag in (
                "exportable",
                "allow_plaintext_backup",
                "deletion_allowed",
                "imported_key",
            ):
                ensure(data[flag] is False, f"{reference} {flag}")
            ensure(
                call(
                    "POST", f"transit/sign/{reference}", managed, {"input": "dGVzdA=="}
                )[0]
                == 200,
                f"sign {reference}",
            )
            ensure(
                call(
                    "POST",
                    f"{path}/import",
                    managed,
                    {"type": algorithm, "public_key": "invalid"},
                )[0]
                == 403,
                f"deny import {reference}",
            )
            ensure(
                call("POST", f"{path}/config", managed, {"exportable": True})[0] == 403,
                f"deny exportable {reference}",
            )

        for reference in ("cred-holder-probe", "cred-presenter-probe"):
            path = f"transit/keys/{reference}"
            status, _ = call("POST", f"{path}/config", managed, {"deletion_allowed": True})
            ensure(
                status in (200, 204),
                f"allow scoped holder revocation {reference}: HTTP {status}",
            )
            ensure(
                call("DELETE", path, managed)[0] in (200, 204),
                f"delete retired holder key {reference}",
            )
            ensure(call("GET", path, managed)[0] == 404, f"retired {reference} absent")
        ensure(
            call("POST", "transit/keys/cred-issuer-probe/config", managed,
                 {"deletion_allowed": True})[0] == 403,
            "deny issuer deletion enablement",
        )
        ensure(
            call("DELETE", "transit/keys/cred-issuer-probe", managed)[0] == 403,
            "deny issuer deletion",
        )

        ensure(
            call(
                "POST", "transit/keys/cred-issuer-plain", plain, {"type": "ecdsa-p256"}
            )[0]
            == 403,
            "plain token create",
        )
        ensure(
            call("POST", "transit/keys/cred-issuer-probe/rotate", plain, {})[0] == 403,
            "plain token rotate",
        )
        ensure(
            call(
                "POST",
                "transit/keys/cred-issuer-probe/import_version",
                managed,
                {"ciphertext": "invalid"},
            )[0]
            == 403,
            "deny import version",
        )
        ensure(
            call("GET", "transit/export/signing-key/cred-issuer-probe", managed)[0]
            == 403,
            "deny private export",
        )
        ensure(
            call("POST", "transit/keys/auth-session-es256/rotate", managed, {})[0]
            == 403,
            "deny unrelated rotation",
        )
        supported_callback = issue(["passport-provider-callback-service"])
        beta_callback = issue(["passport-callback-hmac-service"])
        provider_profile = "provider-policy-probe"
        provider_key = "passport-provider-callback-" + hashlib.sha256(
            provider_profile.encode("ascii")
        ).hexdigest()
        ensure(
            call("POST", f"transit/keys/{provider_key}", root_token,
                 {"type": "hmac", "key_size": 32, "exportable": False})[0] == 200,
            "create synthetic provider HMAC key",
        )
        status, hmac_response = call(
            "POST", f"transit/hmac/{provider_key}", root_token,
            {"input": "ZXhhY3QtcHJvdmlkZXItYm9keQ=="},
        )
        ensure(status == 200, "root generates synthetic provider HMAC")
        signature = hmac_response["data"]["hmac"]
        status, verified = call(
            "POST", f"transit/verify/{provider_key}", supported_callback,
            {"input": "ZXhhY3QtcHJvdmlkZXItYm9keQ==", "hmac": signature},
        )
        ensure(status == 200 and verified.get("data", {}).get("valid") is True,
               "supported token verifies provider HMAC")
        status, tampered = call(
            "POST", f"transit/verify/{provider_key}", supported_callback,
            {"input": "dGFtcGVyZWQ=", "hmac": signature},
        )
        ensure(status == 200 and tampered.get("data", {}).get("valid") is False,
               "provider HMAC rejects tampered body")
        for method, path, body in (
            ("POST", f"transit/hmac/{provider_key}",
             {"input": "ZXhhY3QtcHJvdmlkZXItYm9keQ=="}),
            ("GET", f"transit/keys/{provider_key}", None),
            ("GET", f"transit/export/hmac-key/{provider_key}", None),
            ("POST", "transit/verify/passport-bureau-callback-marty-hmac",
             {"input": "ZXhhY3QtcHJvdmlkZXItYm9keQ==", "hmac": signature}),
        ):
            ensure(call(method, path, supported_callback, body)[0] == 403,
                   f"supported callback token denies {path}")
        ensure(
            call("POST", f"transit/verify/{provider_key}", beta_callback,
                 {"input": "ZXhhY3QtcHJvdmlkZXItYm9keQ==", "hmac": signature})[0]
            == 403,
            "beta callback token cannot verify provider HMAC",
        )
        grant_origins = (
            "gateway-service", "gateway-issuer-did", "flow-wallet",
            "issuance-credential", "issuance-canvas",
            "issuance-readiness", "issuance-passport",
        )
        grant_mint_tokens = {
            origin: issue([f"sign-grant-mint-{origin}"])
            for origin in grant_origins
        }
        grant_verify_token = issue(["sign-grant-verify"])
        grant_input = base64.b64encode(b"exact scoped signing operation").decode()
        for origin in grant_origins:
            key = f"marty-sign-grant-{origin}-v1"
            status, metadata = call("GET", f"transit/keys/{key}", root_token)
            ensure(status == 200, f"read {origin} grant key")
            ensure(
                metadata["data"]["type"] == "hmac"
                and metadata["data"]["exportable"] is False
                and metadata["data"]["allow_plaintext_backup"] is False,
                f"{origin} grant key custody",
            )
            status, minted = call(
                "POST", f"transit/hmac/{key}/sha2-256",
                grant_mint_tokens[origin], {"input": grant_input},
            )
            ensure(status == 200, f"mint {origin} grant")
            hmac = minted["data"]["hmac"]
            status, verified = call(
                "POST", f"transit/verify/{key}/sha2-256",
                grant_verify_token, {"input": grant_input, "hmac": hmac},
            )
            ensure(
                status == 200 and verified.get("data", {}).get("valid") is True,
                f"verify {origin} grant",
            )
            ensure(
                call("POST", f"transit/verify/{key}/sha2-256",
                     grant_mint_tokens[origin],
                     {"input": grant_input, "hmac": hmac})[0] == 403,
                f"{origin} mint token cannot verify",
            )
            ensure(
                call("POST", f"transit/hmac/{key}/sha2-256",
                     grant_verify_token, {"input": grant_input})[0] == 403,
                f"verify token cannot mint {origin}",
            )
            ensure(
                call("GET", f"transit/export/hmac-key/{key}",
                     grant_mint_tokens[origin])[0] == 403,
                f"{origin} mint token cannot export",
            )
            for other in grant_origins:
                if other == origin:
                    continue
                other_key = f"marty-sign-grant-{other}-v1"
                ensure(
                    call("POST", f"transit/hmac/{other_key}/sha2-256",
                         grant_mint_tokens[origin], {"input": grant_input})[0]
                    == 403,
                    f"{origin} mint token cannot mint {other}",
                )
                status, wrong_origin = call(
                    "POST", f"transit/verify/{other_key}/sha2-256",
                    grant_verify_token, {"input": grant_input, "hmac": hmac},
                )
                ensure(
                    status == 200
                    and wrong_origin.get("data", {}).get("valid") is False,
                    f"{origin} grant cannot verify as {other}",
                )
        if grant_verifier:
            require_docker(
                "run", "--rm", "-d", "--name", redis_name,
                "--label", "marty.disposable=kms-signing-policy",
                "-p", "127.0.0.1::6379", REDIS_IMAGE,
            )
            redis_started = True
            redis_port = int(
                require_docker("port", redis_name, "6379/tcp")
                .splitlines()[0].rsplit(":", 1)[1]
            )
            redis_nonce = uuid.uuid4().hex
            for _ in range(40):
                ready = docker("exec", redis_name, "redis-cli", "ping")
                if ready.returncode == 0 and ready.stdout.strip() == "PONG":
                    break
                time.sleep(0.25)
            else:
                raise RuntimeError("Disposable Redis did not become healthy")
            require_docker(
                "exec", redis_name, "redis-cli", "-n", "13", "SET",
                "marty:tests:disposable-guard", redis_nonce,
            )
            nonce = uuid.uuid4().hex
            status, _ = call(
                "POST", "secret/data/marty-test-disposable-guard",
                root_token, {"data": {"nonce": nonce}},
            )
            ensure(status in (200, 204), "write disposable grant verifier guard")
            environment = os.environ.copy()
            environment.update({
                "MARTY_TEST_OPENBAO_URL": endpoint.removesuffix("/v1"),
                "BAO_ADDR": endpoint.removesuffix("/v1"),
                "MARTY_TEST_OPENBAO_ROOT_TOKEN": root_token,
                "MARTY_TEST_OPENBAO_DISPOSABLE_NONCE": nonce,
                "MARTY_TEST_OPENBAO_TOKEN": root_token,
                "BAO_TOKEN": root_token,
                "MARTY_TEST_GRANT_MINT_TOKEN": grant_mint_tokens["gateway-service"],
                "MARTY_TEST_GRANT_ISSUER_MINT_TOKEN": grant_mint_tokens["gateway-issuer-did"],
                "MARTY_TEST_GRANT_PASSPORT_MINT_TOKEN": grant_mint_tokens["issuance-passport"],
                "MARTY_TEST_GRANT_VERIFY_TOKEN": grant_verify_token,
                "MARTY_TEST_REDIS_URL": f"redis://127.0.0.1:{redis_port}/13",
                "MARTY_TEST_REDIS_DISPOSABLE_NONCE": redis_nonce,
            })
            result = subprocess.run(
                ["cargo", "+1.95.0", "test", "-p", "marty-signing-grant",
                 "--lib", "--locked", "--offline", "-j1",
                 "live_grant_verification_is_one_use_before_kms_signing",
                 "--", "--ignored", "--nocapture"],
                cwd=ROOT / "rust", env=environment, capture_output=True,
                text=True, timeout=600, check=False,
            )
            if result.returncode:
                detail = (result.stdout + result.stderr).replace(root_token, "[root]")
                detail = detail.replace(grant_verify_token, "[verify]")
                detail = detail.replace(
                    grant_mint_tokens["gateway-service"], "[mint]",
                )
                raise RuntimeError(f"Rust live grant verifier failed:\n{detail[-2000:]}")
            result = subprocess.run(
                ["cargo", "+1.95.0", "test", "-p", "marty-signing-keys",
                 "--test", "service_certificate_live_kms", "--locked", "--offline",
                 "-j1", "registered_service_csr_is_signed_by_kms_through_public_rust_route",
                 "--", "--ignored", "--nocapture"],
                cwd=ROOT / "rust", env=environment, capture_output=True,
                text=True, timeout=600, check=False,
            )
            if result.returncode:
                detail = (result.stdout + result.stderr).replace(root_token, "[root]")
                detail = detail.replace(managed, "[managed]")
                detail = detail.replace(grant_verify_token, "[verify]")
                detail = detail.replace(
                    grant_mint_tokens["gateway-service"], "[mint]",
                )
                raise RuntimeError(f"Rust live Signing Keys route failed:\n{detail[-2000:]}")
            result = subprocess.run(
                ["cargo", "+1.95.0", "test", "-p", "marty-service-acceptance",
                 "--test", "passport_managed_kms_chain", "--locked", "--offline",
                 "-j1", "managed_passport_chain_issues_and_verifies_sod_without_exporting_private_keys",
                 "--", "--ignored", "--exact", "--nocapture"],
                cwd=ROOT / "rust", env=environment, capture_output=True,
                text=True, timeout=600, check=False,
            )
            if result.returncode:
                detail = (result.stdout + result.stderr).replace(root_token, "[root]")
                detail = detail.replace(grant_verify_token, "[verify]")
                for token in grant_mint_tokens.values():
                    detail = detail.replace(token, "[mint]")
                raise RuntimeError(f"Rust live managed passport chain failed:\n{detail[-2000:]}")
        if rust_adapter:
            require_docker(
                "run",
                "--rm",
                "-d",
                "--name",
                redis_name,
                "--label",
                "marty.disposable=kms-signing-policy",
                "-p",
                "127.0.0.1::6379",
                REDIS_IMAGE,
            )
            redis_started = True
            redis_port = int(
                require_docker("port", redis_name, "6379/tcp")
                .splitlines()[0]
                .rsplit(":", 1)[1]
            )
            redis_nonce = uuid.uuid4().hex
            for _ in range(40):
                ready = docker("exec", redis_name, "redis-cli", "ping")
                if ready.returncode == 0 and ready.stdout.strip() == "PONG":
                    break
                time.sleep(0.25)
            else:
                raise RuntimeError("Disposable Redis did not become healthy")
            require_docker(
                "exec",
                redis_name,
                "redis-cli",
                "-n",
                "13",
                "SET",
                "marty:tests:disposable-guard",
                redis_nonce,
            )
            require_docker(
                "run", "--rm", "-d", "--name", postgres_name,
                "--label", "marty.disposable=kms-signing-policy",
                "-e", f"POSTGRES_PASSWORD={postgres_password}",
                "-e", "POSTGRES_DB=marty_holder_test",
                "-p", "127.0.0.1::5432", POSTGRES_IMAGE,
            )
            postgres_started = True
            postgres_port = int(
                require_docker("port", postgres_name, "5432/tcp")
                .splitlines()[0].rsplit(":", 1)[1]
            )
            for _ in range(80):
                ready = docker(
                    "exec", postgres_name, "pg_isready", "-U", "postgres",
                    "-d", "marty_holder_test",
                )
                if ready.returncode == 0:
                    break
                time.sleep(0.25)
            else:
                raise RuntimeError("Disposable holder PostgreSQL did not become healthy")
            nonce = uuid.uuid4().hex
            status, _ = call(
                "POST",
                "secret/data/marty-test-disposable-guard",
                root_token,
                {"data": {"nonce": nonce}},
            )
            ensure(status in (200, 204), "write disposable Rust guard")
            environment = os.environ.copy()
            environment.update(
                {
                    "MARTY_TEST_OPENBAO_URL": endpoint.removesuffix("/v1"),
                    "BAO_ADDR": endpoint.removesuffix("/v1"),
                    "MARTY_TEST_OPENBAO_TOKEN": managed,
                    "MARTY_TEST_OPENBAO_ROOT_TOKEN": root_token,
                    "MARTY_TEST_OPENBAO_DISPOSABLE_NONCE": nonce,
                    "BAO_TOKEN": managed,
                    "MARTY_TEST_GRANT_MINT_TOKEN": grant_mint_tokens["gateway-service"],
                    "MARTY_TEST_GRANT_ISSUER_MINT_TOKEN": grant_mint_tokens["gateway-issuer-did"],
                    "MARTY_TEST_GRANT_VERIFY_TOKEN": grant_verify_token,
                    "MARTY_TEST_REDIS_URL": f"redis://127.0.0.1:{redis_port}/13",
                    "MARTY_TEST_REDIS_DISPOSABLE_NONCE": redis_nonce,
                    "DEVICE_REGISTRATION_POSTGRES_TEST_URL": (
                        f"postgres://postgres:{postgres_password}@127.0.0.1:"
                        f"{postgres_port}/marty_holder_test"
                    ),
                }
            )
            provider_environment = dict(environment)
            provider_environment.update({
                "MARTY_TEST_PROVIDER_CALLBACK_TOKEN": supported_callback,
                "MARTY_TEST_PROVIDER_PROFILE_ID": provider_profile,
                "MARTY_TEST_PROVIDER_CALLBACK_BODY_B64": "ZXhhY3QtcHJvdmlkZXItYm9keQ==",
                "MARTY_TEST_PROVIDER_CALLBACK_HMAC_HEX": base64.b64decode(
                    signature.split(":", 2)[2], validate=True
                ).hex(),
            })
            result = subprocess.run(
                ["cargo", "+1.95", "test", "-p", "marty-signing-keys",
                 "--test", "provider_callback_live_kms", "--locked", "--offline",
                 "-j2", "--", "--ignored", "--nocapture"],
                cwd=ROOT / "rust", env=provider_environment,
                capture_output=True, text=True, timeout=600, check=False,
            )
            if result.returncode:
                detail = (result.stdout + result.stderr).replace(root_token, "[root]")
                detail = detail.replace(supported_callback, "[scoped]")
                raise RuntimeError(f"Rust provider HMAC verifier failed:\n{detail[-2000:]}")
            result = subprocess.run(
                [
                    "cargo",
                    "+1.95",
                    "test",
                    "-p",
                    "marty-signing-keys",
                    "--test",
                    "managed_policy_live_kms",
                    "--locked",
                    "--offline",
                    "-j2",
                    "--",
                    "--ignored",
                    "--nocapture",
                ],
                cwd=ROOT / "rust",
                env=environment,
                capture_output=True,
                text=True,
                timeout=600,
                check=False,
            )
            if result.returncode:
                detail = (result.stdout + result.stderr).replace(root_token, "[root]")
                detail = detail.replace(managed, "[scoped]")
                raise RuntimeError(
                    f"Rust managed-key adapter failed:\n{detail[-2000:]}"
                )
            for algorithm, key_type in (
                ("es256", "ecdsa-p256"),
                ("es384", "ecdsa-p384"),
                ("es512", "ecdsa-p521"),
            ):
                reference = f"cred-dsc-csr-contract-{algorithm}"
                ensure(
                    call("POST", f"transit/keys/{reference}", managed,
                         {"type": key_type})[0] == 200,
                    f"create non-exportable CSR key {algorithm}",
                )
                status, metadata = call("GET", f"transit/keys/{reference}", managed)
                ensure(
                    status == 200
                    and metadata["data"]["type"] == key_type
                    and metadata["data"]["exportable"] is False
                    and metadata["data"]["allow_plaintext_backup"] is False,
                    f"non-exportable CSR key metadata {algorithm}",
                )
            result = subprocess.run(
                [
                    "cargo", "+1.95", "test", "-p", "marty-signing-keys",
                    "--test", "certificate_csr_live_kms", "--locked", "--offline",
                    "-j2", "csr_is_signed_and_verified_for_every_passport_ecdsa_curve_in_kms",
                    "--", "--ignored", "--exact", "--nocapture",
                ],
                cwd=ROOT / "rust", env=environment,
                capture_output=True, text=True, timeout=600, check=False,
            )
            if result.returncode:
                detail = (result.stdout + result.stderr).replace(root_token, "[root]")
                detail = detail.replace(managed, "[scoped]")
                raise RuntimeError(f"Rust live CSR custody failed:\n{detail[-2000:]}")
            result = subprocess.run(
                [
                    "cargo", "+1.95", "test", "-p", "marty-device-registration",
                    "--test", "holder_remote_live_kms", "--locked", "--offline",
                    "-j2", "--", "--ignored", "--nocapture",
                ],
                cwd=ROOT / "rust", env=environment,
                capture_output=True, text=True, timeout=600, check=False,
            )
            if result.returncode:
                detail = (result.stdout + result.stderr).replace(root_token, "[root]")
                detail = detail.replace(managed, "[scoped]")
                detail = detail.replace(postgres_password, "[postgres]")
                raise RuntimeError(
                    f"Rust holder service/DB/OpenBao lifecycle failed:\n{detail[-2000:]}"
                )
            result = subprocess.run(
                [
                    "cargo", "+1.95", "test", "-p", "marty-device-registration",
                    "--test", "holder_credential_persistence", "--locked", "--offline",
                    "-j2", "--", "--nocapture",
                ],
                cwd=ROOT / "rust", env=environment,
                capture_output=True, text=True, timeout=600, check=False,
            )
            if result.returncode:
                detail = (result.stdout + result.stderr).replace(root_token, "[root]")
                detail = detail.replace(managed, "[scoped]")
                detail = detail.replace(postgres_password, "[postgres]")
                raise RuntimeError(
                    f"Rust holder credential durability failed:\n{detail[-2000:]}"
                )
            result = subprocess.run(
                [
                    "cargo", "+1.95", "test", "-p", "marty-device-registration",
                    "--test", "postgres_custody", "--locked", "--offline", "-j2",
                    "--", "--nocapture",
                ],
                cwd=ROOT / "rust", env=environment,
                capture_output=True, text=True, timeout=600, check=False,
            )
            if result.returncode:
                detail = (result.stdout + result.stderr).replace(root_token, "[root]")
                detail = detail.replace(postgres_password, "[postgres]")
                raise RuntimeError(
                    f"Rust fresh keyless schema custody failed:\n{detail[-2000:]}"
                )
            result = subprocess.run(
                [
                    "cargo", "+1.95", "test", "-p", "marty-device-registration",
                    "--test", "pairing_ticket_redis", "--locked", "--offline",
                    "-j2", "--", "--ignored", "--nocapture",
                ],
                cwd=ROOT / "rust", env=environment,
                capture_output=True, text=True, timeout=600, check=False,
            )
            if result.returncode:
                detail = (result.stdout + result.stderr).replace(root_token, "[root]")
                detail = detail.replace(managed, "[scoped]")
                detail = detail.replace(postgres_password, "[postgres]")
                raise RuntimeError(
                    f"Rust one-time pairing Redis contract failed:\n{detail[-2000:]}"
                )
            result = subprocess.run(
                [
                    "cargo",
                    "+1.95",
                    "test",
                    "-p",
                    "marty-signing-keys",
                    "--test",
                    "public_service_sign_live_kms",
                    "--locked",
                    "--offline",
                    "-j2",
                    "managed_openbao_rs256_signature_matches_jose_pkcs1_profile",
                    "--",
                    "--ignored",
                    "--nocapture",
                ],
                cwd=ROOT / "rust",
                env=environment,
                capture_output=True,
                text=True,
                timeout=600,
                check=False,
            )
            if result.returncode:
                detail = (result.stdout + result.stderr).replace(root_token, "[root]")
                detail = detail.replace(managed, "[scoped]")
                raise RuntimeError(f"Rust live RS256 profile failed:\n{detail[-2000:]}")
            result = subprocess.run(
                [
                    "cargo",
                    "+1.95",
                    "test",
                    "-p",
                    "marty-signing-keys",
                    "--test",
                    "public_service_sign_live_kms",
                    "--locked",
                    "--offline",
                    "-j2",
                    "live_managed_alias_requires_tenant_purpose_and_algorithm_before_kms_sign",
                    "--",
                    "--ignored",
                    "--nocapture",
                ],
                cwd=ROOT / "rust",
                env=environment,
                capture_output=True,
                text=True,
                timeout=600,
                check=False,
            )
            if result.returncode:
                detail = (result.stdout + result.stderr).replace(root_token, "[root]")
                detail = detail.replace(managed, "[scoped]")
                raise RuntimeError(
                    f"Rust cross-tenant route check failed:\n{detail[-2000:]}"
                )
            result = subprocess.run(
                [
                    "cargo",
                    "+1.95",
                    "test",
                    "-p",
                    "marty-signing-keys",
                    "--test",
                    "public_service_sign_live_kms",
                    "--locked",
                    "--offline",
                    "-j2",
                    "live_managed_provider_rejects_foreign_profile_for_explicit_and_default_signing",
                    "--",
                    "--ignored",
                    "--nocapture",
                ],
                cwd=ROOT / "rust",
                env=environment,
                capture_output=True,
                text=True,
                timeout=600,
                check=False,
            )
            if result.returncode:
                detail = (result.stdout + result.stderr).replace(root_token, "[root]")
                detail = detail.replace(managed, "[scoped]")
                raise RuntimeError(
                    f"Rust live-provider tenant check failed:\n{detail[-2000:]}"
                )
            result = subprocess.run(
                [
                    "cargo", "+1.95", "test", "-p", "marty-signing-keys",
                    "--test", "public_service_sign_live_kms", "--locked", "--offline",
                    "-j2", "public_service_sign_uses_registered_kms_key_and_rejects_unbound_selection",
                    "--", "--ignored", "--nocapture",
                ],
                cwd=ROOT / "rust", env=environment,
                capture_output=True, text=True, timeout=600, check=False,
            )
            if result.returncode:
                detail = (result.stdout + result.stderr).replace(root_token, "[root]")
                detail = detail.replace(managed, "[scoped]")
                raise RuntimeError(
                    f"Rust registered-service signing check failed:\n{detail[-2000:]}"
                )
            mock_environment = dict(environment, BAO_TOKEN="test-only")
            result = subprocess.run(
                [
                    "cargo",
                    "+1.95",
                    "test",
                    "-p",
                    "marty-signing-keys",
                    "--test",
                    "managed_key_create_live_contract",
                    "--locked",
                    "--offline",
                    "-j1",
                    "--",
                    "--ignored",
                    "--nocapture",
                ],
                cwd=ROOT / "rust",
                env=mock_environment,
                capture_output=True,
                text=True,
                timeout=600,
                check=False,
            )
            if result.returncode:
                detail = (result.stdout + result.stderr).replace(root_token, "[root]")
                detail = detail.replace(managed, "[scoped]")
                raise RuntimeError(
                    f"Rust managed-profile route check failed:\n{detail[-2000:]}"
                )
            result = subprocess.run(
                [
                    "cargo", "+1.95", "test", "-p", "marty-service-acceptance",
                    "--test", "gateway_signing_acceptance", "--locked", "--offline",
                    "-j2", "authenticated_gateway_reaches_rust_managed_key_route_without_custody",
                    "--", "--ignored", "--exact", "--nocapture",
                ],
                cwd=ROOT / "rust", env=mock_environment,
                capture_output=True, text=True, timeout=600, check=False,
            )
            if result.returncode:
                detail = (result.stdout + result.stderr).replace(root_token, "[root]")
                detail = detail.replace(managed, "[scoped]")
                raise RuntimeError(
                    f"Rust Gateway managed-key route check failed:\n{detail[-2000:]}"
                )
            result = subprocess.run(
                [
                    "cargo", "+1.95", "test", "-p", "marty-service-acceptance",
                    "--test", "gateway_signing_acceptance", "--locked", "--offline",
                    "-j2", "authenticated_gateway_generates_profile_scoped_passport_csrs_in_openbao",
                    "--", "--ignored", "--exact", "--nocapture",
                ],
                cwd=ROOT / "rust", env=environment,
                capture_output=True, text=True, timeout=600, check=False,
            )
            if result.returncode:
                detail = (result.stdout + result.stderr).replace(root_token, "[root]")
                detail = detail.replace(managed, "[scoped]")
                raise RuntimeError(
                    f"Rust Gateway profile CSR check failed:\n{detail[-2000:]}"
                )
            result = subprocess.run(
                [
                    "cargo", "+1.95", "test", "-p", "marty-service-acceptance",
                    "--test", "gateway_signing_acceptance", "--locked", "--offline",
                    "-j2", "authenticated_gateway_generates_a_dedicated_service_csr_in_openbao",
                    "--", "--ignored", "--exact", "--nocapture",
                ],
                cwd=ROOT / "rust", env=environment,
                capture_output=True, text=True, timeout=600, check=False,
            )
            if result.returncode:
                detail = (result.stdout + result.stderr).replace(root_token, "[root]")
                detail = detail.replace(managed, "[scoped]")
                raise RuntimeError(
                    f"Rust Gateway real-provider sign/CSR check failed:\n{detail[-2000:]}"
                )
        print(
            "Scoped signing-keys policy passed against disposable OpenBao for six managed prefixes, isolated provider HMAC verification, and seven origin-bound signing-grant keys"
        )
        if rust_adapter:
            print(
                "Rust managed-key adapter, ES256/ES384/ES512 CSR custody, holder service/DB/OpenBao lifecycle, credential durability, Redis pairing tickets, tenant routes, and managed-profile routes passed"
            )
        if grant_verifier:
            print("Rust grant verifier, Signing Keys public CSR route, and managed passport CSCA/DSC/SOD chain passed with scoped grants and disposable Redis")
    finally:
        if postgres_started:
            docker("rm", "-f", postgres_name, timeout=30)
        if redis_started:
            docker("rm", "-f", redis_name, timeout=30)
        if started:
            docker("rm", "-f", name, timeout=30)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rust-adapter", action="store_true")
    parser.add_argument("--grant-verifier", action="store_true")
    args = parser.parse_args()
    qualify(rust_adapter=args.rust_adapter, grant_verifier=args.grant_verifier)
