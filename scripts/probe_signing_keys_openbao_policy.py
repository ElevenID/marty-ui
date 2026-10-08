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


def qualify(*, rust_adapter: bool = False) -> None:
    version = require_docker("run", "--rm", IMAGE, "version")
    ensure(
        f"OpenBao v{OPENBAO['version']}" in version
        and OPENBAO["source_revision"] in version,
        "pinned image metadata",
    )
    name = f"kms-signing-policy-{uuid.uuid4().hex[:12]}"
    redis_name = f"kms-signing-redis-{uuid.uuid4().hex[:12]}"
    root_token = f"disposable-root-{uuid.uuid4().hex}"
    started = False
    redis_started = False
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
                    "MARTY_TEST_OPENBAO_TOKEN": managed,
                    "MARTY_TEST_OPENBAO_ROOT_TOKEN": root_token,
                    "MARTY_TEST_OPENBAO_DISPOSABLE_NONCE": nonce,
                    "BAO_TOKEN": managed,
                    "MARTY_TEST_REDIS_URL": f"redis://127.0.0.1:{redis_port}/13",
                    "MARTY_TEST_REDIS_DISPOSABLE_NONCE": redis_nonce,
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
        print(
            "Scoped signing-keys policy passed against disposable OpenBao for six managed prefixes and isolated provider HMAC verification"
        )
        if rust_adapter:
            print(
                "Rust managed-key adapter, tenant routes, and managed-profile routes passed"
            )
    finally:
        if redis_started:
            docker("rm", "-f", redis_name, timeout=30)
        if started:
            docker("rm", "-f", name, timeout=30)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rust-adapter", action="store_true")
    qualify(rust_adapter=parser.parse_args().rust_adapter)
