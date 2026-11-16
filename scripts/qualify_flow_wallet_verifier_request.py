#!/usr/bin/env python3
"""Run exact Flow request-owner cases on newly owned TLS non-exportable keys.

This is real Transit signing plus an application/provider adapter, not a deployed
Signing Keys service, Trust Profile authority or installed-wallet acceptance.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

import probe_signing_keys_openbao_policy as fixtures

CASES = {
    "wallet_verifier_request::tests::immutable_owner_request_is_revalidated_without_resigning_or_shortening_instance",
    "wallet_verifier_request::tests::persisted_scope_and_original_jws_cannot_be_replaced_by_a_sibling_or_tampering",
    "wallet_verifier_request::tests::http_owner_persists_exact_request_and_cancellation_wins_async_reads",
}
OWNER = "flow-wallet-verifier-request-qualification"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def remove_owned(name, cid):
    require(re.fullmatch(r"[a-f0-9]{64}", cid), "invalid owned container identity")
    if not fixtures.require_docker("ps", "-aq", "--filter", f"id={cid}"):
        return
    actual = json.loads(fixtures.require_docker("inspect", cid))[0]
    labels = actual["Config"].get("Labels") or {}
    require(actual["Id"] == cid and actual["Name"] == f"/{name}"
            and labels.get("codex.purpose") == OWNER
            and labels.get("marty.disposable") == "flow-wallet-request",
            "refuse unowned Flow fixture cleanup")
    fixtures.require_docker("rm", "-f", "-v", cid, timeout=30)
    require(not fixtures.require_docker("ps", "-aq", "--filter", f"id={cid}"),
            "owned Flow fixture removal not verified")


def qualify(binary: Path):
    binary = binary.resolve(strict=True)
    require(binary.is_file() and os.access(binary, os.X_OK), "native executable required")
    discovery = subprocess.run([str(binary), "wallet_verifier_request::tests::", "--ignored", "--list"],
                               capture_output=True, text=True, timeout=30, check=False)
    require(discovery.returncode == 0 and {
        line.removesuffix(": test") for line in discovery.stdout.splitlines()
        if line.endswith(": test")
    } == CASES, "exact three ignored native cases must exist before fixture allocation")
    fixtures.pull_pinned_openbao()
    nonce, root_token = secrets.token_hex(32), secrets.token_urlsafe(32)
    name, key = "wallet-flow-request-" + nonce[:12], "wallet-request-" + nonce
    cid = pg_cid = None
    pg_name = name + "-postgres"
    pg_password = secrets.token_urlsafe(32)
    with tempfile.TemporaryDirectory(prefix="marty-flow-request-") as directory:
        private = Path(directory)
        os.chmod(private, 0o700)
        try:
            # Reuse the pinned catalog image already present locally. This
            # allocates only a task-owned, bounded, ephemeral local fixture.
            fixtures.require_docker("image", "inspect", fixtures.POSTGRES_IMAGE)
            database = "wallet_request_" + nonce[:12]
            pg_cid = fixtures.require_docker("run", "--rm", "-d", "--name", pg_name,
                "--label", f"codex.purpose={OWNER}", "--label", "marty.disposable=flow-wallet-request",
                "--memory", "256m", "--memory-swap", "256m",
                "--tmpfs", "/var/lib/postgresql/data:rw,mode=0700",
                "-e", f"POSTGRES_PASSWORD={pg_password}", "-e", f"POSTGRES_DB={database}",
                "-p", "127.0.0.1::5432", fixtures.POSTGRES_IMAGE)
            pg_port = int(fixtures.require_docker("port", pg_cid, "5432/tcp").splitlines()[0].rsplit(":", 1)[1])
            for _ in range(60):
                ready = fixtures.docker("exec", pg_cid, "pg_isready", "-h", "127.0.0.1", "-U", "postgres", "-d", database)
                if ready.returncode == 0:
                    break
                time.sleep(0.25)
            else:
                raise RuntimeError("owned PostgreSQL did not become ready")
            cid = fixtures.require_docker("run", "--rm", "-d", "--name", name,
                "--label", f"codex.purpose={OWNER}", "--label", "marty.disposable=flow-wallet-request",
                "--memory", "256m", "--memory-swap", "256m", "--tmpfs", "/tmp/bao-tls:rw,mode=1777",
                "-e", f"BAO_DEV_ROOT_TOKEN_ID={root_token}", "-p", "127.0.0.1::8200",
                fixtures.IMAGE, "server", "-dev", "-dev-tls", "-dev-listen-address=0.0.0.0:8200",
                "-dev-tls-cert-dir=/tmp/bao-tls")
            port = int(fixtures.require_docker("port", cid, "8200/tcp").splitlines()[0].rsplit(":", 1)[1])
            base = f"https://127.0.0.1:{port}/v1"
            ca = private / "public-ca.pem"
            for _ in range(40):
                candidate = fixtures.docker("exec", cid, "cat", "/tmp/bao-tls/vault-ca.pem")
                if candidate.returncode == 0 and "BEGIN CERTIFICATE" in candidate.stdout:
                    ca.write_text(candidate.stdout, encoding="ascii")
                    break
                time.sleep(0.25)
            require(ca.is_file(), "owned public CA unavailable")
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), fixtures.NoRedirect(),
                urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(ca))))

            def call(method, path, body=None, token=root_token):
                request = urllib.request.Request(base + "/" + path,
                    data=None if body is None else json.dumps(body).encode(), method=method,
                    headers={"X-Vault-Token": token, "Content-Type": "application/json"})
                try:
                    with opener.open(request, timeout=10) as response:
                        raw = response.read(128 * 1024)
                        return response.status, json.loads(raw) if raw else {}
                except urllib.error.HTTPError as error:
                    return error.code, {}

            for _ in range(40):
                try:
                    if call("GET", "sys/health")[0] == 200:
                        break
                except (OSError, urllib.error.URLError):
                    pass
                time.sleep(0.25)
            else:
                raise RuntimeError("owned TLS OpenBao did not become ready")
            require(call("POST", "sys/mounts/transit", {"type": "transit"})[0] in (200, 204), "owned Transit mount failed")
            require(call("POST", f"transit/keys/{key}", {"type": "ecdsa-p256", "exportable": False,
                "allow_plaintext_backup": False})[0] in (200, 204), "non-exportable fixture key creation failed")
            status, metadata = call("GET", f"transit/keys/{key}")
            require(status == 200 and metadata["data"]["exportable"] is False
                    and metadata["data"]["allow_plaintext_backup"] is False, "fixture key custody mismatch")
            pem = metadata["data"]["keys"]["1"]["public_key"].encode()
            public = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "DER"], input=pem,
                                    capture_output=True, timeout=10, check=False)
            require(public.returncode == 0 and public.stdout.startswith(bytes.fromhex(
                "3059301306072a8648ce3d020106082a8648ce3d03010703420004")) and len(public.stdout) == 91,
                "fixture public key must be P-256 SPKI")
            point = public.stdout[-65:]
            def encode(value):
                return base64.urlsafe_b64encode(value).decode().rstrip("=")
            jwk = {"kty": "EC", "crv": "P-256", "x": encode(point[1:33]), "y": encode(point[33:])}
            require(call("GET", f"transit/export/signing-key/{key}")[0] >= 400, "fixture key export was not refused")
            require(call("PUT", "sys/policies/acl/wallet-request-fixture", {"policy":
                f'path "transit/sign/{key}" {{ capabilities = ["update"] }}'})[0] in (200, 204), "fixture signer policy failed")
            status, issued = call("POST", "auth/token/create", {"policies": ["wallet-request-fixture"],
                "no_default_policy": True, "ttl": "5m", "explicit_max_ttl": "5m", "renewable": False})
            require(status == 200, "scoped signer token failed")
            signer_token = issued["auth"]["client_token"]
            token_file = private / "signer-token"
            token_file.write_text(signer_token)
            os.chmod(token_file, 0o600)
            environment = {key: value for key, value in os.environ.items()
                           if not key.startswith("MARTY_TEST_WALLET_REQUEST_")}
            environment.update(MARTY_TEST_WALLET_REQUEST_FIXTURE_NONCE=nonce,
                MARTY_TEST_WALLET_REQUEST_DATABASE_URL=f"postgresql://postgres:{pg_password}@127.0.0.1:{pg_port}/{database}",
                MARTY_TEST_WALLET_REQUEST_SIGN_URL=f"{base}/transit/sign/{key}",
                MARTY_TEST_WALLET_REQUEST_CA=str(ca), MARTY_TEST_WALLET_REQUEST_TOKEN_FILE=str(token_file),
                MARTY_TEST_WALLET_REQUEST_PUBLIC_JWK=json.dumps(jwk))
            result = subprocess.run([str(binary), "wallet_verifier_request::tests::", "--ignored", "--nocapture"],
                env=environment, capture_output=True, text=True, timeout=90, check=False)
            output = (result.stdout + result.stderr).replace(root_token, "<redacted>").replace(signer_token, "<redacted>").replace(pg_password, "<redacted>")
            if path := os.environ.get("MARTY_FLOW_OWNER_DIAGNOSTIC"):
                Path(path).write_text(output)
            if result.returncode or not re.search(r"test result: ok\. 3 passed; 0 failed; 0 ignored;", result.stdout):
                print(output[-6000:], file=sys.stderr)
                raise RuntimeError("owned Flow request native cases failed; no pass claimed")
            print(result.stdout)
        finally:
            try:
                if cid:
                    remove_owned(name, cid)
            finally:
                if pg_cid:
                    remove_owned(pg_name, pg_cid)
    print(json.dumps({"passed": 3, "ignored": 0, "nonExportableKey": True, "tlsVerified": True,
        "postgresqlHttpPersistenceAndCancellation": True,
        "ownedContainerRemoved": True, "temporaryMaterialRemoved": True,
        "scope": "actual PostgreSQL HTTP persistence/CAS and TLS Transit signatures with application/provider adapter; not deployed owner, rootless installation or installed-wallet acceptance"}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-binary", type=Path, required=True)
    qualify(parser.parse_args().test_binary)
