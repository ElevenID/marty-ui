#!/usr/bin/env python3
"""Run keyless workload TLS contracts with disposable OpenBao.

Only public certificates and a scoped signer token leave the container.
OpenBao's dev TLS key remains inside the disposable container and is deleted
with it; no product workload private key is generated or written to a file.
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
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener


IMAGE = re.compile(r"quay\.io/openbao/openbao@sha256:[0-9a-f]{64}\Z")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def run(args: list[str], timeout: int = 30) -> str:
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    if result.returncode:
        raise RuntimeError(f"disposable fixture command failed: {args[0]} {args[1]}")
    return result.stdout.strip()


def require_pinned_image(image: str) -> None:
    """Acquire a pinned image before the bounded container startup."""
    try:
        run(["docker", "image", "inspect", image], timeout=20)
    except RuntimeError:
        run(["docker", "pull", image], timeout=180)


class Bao:
    def __init__(self, endpoint: str, ca: Path, token: str) -> None:
        self.endpoint = endpoint
        self.token = token
        self.opener = build_opener(
            ProxyHandler({}), HTTPSHandler(context=ssl.create_default_context(cafile=str(ca))),
            NoRedirect(),
        )

    def request(
        self, method: str, path: str, body: dict | None = None, *, token: str | None = None
    ) -> dict:
        data = None if body is None else json.dumps(body).encode("utf-8")
        request = Request(
            f"{self.endpoint}/v1/{path}", data=data, method=method,
            headers={"X-Vault-Token": token or self.token, "Content-Type": "application/json"},
        )
        with self.opener.open(request, timeout=10) as response:
            content = response.read(1024 * 1024 + 1)
        if len(content) > 1024 * 1024:
            raise RuntimeError("disposable OpenBao response exceeded size bound")
        return json.loads(content) if content else {}


def provision_server_identity(bao: Bao, root: Path, role: str) -> dict[str, str]:
    if role not in {"event-stream", "signing-keys", "signing-keys-image", "passport-edge", "oidf-edge"}:
        raise RuntimeError("unknown disposable server TLS role")
    bao.request("POST", "sys/mounts/transit", {"type": "transit"})
    key_name = role + "-tls-" + secrets.token_hex(8)
    bao.request("POST", f"transit/keys/{key_name}", {
        "type": "ecdsa-p256", "exportable": False, "allow_plaintext_backup": False,
    })
    metadata = bao.request("GET", f"transit/keys/{key_name}")["data"]
    if (metadata["type"] != "ecdsa-p256" or metadata["exportable"] is not False
            or metadata["allow_plaintext_backup"] is not False):
        raise RuntimeError("disposable server signer is not non-exportable")
    bao.request("POST", "sys/mounts/pki", {"type": "pki"})
    ca = bao.request("POST", "pki/root/generate/internal", {
        "common_name": f"Disposable {role} CA", "ttl": "48h",
        "key_type": "ec", "key_bits": 256,
    })
    if "private_key" in ca.get("data", {}):
        raise RuntimeError("OpenBao PKI returned private key material")
    bao.request("POST", f"pki/roles/{role}", {
        "allow_any_name": True, "allow_localhost": True, "server_flag": True,
        "allow_ip_sans": True, "client_flag": False, "key_type": "ec", "key_bits": 256,
        "max_ttl": "24h", "use_csr_common_name": False,
        "use_csr_sans": False,
    })
    csr = bao.request("POST", f"transit/keys/{key_name}/csr", {"version": 1})
    common_name = "synthetic-secret-service" if role == "signing-keys-image" else "localhost"
    sign_request = {"csr": csr["data"]["csr"], "common_name": common_name, "ttl": "1h"}
    if role in {"signing-keys", "signing-keys-image"}:
        sign_request["ip_sans"] = "127.0.0.1"
    if role == "signing-keys-image":
        sign_request["alt_names"] = "localhost"
    signed = bao.request("POST", f"pki/sign/{role}", sign_request)
    if "private_key" in signed.get("data", {}):
        raise RuntimeError("OpenBao PKI returned a leaf private key")
    cert = root / f"{role}-public.pem"
    workload_ca = root / "workload-public-ca.pem"
    cert.write_text(signed["data"]["certificate"], encoding="ascii")
    workload_ca.write_text(ca["data"]["certificate"], encoding="ascii")
    policy_name = role + "-tls-" + secrets.token_hex(4)
    bao.request("PUT", f"sys/policies/acl/{policy_name}", {
        "policy": (
            f'path "transit/keys/{key_name}" {{ capabilities = ["read"] }}\n'
            f'path "transit/sign/{key_name}" {{ capabilities = ["update"] }}'
        ),
    })
    token = bao.request("POST", "auth/token/create", {
        "policies": [policy_name], "no_default_policy": True,
        "ttl": "1h" if role in {"signing-keys", "passport-edge", "oidf-edge"} else "10m",
    })["auth"]["client_token"]
    foreign_key = "foreign-tls-" + secrets.token_hex(8)
    bao.request("POST", f"transit/keys/{foreign_key}", {
        "type": "ecdsa-p256", "exportable": False, "allow_plaintext_backup": False,
    })
    try:
        bao.request("POST", f"transit/sign/{foreign_key}", {
            "input": base64.b64encode(b"cross-scope-denial").decode("ascii"),
        }, token=token)
    except HTTPError as error:
        if error.code != 403:
            raise RuntimeError("cross-scope signer denial returned an unexpected status") from error
    else:
        raise RuntimeError("scoped server TLS token signed with a foreign key")
    token_file = root / f"{role}-signer-token"
    token_file.write_text(token, encoding="ascii")
    if os.name != "nt":
        token_file.chmod(0o600)
    return {
        "cert": str(cert),
        "workload_ca": str(workload_ca),
        "token_file": str(token_file),
        "key_name": key_name,
    }


def provision(bao: Bao, root: Path) -> dict[str, str]:
    identity = provision_server_identity(bao, root, "event-stream")
    return {
        "MARTY_TEST_EVENT_STREAM_CERT": identity["cert"],
        "MARTY_TEST_EVENT_STREAM_WORKLOAD_CA": identity["workload_ca"],
        "MARTY_TEST_EVENT_STREAM_KMS_TOKEN_FILE": identity["token_file"],
        "MARTY_TEST_EVENT_STREAM_KMS_KEY_NAME": identity["key_name"],
        "MARTY_TEST_EVENT_STREAM_SERVICE_TOKEN": secrets.token_hex(32),
    }


def provision_notification(bao: Bao, root: Path) -> dict[str, str]:
    name = "notification-webhook-envelope-marty-aes256"
    bao.request("POST", "sys/mounts/transit", {"type": "transit"})
    bao.request("POST", f"transit/keys/{name}", {
        "type": "aes256-gcm96", "exportable": False, "allow_plaintext_backup": False,
    })
    metadata = bao.request("GET", f"transit/keys/{name}")["data"]
    if (metadata["type"] != "aes256-gcm96" or metadata["exportable"] is not False
            or metadata["allow_plaintext_backup"] is not False):
        raise RuntimeError("disposable Notification key has unsafe attributes")
    policy = "notification-probe-" + secrets.token_hex(6)
    bao.request("PUT", f"sys/policies/acl/{policy}", {"policy": (
        f'path "transit/keys/{name}" {{ capabilities = ["read"] }}\n'
        f'path "transit/encrypt/{name}" {{ capabilities = ["update"] }}\n'
        f'path "transit/decrypt/{name}" {{ capabilities = ["update"] }}'
    )})
    token = bao.request("POST", "auth/token/create", {
        "policies": [policy], "no_default_policy": True, "ttl": "10m",
    })["auth"]["client_token"]
    token_file = root / "notification-scoped-token"
    token_file.write_text(token, encoding="ascii")
    if os.name != "nt":
        token_file.chmod(0o600)
    foreign = "foreign-notification-" + secrets.token_hex(5)
    bao.request("POST", f"transit/keys/{foreign}", {"type": "aes256-gcm96"})
    try:
        bao.request("GET", f"transit/keys/{foreign}", token=token)
    except HTTPError as error:
        if error.code != 403:
            raise RuntimeError("Notification foreign-key denial failed") from error
    else:
        raise RuntimeError("Notification token accessed a foreign Transit key")
    return {"BAO_ADDR": bao.endpoint,
            "NOTIFICATION_OPENBAO_TOKEN_FILE": str(token_file)}


def provision_integration_secret_fixture(bao: Bao, root: Path) -> dict[str, str]:
    """Give the packaged Signing Keys test only envelope and grant-verification rights."""
    key = "integration-secret-envelope-marty-aes256"
    bao.request("POST", f"transit/keys/{key}", {
        "type": "aes256-gcm96", "exportable": False,
        "allow_plaintext_backup": False,
    })
    metadata = bao.request("GET", f"transit/keys/{key}")["data"]
    if (metadata["type"] != "aes256-gcm96" or metadata["exportable"] is not False
            or metadata["allow_plaintext_backup"] is not False):
        raise RuntimeError("disposable integration-secret key is exportable")
    policy = "integration-secret-image-" + secrets.token_hex(6)
    bao.request("PUT", f"sys/policies/acl/{policy}", {"policy": (
        f'path "transit/keys/{key}" {{ capabilities = ["read"] }}\n'
        f'path "transit/encrypt/{key}" {{ capabilities = ["update"] }}\n'
        f'path "transit/decrypt/{key}" {{ capabilities = ["update"] }}'
    )})
    envelope_token = bao.request("POST", "auth/token/create", {
        "policies": [policy], "no_default_policy": True, "ttl": "1h",
    })["auth"]["client_token"]
    grant_policy = "integration-secret-grant-verify-" + secrets.token_hex(6)
    bao.request("PUT", f"sys/policies/acl/{grant_policy}", {"policy": (
        'path "transit/verify/marty-grant-test/sha2-256" '
        '{ capabilities = ["update"] }'
    )})
    grant_token = bao.request("POST", "auth/token/create", {
        "policies": [grant_policy], "no_default_policy": True, "ttl": "1h",
    })["auth"]["client_token"]
    foreign = "foreign-integration-secret-" + secrets.token_hex(5)
    bao.request("POST", f"transit/keys/{foreign}", {
        "type": "aes256-gcm96", "exportable": False,
        "allow_plaintext_backup": False,
    })
    for token, path in (
        (envelope_token, f"transit/keys/{foreign}"),
        (grant_token, f"transit/keys/{key}"),
    ):
        try:
            bao.request("GET", path, token=token)
        except HTTPError as error:
            if error.code != 403:
                raise RuntimeError("integration-secret fixture returned an unexpected scope denial") from error
        else:
            raise RuntimeError("integration-secret fixture token crossed its scope")
    for name, token in (("envelope", envelope_token), ("grant-verify", grant_token)):
        path = root / f"integration-secret-{name}-token"
        path.write_text(token, encoding="ascii")
        # The disposable, scoped token is mounted read-only by the image's
        # unprivileged uid 10001. The parent directory is short-lived.
        path.chmod(0o644)
    return {
        "MARTY_TEST_SIGNING_KEYS_ENVELOPE_TOKEN_FILE": str(root / "integration-secret-envelope-token"),
        "MARTY_TEST_SIGNING_KEYS_GRANT_VERIFY_TOKEN_FILE": str(root / "integration-secret-grant-verify-token"),
    }


def provision_signing_transit(bao: Bao, ca: Path) -> dict[str, str]:
    """Live managed-key transport proof with a scoped, non-exporting token."""
    bao.request("POST", "sys/mounts/transit", {"type": "transit"})
    nonce = secrets.token_hex(16)
    bao.request("POST", "secret/data/marty-test-disposable-guard", {"data": {"nonce": nonce}})
    policy = "signing-transit-probe-" + secrets.token_hex(6)
    bao.request("PUT", f"sys/policies/acl/{policy}", {"policy": (
        'path "transit/keys" { capabilities = ["list"] }\n'
        'path "transit/keys/cred-issuer-*" { capabilities = ["create", "update", "read"] '
        'allowed_parameters = { "type" = ["ecdsa-p256", "ed25519"] } }\n'
        'path "transit/keys/cred-issuer-*/rotate" { capabilities = ["update"] }\n'
        'path "transit/sign/cred-issuer-*" { capabilities = ["update"] }\n'
        'path "transit/keys/cred-holder-*" { capabilities = ["create", "update", "read", "delete"] '
        'allowed_parameters = { "type" = ["ed25519"], "deletion_allowed" = [true, "true"] } }\n'
        'path "transit/keys/cred-holder-*/config" { capabilities = ["update"] }\n'
        'path "transit/sign/cred-holder-*" { capabilities = ["update"] }'
    )})
    token = bao.request("POST", "auth/token/create", {
        "policies": [policy], "no_default_policy": True, "ttl": "10m",
    })["auth"]["client_token"]
    try:
        bao.request("GET", "transit/keys/foreign-signing-probe", token=token)
    except HTTPError as error:
        if error.code != 403:
            raise RuntimeError("scoped signing token returned unexpected foreign-key status") from error
    else:
        raise RuntimeError("scoped signing token accessed a foreign key")
    return {
        "BAO_ADDR": bao.endpoint,
        "BAO_CACERT": str(ca),
        "BAO_TOKEN": token,
        "MARTY_TEST_OPENBAO_URL": bao.endpoint,
        "MARTY_TEST_OPENBAO_TOKEN": token,
        "MARTY_TEST_OPENBAO_ROOT_TOKEN": bao.token,
        "MARTY_TEST_OPENBAO_DISPOSABLE_NONCE": nonce,
    }


def provision_signing_grant(bao: Bao, ca: Path) -> dict[str, str]:
    environment = provision_signing_transit(bao, ca)
    key = "marty-grant-test"
    bao.request("POST", f"transit/keys/{key}", {
        "type": "hmac", "key_size": 32, "exportable": False,
    })
    metadata = bao.request("GET", f"transit/keys/{key}")["data"]
    if metadata["type"] != "hmac" or metadata["exportable"] is not False:
        raise RuntimeError("disposable signing grant key is exportable")
    tokens = {}
    for action in ("mint", "verify"):
        operation = "hmac" if action == "mint" else "verify"
        policy = f"signing-grant-{action}-" + secrets.token_hex(6)
        bao.request("PUT", f"sys/policies/acl/{policy}", {"policy": (
            f'path "transit/{operation}/{key}/sha2-256" '
            '{ capabilities = ["update"] }'
        )})
        tokens[action] = bao.request("POST", "auth/token/create", {
            "policies": [policy], "no_default_policy": True, "ttl": "10m",
        })["auth"]["client_token"]
    try:
        bao.request("POST", f"transit/hmac/{key}/sha2-256", {
            "input": base64.b64encode(b"cross-policy-denial").decode("ascii"),
        }, token=tokens["verify"])
    except HTTPError as error:
        if error.code != 403:
            raise RuntimeError("grant verify token returned unexpected HMAC status") from error
    else:
        raise RuntimeError("grant verify token can mint HMACs")
    environment.update({
        "MARTY_TEST_GRANT_MINT_TOKEN": tokens["mint"],
        "MARTY_TEST_GRANT_VERIFY_TOKEN": tokens["verify"],
    })
    return environment


def provision_workload_pair(bao: Bao, root: Path, profile: str) -> dict[str, str]:
    if profile == "auth-gateway":
        server_role, service_name, client_role = "AUTH_SERVER", "auth", "GATEWAY_CLIENT"
        client_service = "gateway"
        prefix = "MARTY_TEST_AUTH_GATEWAY"
    elif profile == "flow-issuance":
        server_role, service_name, client_role = "ISSUANCE_SERVER", "issuance-native", "FLOW_CLIENT"
        client_service = "flow"
        prefix = "MARTY_TEST_FLOW_ISSUANCE"
    else:
        raise RuntimeError("unknown disposable workload pair")
    bao.request("POST", "sys/mounts/transit", {"type": "transit"})
    bao.request("POST", "sys/mounts/pki", {"type": "pki"})
    ca = bao.request("POST", "pki/root/generate/internal", {
        "common_name": "Disposable workload pair CA", "ttl": "48h",
        "key_type": "ec", "key_bits": 256,
    })
    if "private_key" in ca.get("data", {}):
        raise RuntimeError("OpenBao PKI returned private key material")
    workload_ca = root / "workload-public-ca.pem"
    workload_ca.write_text(ca["data"]["certificate"], encoding="ascii")
    environment = {
        f"{prefix}_WORKLOAD_CA": str(workload_ca),
        f"{prefix}_SERVICE_TOKEN": secrets.token_hex(32),
    }
    scoped_tokens: dict[str, str] = {}
    key_names: dict[str, str] = {}
    for role, common_name, server_flag, client_flag in (
        (server_role, "localhost", True, False),
        (client_role, client_service, False, True),
    ):
        key_name = role.lower().replace("_", "-") + "-" + secrets.token_hex(8)
        bao.request("POST", f"transit/keys/{key_name}", {
            "type": "ecdsa-p256", "exportable": False,
            "allow_plaintext_backup": False,
        })
        metadata = bao.request("GET", f"transit/keys/{key_name}")["data"]
        if (metadata["type"] != "ecdsa-p256" or metadata["exportable"] is not False
                or metadata["allow_plaintext_backup"] is not False):
            raise RuntimeError(f"{role} signer is not non-exportable")
        pki_role = role.lower().replace("_", "-")
        bao.request("POST", f"pki/roles/{pki_role}", {
            "allow_any_name": True, "allow_localhost": True,
            "server_flag": server_flag, "client_flag": client_flag,
            "key_type": "ec", "key_bits": 256,
            "max_ttl": "24h", "use_csr_common_name": False,
        })
        csr = bao.request("POST", f"transit/keys/{key_name}/csr", {"version": 1})
        certificate_request = {
            "csr": csr["data"]["csr"], "common_name": common_name, "ttl": "1h",
        }
        if role == server_role:
            certificate_request["alt_names"] = service_name
        else:
            certificate_request["uri_sans"] = f"spiffe://marty.internal/service/{client_service}"
        signed = bao.request("POST", f"pki/sign/{pki_role}", certificate_request)
        if "private_key" in signed.get("data", {}):
            raise RuntimeError(f"{role} certificate response exposed a private key")
        cert = root / f"{pki_role}-public.pem"
        cert.write_text(signed["data"]["certificate"], encoding="ascii")
        policy_name = f"{pki_role}-{secrets.token_hex(4)}"
        bao.request("PUT", f"sys/policies/acl/{policy_name}", {
            "policy": (
                f'path "transit/keys/{key_name}" {{ capabilities = ["read"] }}\n'
                f'path "transit/sign/{key_name}" {{ capabilities = ["update"] }}'
            ),
        })
        token = bao.request("POST", "auth/token/create", {
            "policies": [policy_name], "no_default_policy": True, "ttl": "10m",
        })["auth"]["client_token"]
        scoped_tokens[role] = token
        key_names[role] = key_name
        token_file = root / f"{pki_role}-token"
        token_file.write_text(token, encoding="ascii")
        if os.name != "nt":
            token_file.chmod(0o600)
        environment.update({
            f"{prefix}_{role}_CERT": str(cert),
            f"{prefix}_{role}_KMS_TOKEN_FILE": str(token_file),
            f"{prefix}_{role}_KMS_KEY_NAME": key_name,
        })
    for role, foreign_role in ((server_role, client_role),
                               (client_role, server_role)):
        try:
            bao.request("POST", f"transit/sign/{key_names[foreign_role]}", {
                "input": base64.b64encode(b"cross-scope-denial").decode("ascii"),
            }, token=scoped_tokens[role])
        except HTTPError as error:
            if error.code != 403:
                raise RuntimeError(f"{role} foreign signer denial returned {error.code}") from error
        else:
            raise RuntimeError(f"{role} scoped token signed with {foreign_role} key")
    return environment


def execute(image: str, command: list[str], profile: str = "event-stream") -> int:
    if not IMAGE.fullmatch(image):
        raise RuntimeError("disposable OpenBao image must use a pinned upstream digest")
    if not command:
        raise RuntimeError("an acceptance command is required")
    if command[0] == "--":
        command = command[1:]
    if not command:
        raise RuntimeError("an acceptance command is required")
    require_pinned_image(image)
    container = "marty-event-stream-kms-" + secrets.token_hex(8)
    root_token = secrets.token_hex(32 if profile == "passport-bootstrap" else 24)
    attempted = False
    with tempfile.TemporaryDirectory(prefix="marty-event-stream-kms-") as temporary:
        root = Path(temporary).resolve()
        try:
            attempted = True
            run([
                "docker", "run", "-d", "--pull=never", "--name", container,
                "--label", "marty.disposable=event-stream-kms",
                "-p", "127.0.0.1::8200", "--tmpfs", "/tmp/bao-tls:rw,mode=1777",
                "-e", "BAO_DEV_LISTEN_ADDRESS=0.0.0.0:8200",
                "-e", f"BAO_DEV_ROOT_TOKEN_ID={root_token}", image,
                "server", "-dev", "-dev-tls", "-dev-tls-cert-dir=/tmp/bao-tls",
            ], timeout=60)
            binding = run(["docker", "port", container, "8200/tcp"])
            if not binding.startswith("127.0.0.1:"):
                raise RuntimeError("disposable OpenBao must bind only to loopback")
            port = int(binding.rsplit(":", 1)[1])
            ca = root / "openbao-public-ca.pem"
            deadline = time.monotonic() + 20
            last_error = "not started"
            while time.monotonic() < deadline:
                try:
                    ca.write_text(
                        run(["docker", "exec", container, "cat", "/tmp/bao-tls/vault-ca.pem"]) + "\n",
                        encoding="ascii",
                    )
                    bao = Bao(f"https://127.0.0.1:{port}", ca, root_token)
                    bao.request("GET", "sys/health")
                    break
                except (RuntimeError, HTTPError, URLError, OSError) as error:
                    last_error = f"{type(error).__name__}: {error}".replace(root_token, "[redacted]")
                    time.sleep(0.2)
            else:
                raise RuntimeError(f"disposable HTTPS OpenBao did not become ready: {last_error}")
            environment = os.environ.copy()
            if profile == "event-stream":
                environment.update(provision(bao, root))
                environment.update({
                    "MARTY_TEST_EVENT_STREAM_KMS_URL": bao.endpoint,
                    "MARTY_TEST_EVENT_STREAM_KMS_CA": str(ca),
                })
            elif profile in ("auth-gateway", "flow-issuance"):
                environment.update(provision_workload_pair(bao, root, profile))
                prefix = "MARTY_TEST_AUTH_GATEWAY" if profile == "auth-gateway" else "MARTY_TEST_FLOW_ISSUANCE"
                environment.update({
                    f"{prefix}_KMS_URL": bao.endpoint,
                    f"{prefix}_KMS_CA": str(ca),
                })
            elif profile in ("signing-keys", "signing-keys-image"):
                identity = provision_server_identity(
                    bao, root,
                    "signing-keys-image" if profile == "signing-keys-image" else "signing-keys",
                )
                environment.update({
                    "MARTY_TEST_SIGNING_KEYS_TLS_CERT": identity["cert"],
                    "MARTY_TEST_SIGNING_KEYS_TLS_CA": identity["workload_ca"],
                    "MARTY_TEST_SIGNING_KEYS_TLS_KMS_TOKEN_FILE": identity["token_file"],
                    "MARTY_TEST_SIGNING_KEYS_TLS_KMS_KEY_NAME": identity["key_name"],
                    "MARTY_TEST_SIGNING_KEYS_TLS_KMS_URL": bao.endpoint,
                    "MARTY_TEST_SIGNING_KEYS_TLS_KMS_CA": str(ca),
                })
                if profile == "signing-keys-image":
                    environment.update(provision_integration_secret_fixture(bao, root))
                    environment["MARTY_TEST_SIGNING_KEYS_BAO_CONTAINER"] = container
                    identity_token = Path(identity["token_file"])
                    identity_token.chmod(0o644)
            elif profile == "passport-edge":
                identity = provision_server_identity(bao, root, "passport-edge")
                environment.update({
                    "PASSPORT_EDGE_TLS_CERT_FILE": identity["cert"],
                    "PASSPORT_EDGE_TLS_KMS_CA_CERT_FILE": str(ca),
                    "PASSPORT_EDGE_TLS_KMS_TOKEN_FILE": identity["token_file"],
                    "PASSPORT_EDGE_TLS_KMS_KEY_NAME": identity["key_name"],
                    "PASSPORT_EDGE_TLS_KMS_KEY_VERSION": "1",
                    "PASSPORT_EDGE_TLS_KMS_ADDR": bao.endpoint,
                    "MARTY_TEST_PASSPORT_EDGE_CA": identity["workload_ca"],
                })
            elif profile == "oidf-edge":
                identity = provision_server_identity(bao, root, "oidf-edge")
                environment.update({
                    "OIDF_EDGE_TLS_CERT_FILE": identity["cert"],
                    "OIDF_EDGE_TLS_KMS_CA_CERT_FILE": str(ca),
                    "OIDF_EDGE_TLS_KMS_TOKEN_FILE": identity["token_file"],
                    "OIDF_EDGE_TLS_KMS_KEY_NAME": identity["key_name"],
                    "OIDF_EDGE_TLS_KMS_KEY_VERSION": "1",
                    "OIDF_EDGE_TLS_KMS_ADDR": bao.endpoint,
                    "MARTY_TEST_OIDF_EDGE_CA": identity["workload_ca"],
                })
            elif profile == "passport-bootstrap":
                token_file = root / "bootstrap-root-token"
                token_file.write_text(root_token, encoding="ascii")
                if os.name != "nt":
                    token_file.chmod(0o600)
                output = root / "passport-tls-output"
                output.mkdir(mode=0o700)
                environment.update({
                    "BAO_ADDR": bao.endpoint,
                    "BAO_CACERT": str(ca),
                    "BAO_ROOT_TOKEN_FILE": str(token_file),
                    "PASSPORT_ACCEPTANCE_PROJECT": "marty-passport-acceptance-base-"
                    + secrets.token_hex(5),
                    "PASSPORT_TLS_OUTPUT_DIR": str(output),
                })
            elif profile == "notification":
                environment.update(provision_notification(bao, root))
                environment["NOTIFICATION_OPENBAO_CA_CERT_FILE"] = str(ca)
                environment.pop("NOTIFICATION_OPENBAO_TOKEN", None)
            elif profile == "signing-transit":
                environment.update(provision_signing_transit(bao, ca))
            elif profile == "signing-grant":
                environment.update(provision_signing_grant(bao, ca))
            else:
                raise RuntimeError("unknown disposable workload TLS profile")
            return subprocess.run(command, env=environment, check=False).returncode
        finally:
            if attempted:
                try:
                    owned = subprocess.run(
                        ["docker", "inspect", "--format", "{{json .Config.Labels}}", container],
                        capture_output=True, text=True, timeout=10, check=False,
                    )
                    labels = json.loads(owned.stdout) if owned.returncode == 0 else {}
                    if labels.get("marty.disposable") == "event-stream-kms":
                        subprocess.run(
                            ["docker", "rm", "-f", container], check=False,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30,
                        )
                except (OSError, ValueError, subprocess.TimeoutExpired):
                    # Preserve the original fixture failure; an operator can
                    # locate a timed-out container by its disposable label.
                    pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--profile", choices=("event-stream", "auth-gateway", "flow-issuance", "signing-keys", "signing-keys-image", "signing-transit", "signing-grant", "passport-edge", "oidf-edge", "passport-bootstrap", "notification"), default="event-stream")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    return execute(args.image, args.command, args.profile)


if __name__ == "__main__":
    raise SystemExit(main())
