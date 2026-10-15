#!/usr/bin/env python3
"""Disposable pinned Keycloak/OpenBao RS256 probe; never prints tokens or keys."""

from __future__ import annotations

import argparse
import base64
from http.cookiejar import CookieJar
from html.parser import HTMLParser
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import tempfile
import threading
from typing import Callable
import time
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlparse
from urllib.request import (HTTPCookieProcessor, HTTPRedirectHandler, Request,
                            build_opener, urlopen)

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


ROOT = Path(__file__).resolve().parents[1]


def run(*args: str, input_text: str | None = None) -> str:
    result = subprocess.run(args, input=input_text, text=True,
                            capture_output=True, timeout=90, check=False)
    if result.returncode:
        raise RuntimeError(f"Disposable command failed: {args[0]} {args[1]}: "
                           f"{result.stderr[:300]}")
    return result.stdout.strip()


def host_gateway_alias(network: str) -> str:
    """Bind the host callback to this probe's exact disposable bridge."""
    config = json.loads(run(
        "docker", "network", "inspect", "--format", "{{json .IPAM.Config}}", network,
    ))
    if not isinstance(config, list) or not config:
        raise RuntimeError("Disposable Keycloak network has no unique IPv4 gateway")
    gateways = []
    for entry in config:
        if not isinstance(entry, dict):
            raise RuntimeError("Disposable Keycloak network has no valid gateway")
        try:
            address = ipaddress.ip_address(entry["Gateway"])
        except (KeyError, TypeError, ValueError) as error:
            raise RuntimeError("Disposable Keycloak network has no valid gateway") from error
        if address.version == 4:
            gateways.append(address)
    if len(gateways) != 1:
        raise RuntimeError("Disposable Keycloak network has no unique IPv4 gateway")
    gateway = gateways[0]
    if not gateway.is_private or gateway.is_loopback:
        raise RuntimeError("Disposable Keycloak network gateway is not private IPv4")
    return f"host.docker.internal:{gateway}"


def http_json(url: str, body: dict[str, str] | None = None) -> dict:
    request = Request(url, data=urlencode(body).encode() if body else None)
    with urlopen(request, timeout=5) as response:
        return json.load(response)


def jwe_header(compact: str) -> dict:
    if len(compact.split(".")) != 5:
        raise RuntimeError("Keycloak did not return a compact JWE")
    return json.loads(base64.urlsafe_b64decode(compact.split(".")[0] + "=="))


def post_admin(url: str, token: str, payload: dict) -> None:
    request = Request(url, data=json.dumps(payload).encode(), method="POST",
                      headers={"Authorization": "Bearer " + token,
                               "Content-Type": "application/json"})
    with urlopen(request, timeout=8) as response:
        if response.status not in (201, 204):
            raise RuntimeError("Keycloak admin write returned an unexpected status")


def get_admin(url: str, token: str) -> dict | list:
    with urlopen(Request(url, headers={"Authorization": "Bearer " + token}),
                 timeout=8) as response:
        return json.load(response)


class LoginForm(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.action: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "form" and values.get("id") == "kc-form-login":
            self.action = values.get("action")


class StopAtCallback(HTTPRedirectHandler):
    def __init__(self, callback: str) -> None:
        self.callback = callback

    def redirect_request(self, request: Request, fp, code: int, message: str,
                         headers, newurl: str) -> Request | None:
        if newurl.startswith(self.callback + "?"):
            return None
        return super().redirect_request(request, fp, code, message, headers,
                                        newurl)


class PendingCibaDevice(BaseHTTPRequestHandler):
    received_tokens: list[str] = []

    def do_POST(self) -> None:
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        authorization = self.headers.get("Authorization", "")
        if authorization.startswith("Bearer "):
            self.received_tokens.append(authorization)
        self.send_response(201)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        pass


def browser_code(opener, base: str, callback: str, realm: str,
                 username: str, *, login: bool,
                 before_submit: Callable[[], None] | None = None) -> dict:
    verifier = secrets.token_urlsafe(32)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()) \
        .rstrip(b"=").decode()
    state = secrets.token_urlsafe(16)
    params = {
        "client_id": "probe-browser", "response_type": "code",
        "scope": "openid", "redirect_uri": callback, "state": state,
        "code_challenge": challenge, "code_challenge_method": "S256",
    }
    if not login:
        params["prompt"] = "none"
    url = base + f"/realms/{realm}/protocol/openid-connect/auth?" + urlencode(params)
    location = ""
    try:
        with opener.open(url, timeout=8) as response:
            form = LoginForm()
            form.feed(response.read().decode())
            if not login or not form.action:
                raise RuntimeError("Keycloak did not present the expected browser login")
            if before_submit:
                before_submit()
            try:
                opener.open(Request(form.action, data=urlencode({
                    "username": username, "password": "synthetic-probe-only",
                }).encode()), timeout=8)
            except HTTPError as callback_response:
                if callback_response.code != 302:
                    raise
                location = callback_response.headers.get("Location", "")
            else:
                raise RuntimeError("Browser login did not redirect to the callback")
    except HTTPError as callback_response:
        if callback_response.code != 302:
            raise RuntimeError(f"Browser authorization failed: HTTP "
                               f"{callback_response.code}") from callback_response
        location = callback_response.headers.get("Location", "")
    if not location.startswith(callback + "?"):
        raise RuntimeError("Keycloak redirected browser to an unexpected callback")
    query = parse_qs(urlparse(location).query)
    if query.get("state") != [state] or len(query.get("code", [])) != 1:
        raise RuntimeError("Keycloak browser flow did not return a valid code/state")
    return http_json(base + f"/realms/{realm}/protocol/openid-connect/token", {
        "client_id": "probe-browser", "grant_type": "authorization_code",
        "code": query["code"][0], "redirect_uri": callback,
        "code_verifier": verifier,
    })


def wait_for(path: Path, seconds: int = 30) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if path.is_file() and path.stat().st_size:
            return
        time.sleep(0.3)
    raise RuntimeError("OpenBao public CA did not become ready")


def wait_for_keycloak(base: str, container: str, seconds: int = 35) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            http_json(base + "/realms/master/.well-known/openid-configuration")
            return
        except (HTTPError, URLError, OSError):
            pass
        state = run("docker", "inspect", "-f", "{{.State.Running}}", container)
        if state != "true":
            raise RuntimeError("Keycloak exited before OIDC discovery was ready")
        time.sleep(0.4)
    raise RuntimeError("Keycloak OIDC discovery did not become ready")


def database_key_counts(container: str) -> tuple[int, int]:
    output = run(
        "docker", "exec", container, "psql", "-U", "keycloak", "-d", "keycloak",
        "-AtF", "|", "-c",
        "SELECT cc.name, count(*) FROM component_config AS cc "
        "JOIN component AS c ON c.id = cc.component_id "
        "WHERE c.provider_type = 'org.keycloak.keys.KeyProvider' "
        "AND cc.name IN ('privateKey','secret') GROUP BY cc.name",
    )
    counts = {name: int(value) for name, value in (
        line.split("|") for line in output.splitlines() if "|" in line)}
    return counts.get("privateKey", 0), counts.get("secret", 0)


def verify_database_gate(container: str) -> None:
    run("docker", "exec", "-i", container, "psql", "-v", "ON_ERROR_STOP=1",
        "-U", "keycloak", "-d", "keycloak",
        input_text=(ROOT / "scripts/sql/keycloak-kms-only-verify.sql").read_text())


def verify_jwt(jwt: str, jwks: dict, expected_kid: str,
               expected_issuer: str) -> bytes:
    parts = jwt.split(".")
    if len(parts) != 3:
        raise RuntimeError("Keycloak did not return a JWT")

    def decoded(value: str) -> bytes:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

    header = json.loads(decoded(parts[0]))
    if header.get("alg") != "RS256" or header.get("kid") != expected_kid:
        raise RuntimeError("Keycloak JWT did not use the pinned remote RS256 key")
    claims = json.loads(decoded(parts[1]))
    if claims.get("iss") != expected_issuer:
        raise RuntimeError("Keycloak JWT came from an unexpected realm")
    key = next((item for item in jwks["keys"] if item.get("kid") == expected_kid), None)
    if key is None or key.get("kty") != "RSA":
        raise RuntimeError("Keycloak JWKS omitted the remote RSA public key")
    public = rsa.RSAPublicNumbers(
        int.from_bytes(decoded(key["e"]), "big"),
        int.from_bytes(decoded(key["n"]), "big"),
    ).public_key()
    public.verify(decoded(parts[2]), f"{parts[0]}.{parts[1]}".encode(),
                  padding.PKCS1v15(), hashes.SHA256())
    return decoded(key["n"])


def probe(keycloak_image: str, openbao_image: str, jar: Path,
          require_browser: bool = False) -> None:
    if not require_browser and not jar.is_file():
        raise RuntimeError("Build keycloak/openbao-provider with Maven first")
    suffix = secrets.token_hex(5)
    network = "marty-keycloak-kms-net-" + suffix
    bao_name = "marty-keycloak-kms-bao-" + suffix
    kc_name = "marty-keycloak-kms-oidc-" + suffix
    pg_name = "marty-keycloak-kms-pg-" + suffix
    prefix = "kmsprobe" + suffix
    created_network = False
    started_bao = False
    started_kc = False
    started_pg = False
    ciba_device = None
    with tempfile.TemporaryDirectory(prefix="marty-keycloak-kms-") as temporary:
        root = Path(temporary)
        ca_dir = root / "ca"
        ca_dir.mkdir()
        cert_dir = root / "certs"
        cert_dir.mkdir()
        jwe_token_dir = root / "jwe-tokens"
        jwe_token_dir.mkdir()
        root_token = root / "root-token"
        scoped_token = root / "keycloak-token"
        root_token.write_text(secrets.token_hex(32), encoding="ascii")
        try:
            if require_browser:
                PendingCibaDevice.received_tokens = []
                ciba_device = ThreadingHTTPServer(("0.0.0.0", 0), PendingCibaDevice)
                threading.Thread(target=ciba_device.serve_forever, daemon=True).start()
            run("docker", "network", "create", network)
            created_network = True
            run("docker", "run", "-d", "--name", pg_name,
                "--network", network, "--network-alias", "postgres",
                "-e", "POSTGRES_USER=keycloak",
                "-e", "POSTGRES_PASSWORD=synthetic-probe-only",
                "-e", "POSTGRES_DB=keycloak",
                "postgres:15-alpine")
            started_pg = True
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                ready = subprocess.run(["docker", "exec", pg_name, "pg_isready",
                                        "-U", "keycloak", "-d", "keycloak"],
                                       capture_output=True, timeout=5)
                if ready.returncode == 0:
                    break
                time.sleep(0.3)
            else:
                raise RuntimeError("Disposable Keycloak PostgreSQL did not start")
            plugin_environment = (
                ["-e", 'BAO_LOCAL_CONFIG={"plugin_directory":"/plugins"}']
                if require_browser else []
            )
            run(
                "docker", "run", "-d", "--name", bao_name,
                "--network", network, "--network-alias", "openbao",
                "--hostname", "openbao", "-p", "127.0.0.1::8200",
                "--tmpfs", "/tmp/bao-tls:rw,mode=1777",
                "--mount", f"type=bind,src={ROOT / 'scripts/passport_supported_openbao_start.sh'},dst=/usr/local/bin/passport-supported-openbao-start,readonly",
                "--mount", f"type=bind,src={root_token},dst=/run/secrets/bao_root_token,readonly",
                "--mount", f"type=bind,src={ca_dir},dst=/bao/public-ca",
                "-e", "PASSPORT_BAO_TLS_MODE=required",
                *plugin_environment,
                "--entrypoint", "/bin/sh", openbao_image,
                "/usr/local/bin/passport-supported-openbao-start",
            )
            started_bao = True
            wait_for(ca_dir / "ca.crt")
            if b"PRIVATE KEY" in (ca_dir / "ca.crt").read_bytes():
                raise RuntimeError("OpenBao public CA export contains private material")
            bao_port = run("docker", "port", bao_name, "8200/tcp").rsplit(":", 1)[-1]
            bao_base = f"https://127.0.0.1:{bao_port}/v1/"
            bao_tls = ssl.create_default_context(cafile=str(ca_dir / "ca.crt"))

            def bao_api(path: str, payload: dict, token: str | None = None) -> dict:
                request = Request(bao_base + path, data=json.dumps(payload).encode(),
                                  headers={"X-Vault-Token": token or root_token.read_text(),
                                           "Content-Type": "application/json"})
                with urlopen(request, context=bao_tls, timeout=8) as response:
                    body = response.read()
                    return json.loads(body) if body else {}

            def bao(*args: str, input_text: str | None = None) -> str:
                command = "export BAO_ADDR=https://127.0.0.1:8200 " \
                    "BAO_CACERT=/tmp/bao-tls/vault-ca.pem " \
                    "BAO_TOKEN=$(cat /run/secrets/bao_root_token); exec bao " \
                    + " ".join(args)
                return run("docker", "exec", "-i", bao_name,
                           "/bin/sh", "-c", command, input_text=input_text)

            def jwe_policy(realm: str, purpose: str, versions: tuple[str, ...]) -> str:
                policy = f'path "didcomm/keycloak/keys/{realm}/{purpose}" {{ capabilities = ["read"] }}\n'
                for version in versions:
                    policy += (
                        f'path "didcomm/keycloak/jwe/encode/{realm}/{purpose}/{version}" {{ capabilities = ["update"] }}\n'
                        f'path "didcomm/keycloak/jwe/decode/{realm}/{purpose}/{version}" {{ capabilities = ["update"] }}\n'
                    )
                return policy

            def rotate_jwe(realm: str, purpose: str, old_version: str) -> str:
                rotated = bao_api(f"didcomm/keycloak/keys/{realm}/{purpose}/rotate", {})["data"]
                version = rotated["version"]
                if version == old_version or rotated.get("kid") != f"keycloak-{realm}-{purpose}-{version}":
                    raise RuntimeError("Remote JWE rotation did not advance the key version")
                bao("policy", "write", f"keycloak-{realm}-{purpose}-probe", "-",
                    input_text=jwe_policy(realm, purpose, (old_version, version)))
                return version

            deadline = time.monotonic() + 25
            while time.monotonic() < deadline:
                try:
                    bao("status")
                    break
                except RuntimeError:
                    time.sleep(0.3)
            else:
                raise RuntimeError("OpenBao HTTPS did not become healthy")

            bao("secrets", "enable", "transit")
            ciba_version = ""
            cookie_versions = {}
            if require_browser:
                digest = run("docker", "exec", bao_name, "sha256sum",
                             "/plugins/openbao-didcomm-authcrypt").split()[0]
                bao_api("sys/plugins/catalog/secret/openbao-didcomm-authcrypt", {
                    "command": "openbao-didcomm-authcrypt", "sha256": digest,
                })
                bao_api("sys/mounts/didcomm", {"type": "openbao-didcomm-authcrypt"})
                for realm, purpose in (("master", "cookie"), ("11id", "cookie"),
                                       ("11id", "ciba")):
                    reference = bao_api(f"didcomm/keycloak/keys/{realm}/{purpose}", {})["data"]
                    version = reference["version"]
                    if realm == "11id" and purpose == "ciba":
                        ciba_version = version
                    if purpose == "cookie":
                        cookie_versions[realm] = version
                    policy_name = f"keycloak-{realm}-{purpose}-probe"
                    bao("policy", "write", policy_name, "-",
                        input_text=jwe_policy(realm, purpose, (version,)))
                    (jwe_token_dir / f"{realm}-{purpose}.token").write_text(
                        bao("token", "create", f"-policy={policy_name}",
                            "-ttl=1h", "-field=token"), encoding="ascii")
            bao_api("sys/mounts/pki", {"type": "pki"})
            ca = bao_api("pki/root/generate/internal", {
                "common_name": "Marty disposable Keycloak CA", "ttl": "24h",
                "key_type": "ec", "key_bits": 256,
            })["data"]
            if "private_key" in ca:
                raise RuntimeError("OpenBao exported the disposable CA key")
            bao_api("pki/roles/keycloak-rs256", {
                "allow_any_name": True, "key_type": "rsa", "key_bits": 2048,
                "max_ttl": "1h", "use_csr_common_name": False,
                "use_csr_sans": False,
            })
            policy = ""
            for realm in ("master", "11id"):
                name = f"{prefix}-{realm}-rs256"
                hmac_name = f"{prefix}-{realm}-hs512"
                bao("write", f"transit/keys/{name}", "type=rsa-2048",
                    "exportable=false")
                bao("write", f"transit/keys/{hmac_name}", "type=hmac",
                    "key_size=64", "exportable=false")
                csr = bao_api(f"transit/keys/{name}/csr", {"version": 1})["data"]["csr"]
                signed = bao_api("pki/sign/keycloak-rs256", {
                    "csr": csr, "common_name": f"{realm}.keycloak.internal", "ttl": "1h",
                })["data"]
                if "private_key" in signed:
                    raise RuntimeError("OpenBao exported a remote RS256 private key")
                (cert_dir / f"{name}.crt").write_text(signed["certificate"],
                                                        encoding="ascii")
                policy += f'path "transit/keys/{name}" {{ capabilities = ["read"] }}\n' \
                          f'path "transit/sign/{name}" {{ capabilities = ["update"] }}\n' \
                          f'path "transit/keys/{hmac_name}" {{ capabilities = ["read"] }}\n' \
                          f'path "transit/hmac/{hmac_name}/sha2-512" {{ capabilities = ["update"] }}\n' \
                          f'path "transit/verify/{hmac_name}/sha2-512" {{ capabilities = ["update"] }}\n'
            bao("policy", "write", "keycloak-rs256-probe", "-", input_text=policy)
            scoped_token.write_text(bao("token", "create", "-policy=keycloak-rs256-probe",
                                        "-ttl=1h", "-field=token"), encoding="ascii")
            if not scoped_token.read_text().strip():
                raise RuntimeError("Scoped OpenBao token is empty")

            provider_mount = [] if require_browser else [
                "--mount", f"type=bind,src={jar},dst=/opt/keycloak/providers/marty-kms-probe.jar,readonly",
            ]
            run(
                "docker", "run", "-d", "--name", kc_name,
                "--network", network, "-p", "127.0.0.1::8080",
                *(["--add-host", host_gateway_alias(network)]
                  if require_browser and os.name != "nt" else []),
                *provider_mount,
                "--mount", f"type=bind,src={ca_dir / 'ca.crt'},dst=/run/kms/ca.crt,readonly",
                "--mount", f"type=bind,src={scoped_token},dst=/run/kms/token,readonly",
                "--mount", f"type=bind,src={cert_dir},dst=/run/kms/certs,readonly",
                "--mount", f"type=bind,src={jwe_token_dir},dst=/run/kms/jwe-tokens,readonly",
                "-e", "KEYCLOAK_ADMIN=probe",
                "-e", "KEYCLOAK_ADMIN_PASSWORD=synthetic-probe-only",
                "-e", "KC_DB=postgres",
                "-e", "KC_DB_URL=jdbc:postgresql://postgres:5432/keycloak",
                "-e", "KC_DB_USERNAME=keycloak",
                "-e", "KC_DB_PASSWORD=synthetic-probe-only",
                "-e", "BAO_ADDR=https://openbao:8200",
                "-e", "BAO_CACERT=/run/kms/ca.crt",
                "-e", "BAO_TOKEN_FILE=/run/kms/token",
                "-e", "MARTY_KEYCLOAK_RS256_CERT_DIR=/run/kms/certs",
                "-e", "MARTY_KEYCLOAK_JWE_TOKEN_DIR=/run/kms/jwe-tokens",
                "-e", "MARTY_KEYCLOAK_JWE_MOUNT=didcomm",
                "-e", f"MARTY_KEYCLOAK_KMS_KEY_PREFIX={prefix}",
                "-e", "MARTY_KEYCLOAK_KMS_KEY_VERSION=1",
                *(["-e", "KC_SPI_CIBA_AUTH_CHANNEL_CIBA_HTTP_AUTH_CHANNEL_HTTP_AUTHENTICATION_CHANNEL_URI="
                   f"http://host.docker.internal:{ciba_device.server_port}/"]
                  if ciba_device else []),
                keycloak_image, "start-dev",
            )
            started_kc = True
            port = run("docker", "port", kc_name, "8080/tcp").rsplit(":", 1)[-1]
            base = f"http://127.0.0.1:{port}"
            try:
                wait_for_keycloak(base, kc_name)
            except RuntimeError as error:
                observed = subprocess.run(["docker", "logs", "--tail", "100", kc_name],
                                          capture_output=True, text=True, timeout=10)
                logs = "\n".join(line for line in (observed.stdout + observed.stderr).splitlines()
                                 if "ERROR" in line or "Caused by" in line or "Remote key providers" in line)[:1800]
                raise RuntimeError(f"Keycloak did not start: {error}\n{logs}") from error
            if database_key_counts(pg_name) != (0, 0):
                raise RuntimeError("Keycloak bootstrap stored private key material")
            try:
                master_tokens = http_json(base + "/realms/master/protocol/openid-connect/token", {
                    "client_id": "admin-cli", "grant_type": "password",
                    "username": "probe", "password": "synthetic-probe-only",
                })
                token = master_tokens["access_token"]
            except HTTPError as error:
                observed = subprocess.run(["docker", "logs", "--tail", "100", kc_name],
                                          capture_output=True, text=True, timeout=10)
                logs = "\n".join(line for line in (observed.stdout + observed.stderr).splitlines()
                                 if "ERROR" in line or "Caused by" in line)[:2500]
                raise RuntimeError(f"Keycloak token request failed: HTTP {error.code}\n{logs}") from error
            if require_browser:
                server_info = get_admin(base + "/admin/serverinfo", token)
                providers = server_info.get("componentTypes", {}).get(
                    "org.keycloak.keys.KeyProvider", [])
                expected_providers = {
                    "rsa-generated", "rsa-enc-generated",
                    "hmac-generated", "aes-generated",
                }
                discovered = {provider.get("id") for provider in providers}
                if discovered != expected_providers or len(providers) != 4:
                    raise RuntimeError(f"Keycloak exposed unexpected key factories: {discovered}")
                master_id = get_admin(base + "/admin/realms/master", token)["id"]
                for field, value in (("privateKey", "synthetic-forbidden"),
                                     ("algorithm", "synthetic-forbidden")):
                    forbidden = Request(
                        base + "/admin/realms/master/components",
                        data=json.dumps({
                            "name": "forbidden-local-key-probe",
                            "parentId": master_id,
                            "providerType": "org.keycloak.keys.KeyProvider",
                            "providerId": "rsa-generated",
                            "config": {field: [value]},
                        }).encode(),
                        headers={"Authorization": "Bearer " + token,
                                 "Content-Type": "application/json"},
                    )
                    try:
                        urlopen(forbidden, timeout=8)
                    except HTTPError as error:
                        if error.code < 400 or error.code >= 500:
                            raise RuntimeError("Local-key component returned an unexpected status") from error
                    else:
                        raise RuntimeError("Keycloak accepted a local-key component")
                    if database_key_counts(pg_name) != (0, 0):
                        raise RuntimeError("Rejected local-key component reached PostgreSQL")
                components = get_admin(
                    base + "/admin/realms/master/components?type=org.keycloak.keys.KeyProvider",
                    token,
                )
                rsa_component = next((component for component in components
                                      if component.get("providerId") == "rsa-generated"), None)
                if rsa_component is None:
                    raise RuntimeError("Master remote RSA component is missing")
                poisoned = {**rsa_component, "config": {"privateKey": ["synthetic-forbidden"]}}
                update = Request(
                    base + f"/admin/realms/master/components/{rsa_component['id']}",
                    data=json.dumps(poisoned).encode(), method="PUT",
                    headers={"Authorization": "Bearer " + token,
                             "Content-Type": "application/json"},
                )
                try:
                    with urlopen(update, timeout=8):
                        pass
                except HTTPError as error:
                    if error.code < 400 or error.code >= 500:
                        raise RuntimeError("Private-key component update returned an unexpected status") from error
                else:
                    updated = get_admin(
                        base + f"/admin/realms/master/components/{rsa_component['id']}",
                        token,
                    )
                    if "synthetic-forbidden" in json.dumps(updated.get("config", {})):
                        raise RuntimeError("Keycloak retained a private-key component update")
                if database_key_counts(pg_name) != (0, 0):
                    raise RuntimeError("Rejected private-key update reached PostgreSQL")
            try:
                jwks = http_json(base + "/realms/master/protocol/openid-connect/certs")
            except HTTPError as error:
                observed = subprocess.run(["docker", "logs", "--tail", "100", kc_name],
                                          capture_output=True, text=True, timeout=10)
                logs = "\n".join(line for line in (observed.stdout + observed.stderr).splitlines()
                                 if "ERROR" in line or "Caused by" in line)[:2500]
                raise RuntimeError(f"Keycloak JWKS request failed: HTTP {error.code}\n{logs}") from error
            master_modulus = verify_jwt(token, jwks, f"{prefix}-master-rs256-v1",
                                        base + "/realms/master")
            post_admin(base + "/admin/realms", token,
                       {"realm": "11id", "enabled": True,
                        "sslRequired": "NONE"})
            post_admin(base + "/admin/realms/11id/users", token, {
                "username": "probe11", "enabled": True,
                "firstName": "Disposable", "lastName": "Probe",
                "email": "probe11@example.invalid", "emailVerified": True,
                "credentials": [{"type": "password", "value": "synthetic-probe-only",
                                 "temporary": False}],
            })
            if database_key_counts(pg_name) != (0, 0):
                raise RuntimeError("11id realm creation stored private key material")
            try:
                realm_tokens = http_json(base + "/realms/11id/protocol/openid-connect/token", {
                    "client_id": "admin-cli", "grant_type": "password",
                    "username": "probe11", "password": "synthetic-probe-only",
                })
                token_11id = realm_tokens["access_token"]
            except HTTPError as error:
                response = json.loads(error.read())
                raise RuntimeError(f"11id token request failed: {error.code} "
                                   f"{response.get('error')} {response.get('error_description')}") from error
            jwks_11id = http_json(base + "/realms/11id/protocol/openid-connect/certs")
            realm_modulus = verify_jwt(token_11id, jwks_11id,
                                       f"{prefix}-11id-rs256-v1",
                                       base + "/realms/11id")
            if realm_modulus == master_modulus:
                raise RuntimeError("master and 11id reused one remote RSA key")
            if require_browser:
                callback = base + "/probe-callback"
                for realm in ("master", "11id"):
                    post_admin(base + f"/admin/realms/{realm}/clients", token, {
                        "clientId": "probe-browser", "enabled": True,
                        "publicClient": True, "standardFlowEnabled": True,
                        "directAccessGrantsEnabled": False,
                        "protocol": "openid-connect", "redirectUris": [callback],
                        "attributes": {"pkce.code.challenge.method": "S256"},
                    })
                post_admin(base + "/admin/realms/11id/clients", token, {
                    "clientId": "probe-ciba", "enabled": True,
                    "publicClient": False, "clientAuthenticatorType": "client-secret",
                    "secret": "synthetic-ciba-probe-only",
                    "standardFlowEnabled": False,
                    "directAccessGrantsEnabled": False,
                    "protocol": "openid-connect",
                    "attributes": {"oidc.ciba.grant.enabled": "true"},
                })
                ciba = http_json(base + "/realms/11id/protocol/openid-connect/ext/ciba/auth", {
                    "client_id": "probe-ciba",
                    "client_secret": "synthetic-ciba-probe-only",
                    "login_hint": "probe11", "scope": "openid",
                })
                auth_req_id = ciba.get("auth_req_id", "")
                header = jwe_header(auth_req_id)
                if (header.get("alg"), header.get("enc"), header.get("kid")) != (
                    "dir", "A256CBC-HS512", f"keycloak-11id-ciba-{ciba_version}"
                ):
                    raise RuntimeError("CIBA request ID did not use the scoped remote JWE key")
                new_ciba_version = rotate_jwe("11id", "ciba", ciba_version)
                try:
                    http_json(base + "/realms/11id/protocol/openid-connect/token", {
                        "client_id": "probe-ciba",
                        "client_secret": "synthetic-ciba-probe-only",
                        "grant_type": "urn:openid:params:grant-type:ciba",
                        "auth_req_id": auth_req_id,
                    })
                except HTTPError as error:
                    if error.code != 400 or json.loads(error.read()).get("error") != "authorization_pending":
                        raise RuntimeError("CIBA polling did not decrypt the remote request ID") from error
                else:
                    raise RuntimeError("Unapproved CIBA request unexpectedly issued a token")
                if len(PendingCibaDevice.received_tokens) != 1:
                    raise RuntimeError("CIBA device did not receive one callback capability")
                callback_request = Request(
                    base + "/realms/11id/protocol/openid-connect/ext/ciba/auth/callback",
                    data=json.dumps({"status": "SUCCEED"}).encode(),
                    headers={"Content-Type": "application/json",
                             "Authorization": PendingCibaDevice.received_tokens.pop()},
                )
                with urlopen(callback_request, timeout=8) as response:
                    if response.status != 200:
                        raise RuntimeError("CIBA device approval was not acknowledged")
                approved = None
                for _ in range(4):
                    time.sleep(max(1, int(ciba.get("interval", 5))))
                    try:
                        approved = http_json(base + "/realms/11id/protocol/openid-connect/token", {
                            "client_id": "probe-ciba",
                            "client_secret": "synthetic-ciba-probe-only",
                            "grant_type": "urn:openid:params:grant-type:ciba",
                            "auth_req_id": auth_req_id,
                        })
                        break
                    except HTTPError as error:
                        details = json.loads(error.read())
                        if error.code != 400 or details.get("error") not in (
                            "authorization_pending", "slow_down"
                        ):
                            raise RuntimeError(
                                f"Approved CIBA poll failed: HTTP {error.code} "
                                f"{details.get('error')}"
                            ) from error
                if approved is None:
                    raise RuntimeError("Approved CIBA request never issued a token")
                for field in ("access_token", "id_token"):
                    verify_jwt(approved[field], jwks_11id,
                               f"{prefix}-11id-rs256-v1", base + "/realms/11id")
                approved_claims = json.loads(base64.urlsafe_b64decode(
                    approved["access_token"].split(".")[1] + "=="))
                if approved_claims.get("preferred_username") != "probe11":
                    raise RuntimeError("CIBA approved the wrong user")
                after_rotation = http_json(
                    base + "/realms/11id/protocol/openid-connect/ext/ciba/auth", {
                        "client_id": "probe-ciba",
                        "client_secret": "synthetic-ciba-probe-only",
                        "login_hint": "probe11", "scope": "openid",
                    })
                new_header = jwe_header(after_rotation["auth_req_id"])
                if new_header.get("kid") != f"keycloak-11id-ciba-{new_ciba_version}":
                    raise RuntimeError("CIBA did not use the new remote key after rotation")
                (jwe_token_dir / "11id-ciba.token").write_text(
                    "invalid-disposable-token", encoding="ascii")
                try:
                    http_json(base + "/realms/11id/protocol/openid-connect/ext/ciba/auth", {
                        "client_id": "probe-ciba",
                        "client_secret": "synthetic-ciba-probe-only",
                        "login_hint": "probe11", "scope": "openid",
                    })
                except HTTPError as error:
                    if error.code != 503:
                        raise RuntimeError("CIBA key loss returned an unexpected status") from error
                else:
                    raise RuntimeError("CIBA request succeeded without its remote key")
                for realm, username, realm_jwks in (
                    ("master", "probe", jwks),
                    ("11id", "probe11", jwks_11id),
                ):
                    browser_cookies = CookieJar()
                    browser = build_opener(HTTPCookieProcessor(browser_cookies),
                                           StopAtCallback(callback))
                    def rotate_during_login() -> None:
                        restart = next((cookie for cookie in browser_cookies
                                        if cookie.name == "KC_RESTART"), None)
                        if restart is None:
                            raise RuntimeError("Keycloak did not issue a restart cookie before rotation")
                        old_version = cookie_versions[realm]
                        if jwe_header(restart.value).get("kid") != f"keycloak-{realm}-cookie-{old_version}":
                            raise RuntimeError("Restart cookie did not use the old remote key")
                        cookie_versions[realm] = rotate_jwe(realm, "cookie", old_version)
                        decrypted = bao_api(
                            f"didcomm/keycloak/jwe/decode/{realm}/cookie/{old_version}",
                            {"jwe": restart.value},
                            token=(jwe_token_dir / f"{realm}-cookie.token").read_text(),
                        )["data"]["plaintext_base64"]
                        if len(base64.b64decode(decrypted).split(b".")) != 3:
                            raise RuntimeError("Old restart cookie did not survive remote rotation")
                    for login in (True, False):
                        try:
                            browser_tokens = browser_code(browser, base, callback,
                                                          realm, username, login=login,
                                                          before_submit=rotate_during_login
                                                          if login else None)
                        except Exception as error:
                            observed = subprocess.run(["docker", "logs", "--tail", "120", kc_name],
                                                      capture_output=True, text=True, timeout=10)
                            lines = (observed.stdout + observed.stderr).splitlines()
                            logs = "\n".join(line for line in lines
                                             if "Failed to create fallback key" in line
                                             or "Caused by:" in line
                                             or "Error encoding cookie" in line)[:1200]
                            raise RuntimeError(f"{realm} browser flow failed: {error}\n{logs}") from error
                        for field in ("access_token", "id_token"):
                            verify_jwt(browser_tokens[field], realm_jwks,
                                       f"{prefix}-{realm}-rs256-v1",
                                       base + f"/realms/{realm}")
                    fresh_cookies = CookieJar()
                    fresh_browser = build_opener(HTTPCookieProcessor(fresh_cookies),
                                                 StopAtCallback(callback))
                    def verify_new_cookie() -> None:
                        restart = next((cookie for cookie in fresh_cookies
                                        if cookie.name == "KC_RESTART"), None)
                        if (restart is None or jwe_header(restart.value).get("kid") !=
                                f"keycloak-{realm}-cookie-{cookie_versions[realm]}"):
                            raise RuntimeError("New restart cookie did not use the rotated key")
                    fresh_tokens = browser_code(fresh_browser, base, callback,
                                                realm, username, login=True,
                                                before_submit=verify_new_cookie)
                    verify_jwt(fresh_tokens["access_token"], realm_jwks,
                               f"{prefix}-{realm}-rs256-v1",
                               base + f"/realms/{realm}")
                    (jwe_token_dir / f"{realm}-cookie.token").write_text(
                        "invalid-disposable-token", encoding="ascii")
                    denied_browser = build_opener(HTTPCookieProcessor(CookieJar()),
                                                  StopAtCallback(callback))
                    try:
                        browser_code(denied_browser, base, callback,
                                     realm, username, login=True)
                    except RuntimeError as error:
                        if "HTTP 400" not in str(error) and "HTTP 500" not in str(error):
                            raise RuntimeError("Unexpected browser KMS-loss result") from error
                    else:
                        raise RuntimeError(f"{realm} browser login succeeded without its remote cookie key")
            refreshed_tokens = {}
            for realm, issued, jwks_for_realm in (
                ("master", master_tokens, jwks),
                ("11id", realm_tokens, jwks_11id),
            ):
                refresh = issued.get("refresh_token")
                if not refresh:
                    raise RuntimeError(f"{realm} did not issue a refresh token")
                refreshed = http_json(base + f"/realms/{realm}/protocol/openid-connect/token", {
                    "client_id": "admin-cli", "grant_type": "refresh_token",
                    "refresh_token": refresh,
                })
                verify_jwt(refreshed["access_token"], jwks_for_realm,
                           f"{prefix}-{realm}-rs256-v1", base + f"/realms/{realm}")
                repeated = http_json(base + f"/realms/{realm}/protocol/openid-connect/token", {
                    "client_id": "admin-cli", "grant_type": "refresh_token",
                    "refresh_token": refreshed["refresh_token"],
                })
                verify_jwt(repeated["access_token"], jwks_for_realm,
                           f"{prefix}-{realm}-rs256-v1", base + f"/realms/{realm}")
                refreshed_tokens[realm] = repeated
            if database_key_counts(pg_name) != (0, 0):
                raise RuntimeError("Keycloak token issuance stored private key material")
            verify_database_gate(pg_name)
            scoped_token.write_text("invalid-disposable-token", encoding="ascii")
            for realm, username in (
                ("master", "probe"),
                ("11id", "probe11"),
            ):
                for request in (
                    {"client_id": "admin-cli", "grant_type": "refresh_token",
                     "refresh_token": refreshed_tokens[realm]["refresh_token"]},
                    {"client_id": "admin-cli", "grant_type": "password",
                     "username": username, "password": "synthetic-probe-only"},
                ):
                    try:
                        http_json(base + f"/realms/{realm}/protocol/openid-connect/token",
                                  request)
                    except HTTPError as error:
                        details = json.loads(error.read())
                        denied = error.code == 500 or (
                            request["grant_type"] == "refresh_token"
                            and error.code == 400
                            and details.get("error") == "invalid_grant"
                        )
                        if not denied:
                            raise RuntimeError(
                                f"OpenBao loss returned {error.code} for "
                                f"{realm} {request['grant_type']}: "
                                f"{details.get('error')} {details.get('error_description')}"
                            ) from error
                    else:
                        raise RuntimeError(f"{realm} issued a token without its remote signer")
            if database_key_counts(pg_name) != (0, 0):
                raise RuntimeError("OpenBao loss caused local key storage")
            verify_database_gate(pg_name)
            browser_result = "rotated browser/cookie and completed CIBA, " if require_browser else ""
            print(f"Remote RS256 master/11id {browser_result}token/refresh/JWKS, KMS-loss denial, and PostgreSQL custody gate passed")
        finally:
            if ciba_device:
                ciba_device.shutdown()
                ciba_device.server_close()
            if started_kc:
                subprocess.run(["docker", "rm", "-f", kc_name], capture_output=True)
            if started_bao:
                subprocess.run(["docker", "rm", "-f", bao_name], capture_output=True)
            if started_pg:
                subprocess.run(["docker", "rm", "-f", pg_name], capture_output=True)
            if created_network:
                subprocess.run(["docker", "network", "rm", network], capture_output=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--keycloak-image", default="quay.io/keycloak/keycloak:26.8.0")
    parser.add_argument("--openbao-image", default="quay.io/openbao/openbao:2")
    parser.add_argument("--jar", type=Path,
                        default=ROOT / "keycloak/openbao-provider/target/keycloak-openbao-provider-0.0.0-probe.jar")
    parser.add_argument("--require-browser", action="store_true",
                        help="Require an authorization-code login and silent session reuse")
    args = parser.parse_args()
    probe(args.keycloak_image, args.openbao_image, args.jar.resolve(),
          require_browser=args.require_browser)
