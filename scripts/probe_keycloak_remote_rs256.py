#!/usr/bin/env python3
"""Disposable Keycloak 25/OpenBao RS256 probe; never prints tokens or keys."""

from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path
import secrets
import ssl
import subprocess
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

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


def http_json(url: str, body: dict[str, str] | None = None) -> dict:
    request = Request(url, data=urlencode(body).encode() if body else None)
    with urlopen(request, timeout=5) as response:
        return json.load(response)


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
    run("docker", "exec", container, "/bin/sh", "-c",
        "cp /opt/keycloak/data/h2/keycloakdb.mv.db /tmp/kms-probe.mv.db")
    output = run(
        "docker", "exec", container, "java", "-cp",
        "/opt/keycloak/lib/lib/main/com.h2database.h2-2.2.224.jar",
        "org.h2.tools.Shell", "-url", "jdbc:h2:file:/tmp/kms-probe",
        "-user", "sa", "-password", "password", "-sql",
        "SELECT NAME, COUNT(*) AS N FROM COMPONENT_CONFIG "
        "WHERE NAME IN ('privateKey','secret') GROUP BY NAME",
    )
    counts = {name: int(value) for name, value in (
        line.split("|") for line in output.splitlines() if "|" in line
        and not line.startswith("NAME"))}
    return counts.get("privateKey", 0), counts.get("secret", 0)


def verify_jwt(jwt: str, jwks: dict, expected_kid: str) -> None:
    parts = jwt.split(".")
    if len(parts) != 3:
        raise RuntimeError("Keycloak did not return a JWT")

    def decoded(value: str) -> bytes:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

    header = json.loads(decoded(parts[0]))
    if header.get("alg") != "RS256" or header.get("kid") != expected_kid:
        raise RuntimeError("Keycloak JWT did not use the pinned remote RS256 key")
    key = next((item for item in jwks["keys"] if item.get("kid") == expected_kid), None)
    if key is None or key.get("kty") != "RSA":
        raise RuntimeError("Keycloak JWKS omitted the remote RSA public key")
    public = rsa.RSAPublicNumbers(
        int.from_bytes(decoded(key["e"]), "big"),
        int.from_bytes(decoded(key["n"]), "big"),
    ).public_key()
    public.verify(decoded(parts[2]), f"{parts[0]}.{parts[1]}".encode(),
                  padding.PKCS1v15(), hashes.SHA256())


def probe(keycloak_image: str, openbao_image: str, jar: Path) -> None:
    if not jar.is_file():
        raise RuntimeError("Build keycloak/openbao-provider with Maven first")
    suffix = secrets.token_hex(5)
    network = "marty-keycloak-kms-net-" + suffix
    bao_name = "marty-keycloak-kms-bao-" + suffix
    kc_name = "marty-keycloak-kms-oidc-" + suffix
    prefix = "kmsprobe" + suffix
    created_network = False
    started_bao = False
    started_kc = False
    with tempfile.TemporaryDirectory(prefix="marty-keycloak-kms-") as temporary:
        root = Path(temporary)
        ca_dir = root / "ca"
        ca_dir.mkdir()
        root_token = root / "root-token"
        scoped_token = root / "keycloak-token"
        root_token.write_text(secrets.token_hex(32), encoding="ascii")
        try:
            run("docker", "network", "create", network)
            created_network = True
            run(
                "docker", "run", "-d", "--name", bao_name,
                "--network", network, "--network-alias", "openbao",
                "--hostname", "openbao", "-p", "127.0.0.1::8200",
                "--tmpfs", "/tmp/bao-tls:rw,mode=1777",
                "--mount", f"type=bind,src={ROOT / 'scripts/passport_supported_openbao_start.sh'},dst=/usr/local/bin/passport-supported-openbao-start,readonly",
                "--mount", f"type=bind,src={root_token},dst=/run/secrets/bao_root_token,readonly",
                "--mount", f"type=bind,src={ca_dir},dst=/bao/public-ca",
                "-e", "PASSPORT_BAO_TLS_MODE=required",
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

            def bao_api(path: str, payload: dict) -> dict:
                request = Request(bao_base + path, data=json.dumps(payload).encode(),
                                  headers={"X-Vault-Token": root_token.read_text(),
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
            name = f"{prefix}-master-rs256"
            hmac_name = f"{prefix}-master-hs512"
            bao("write", f"transit/keys/{name}", "type=rsa-2048", "exportable=false")
            bao("write", f"transit/keys/{hmac_name}", "type=hmac",
                "key_size=64", "exportable=false")
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
            csr = bao_api(f"transit/keys/{name}/csr", {"version": 1})["data"]["csr"]
            signed = bao_api("pki/sign/keycloak-rs256", {
                "csr": csr, "common_name": "master.keycloak.internal", "ttl": "1h",
            })["data"]
            if "private_key" in signed:
                raise RuntimeError("OpenBao exported the remote RS256 private key")
            certificate = root / "master-rs256.crt"
            certificate.write_text(signed["certificate"], encoding="ascii")
            policy = f'path "transit/keys/{name}" {{ capabilities = ["read"] }}\n' \
                     f'path "transit/sign/{name}" {{ capabilities = ["update"] }}\n' \
                     f'path "transit/keys/{hmac_name}" {{ capabilities = ["read"] }}\n' \
                     f'path "transit/hmac/{hmac_name}/sha2-512" {{ capabilities = ["update"] }}\n' \
                     f'path "transit/verify/{hmac_name}/sha2-512" {{ capabilities = ["update"] }}\n'
            bao("policy", "write", "keycloak-rs256-probe", "-", input_text=policy)
            scoped_token.write_text(bao("token", "create", "-policy=keycloak-rs256-probe",
                                        "-ttl=1h", "-field=token"), encoding="ascii")
            if not scoped_token.read_text().strip():
                raise RuntimeError("Scoped OpenBao token is empty")

            run(
                "docker", "run", "-d", "--name", kc_name,
                "--network", network, "-p", "127.0.0.1::8080",
                "--mount", f"type=bind,src={jar},dst=/opt/keycloak/providers/marty-kms-probe.jar,readonly",
                "--mount", f"type=bind,src={ca_dir / 'ca.crt'},dst=/run/kms/ca.crt,readonly",
                "--mount", f"type=bind,src={scoped_token},dst=/run/kms/token,readonly",
                "--mount", f"type=bind,src={certificate},dst=/run/kms/rs256.crt,readonly",
                "-e", "KEYCLOAK_ADMIN=probe",
                "-e", "KEYCLOAK_ADMIN_PASSWORD=synthetic-probe-only",
                "-e", "BAO_ADDR=https://openbao:8200",
                "-e", "BAO_CACERT=/run/kms/ca.crt",
                "-e", "BAO_TOKEN_FILE=/run/kms/token",
                "-e", "MARTY_KEYCLOAK_RS256_CERT_FILE=/run/kms/rs256.crt",
                "-e", f"MARTY_KEYCLOAK_KMS_KEY_PREFIX={prefix}",
                "-e", "MARTY_KEYCLOAK_KMS_KEY_VERSION=1",
                keycloak_image, "start-dev",
            )
            started_kc = True
            port = run("docker", "port", kc_name, "8080/tcp").rsplit(":", 1)[-1]
            base = f"http://127.0.0.1:{port}"
            wait_for_keycloak(base, kc_name)
            if database_key_counts(kc_name) != (0, 0):
                raise RuntimeError("Keycloak bootstrap stored private key material")
            try:
                token = http_json(base + "/realms/master/protocol/openid-connect/token", {
                    "client_id": "admin-cli", "grant_type": "password",
                    "username": "probe", "password": "synthetic-probe-only",
                })["access_token"]
            except HTTPError as error:
                observed = subprocess.run(["docker", "logs", "--tail", "100", kc_name],
                                          capture_output=True, text=True, timeout=10)
                logs = "\n".join(line for line in (observed.stdout + observed.stderr).splitlines()
                                 if "ERROR" in line or "Caused by" in line)[:2500]
                raise RuntimeError(f"Keycloak token request failed: HTTP {error.code}\n{logs}") from error
            try:
                jwks = http_json(base + "/realms/master/protocol/openid-connect/certs")
            except HTTPError as error:
                observed = subprocess.run(["docker", "logs", "--tail", "100", kc_name],
                                          capture_output=True, text=True, timeout=10)
                logs = "\n".join(line for line in (observed.stdout + observed.stderr).splitlines()
                                 if "ERROR" in line or "Caused by" in line)[:2500]
                raise RuntimeError(f"Keycloak JWKS request failed: HTTP {error.code}\n{logs}") from error
            verify_jwt(token, jwks, name + "-v1")
            if database_key_counts(kc_name) != (0, 0):
                raise RuntimeError("Keycloak token issuance stored private key material")
            scoped_token.write_text("invalid-disposable-token", encoding="ascii")
            try:
                http_json(base + "/realms/master/protocol/openid-connect/token", {
                    "client_id": "admin-cli", "grant_type": "password",
                    "username": "probe", "password": "synthetic-probe-only",
                })
            except HTTPError as error:
                if error.code != 500:
                    raise RuntimeError("OpenBao loss returned an unexpected status") from error
            else:
                raise RuntimeError("Keycloak issued a token without its remote signer")
            if database_key_counts(kc_name) != (0, 0):
                raise RuntimeError("OpenBao loss caused local key storage")
            print("Remote RS256 Keycloak token/JWKS, KMS-loss denial, and zero-private-row probe passed")
        finally:
            if started_kc:
                subprocess.run(["docker", "rm", "-f", kc_name], capture_output=True)
            if started_bao:
                subprocess.run(["docker", "rm", "-f", bao_name], capture_output=True)
            if created_network:
                subprocess.run(["docker", "network", "rm", network], capture_output=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--keycloak-image", default="quay.io/keycloak/keycloak:25.0")
    parser.add_argument("--openbao-image", default="quay.io/openbao/openbao:2")
    parser.add_argument("--jar", type=Path,
                        default=ROOT / "keycloak/openbao-provider/target/keycloak-openbao-provider-0.0.0-probe.jar")
    args = parser.parse_args()
    probe(args.keycloak_image, args.openbao_image, args.jar.resolve())
