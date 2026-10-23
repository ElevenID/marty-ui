#!/usr/bin/env python3
"""Run a release verifier command with two scoped, disposable OpenBao signers.

Credential keys stay inside Transit. The Core test wallet and signer agents
receive public JWKs, scoped tokens and authenticated local IPC endpoints only.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
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
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener

IMAGE = re.compile(r"(?:quay\.io/openbao/openbao)@sha256:[0-9a-f]{64}\Z")
ISSUER_KID = "did:example:verifier-runtime-gate-issuer#key-1"
HOLDER_KID = "did:example:runtime-gate-holder"


class FixtureError(RuntimeError):
    pass


def run(args: list[str], *, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(args, capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=timeout,
                                check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise FixtureError("disposable fixture command unavailable") from exc
    if result.returncode != 0:
        raise FixtureError("disposable fixture command failed")
    return result


def port_for(container: str) -> int:
    result = run(["docker", "port", container, "8200/tcp"])
    address = result.stdout.strip()
    if not address.startswith("127.0.0.1:"):
        raise FixtureError("OpenBao must publish only a loopback port")
    port = int(address.rsplit(":", 1)[1])
    if not 1 <= port <= 65535:
        raise FixtureError("OpenBao loopback port is invalid")
    return port


class Bao:
    def __init__(self, port: int, ca: Path, token: str) -> None:
        self.base = f"https://127.0.0.1:{port}/v1/"
        self.token = token
        self.opener = build_opener(
            ProxyHandler({}), HTTPSHandler(context=ssl.create_default_context(cafile=str(ca)))
        )

    def request(self, method: str, route: str, body: dict | None = None,
                *, token: str | None = None) -> dict:
        encoded = None if body is None else json.dumps(body).encode("utf-8")
        request = Request(self.base + route, data=encoded, method=method,
                          headers={"X-Vault-Token": token or self.token,
                                   "Content-Type": "application/json"})
        try:
            with self.opener.open(request, timeout=10) as response:
                payload = response.read(128 * 1024 + 1)
        except (HTTPError, URLError, TimeoutError) as exc:
            raise FixtureError(f"OpenBao {method} {route} failed") from exc
        if len(payload) > 128 * 1024:
            raise FixtureError("OpenBao response exceeded bound")
        return json.loads(payload) if payload else {}


def public_jwk(pem: str, tool: Path, *, issuer: bool) -> dict[str, str]:
    try:
        result = subprocess.run([str(tool)], input=pem, capture_output=True,
                                text=True, timeout=10, check=False)
        if result.returncode or len(result.stdout) > 16 * 1024:
            raise FixtureError("Rust public-key conversion failed")
        parsed = json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        raise FixtureError("Rust public-key conversion failed") from exc
    if not isinstance(parsed, dict) or parsed.get("kty") != "EC" or parsed.get("crv") != "P-256":
        raise FixtureError("OpenBao returned a non-P-256 public key")
    try:
        jwk = {name: parsed[name] for name in ("kty", "crv", "x", "y")}
    except KeyError as exc:
        raise FixtureError("OpenBao returned incomplete public coordinates") from exc
    if any(not isinstance(value, str) or not value for value in jwk.values()):
        raise FixtureError("OpenBao returned malformed public coordinates")
    if issuer:
        jwk.update({"kid": ISSUER_KID, "alg": "ES256"})
    return jwk


def create_key(bao: Bao, name: str, tool: Path, *, issuer: bool) -> dict[str, str]:
    bao.request("POST", f"transit/keys/{name}", {
        "type": "ecdsa-p256", "exportable": False, "allow_plaintext_backup": False,
    })
    data = bao.request("GET", f"transit/keys/{name}").get("data", {})
    if data.get("type") != "ecdsa-p256" or data.get("exportable") is not False or data.get(
        "allow_plaintext_backup"
    ) is not False:
        raise FixtureError("OpenBao key custody attributes changed")
    latest = data.get("latest_version")
    pem = data.get("keys", {}).get(str(latest), {}).get("public_key")
    if not isinstance(pem, str):
        raise FixtureError("OpenBao public key is unavailable")
    return public_jwk(pem, tool, issuer=issuer)


def scoped_token(bao: Bao, name: str) -> str:
    policy = f"verifier-positive-{name}"
    bao.request("PUT", f"sys/policies/acl/{policy}", {
        "policy": f'path "transit/sign/{name}" {{ capabilities = ["update"] }}',
    })
    token = bao.request("POST", "auth/token/create", {
        "policies": [policy], "no_default_policy": True, "ttl": "10m",
    }).get("auth", {}).get("client_token")
    if not isinstance(token, str) or not token:
        raise FixtureError("scoped OpenBao token is unavailable")
    return token


def require_cross_scope_denial(bao: Bao, token: str, foreign_key: str) -> None:
    body = {"input": base64.b64encode(b"cross-scope-denial-probe").decode("ascii")}
    request = Request(bao.base + f"transit/sign/{foreign_key}",
                      data=json.dumps(body).encode("utf-8"), method="POST",
                      headers={"X-Vault-Token": token, "Content-Type": "application/json"})
    try:
        with bao.opener.open(request, timeout=10):
            pass
    except HTTPError as exc:
        if exc.code == 403:
            return
    raise FixtureError("scoped token reached a foreign signing key")


def authentication_key() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")


def agent_endpoint(root: Path, label: str) -> str:
    if os.name == "nt":
        return rf"\\.\pipe\marty-test-wallet-{label}-{secrets.token_hex(6)}"
    return str(root / f"{label}.sock")


def start_agent(binary: Path, environment: dict[str, str], endpoint: str) -> subprocess.Popen:
    try:
        process = subprocess.Popen([str(binary)], env=environment,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError as exc:
        raise FixtureError("Core signer agent could not start") from exc
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise FixtureError("Core signer agent exited before readiness")
        if os.name == "nt":
            time.sleep(0.25)
            return process
        if Path(endpoint).is_socket():
            return process
        time.sleep(0.1)
    process.terminate()
    raise FixtureError("Core signer agent socket was not ready")


def execute(openbao_image: str, producer: Path, agent: Path, jwk_tool: Path,
            command: list[str], evidence_output: Path | None = None) -> int:
    if not IMAGE.fullmatch(openbao_image):
        raise FixtureError("OpenBao fixture image must use the pinned upstream digest")
    if any(not tool.is_absolute() or not tool.is_file()
           for tool in (producer, agent, jwk_tool)):
        raise FixtureError("Rust fixture executables must be absolute files")
    if not command:
        raise FixtureError("a verifier qualification command is required")
    if evidence_output is not None and evidence_output.exists():
        raise FixtureError("KMS fixture evidence output must be fresh")
    with tempfile.TemporaryDirectory(prefix="marty-verifier-kms-") as temporary:
        root = Path(temporary)
        if os.name == "posix":
            root.chmod(0o700)
        tls = root / "tls"
        tls.mkdir(mode=0o700)
        if os.name == "posix":
            # The OpenBao image drops root before generating its dev TLS
            # certificate. Docker bind mounts retain this host directory's
            # mode; only the private 0700 parent is host-traversable.
            tls.chmod(0o777)
        container = "marty-verifier-kms-" + secrets.token_hex(8)
        root_token = secrets.token_hex(24)
        agents: list[subprocess.Popen] = []
        started = False
        try:
            run(["docker", "run", "-d", "--name", container,
                 "-p", "127.0.0.1::8200", "-v", f"{tls}:/tmp/bao-tls",
                 "-e", "BAO_DEV_LISTEN_ADDRESS=0.0.0.0:8200",
                 "-e", f"BAO_DEV_ROOT_TOKEN_ID={root_token}", openbao_image,
                 "server", "-dev", "-dev-tls", "-dev-tls-cert-dir=/tmp/bao-tls"])
            started = True
            port = port_for(container)
            ca = tls / "vault-ca.pem"
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if ca.is_file():
                    try:
                        # The CA is public; the generated server key remains private.
                        run(["docker", "exec", container, "chmod", "644",
                             "/tmp/bao-tls/vault-ca.pem"])
                        bao = Bao(port, ca, root_token)
                        bao.request("GET", "sys/health")
                        break
                    except FixtureError:
                        pass
                time.sleep(0.2)
            else:
                raise FixtureError("disposable OpenBao TLS endpoint did not become ready")
            bao.request("POST", "sys/mounts/transit", {"type": "transit"})
            issuer_name = "positive-issuer-" + secrets.token_hex(4)
            holder_name = "positive-holder-" + secrets.token_hex(4)
            issuer_public = create_key(bao, issuer_name, jwk_tool, issuer=True)
            holder_public = create_key(bao, holder_name, jwk_tool, issuer=False)
            issuer_token = scoped_token(bao, issuer_name)
            holder_token = scoped_token(bao, holder_name)
            require_cross_scope_denial(bao, issuer_token, holder_name)
            require_cross_scope_denial(bao, holder_token, issuer_name)
            environment = os.environ.copy()
            identities = (
                ("issuer", issuer_name, ISSUER_KID, issuer_token),
                ("holder", holder_name, HOLDER_KID, holder_token),
            )
            for label, key_name, kid, token in identities:
                endpoint = agent_endpoint(root, label)
                authentication = authentication_key()
                agent_env = environment.copy()
                agent_env.update({
                    "MARTY_TEST_WALLET_HOLDER_SIGNER_ENDPOINT": endpoint,
                    "MARTY_TEST_WALLET_HOLDER_SIGNER_AUTHENTICATION_KEY": authentication,
                    "MARTY_TEST_SIGNER_AGENT_ALLOWED_KEY_ID": kid,
                    "MARTY_TEST_SIGNER_AGENT_KMS_PROVIDER": "openbao-transit",
                    "MARTY_TEST_SIGNER_AGENT_KMS_URL": bao.base + f"transit/sign/{key_name}",
                    "MARTY_TEST_SIGNER_AGENT_KMS_BEARER_TOKEN": token,
                    "MARTY_TEST_SIGNER_AGENT_KMS_CA_CERT_PEM": str(ca),
                })
                agents.append(start_agent(agent, agent_env, endpoint))
                prefix = "MARTY_POSITIVE_GATE_ISSUER" if label == "issuer" else "MARTY_TEST_WALLET_HOLDER"
                environment[f"{prefix}_SIGNER_ENDPOINT"] = endpoint
                environment[f"{prefix}_SIGNER_AUTHENTICATION_KEY"] = authentication
            environment.update({
                "MARTY_POSITIVE_GATE_ISSUER_PUBLIC_JWK": json.dumps(issuer_public),
                "MARTY_POSITIVE_GATE_ISSUER_KID": ISSUER_KID,
                "MARTY_TEST_WALLET_HOLDER_PUBLIC_JWK": json.dumps(holder_public),
                "MARTY_TEST_WALLET_HOLDER_KID": HOLDER_KID,
                "MARTY_VERIFIER_POSITIVE_PRODUCER": str(producer),
                "MARTY_VERIFIER_POSITIVE_PRODUCER_SHA256": hashlib.sha256(producer.read_bytes()).hexdigest(),
            })
            try:
                status = subprocess.run(command, env=environment, check=False).returncode
            except OSError as exc:
                raise FixtureError("verifier qualification command unavailable") from exc
            if status == 0 and evidence_output is not None:
                evidence = {
                    "schema": "marty.verifier-disposable-kms/v1",
                    "status": "passed",
                    "provider_image": openbao_image,
                    "producer_sha256": environment["MARTY_VERIFIER_POSITIVE_PRODUCER_SHA256"],
                    "issuer_public_jwk_sha256": hashlib.sha256(
                        json.dumps(issuer_public, sort_keys=True).encode("utf-8")
                    ).hexdigest(),
                    "holder_public_jwk_sha256": hashlib.sha256(
                        json.dumps(holder_public, sort_keys=True).encode("utf-8")
                    ).hexdigest(),
                    "issuer_and_holder_keys_non_exportable": True,
                    "cross_key_signing_denied": True,
                }
                evidence_output.parent.mkdir(parents=True, exist_ok=True)
                evidence_output.write_text(json.dumps(evidence, sort_keys=True) + "\n",
                                           encoding="utf-8")
            return status
        finally:
            for process in reversed(agents):
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            if started:
                subprocess.run(["docker", "rm", "-f", container],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               check=False, timeout=30)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--openbao-image", required=True)
    parser.add_argument("--producer", type=Path, required=True)
    parser.add_argument("--agent", type=Path, required=True)
    parser.add_argument("--jwk-tool", type=Path, required=True)
    parser.add_argument("--evidence-output", type=Path)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    try:
        return execute(args.openbao_image, args.producer, args.agent, args.jwk_tool,
                       command, args.evidence_output)
    except FixtureError as exc:
        parser.exit(1, f"Disposable KMS verifier fixture failed: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
