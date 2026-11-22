#!/usr/bin/env python3
"""Run a receipt-signing contract against new native TLS OpenBao and Redis.

Supply independently verified OpenBao 2.5.5 and Redis 7.4.12 executables. Version
checks ensure compatibility, not release authenticity. Build the Rust test
before entering this short-lived fixture. No existing provider or Redis process
is contacted, and the administrative OpenBao credential never reaches the test.

The Redis instance uses a random password, database 15, a nonce sentinel, and no
persistence. OpenBao uses TLS, a separate nonce sentinel, non-exportable Transit
keys and narrowly scoped leaf tokens. The historical ROOT_TOKEN guard variable
contains only a marker-read token. A separate rotation token can rotate exactly
the two disposable receipt keys; it cannot sign or export them. Audit records
are private temporary files used to count real provider requests, then removed.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from urllib.error import HTTPError

if __package__:
    from .selfhost_openbao_client import Bao
    from .with_disposable_policy_owner_kms import compatible_executable, wait_for_openbao
else:
    from selfhost_openbao_client import Bao
    from with_disposable_policy_owner_kms import compatible_executable, wait_for_openbao


RECEIPT_MAC_KEY = "marty-sign-grant-delegated-decision-v1"
GATEWAY_MAC_KEY = "marty-sign-grant-gateway-service-v1"
ENVELOPE_KEY = "integration-secret-envelope-marty-aes256"
SIGNING_KEYS = {"ED25519": ("receipt-ed25519", "ed25519"), "ES256": ("receipt-es256", "ecdsa-p256")}


def redis_executable(path: Path) -> Path:
    executable = path.expanduser().resolve(strict=True)
    version = subprocess.run([str(executable), "--version"], capture_output=True,
                             text=True, check=True, timeout=10)
    if not re.search(r"\bv=7\.4\.12\b", version.stdout):
        raise RuntimeError("the isolated fixture requires Redis 7.4.12")
    return executable


def available_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def write_private(root: Path, name: str, value: str) -> Path:
    path = root / name
    path.write_text(value, encoding="ascii")
    path.chmod(0o600)
    return path


def redis_command(connection, *args: str) -> bytes:
    encoded = [arg.encode("ascii") for arg in args]
    command = b"*" + str(len(encoded)).encode() + b"\r\n"
    command += b"".join(b"$" + str(len(arg)).encode() + b"\r\n" + arg + b"\r\n"
                        for arg in encoded)
    connection.write(command)
    connection.flush()
    answer = connection.readline()
    if not answer.startswith(b"+"):
        raise RuntimeError("isolated Redis fixture command failed")
    return answer[1:].rstrip(b"\r\n")


def wait_for_redis(server: subprocess.Popen, port: int, password: str, nonce: str) -> None:
    deadline = time.monotonic() + 20
    while True:
        if server.poll() is not None:
            raise RuntimeError("isolated Redis stopped before becoming ready")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1) as connection:
                with connection.makefile("rwb") as stream:
                    for args, expected in [
                        (("AUTH", password), b"OK"),
                        (("SELECT", "15"), b"OK"),
                        (("SET", "marty:tests:disposable-guard", nonce), b"OK"),
                        (("PING",), b"PONG"),
                    ]:
                        if redis_command(stream, *args) != expected:
                            raise RuntimeError("isolated Redis fixture setup failed")
            return
        except (OSError, RuntimeError):
            if time.monotonic() >= deadline:
                raise RuntimeError("isolated Redis readiness timed out") from None
            time.sleep(0.05)


def leaf(bao: Bao, name: str, paths: dict[str, list[str]]) -> str:
    policy = "\n".join(f'path "{path}" {{ capabilities = {json.dumps(capabilities)} }}'
                       for path, capabilities in paths.items())
    bao.request("PUT", f"sys/policies/acl/receipt-fixture-{name}", {"policy": policy})
    token = bao.request("POST", "auth/token/create", {
        "policies": [f"receipt-fixture-{name}"], "no_default_policy": True,
        "ttl": "1h", "renewable": False,
    })["auth"]["client_token"]
    if token == bao.token:
        raise RuntimeError("fixture leaf unexpectedly has administrative identity")
    return token


def denied(bao: Bao, token: str, method: str, path: str, body=None) -> None:
    try:
        bao.request(method, path, body, token=token)
    except HTTPError as error:
        if error.code == 403:
            return
    raise RuntimeError("disposable provider privilege separation failed")


def provision(bao: Bao, root: Path, address: str, nonce: str) -> dict[str, str]:
    bao.request("POST", "sys/mounts/transit", {"type": "transit"})
    bao.request("POST", "secret/data/marty-test-disposable-guard", {"data": {"nonce": nonce}})
    for key, kind in [*(value for value in SIGNING_KEYS.values()),
                      (RECEIPT_MAC_KEY, "hmac"), (GATEWAY_MAC_KEY, "hmac"),
                      (ENVELOPE_KEY, "aes256-gcm96")]:
        creation = {
            "type": kind, "exportable": False, "allow_plaintext_backup": False,
        }
        if kind == "hmac":
            creation["key_size"] = 32
        bao.request("POST", f"transit/keys/{key}", creation)
        metadata = bao.request("GET", f"transit/keys/{key}")["data"]
        if (metadata["type"] != kind or metadata["latest_version"] != 1
                or metadata["exportable"] is not False
                or metadata["allow_plaintext_backup"] is not False):
            raise RuntimeError("disposable Transit key custody metadata is invalid")

    signer_paths = {f"transit/keys/{key}": ["read"] for key, _ in SIGNING_KEYS.values()}
    signer_paths.update({f"transit/sign/{key}": ["update"] for key, _ in SIGNING_KEYS.values()})
    tokens = {
        "SIGNER": leaf(bao, "signer", signer_paths),
        "READ_ONLY": leaf(bao, "read-only", {
            f"transit/keys/{key}": ["read"] for key, _ in SIGNING_KEYS.values()}),
        "ROTATOR": leaf(bao, "rotator", {
            f"transit/keys/{key}/rotate": ["update"] for key, _ in SIGNING_KEYS.values()}),
        "MINT": leaf(bao, "mint", {f"transit/hmac/{RECEIPT_MAC_KEY}/sha2-256": ["update"]}),
        "GATEWAY_MINT": leaf(bao, "gateway-mint", {f"transit/hmac/{GATEWAY_MAC_KEY}/sha2-256": ["update"]}),
        "VERIFY": leaf(bao, "verify", {
            f"transit/verify/{RECEIPT_MAC_KEY}/sha2-256": ["update"],
            f"transit/verify/{GATEWAY_MAC_KEY}/sha2-256": ["update"],
        }),
        "ENVELOPE": leaf(bao, "envelope", {
            f"transit/keys/{ENVELOPE_KEY}": ["read"],
            f"transit/encrypt/{ENVELOPE_KEY}": ["update"],
            f"transit/decrypt/{ENVELOPE_KEY}": ["update"],
        }),
        "MARKER": leaf(bao, "marker", {"secret/data/marty-test-disposable-guard": ["read"]}),
    }
    if len(set(tokens.values())) != len(tokens):
        raise RuntimeError("disposable provider roles reused a token")

    proof = {"input": base64.b64encode(b"disposable-receipt-scope-proof").decode("ascii")}
    mac_path = f"transit/hmac/{RECEIPT_MAC_KEY}/sha2-256"
    verify_path = f"transit/verify/{RECEIPT_MAC_KEY}/sha2-256"
    hmac = bao.request("POST", mac_path, proof, token=tokens["MINT"])["data"]["hmac"]
    verification = {**proof, "hmac": hmac}
    if bao.request("POST", verify_path, verification, token=tokens["VERIFY"])["data"]["valid"] is not True:
        raise RuntimeError("disposable receipt MAC verification failed")
    denied(bao, tokens["MINT"], "POST", verify_path, verification)
    denied(bao, tokens["VERIFY"], "POST", mac_path, proof)
    denied(bao, tokens["MINT"], "POST", f"transit/hmac/{GATEWAY_MAC_KEY}/sha2-256", proof)
    denied(bao, tokens["GATEWAY_MINT"], "POST", mac_path, proof)
    for key, _ in SIGNING_KEYS.values():
        for role in ["MINT", "VERIFY", "READ_ONLY", "ROTATOR", "MARKER", "ENVELOPE"]:
            denied(bao, tokens[role], "POST", f"transit/sign/{key}", proof)
        denied(bao, tokens["SIGNER"], "POST", f"transit/keys/{key}/rotate", {})
        denied(bao, tokens["SIGNER"], "GET", f"transit/export/signing-key/{key}")
        denied(bao, tokens["ROTATOR"], "GET", f"transit/export/signing-key/{key}")
    denied(bao, tokens["SIGNER"], "POST", mac_path, proof)
    denied(bao, tokens["MARKER"], "GET", f"transit/keys/{ENVELOPE_KEY}")

    audit = root / "provider-audit.jsonl"
    if not audit.is_file() or audit.stat().st_size == 0:
        raise RuntimeError("declarative provider audit is unavailable")
    environment = {
        "BAO_ADDR": address, "BAO_CACERT": str(root / "vault-ca.pem"),
        "BAO_TOKEN": tokens["ENVELOPE"],
        "MARTY_TEST_OPENBAO_URL": address,
        "MARTY_TEST_OPENBAO_TOKEN": tokens["ENVELOPE"],
        "MARTY_TEST_OPENBAO_ROOT_TOKEN": tokens["MARKER"],
        "MARTY_TEST_OPENBAO_DISPOSABLE_NONCE": nonce,
        "MARTY_TEST_RECEIPT_AUDIT_FILE": str(audit),
    }
    for role, token in tokens.items():
        environment[f"MARTY_TEST_RECEIPT_{role}_TOKEN_FILE"] = str(
            write_private(root, role.lower() + "-token", token))
    for algorithm, (key, _) in SIGNING_KEYS.items():
        environment[f"MARTY_TEST_RECEIPT_{algorithm}_KEY"] = key
    return environment


def terminate(server: subprocess.Popen) -> None:
    if server.poll() is None:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=10)


def execute(bao_binary: Path, redis_binary: Path, command: list[str]) -> int:
    with tempfile.TemporaryDirectory(prefix="marty-delegated-receipt-kms-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        address = f"https://127.0.0.1:{available_port()}"
        root_token = secrets.token_hex(32)
        audit = write_private(root, "provider-audit.jsonl", "")
        configuration = write_private(root, "openbao.hcl", (
            'audit "file" "receipt-fixture" {\n'
            '  options {\n'
            f'    file_path = {json.dumps(str(audit))}\n'
            '    mode = "0600"\n'
            '  }\n'
            '}\n'
        ))
        openbao_environment = os.environ.copy()
        openbao_environment["BAO_DEV_ROOT_TOKEN_ID"] = root_token
        bao_server = subprocess.Popen([
            str(bao_binary), "server", "-dev", "-dev-tls", "-dev-no-store-token",
            "-dev-listen-address=" + address.removeprefix("https://"),
            "-dev-tls-cert-dir=" + str(root),
            "-config=" + str(configuration),
        ], env=openbao_environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        redis_server = None
        try:
            bao = wait_for_openbao(bao_server, address, root / "vault-ca.pem", root_token)
            environment = {key: value for key, value in os.environ.items()
                           if not key.startswith(("BAO_", "VAULT_", "MARTY_TEST_"))
                           and key.lower() not in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}}
            environment.update(provision(bao, root, address, secrets.token_hex(32)))
            redis_port, redis_password, redis_nonce = available_port(), secrets.token_hex(32), secrets.token_hex(32)
            redis_config = write_private(root, "redis.conf", "\n".join([
                "bind 127.0.0.1", f"port {redis_port}", "protected-mode yes",
                f"requirepass {redis_password}", "databases 16", 'save ""',
                "appendonly no", "daemonize no", f"dir {root}", "loglevel warning", "",
            ]))
            redis_server = subprocess.Popen([str(redis_binary), str(redis_config)],
                                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                            stderr=subprocess.DEVNULL)
            wait_for_redis(redis_server, redis_port, redis_password, redis_nonce)
            environment.update({
                "MARTY_TEST_REDIS_URL": f"redis://:{redis_password}@127.0.0.1:{redis_port}/15",
                "MARTY_TEST_REDIS_DISPOSABLE_NONCE": redis_nonce,
            })
            print("Disposable receipt fixture ready: TLS OpenBao, Redis, separate leaf roles and non-exportable keys.", flush=True)
            return subprocess.run(command, env=environment, check=False).returncode
        finally:
            if redis_server is not None:
                terminate(redis_server)
            terminate(bao_server)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--openbao", required=True, type=Path)
    parser.add_argument("--redis-server", required=True, type=Path)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    arguments = parser.parse_args()
    command = arguments.command
    if command[:1] == ["--"]:
        command = command[1:]
    if not command:
        parser.error("a test command is required after --")
    try:
        return execute(compatible_executable(arguments.openbao),
                       redis_executable(arguments.redis_server), command)
    except (Exception, KeyboardInterrupt) as error:
        # Provider exception strings, child arguments and environment can carry
        # credentials. Expose only a bounded failure category.
        print(f"Disposable receipt fixture failed ({type(error).__name__}).", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
