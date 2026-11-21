#!/usr/bin/env python3
"""Run the actual delegated-use executable gate with disposable remote custody.

Supply the already independently verified OpenBao 2.5.5 / Redis 7.4.12 binaries
and a compiled test command. Compose this under a disposable PostgreSQL wrapper.
This fixture never contacts an existing provider and never exports private keys.
It provisions real keyless TLS identities, receipt custody, separate signing-grant
mint roles, and encrypted Signing Keys registry storage. The Rust test explicitly
uses read-only gRPC/health wire fixtures, not the actual catalog owner services.
No request or receipt is signed by this startup/readiness qualification.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import sys
import tempfile

if __package__:
    from . import with_disposable_delegated_receipt_kms as receipt
    from .with_disposable_policy_owner_kms import (
        compatible_executable, owner_environment, policy_workload_environment,
        public_certificate, wait_for_openbao,
    )
else:
    import with_disposable_delegated_receipt_kms as receipt
    from with_disposable_policy_owner_kms import (
        compatible_executable, owner_environment, policy_workload_environment,
        public_certificate, wait_for_openbao,
    )


FLOW_MAC_KEY = "marty-sign-grant-flow-wallet-v1"
CALLER_URI = "spiffe://delegated-use.test/machine/startup-caller"


def identity(bao, root: Path, address: str, name: str, *, server: bool) -> dict[str, str]:
    key = name + "-" + secrets.token_hex(8)
    bao.request("POST", f"transit/keys/{key}", {
        "type": "ecdsa-p256", "exportable": False, "allow_plaintext_backup": False,
    })
    metadata = bao.request("GET", f"transit/keys/{key}")["data"]
    if (metadata["latest_version"] != 1 or metadata["exportable"] is not False
            or metadata["allow_plaintext_backup"] is not False):
        raise RuntimeError("invalid disposable keyless identity metadata")
    uri = "spiffe://marty.internal/service/delegated-use" if server else CALLER_URI
    role = {
        "allow_any_name": False, "allowed_domains": ["localhost"],
        "allow_bare_domains": True, "allow_localhost": True,
        "allow_ip_sans": server, "allowed_uri_sans": [uri],
        "server_flag": server, "client_flag": not server,
        "key_type": "ec", "key_bits": 256, "max_ttl": "1h",
        "use_csr_common_name": False, "use_csr_sans": False,
    }
    bao.request("POST", f"pki/roles/{name}", role)
    certificate = public_certificate(bao, key, 1, name, "localhost",
                                     "127.0.0.1" if server else None, uri)
    cert_file = receipt.write_private(root, name + "-public.pem", certificate)
    token = receipt.leaf(bao, name, {
        f"transit/keys/{key}": ["read"], f"transit/sign/{key}": ["update"],
    })
    proof = {"input": base64.b64encode(b"delegated-host-keyless-scope").decode("ascii")}
    receipt.denied(bao, token, "GET", f"transit/export/signing-key/{key}")
    receipt.denied(bao, token, "POST", "transit/sign/receipt-es256", proof)
    receipt.denied(bao, token, "POST", f"transit/hmac/{FLOW_MAC_KEY}/sha2-256", proof)
    prefix = "MARTY_TEST_USE_SERVER_TLS_" if server else "MARTY_TEST_USE_CALLER_TLS_"
    environment = {
        prefix + "CERT_FILE": str(cert_file), prefix + "KMS_PROVIDER": "openbao-transit",
        prefix + "KMS_ADDR": address, prefix + "KMS_CA_CERT_FILE": str(root / "vault-ca.pem"),
        prefix + "KMS_TOKEN_FILE": str(receipt.write_private(root, name + "-token", token)),
        prefix + "KMS_KEY_NAME": key, prefix + "KMS_KEY_VERSION": "1",
    }
    if not server:
        leaf = ssl.PEM_cert_to_DER_cert(certificate)
        environment.update({
            "MARTY_TEST_USE_CALLER_URI": uri,
            "MARTY_TEST_USE_CALLER_LEAF_SHA256": "sha256:" + hashlib.sha256(leaf).hexdigest(),
        })
        # Same trusted CA, same provider key, valid client EKU, different URI.
        wrong_uri = "spiffe://delegated-use.test/machine/unmapped-caller"
        bao.request("POST", f"pki/roles/{name}-unmapped", {**role, "allowed_uri_sans": [wrong_uri]})
        wrong_cert = public_certificate(bao, key, 1, name + "-unmapped", "localhost", uri_sans=wrong_uri)
        environment["MARTY_TEST_USE_UNMAPPED_CALLER_CERT_FILE"] = str(
            receipt.write_private(root, name + "-unmapped-public.pem", wrong_cert))
    return environment


def provision(bao, root: Path, address: str) -> dict[str, str]:
    environment = receipt.provision(bao, root, address, secrets.token_hex(32))
    bao.request("POST", f"transit/keys/{FLOW_MAC_KEY}", {
        "type": "hmac", "key_size": 32, "exportable": False, "allow_plaintext_backup": False,
    })
    mint = receipt.leaf(bao, "flow-wallet-mint", {
        f"transit/hmac/{FLOW_MAC_KEY}/sha2-256": ["update"],
    })
    environment["MARTY_TEST_USE_REQUEST_MINT_TOKEN_FILE"] = str(
        receipt.write_private(root, "request-mint-token", mint))
    proof = {"input": base64.b64encode(b"delegated-host-mint-scope").decode("ascii")}
    receipt.denied(bao, mint, "POST", f"transit/hmac/{receipt.RECEIPT_MAC_KEY}/sha2-256", proof)
    receipt.denied(bao, mint, "POST", "transit/sign/receipt-es256", proof)
    receipt.denied(bao, Path(environment["MARTY_TEST_RECEIPT_MINT_TOKEN_FILE"]).read_text(),
                   "POST", f"transit/hmac/{FLOW_MAC_KEY}/sha2-256", proof)
    owner = owner_environment(bao, root, address, reuse_transit=True)
    environment.update(owner)
    environment.update(policy_workload_environment(bao, root, address, owner))
    environment.update(identity(bao, root, address, "delegated-host", server=True))
    environment.update(identity(bao, root, address, "delegated-caller", server=False))
    ca = Path(owner["MARTY_TEST_POLICY_OWNER_CA_CERT"])
    ca_der = root / "workload-ca.der"
    ca_der.write_bytes(ssl.PEM_cert_to_DER_cert(ca.read_text(encoding="ascii")))
    environment.update({
        "MARTY_TEST_USE_CA_DER_FILE": str(ca_der),
        "MARTY_TEST_USE_ROOT": str(root),
        "MARTY_TEST_DELEGATED_USE_LIVE": "true",
        # Only the test child and its actual executable children trust this CA.
        # Production HTTP clients still perform ordinary certificate/name checks.
        "SSL_CERT_FILE": str(ca), "SSL_CERT_DIR": str(root / "empty-ca-directory"),
    })
    (root / "empty-ca-directory").mkdir()
    return environment


def execute(bao_binary: Path, redis_binary: Path, command: list[str], *, provisioner=provision) -> int:
    with tempfile.TemporaryDirectory(prefix="marty-delegated-use-runtime-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        address = f"https://127.0.0.1:{receipt.available_port()}"
        root_token = secrets.token_hex(32)
        audit = receipt.write_private(root, "provider-audit.jsonl", "")
        config = receipt.write_private(root, "openbao.hcl", (
            'audit "file" "receipt-fixture" {\n  options {\n'
            f'    file_path = {json.dumps(str(audit))}\n    mode = "0600"\n  }}\n}}\n'
        ))
        provider_environment = os.environ.copy()
        provider_environment["BAO_DEV_ROOT_TOKEN_ID"] = root_token
        bao_server = subprocess.Popen([
            str(bao_binary), "server", "-dev", "-dev-tls", "-dev-no-store-token",
            "-dev-listen-address=" + address.removeprefix("https://"),
            "-dev-tls-cert-dir=" + str(root), "-config=" + str(config),
        ], env=provider_environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        redis_server = None
        try:
            bao = wait_for_openbao(bao_server, address, root / "vault-ca.pem", root_token)
            environment = {key: value for key, value in os.environ.items()
                           if not key.startswith(("BAO_", "VAULT_", "MARTY_TEST_", "DELEGATED_USE_"))
                           and key != "MARTY_DELEGATED_USE_ENABLED"
                           and key.lower() not in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}}
            environment.update(provisioner(bao, root, address))
            port, password, nonce = receipt.available_port(), secrets.token_hex(32), secrets.token_hex(32)
            redis_config = receipt.write_private(root, "redis.conf", "\n".join([
                "bind 127.0.0.1", f"port {port}", "protected-mode yes", f"requirepass {password}",
                "databases 16", 'save ""', "appendonly no", "daemonize no", f"dir {root}",
                "loglevel warning", "",
            ]))
            redis_server = subprocess.Popen([str(redis_binary), str(redis_config)],
                                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                            stderr=subprocess.DEVNULL)
            receipt.wait_for_redis(redis_server, port, password, nonce)
            environment.update({
                "MARTY_TEST_REDIS_URL": f"redis://:{password}@127.0.0.1:{port}/15",
                "MARTY_TEST_REDIS_DISPOSABLE_NONCE": nonce,
            })
            print("Disposable delegated-use runtime fixture ready: remote TLS identities, receipt custody, Redis.", flush=True)
            return subprocess.run(command, env=environment, check=False).returncode
        finally:
            if redis_server is not None:
                receipt.terminate(redis_server)
            receipt.terminate(bao_server)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--openbao", required=True, type=Path)
    parser.add_argument("--redis-server", required=True, type=Path)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    arguments = parser.parse_args()
    command = arguments.command[1:] if arguments.command[:1] == ["--"] else arguments.command
    if not command:
        parser.error("a compiled test command is required after --")
    try:
        return execute(compatible_executable(arguments.openbao),
                       receipt.redis_executable(arguments.redis_server), command)
    except (Exception, KeyboardInterrupt) as error:
        print(f"Disposable delegated-use runtime fixture failed ({type(error).__name__}).", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
