#!/usr/bin/env python3
"""Run the delegated-use lifecycle qualification with isolated remote custody.

Compose under a disposable PostgreSQL wrapper and supply already verified native
OpenBao / Redis binaries. This extends the unchanged startup fixture with three
separate, nonexportable signing keys, per-origin mint roles, verify-only grants,
and a dedicated delegated-use outbound workload certificate. The child receives
only scoped leaf credentials; it never receives the provider's root token.
"""

from __future__ import annotations

import argparse
import base64
from pathlib import Path
import secrets
import sys

if __package__:
    from . import with_disposable_delegated_use_runtime as runtime
else:
    import with_disposable_delegated_use_runtime as runtime

receipt = runtime.receipt
ISSUANCE_MAC_KEY = "marty-sign-grant-issuance-credential-v1"
SIGNING_KEYS = {
    "REQUEST": "lifecycle-request-es256",
    "CREDENTIAL": "lifecycle-machine-es256",
    "RECEIPT": "lifecycle-receipt-es256",
}
WORKLOAD_URI = "spiffe://marty.internal/service/delegated-use"


def workload_identity(bao, root: Path, address: str) -> dict[str, str]:
    name = "delegated-use-workload"
    key = name + "-" + secrets.token_hex(8)
    bao.request("POST", f"transit/keys/{key}", {
        "type": "ecdsa-p256", "exportable": False, "allow_plaintext_backup": False,
    })
    metadata = bao.request("GET", f"transit/keys/{key}")["data"]
    if (metadata["latest_version"] != 1 or metadata["exportable"] is not False
            or metadata["allow_plaintext_backup"] is not False):
        raise RuntimeError("invalid delegated-use workload key custody")
    bao.request("POST", f"pki/roles/{name}", {
        "allow_any_name": False, "allowed_domains": ["localhost"],
        "allow_bare_domains": True, "allow_localhost": True,
        "allow_ip_sans": False, "allowed_uri_sans": [WORKLOAD_URI],
        "server_flag": False, "client_flag": True,
        "key_type": "ec", "key_bits": 256, "max_ttl": "1h",
        "use_csr_common_name": False, "use_csr_sans": False,
    })
    certificate = runtime.public_certificate(
        bao, key, 1, name, "localhost", uri_sans=WORKLOAD_URI)
    token = receipt.leaf(bao, name, {
        f"transit/keys/{key}": ["read"], f"transit/sign/{key}": ["update"],
    })
    proof = {"input": base64.b64encode(b"delegated-use-workload-scope").decode("ascii")}
    receipt.denied(bao, token, "GET", f"transit/export/signing-key/{key}")
    for purpose_key in SIGNING_KEYS.values():
        receipt.denied(bao, token, "POST", f"transit/sign/{purpose_key}", proof)
    for mac in (runtime.FLOW_MAC_KEY, ISSUANCE_MAC_KEY, receipt.RECEIPT_MAC_KEY):
        receipt.denied(bao, token, "POST", f"transit/hmac/{mac}/sha2-256", proof)
    prefix = "MARTY_TEST_USE_WORKLOAD_TLS_"
    return {
        prefix + "CERT_FILE": str(receipt.write_private(root, name + "-public.pem", certificate)),
        prefix + "KMS_PROVIDER": "openbao-transit", prefix + "KMS_ADDR": address,
        prefix + "KMS_CA_CERT_FILE": str(root / "vault-ca.pem"),
        prefix + "KMS_TOKEN_FILE": str(receipt.write_private(root, name + "-token", token)),
        prefix + "KMS_KEY_NAME": key, prefix + "KMS_KEY_VERSION": "1",
    }


def provision(bao, root: Path, address: str) -> dict[str, str]:
    environment = runtime.provision(bao, root, address)
    for key in SIGNING_KEYS.values():
        bao.request("POST", f"transit/keys/{key}", {
            "type": "ecdsa-p256", "exportable": False, "allow_plaintext_backup": False,
        })
        metadata = bao.request("GET", f"transit/keys/{key}")["data"]
        if (metadata["type"] != "ecdsa-p256" or metadata["latest_version"] != 1
                or metadata["exportable"] is not False
                or metadata["allow_plaintext_backup"] is not False):
            raise RuntimeError("invalid lifecycle signing key custody")
    bao.request("POST", f"transit/keys/{ISSUANCE_MAC_KEY}", {
        "type": "hmac", "key_size": 32,
        "exportable": False, "allow_plaintext_backup": False,
    })
    mac_metadata = bao.request("GET", f"transit/keys/{ISSUANCE_MAC_KEY}")["data"]
    if (mac_metadata["type"] != "hmac" or mac_metadata["latest_version"] != 1
            or mac_metadata["exportable"] is not False
            or mac_metadata["allow_plaintext_backup"] is not False):
        raise RuntimeError("invalid issuance mint key custody")

    signers = {purpose: receipt.leaf(bao, "lifecycle-" + purpose.lower(), {
        f"transit/keys/{key}": ["read"], f"transit/sign/{key}": ["update"],
    }) for purpose, key in SIGNING_KEYS.items()}
    mint = receipt.leaf(bao, "lifecycle-issuance-mint", {
        f"transit/hmac/{ISSUANCE_MAC_KEY}/sha2-256": ["update"],
    })
    origins = (runtime.FLOW_MAC_KEY, ISSUANCE_MAC_KEY, receipt.RECEIPT_MAC_KEY)
    verifier = receipt.leaf(bao, "lifecycle-grant-verify", {
        f"transit/verify/{key}/sha2-256": ["update"] for key in origins
    })
    minters = {
        runtime.FLOW_MAC_KEY: Path(environment["MARTY_TEST_USE_REQUEST_MINT_TOKEN_FILE"]).read_text(),
        ISSUANCE_MAC_KEY: mint,
        receipt.RECEIPT_MAC_KEY: Path(environment["MARTY_TEST_RECEIPT_MINT_TOKEN_FILE"]).read_text(),
    }
    if len(set([*signers.values(), *minters.values(), verifier])) != 7:
        raise RuntimeError("lifecycle signing roles reused provider authority")
    proof = {"input": base64.b64encode(b"lifecycle-purpose-scope-proof").decode("ascii")}
    for purpose, signer in signers.items():
        for other, key in SIGNING_KEYS.items():
            if other != purpose:
                receipt.denied(bao, signer, "POST", f"transit/sign/{key}", proof)
        key = SIGNING_KEYS[purpose]
        receipt.denied(bao, signer, "GET", f"transit/export/signing-key/{key}")
        receipt.denied(bao, signer, "POST", f"transit/keys/{key}/rotate", {})
        for origin in origins:
            receipt.denied(bao, signer, "POST", f"transit/hmac/{origin}/sha2-256", proof)
    for origin, minter in minters.items():
        mac = bao.request("POST", f"transit/hmac/{origin}/sha2-256", proof,
                          token=minter)["data"]["hmac"]
        verification = {**proof, "hmac": mac}
        if bao.request("POST", f"transit/verify/{origin}/sha2-256", verification,
                       token=verifier)["data"]["valid"] is not True:
            raise RuntimeError("lifecycle grant verification failed")
        receipt.denied(bao, minter, "POST", f"transit/verify/{origin}/sha2-256", verification)
        for other in origins:
            if other != origin:
                receipt.denied(bao, minter, "POST", f"transit/hmac/{other}/sha2-256", proof)
        for key in SIGNING_KEYS.values():
            receipt.denied(bao, minter, "POST", f"transit/sign/{key}", proof)
    for origin in origins:
        receipt.denied(bao, verifier, "POST", f"transit/hmac/{origin}/sha2-256", proof)
    for key in SIGNING_KEYS.values():
        receipt.denied(bao, verifier, "POST", f"transit/sign/{key}", proof)
    for purpose, key in SIGNING_KEYS.items():
        prefix = "MARTY_TEST_RECEIPT_" if purpose == "RECEIPT" else "MARTY_TEST_LIFECYCLE_" + purpose + "_"
        environment[prefix + ("ES256_KEY" if purpose == "RECEIPT" else "KEY")] = key
        environment[prefix + "SIGNER_TOKEN_FILE"] = str(receipt.write_private(
            root, "lifecycle-" + purpose.lower() + "-signer-token", signers[purpose]))
    environment["MARTY_TEST_LIFECYCLE_ISSUANCE_MINT_TOKEN_FILE"] = str(
        receipt.write_private(root, "lifecycle-issuance-mint-token", mint))
    environment["MARTY_TEST_LIFECYCLE_VERIFY_TOKEN_FILE"] = str(
        receipt.write_private(root, "lifecycle-verify-token", verifier))
    environment.update(workload_identity(bao, root, address))
    environment["MARTY_TEST_DELEGATED_USE_LIFECYCLE"] = "true"
    return environment


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
        return runtime.execute(runtime.compatible_executable(arguments.openbao),
                               receipt.redis_executable(arguments.redis_server), command,
                               provisioner=provision)
    except (Exception, KeyboardInterrupt) as error:
        print(f"Disposable delegated-use lifecycle fixture failed ({type(error).__name__}).", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
