#!/usr/bin/env python3
"""Run the managed owner HTTPS contract with isolated native OpenBao.

Before using this fixture, verify the official OpenBao 2.5.5 release archive
against its published checksum and signature, then provide its extracted binary
through --openbao or MARTY_TEST_OPENBAO_EXECUTABLE. The executable version check
below enforces fixture compatibility; it does not replace release verification.

Example (build the test before starting this short-lived fixture):
    python3 scripts/with_disposable_policy_owner_kms.py --openbao /path/to/bao -- \
        cargo test --manifest-path rust/Cargo.toml --locked \
        -p marty-presentation-policy --test control_plane_behavior \
        managed_authority_http::live_keyless_managed_owner_channels -- \
        --ignored --exact --nocapture

The OpenBao server and test command share this process's localhost network.
Workload keys remain non-exportable Transit keys. Only public certificates and
a scoped signer-token file reach the test; the administrative token is confined
to provisioning and the OpenBao child environment. All fixture state is removed
when the command exits. This script never contacts an existing OpenBao service.

The same public CA also issues separate Flow-client and Policy-server identities
for the joined managed-evidence contract. Their file-based identity prefixes are
MARTY_TEST_POLICY_FLOW_CLIENT_TLS and MARTY_TEST_POLICY_GRPC_SERVER_TLS; the CA
path is MARTY_TEST_POLICY_WORKLOAD_CA_CERT. Each signer token is restricted to its
own non-exportable key. The existing MARTY_TEST_POLICY_OWNER_TLS values remain
available for the independent owner HTTPS contract.

The ordinary run clears HTTP proxy variables in the test child so its legacy
HTTP decoy remains reachable. Repeat with --poison-proxy to prove that owner and
remote-signer HTTPS bypass ambient proxies. Build dependencies first: that option
deliberately makes proxy-dependent downloads fail in the child.
"""

from __future__ import annotations

import argparse
import base64
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

from selfhost_openbao_client import Bao
from with_disposable_event_stream_kms import provision_server_identity


TLS_PREFIX = "MARTY_TEST_POLICY_OWNER_TLS_"
FLOW_TLS_PREFIX = "MARTY_TEST_POLICY_FLOW_CLIENT_TLS_"
POLICY_TLS_PREFIX = "MARTY_TEST_POLICY_GRPC_SERVER_TLS_"
OPENBAO_VERSION = re.compile(r"\AOpenBao v2\.5\.5(?:\s|$)")


def compatible_executable(path: Path) -> Path:
    """Require the operator's verified, fixture-compatible OpenBao binary."""
    executable = path.expanduser().resolve(strict=True)
    version = subprocess.run(
        [str(executable), "version"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if not OPENBAO_VERSION.match(version.stdout):
        raise RuntimeError("the isolated fixture requires OpenBao 2.5.5")
    return executable


def wait_for_openbao(
    server: subprocess.Popen[bytes],
    address: str,
    ca_certificate: Path,
    root_token: str,
) -> Bao:
    deadline = time.monotonic() + 20
    while True:
        if server.poll() is not None:
            raise RuntimeError("isolated OpenBao stopped before becoming ready")
        try:
            bao = Bao(address, ca_certificate, root_token)
            bao.request("GET", "sys/health")
            return bao
        except Exception:
            # Startup errors may contain provider response details. Keep those
            # private and expose only a bounded readiness failure to the caller.
            if time.monotonic() >= deadline:
                raise RuntimeError("isolated OpenBao readiness timed out") from None
            time.sleep(0.05)


def public_certificate(
    bao: Bao,
    key_name: str,
    key_version: int,
    role: str,
    common_name: str,
    ip_sans: str | None = None,
    uri_sans: str | None = None,
) -> str:
    csr = bao.request(
        "POST", f"transit/keys/{key_name}/csr", {"version": key_version}
    )["data"]["csr"]
    request = {"csr": csr, "common_name": common_name, "ttl": "1h"}
    if ip_sans is not None:
        request["ip_sans"] = ip_sans
    if uri_sans is not None:
        request["uri_sans"] = uri_sans
    signed = bao.request("POST", f"pki/sign/{role}", request)["data"]
    if "private_key" in signed:
        raise RuntimeError("PKI returned private key material")
    return signed["certificate"]


def owner_environment(bao: Bao, root: Path, address: str) -> dict[str, str]:
    # Reuse the established fixture's non-exportable Transit key, internal PKI
    # CA, narrowly scoped token, and explicit denial of signing with another key.
    identity = provision_server_identity(bao, root, "signing-keys")
    key_name = identity["key_name"]
    role = {
        "allow_any_name": True,
        "allow_localhost": True,
        "allow_ip_sans": True,
        "server_flag": True,
        "client_flag": False,
        "key_type": "ec",
        "key_bits": 256,
        "max_ttl": "24h",
        "use_csr_common_name": False,
        # Transit CSRs have no SANs. Use the explicit certificate request names.
        "use_csr_sans": False,
    }
    bao.request("POST", "pki/roles/signing-keys", role)
    Path(identity["cert"]).write_text(
        public_certificate(
            bao, key_name, 1, "signing-keys", "localhost", "127.0.0.1"
        ),
        encoding="ascii",
    )

    # This leaf uses the same owner CA and original key but has the wrong name.
    # Rejection therefore proves name verification independently of CA trust.
    bao.request("POST", "pki/roles/w05-wrong-dns", role)
    alternate_certificate = root / "wrong-dns-public.pem"
    alternate_certificate.write_text(
        public_certificate(bao, key_name, 1, "w05-wrong-dns", "other.example"),
        encoding="ascii",
    )

    bao.request("POST", f"transit/keys/{key_name}/rotate", {})
    metadata = bao.request("GET", f"transit/keys/{key_name}")["data"]
    if (
        metadata["type"] != "ecdsa-p256"
        or metadata["latest_version"] != 2
        or metadata["exportable"] is not False
        or metadata["allow_plaintext_backup"] is not False
    ):
        raise RuntimeError("unexpected rotated signer metadata")
    rotated_certificate = root / "rotated-public.pem"
    rotated_certificate.write_text(
        public_certificate(
            bao, key_name, 2, "signing-keys", "localhost", "127.0.0.1"
        ),
        encoding="ascii",
    )

    return {
        TLS_PREFIX + "CERT_FILE": identity["cert"],
        TLS_PREFIX + "KMS_CA_CERT_FILE": str(root / "vault-ca.pem"),
        TLS_PREFIX + "KMS_TOKEN_FILE": identity["token_file"],
        TLS_PREFIX + "KMS_KEY_NAME": key_name,
        TLS_PREFIX + "KMS_KEY_VERSION": "1",
        TLS_PREFIX + "KMS_ADDR": address,
        TLS_PREFIX + "KMS_PROVIDER": "openbao-transit",
        TLS_PREFIX + "ALT_CERT_FILE": str(alternate_certificate),
        TLS_PREFIX + "ROTATED_CERT_FILE": str(rotated_certificate),
        TLS_PREFIX + "ROTATED_KEY_VERSION": "2",
        "MARTY_TEST_POLICY_OWNER_CA_CERT": identity["workload_ca"],
    }


def policy_workload_environment(
    bao: Bao, root: Path, address: str, owner: dict[str, str]
) -> dict[str, str]:
    """Add a workload pair to the already provisioned owner CA and Transit mount."""
    environment = {
        "MARTY_TEST_POLICY_WORKLOAD_CA_CERT": owner["MARTY_TEST_POLICY_OWNER_CA_CERT"],
    }
    signers = {
        owner[TLS_PREFIX + "KMS_KEY_NAME"]: Path(
            owner[TLS_PREFIX + "KMS_TOKEN_FILE"]
        ).read_text(encoding="ascii"),
    }
    for prefix, role, common_name, service, server in (
        (FLOW_TLS_PREFIX, "policy-flow-client", "flow", "flow", False),
        (
            POLICY_TLS_PREFIX,
            "policy-grpc-server",
            "localhost",
            "presentation-policy",
            True,
        ),
    ):
        key_name = role + "-tls-" + secrets.token_hex(8)
        bao.request("POST", f"transit/keys/{key_name}", {
            "type": "ecdsa-p256",
            "exportable": False,
            "allow_plaintext_backup": False,
        })
        metadata = bao.request("GET", f"transit/keys/{key_name}")["data"]
        if (
            metadata["type"] != "ecdsa-p256"
            or metadata["latest_version"] != 1
            or metadata["exportable"] is not False
            or metadata["allow_plaintext_backup"] is not False
        ):
            raise RuntimeError("unexpected workload signer metadata")
        uri = f"spiffe://marty.internal/service/{service}"
        role_configuration = {
            "allowed_domains": [common_name],
            "allow_bare_domains": True,
            "allow_any_name": False,
            "allow_subdomains": False,
            "allow_localhost": server,
            "allow_ip_sans": server,
            "allowed_uri_sans": [uri],
            "server_flag": server,
            "client_flag": not server,
            "key_type": "ec",
            "key_bits": 256,
            "max_ttl": "1h",
            "use_csr_common_name": False,
            "use_csr_sans": False,
        }
        bao.request("POST", f"pki/roles/{role}", role_configuration)
        certificate = root / f"{role}-public.pem"
        certificate.write_text(
            public_certificate(
                bao, key_name, 1, role, common_name,
                ip_sans="127.0.0.1" if server else None,
                uri_sans=uri,
            ),
            encoding="ascii",
        )
        if not server:
            # Same CA, public key and client-only EKU; only the workload URI is
            # different, so the live negative proves the Policy method ACL.
            wrong_uri = "spiffe://marty.internal/service/auth"
            wrong_uri_role = role + "-wrong-uri"
            bao.request("POST", f"pki/roles/{wrong_uri_role}", {
                **role_configuration,
                "allowed_uri_sans": [wrong_uri],
            })
            wrong_uri_certificate = root / f"{wrong_uri_role}-public.pem"
            wrong_uri_certificate.write_text(
                public_certificate(
                    bao, key_name, 1, wrong_uri_role, common_name,
                    uri_sans=wrong_uri,
                ),
                encoding="ascii",
            )
            environment["MARTY_TEST_POLICY_FLOW_CLIENT_WRONG_URI_CERT_FILE"] = str(
                wrong_uri_certificate
            )
        policy_name = role + "-" + secrets.token_hex(4)
        bao.request("PUT", f"sys/policies/acl/{policy_name}", {
            "policy": (
                f'path "transit/keys/{key_name}" {{ capabilities = ["read"] }}\n'
                f'path "transit/sign/{key_name}" {{ capabilities = ["update"] }}'
            ),
        })
        token = bao.request("POST", "auth/token/create", {
            "policies": [policy_name],
            "no_default_policy": True,
            "ttl": "1h",
        })["auth"]["client_token"]
        if token == bao.token or token in signers.values():
            raise RuntimeError("workload signer tokens are reused or administrative")
        signers[key_name] = token
        token_file = root / f"{role}-signer-token"
        token_file.write_text(token, encoding="ascii")
        if os.name != "nt":
            token_file.chmod(0o600)
        environment.update({
            prefix + "CERT_FILE": str(certificate),
            prefix + "KMS_CA_CERT_FILE": str(root / "vault-ca.pem"),
            prefix + "KMS_TOKEN_FILE": str(token_file),
            prefix + "KMS_KEY_NAME": key_name,
            prefix + "KMS_KEY_VERSION": "1",
            prefix + "KMS_ADDR": address,
            prefix + "KMS_PROVIDER": "openbao-transit",
        })

    # Prove each real token can sign only with its own key, including separation
    # from the pre-existing owner TLS key. Never expose signatures or tokens.
    proof = {
        "input": base64.b64encode(b"policy-workload-signer-scope").decode("ascii"),
        "key_version": 1,
    }
    for own_key, token in signers.items():
        for target_key in signers:
            try:
                signed = bao.request(
                    "POST", f"transit/sign/{target_key}", proof, token=token
                )
            except HTTPError as error:
                if own_key == target_key or error.code != 403:
                    raise RuntimeError("workload signer scope proof failed") from None
            else:
                if own_key != target_key or not signed.get("data", {}).get("signature"):
                    raise RuntimeError("workload signer scope proof failed")
    return environment


def execute(executable: Path, command: list[str], *, poison_proxy: bool = False) -> int:
    with tempfile.TemporaryDirectory(prefix="marty-policy-owner-kms-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        root_token = secrets.token_hex(32)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        address = f"https://127.0.0.1:{port}"
        server_environment = os.environ.copy()
        server_environment["BAO_DEV_ROOT_TOKEN_ID"] = root_token
        server = subprocess.Popen(
            [
                str(executable),
                "server",
                "-dev",
                "-dev-tls",
                "-dev-no-store-token",
                f"-dev-listen-address=127.0.0.1:{port}",
                f"-dev-tls-cert-dir={root}",
            ],
            env=server_environment,
            stdin=subprocess.DEVNULL,
            # OpenBao's development banner contains administrative credentials.
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            bao = wait_for_openbao(server, address, root / "vault-ca.pem", root_token)
            environment = os.environ.copy()
            owner = owner_environment(bao, root, address)
            environment.update(owner)
            environment.update(policy_workload_environment(bao, root, address, owner))
            environment["MARTY_TEST_OPENBAO_EXECUTABLE"] = str(executable)
            # The ordinary run must keep its legacy HTTP decoy reachable:
            # an inherited dead proxy could otherwise conceal a fallback attempt.
            for name in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY"):
                environment.pop(name, None)
                environment.pop(name.lower(), None)
            if poison_proxy:
                # Mutate only the test subprocess environment. OpenBao fixture
                # provisioning keeps its normal environment; product HTTPS
                # clients must independently refuse these ambient proxy routes.
                for name in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY"):
                    environment[name] = "http://127.0.0.1:1"
                    environment[name.lower()] = "http://127.0.0.1:1"
                environment["NO_PROXY"] = ""
                environment["no_proxy"] = ""
            print(
                "Isolated owner TLS fixtures ready (remote key versions 1 and 2).",
                flush=True,
            )
            return subprocess.run(command, env=environment).returncode
        finally:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--openbao",
        type=Path,
        default=os.environ.get("MARTY_TEST_OPENBAO_EXECUTABLE"),
        help="path to the verified official OpenBao 2.5.5 executable",
    )
    parser.add_argument(
        "--poison-proxy",
        action="store_true",
        help="set unusable proxies only for the test child to verify HTTPS bypass",
    )
    parser.add_argument("command", nargs=argparse.REMAINDER)
    arguments = parser.parse_args()
    command = arguments.command
    if command[:1] == ["--"]:
        command = command[1:]
    if arguments.openbao is None:
        parser.error("provide --openbao or MARTY_TEST_OPENBAO_EXECUTABLE")
    if not command:
        parser.error("provide the test command after --")
    try:
        return execute(
            compatible_executable(arguments.openbao),
            command,
            poison_proxy=arguments.poison_proxy,
        )
    except KeyboardInterrupt:
        return 130
    except Exception as error:
        # Do not print raw exceptions, provider responses, or command arguments:
        # fixture administrative credentials must never become test diagnostics.
        print(
            f"Isolated owner TLS fixture failed ({type(error).__name__}).",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
