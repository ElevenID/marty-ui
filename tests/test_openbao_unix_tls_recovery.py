"""Opt-in real OpenBao 2.5.5 Unix-control / expired-TCP-TLS recovery proof.

Run with an independently verified official binary and Python cryptography:
  MARTY_OPENBAO_UNIX_PROOF_BINARY=/absolute/bao \
    python3 tests/test_openbao_unix_tls_recovery.py -v

This isolated test starts no Docker containers, contacts no cloud/CA service,
changes no clock, and never disables client TLS verification. The TCP node key
is deliberately file-backed, as required by the official listener. Only the
PKI issuing key is generated internally and never exported. See
docs/installer-openbao-unix-recovery-proof.md for the precise boundary.
"""

from __future__ import annotations

import hashlib
import http.client
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import unittest


BINARY = os.environ.get("MARTY_OPENBAO_UNIX_PROOF_BINARY")
BUILD_COMMIT = "028992583c693c4de6350b8aa52ff85e30375a99"
HAS_CRYPTOGRAPHY = importlib.util.find_spec("cryptography") is not None


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path: Path):
        super().__init__("localhost", timeout=3)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(str(self.path))


class Proof:
    """Temporary single-node process; no ambient OpenBao or cloud credentials."""

    def __init__(self, binary: Path, directory: Path):
        self.binary = binary
        self.directory = directory
        self.socket_path = directory / "control" / "api.sock"
        self.key_path = directory / "node.key"
        self.cert_path = directory / "node.crt"
        self.ca_path = directory / "trust.crt"
        self.calls: list[tuple[str, str, int]] = []
        self.process = None
        self.log = None

    def request(self, method, path, body=None, token=None, context=None):
        if context is None:
            connection = UnixConnection(self.socket_path)
        else:
            assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
            connection = http.client.HTTPSConnection("127.0.0.1", self.port, timeout=3, context=context)
        headers = {"Connection": "close"}
        if token is not None:
            headers["X-Vault-Token"] = token
        encoded = None if body is None else json.dumps(body).encode()
        if encoded is not None:
            headers["Content-Type"] = "application/json"
        try:
            connection.connect()
            peer = None if context is None else connection.sock.getpeercert(binary_form=True)
            connection.request(method, path, encoded, headers)
            response = connection.getresponse()
            payload = response.read(1_048_577)
            if len(payload) > 1_048_576:
                raise AssertionError("proof response exceeded bound")
            self.calls.append((method, path, response.status))
            data = json.loads(payload) if payload else {}
            return response.status, data, peer
        finally:
            connection.close()

    def ok(self, method, path, body=None, token=None, context=None):
        status, value, peer = self.request(method, path, body, token, context)
        if status not in (200, 204):
            # Do not print response bodies, headers, credentials, or initialization keys.
            raise AssertionError(f"{method} {path} returned HTTP {status}")
        return value, peer

    def wait(self, predicate, timeout=10):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise AssertionError(f"owned OpenBao process exited: {self.process.returncode}")
            try:
                if predicate():
                    return
            except (OSError, http.client.HTTPException):
                pass
            time.sleep(0.1)
        raise AssertionError("bounded OpenBao observation timed out")

    @staticmethod
    def atomic_write(path, data, mode):
        temporary = path.with_name(path.name + ".next")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def start(self):
        from datetime import datetime, timedelta, timezone
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

        for name in ("control", "data"):
            (self.directory / name).mkdir(mode=0o700)
        self.node_key = ec.generate_private_key(ec.SECP256R1())
        key_pem = self.node_key.private_bytes(serialization.Encoding.PEM,
                                             serialization.PrivateFormat.PKCS8,
                                             serialization.NoEncryption())
        self.atomic_write(self.key_path, key_pem, 0o600)
        # Only permits the TLS listener to start while the fixture is initialized
        # over Unix. This self-signed setup certificate is never trusted by a client.
        now = datetime.now(timezone.utc)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        initial = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                   .public_key(self.node_key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - timedelta(seconds=30))
                   .not_valid_after(now + timedelta(minutes=5))
                   .add_extension(x509.SubjectAlternativeName([
                       x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
                   .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
                   .sign(self.node_key, hashes.SHA256()))
        self.atomic_write(self.cert_path, initial.public_bytes(serialization.Encoding.PEM), 0o644)
        self.csr = (x509.CertificateSigningRequestBuilder().subject_name(subject)
                    .sign(self.node_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode())

        # Keep the two ephemeral port reservations until immediately before the
        # owned process starts. A bind race fails the test instead of adopting a listener.
        reserved = []
        for _ in range(2):
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            reserved.append(listener)
        self.port, cluster_port = (listener.getsockname()[1] for listener in reserved)
        config = {
            "disable_mlock": True,
            "disable_cache": True,
            "ui": False,
            "api_addr": f"https://127.0.0.1:{self.port}",
            "cluster_addr": f"https://127.0.0.1:{cluster_port}",
            "storage": {"file": {"path": str(self.directory / "data")}},
            "listener": [
                {"unix": {"address": str(self.socket_path), "socket_mode": "0600",
                          "socket_user": str(os.getuid()), "socket_group": str(os.getgid()),
                          "disable_unauthed_rekey_endpoints": True,
                          "disable_unauthed_generate_root_endpoints": True}},
                {"tcp": {"address": f"127.0.0.1:{self.port}",
                         "cluster_address": f"127.0.0.1:{cluster_port}",
                         "tls_cert_file": str(self.cert_path), "tls_key_file": str(self.key_path),
                         "tls_min_version": "tls12", "tls_acme_ca_directory": "",
                         "disable_unauthed_rekey_endpoints": True,
                         "disable_unauthed_generate_root_endpoints": True}},
            ],
        }
        config_path = self.directory / "server.json"
        self.atomic_write(config_path, json.dumps(config).encode(), 0o600)
        # Do not inherit any BAO/VAULT/AWS tokens or credentials. No dev server,
        # auto-unseal backend, public ACME, plugin, or cloud endpoint is configured.
        environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                       "GOMAXPROCS": "2", "TZ": "UTC"}
        self.log = open(self.directory / "process.log", "xb")
        os.chmod(self.log.name, 0o600)
        for listener in reserved:
            listener.close()
        self.process = subprocess.Popen([str(self.binary), "server", "-config", str(config_path),
                                         "-log-level=error"], env=environment, cwd=self.directory,
                                        stdout=self.log, stderr=subprocess.STDOUT, umask=0o077)
        self.wait(lambda: self.request("GET", "/v1/sys/init")[0] == 200)

    def close(self):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        if self.log is not None:
            self.log.close()

    def sign(self, token, ttl):
        value, _ = self.ok("POST", "/v1/proof-pki/sign/network", {
            "csr": self.csr, "common_name": "localhost", "alt_names": "localhost",
            "ip_sans": "127.0.0.1", "exclude_cn_from_sans": True, "ttl": ttl,
        }, token)
        return value["data"]["certificate"]

    def publish(self, certificate, ca):
        self.atomic_write(self.cert_path, (certificate.rstrip() + "\n" + ca.rstrip() + "\n").encode(), 0o644)


@unittest.skipUnless(BINARY and HAS_CRYPTOGRAPHY and sys.platform == "linux",
                     "opt-in Linux proof requires MARTY_OPENBAO_UNIX_PROOF_BINARY and cryptography")
class OpenBaoUnixRecoveryProof(unittest.TestCase):
    def test_scoped_unix_renewal_recovers_expired_tcp_tls_without_root_or_restart(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        binary = Path(BINARY)
        self.assertTrue(binary.is_absolute() and binary.is_file())
        version = subprocess.run([str(binary), "version"], check=True, capture_output=True,
                                 text=True, timeout=10).stdout.strip()
        self.assertTrue(version.startswith("OpenBao v2.5.5 ") and BUILD_COMMIT in version)
        with tempfile.TemporaryDirectory(prefix="marty-bao-unix-", dir="/tmp") as temporary:
            directory = Path(temporary)
            proof = Proof(binary, directory)
            try:
                proof.start()
                process_id = proof.process.pid
                socket_info = proof.socket_path.stat()
                self.assertTrue(stat.S_ISSOCK(socket_info.st_mode))
                self.assertEqual(stat.S_IMODE(socket_info.st_mode), 0o600)
                self.assertEqual((socket_info.st_uid, socket_info.st_gid), (os.getuid(), os.getgid()))
                self.assertEqual(stat.S_IMODE(proof.socket_path.parent.stat().st_mode), 0o700)
                foreign_uid_denied = False
                if os.getuid() == 0:
                    denied = subprocess.run([
                        sys.executable, "-c",
                        "import socket,sys; s=socket.socket(socket.AF_UNIX); "
                        "s.settimeout(2); "
                        "\ntry: s.connect(sys.argv[1])\nexcept PermissionError: sys.exit(0)"
                        "\nexcept OSError: sys.exit(2)\nelse: sys.exit(3)", str(proof.socket_path),
                    ], user=65534, group=65534, extra_groups=[], capture_output=True, timeout=5)
                    self.assertEqual(denied.returncode, 0, "foreign UID must not reach the Unix API")
                    foreign_uid_denied = True

                initialized, _ = proof.ok("POST", "/v1/sys/init", {"secret_shares": 1, "secret_threshold": 1})
                root_token = initialized["root_token"]
                proof.ok("POST", "/v1/sys/unseal", {"key": initialized["keys"][0]})
                del initialized
                proof.ok("POST", "/v1/sys/mounts/proof-pki", {"type": "pki"}, root_token)
                issuer, _ = proof.ok("POST", "/v1/proof-pki/root/generate/internal", {
                    "common_name": "Marty Unix recovery proof CA", "ttl": "10m",
                    "key_type": "ec", "key_bits": 256, "max_path_length": 0,
                }, root_token)
                issuer = issuer["data"]
                self.assertNotIn("private_key", issuer)
                key_id = issuer["key_id"]
                ca = issuer["certificate"]
                proof.atomic_write(proof.ca_path, ca.encode(), 0o644)
                proof.ok("POST", "/v1/proof-pki/roles/network", {
                    "allowed_domains": ["localhost"], "allow_bare_domains": True,
                    "allow_subdomains": False, "allow_any_name": False, "allow_localhost": True,
                    "allow_ip_sans": True, "server_flag": True, "client_flag": False,
                    "key_type": "ec", "key_bits": 256, "max_ttl": "5m",
                    "use_csr_common_name": False, "use_csr_sans": False,
                    "not_before_duration": "0s", "no_store": True,
                }, root_token)
                policy = '''path "proof-pki/sign/network" {
  capabilities = ["update"]
  required_parameters = ["csr", "common_name", "alt_names", "ip_sans", "ttl", "exclude_cn_from_sans"]
  allowed_parameters = {
    "csr" = []
    "common_name" = ["localhost"]
    "alt_names" = ["localhost"]
    "ip_sans" = ["127.0.0.1"]
    "ttl" = ["15s", "120s"]
    "exclude_cn_from_sans" = [true]
  }
}
''' + f'path "proof-pki/key/{key_id}" {{ capabilities = ["read"] }}\n'
                proof.ok("PUT", "/v1/sys/policies/acl/proof-network-renewal", {"policy": policy}, root_token)
                proof.ok("POST", "/v1/sys/auth/proof-approle", {"type": "approle"}, root_token)
                proof.ok("POST", "/v1/auth/proof-approle/role/network", {
                    "token_policies": ["proof-network-renewal"], "token_ttl": "3m",
                    "token_max_ttl": "5m", "token_no_default_policy": True,
                    "secret_id_ttl": "5m", "secret_id_num_uses": 4, "bind_secret_id": True,
                }, root_token)
                role_id, _ = proof.ok("GET", "/v1/auth/proof-approle/role/network/role-id", token=root_token)
                secret_id, _ = proof.ok("POST", "/v1/auth/proof-approle/role/network/secret-id", {}, root_token)
                credentials = {"role_id": role_id["data"]["role_id"], "secret_id": secret_id["data"]["secret_id"]}
                del role_id, secret_id
                proof.ok("POST", "/v1/auth/token/revoke-self", {}, root_token)
                self.assertEqual(proof.request("GET", "/v1/auth/token/lookup-self", token=root_token)[0], 403)
                del root_token

                def login():
                    value, _ = proof.ok("POST", "/v1/auth/proof-approle/login", credentials)
                    self.assertEqual(value["auth"]["policies"], ["proof-network-renewal"])
                    return value["auth"]["client_token"]

                token = login()
                before_issuer, _ = proof.ok("GET", f"/v1/proof-pki/key/{key_id}", token=token)
                old_pem = proof.sign(token, "15s")
                old_cert = x509.load_pem_x509_certificate(old_pem.encode())
                key_hash = hashlib.sha256(proof.key_path.read_bytes()).hexdigest()
                ca_hash = hashlib.sha256(proof.ca_path.read_bytes()).hexdigest()
                proof.publish(old_pem, ca)
                proof.process.send_signal(signal.SIGHUP)
                context = ssl.create_default_context(cafile=str(proof.ca_path))
                proof.wait(lambda: proof.request("GET", "/v1/sys/health", context=context)[0] == 200)
                baseline, old_peer = proof.ok("GET", "/v1/sys/health", context=context)
                self.assertEqual(old_peer, old_cert.public_bytes(serialization.Encoding.DER))

                # A real expiry under the unchanged wall clock, bounded to 20s.
                expires = old_cert.not_valid_after_utc.timestamp()
                self.assertLess(expires - time.time(), 16)
                deadline = time.monotonic() + 20
                while time.time() <= expires + 0.2:
                    self.assertLess(time.monotonic(), deadline, "certificate expiry wait exceeded bound")
                    time.sleep(0.1)

                def expired_tcp():
                    with self.assertRaises(ssl.SSLCertVerificationError) as failure:
                        proof.request("GET", "/v1/sys/health", context=context)
                    self.assertEqual(failure.exception.verify_code, 10, "failure must be certificate expiry")

                expired_tcp()
                recovery_call_index = len(proof.calls)
                self.assertEqual(proof.request("POST", "/v1/proof-pki/sign/network", {})[0], 403)
                token = login()  # New scoped authentication while TCP verification is unusable.
                self.assertEqual(proof.request("GET", "/v1/sys/mounts", token=token)[0], 403)
                self.assertEqual(proof.request("POST", "/v1/proof-pki/root/generate/internal", {}, token)[0], 403)
                after_issuer, _ = proof.ok("GET", f"/v1/proof-pki/key/{key_id}", token=token)
                self.assertEqual(before_issuer["data"], after_issuer["data"])
                new_pem = proof.sign(token, "120s")
                new_cert = x509.load_pem_x509_certificate(new_pem.encode())
                spki = lambda certificate: certificate.public_key().public_bytes(
                    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
                self.assertEqual(spki(old_cert), spki(new_cert))
                self.assertNotEqual(old_cert.serial_number, new_cert.serial_number)
                self.assertEqual(old_cert.issuer, new_cert.issuer)
                expired_tcp()
                proof.publish(new_pem, ca)
                expired_tcp()  # File publication alone did not change the running listener.
                proof.process.send_signal(signal.SIGHUP)
                proof.wait(lambda: proof.request("GET", "/v1/sys/health", context=context)[0] == 200)
                recovered, new_peer = proof.ok("GET", "/v1/sys/health", context=context)
                self.assertEqual(new_peer, new_cert.public_bytes(serialization.Encoding.DER))
                self.assertEqual(recovered["cluster_id"], baseline["cluster_id"])
                self.assertFalse(recovered["sealed"])
                self.assertEqual(proof.process.pid, process_id)
                self.assertIsNone(proof.process.poll())
                self.assertEqual(hashlib.sha256(proof.key_path.read_bytes()).hexdigest(), key_hash)
                self.assertEqual(hashlib.sha256(proof.ca_path.read_bytes()).hexdigest(), ca_hash)
                proof.ok("GET", f"/v1/proof-pki/key/{key_id}", token=token, context=context)
                self.assertEqual(sum(method == "POST" and path == "/v1/sys/init"
                                     for method, path, _ in proof.calls), 1)
                self.assertFalse(any(path in ("/v1/sys/init", "/v1/sys/unseal", "/v1/auth/token/revoke-self")
                                     for _, path, _ in proof.calls[recovery_call_index:]))
                print(json.dumps({
                    "schema": "elevenid.openbao-unix-tls-recovery-proof/v1",
                    "binary_version": version,
                    "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                    "socket_mode": "0600", "socket_parent_mode": "0700",
                    "socket_owner_matches_operator": True, "foreign_uid_access_denied": foreign_uid_denied,
                    "bootstrap_root_revocation_verified": True, "scoped_auth_while_tcp_expired": True,
                    "unauthenticated_and_overprivileged_requests_denied": True,
                    "tcp_failure_was_expiry": True, "tls_verification_disabled": False,
                    "internal_issuer_key_reused": True, "issuer_private_key_exported": False,
                    "tcp_leaf_key": "retained file-backed node key; not nonexportable",
                    "tcp_leaf_spki_preserved": True, "trust_anchor_preserved": True,
                    "same_process_sighup_recovery": True, "initialization_replayed": False,
                    "network_tls_recovered": True, "container_image_qualified": False,
                    "customer_reboot_or_auto_unseal_qualified": False,
                    "ca_fingerprint_sha256": ca_hash,
                    "leaf_spki_sha256": hashlib.sha256(spki(new_cert)).hexdigest(),
                }, sort_keys=True))
            finally:
                proof.close()


if __name__ == "__main__":
    unittest.main()
