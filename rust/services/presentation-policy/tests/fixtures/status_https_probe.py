"""Owned loopback TLS probe; ephemeral keys stay in a private temp directory."""

import base64
import datetime
import http.server
import json
import os
import signal
import ssl
import subprocess
import tempfile
import threading
import time
import zlib
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def certificate(name, key, issuer=None, issuer_key=None, ca=False):
    now = datetime.datetime.now(datetime.UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer.subject if issuer else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(minutes=20))
        .add_extension(
            x509.BasicConstraints(ca=ca, path_length=0 if ca else None), True
        )
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), False)
    )
    if ca:
        builder = builder.add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False),
            True,
        )
    else:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), False
        )
    return builder.sign(issuer_key or key, hashes.SHA256())


def retire_owned_group(process):
    for signum, seconds in [(signal.SIGTERM, 10), (signal.SIGKILL, 5)]:
        try:
            os.killpg(process.pid, signum)
        except ProcessLookupError:
            process.wait(timeout=5)
            return
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            process.poll()
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                process.wait(timeout=5)
                return
            time.sleep(0.05)
    raise RuntimeError("Owned Cargo process group did not retire within its bound")


assert os.name == "posix", "probe requires POSIX process-group isolation"
os.umask(0o077)
with tempfile.TemporaryDirectory(prefix="standards490-tls-") as directory:
    root = Path(directory)
    root_key = ec.generate_private_key(ec.SECP256R1())
    ca = certificate("fixture-root", root_key, ca=True)
    wrong_key = ec.generate_private_key(ec.SECP256R1())
    wrong_ca = certificate("wrong-root", wrong_key, ca=True)
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = certificate("localhost", leaf_key, ca, root_key)
    (root / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (root / "wrong-ca.pem").write_bytes(
        wrong_ca.public_bytes(serialization.Encoding.PEM)
    )
    (root / "leaf.pem").write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    (root / "leaf.key").write_bytes(
        leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    counts = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            assert not self.headers.get("Authorization")
            assert not self.headers.get("Cookie")
            counts[self.path] = counts.get(self.path, 0) + 1
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", origin + "/valid")
                self.end_headers()
                return
            now = int(datetime.datetime.now(datetime.UTC).timestamp())
            iat = now - 600 if self.path == "/expired" else now - 1
            payload = {
                "sub": origin + self.path,
                "iat": iat,
                "exp": iat + 120,
                "ttl": 60,
                "status_list": {
                    "bits": 2,
                    "lst": b64(
                        zlib.compress(bytes([64 if self.path == "/revoked" else 0]))
                    ),
                },
            }
            signing_input = (
                b64(b'{"typ":"statuslist+jwt","alg":"EdDSA"}')
                + "."
                + b64(json.dumps(payload).encode())
            )
            signer = ed25519.Ed25519PrivateKey.from_private_bytes(
                bytes([8 if self.path == "/bad-signature" else 7]) * 32
            )
            token = (
                signing_input + "." + b64(signer.sign(signing_input.encode()))
            ).encode()
            self.send_response(200)
            self.send_header(
                "Content-Type",
                "text/plain"
                if self.path == "/wrong-content"
                else "application/statuslist+jwt",
            )
            self.send_header(
                "Content-Length",
                str(2 * 1024 * 1024 + 1 if self.path == "/oversized" else len(token)),
            )
            self.end_headers()
            try:
                self.wfile.write(token)
            except (BrokenPipeError, ConnectionResetError):
                pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    origin = "https://localhost:" + str(server.server_port)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(root / "leaf.pem", root / "leaf.key")
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    env = dict(
        os.environ,
        STATUS_HTTPS_TEST_ORIGIN=origin,
        STATUS_HTTPS_TEST_CA=str(root / "ca.pem"),
        STATUS_HTTPS_TEST_WRONG_CA=str(root / "wrong-ca.pem"),
        HTTPS_PROXY="http://127.0.0.1:1",
        ALL_PROXY="http://127.0.0.1:1",
        NO_PROXY="",
        CARGO_INCREMENTAL="0",
    )
    process = None
    try:
        process = subprocess.Popen(
            [
                "cargo",
                "test",
                "--offline",
                "--locked",
                "-p",
                "marty-presentation-policy",
                "--lib",
                "live_fixture_https_transport_and_signed_status",
                "--",
                "--ignored",
                "--nocapture",
            ],
            start_new_session=True,
            cwd=Path(__file__).resolve().parents[2],
            env=env,
        )
        returncode = process.wait(timeout=180)
    finally:
        try:
            if process is not None:
                # This session belongs only to the probe and includes any
                # compiler/test descendants that outlive the Cargo parent.
                retire_owned_group(process)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=10)
            assert not thread.is_alive(), "Owned HTTPS controller did not stop"
    expected = {
        "/valid": 1,
        "/revoked": 1,
        "/redirect": 1,
        "/wrong-content": 1,
        "/oversized": 1,
        "/expired": 1,
        "/bad-signature": 1,
    }
    assert returncode == 0, "Rust TLS probe failed"
    assert counts == expected, (
        "Unexpected HTTP delivery (redirect or default-policy leak)"
    )
    print(
        json.dumps(
            {
                "status": "passed",
                "requests": counts,
                "server_closed": True,
                "scope": "Actual loopback TLS transport plus signed JWT codec; not official product suite acceptance",
            }
        )
    )
