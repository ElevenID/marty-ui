#!/usr/bin/env python3
"""Execute one ignored native test against fresh private loopback TLS fixtures.

No deployed owner, stored wallet, KMS, or installation qualification is implied.
The only private key generated is a short-lived disposable TLS fixture key.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import http.server
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import tempfile
import threading
from urllib.parse import parse_qs, urlsplit

PROFILE = "00000000-0000-4000-8000-000000000002"
CASE = "fixed_owner_tls_authentication_and_closed_response_controls"


def qualify(binary: Path) -> dict:
    binary = binary.resolve(strict=True)
    if not binary.is_file() or not binary.name.startswith("verifier_trust_tls-"):
        raise ValueError("expected the compiled verifier_trust_tls test executable")
    discovery = subprocess.run([str(binary), CASE, "--ignored", "--exact", "--list"],
        capture_output=True, text=True, timeout=30, check=False)
    if discovery.returncode != 0 or [line for line in discovery.stdout.splitlines() if line.endswith(": test")] != [f"{CASE}: test"]:
        raise RuntimeError("exact verifier TLS test discovery failed before fixture allocation")
    fixture = Path(__file__).resolve().parents[1] / "rust/services/trust-profile/tests/fixtures/registered-verifier-source.json"
    registration = json.loads(fixture.read_text())["registered_verifier"]
    token, nonce = secrets.token_hex(32), secrets.token_hex(32)
    requests: list[str] = []
    fixture_errors: list[str] = []
    response_cases: set[str] = set()
    with tempfile.TemporaryDirectory(prefix="marty-verifier-tls-") as directory:
        root = Path(directory)
        os.chmod(root, 0o700)
        ca, ca_key = root / "fixture-ca.pem", root / "fixture-ca-key.pem"
        certificate, key, csr = root / "fixture-cert.pem", root / "fixture-key.pem", root / "fixture.csr"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(ca_key), "-out", str(ca), "-days", "1",
            "-subj", "/CN=Owned verifier transport fixture CA",
            "-addext", "basicConstraints=critical,CA:TRUE",
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run([
            "openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(csr),
            "-subj", "/CN=Owned verifier transport fixture",
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        extensions = root / "leaf-extensions.cnf"
        extensions.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n")
        subprocess.run([
            "openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca),
            "-CAkey", str(ca_key), "-CAcreateserial", "-days", "1",
            "-out", str(certificate), "-extfile", str(extensions),
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        os.chmod(ca_key, 0o600)
        os.chmod(key, 0o600)

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def respond(self, status, body, location=None):
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                if location:
                    self.send_header("Location", location)
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                    pass

            def do_GET(self):
                try:
                    self.handle_get()
                except Exception as error:
                    fixture_errors.append(type(error).__name__)
                    self.respond(500, b"{}")

            def handle_get(self):
                url = urlsplit(self.path)
                if url.path == f"/fixture-guard/{nonce}":
                    self.respond(200, nonce.encode())
                    return
                requests.append(url.path)
                if self.headers.get("x-service-token") != token:
                    self.respond(401, b"{}")
                    return
                query = parse_qs(url.query)
                if self.headers.get("x-user-id") != "browser-user" or query.get("organization_id") != ["org-a"]:
                    self.respond(403, b"{}")
                    return
                if not url.path.startswith(f"/internal/v1/trust-profiles/{PROFILE}/"):
                    self.respond(404, b"{}")
                    return
                now = datetime.now(timezone.utc).replace(microsecond=0)
                snapshot = {"organization_id": "org-a", "trust_profile_id": PROFILE,
                            "observed_at": now.isoformat(), "expires_at": (now + timedelta(seconds=30)).isoformat()}
                if url.path.endswith("/wallet-verifier-profile-admission"):
                    snapshot["contract"] = "marty.wallet/verifier-profile-admission/v1"
                elif url.path.endswith("/wallet-verifier-authority"):
                    client_id = query.get("client_id", [""])[0]
                    response_cases.add(client_id)
                    if client_id == "redirect":
                        self.respond(302, b"{}", "/redirect-target")
                        return
                    if client_id == "oversized":
                        self.respond(200, b" " * 65537)
                        return
                    selected = dict(registration, client_id=client_id,
                                    valid_from=(now-timedelta(seconds=60)).isoformat(),
                                    valid_until=(now+timedelta(seconds=600)).isoformat())
                    snapshot.update(contract="marty.wallet/verifier-authority/v1", authority={
                        "authority_id": f"{PROFILE}/00000000-0000-4000-8000-000000000001",
                        "revision": "fixture-owner-revision", "key_purpose": "oid4vp_request_signing",
                        "algorithm": "ES256", "request_clock_skew_seconds": 30,
                        "max_request_lifetime_seconds": 900, "registration": selected})
                    if client_id == "wrong-scope":
                        snapshot["organization_id"] = "other-org"
                    elif client_id == "expired":
                        snapshot["expires_at"] = (now-timedelta(seconds=1)).isoformat()
                    elif client_id == "private-key":
                        selected["public_jwk"] = dict(selected["public_jwk"], d="forbidden-fixture-field")
                    elif client_id == "duplicate":
                        encoded = json.dumps(snapshot).replace('"revision": "fixture-owner-revision"',
                            '"revision":"first","rev\\u0069sion":"fixture-owner-revision"')
                        duplicate_members = []

                        def inspect_members(pairs):
                            seen = set()
                            for name, _value in pairs:
                                if name in seen:
                                    duplicate_members.append(name)
                                seen.add(name)
                            return dict(pairs)

                        # Inspect decoded JSON names, so an accidental literal
                        # backslash or unknown-field vector cannot pass as this
                        # escaped-equivalent duplicate-member test.
                        json.loads(encoded, object_pairs_hook=inspect_members)
                        if duplicate_members != ["revision"]:
                            raise RuntimeError("invalid duplicate-member fixture vector")
                        self.respond(200, encoded.encode())
                        return
                else:
                    self.respond(404, b"{}")
                    return
                self.respond(200, json.dumps(snapshot).encode())

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            environment = dict(os.environ,
                MARTY_VERIFIER_TLS_FIXTURE_ORIGIN=f"https://127.0.0.1:{server.server_port}/",
                MARTY_VERIFIER_TLS_FIXTURE_CA=str(ca),
                MARTY_VERIFIER_TLS_FIXTURE_TOKEN=token,
                MARTY_VERIFIER_TLS_FIXTURE_NONCE=nonce,
                HTTPS_PROXY="http://127.0.0.1:9", https_proxy="http://127.0.0.1:9")
            result = subprocess.run([str(binary), CASE, "--ignored", "--exact", "--nocapture"],
                env=environment, capture_output=True, text=True, timeout=120, check=False)
            detail = result.stdout + result.stderr
            for private in [token, nonce, str(key)]:
                detail = detail.replace(private, "[fixture-private]")
            passed = result.returncode == 0 and "test result: ok. 1 passed; 0 failed;" in detail
            if not passed:
                raise RuntimeError("owned TLS transport qualification failed:\n" + detail[-6000:])
            if fixture_errors:
                raise RuntimeError("TLS fixture handler failed: " + ",".join(fixture_errors))
            if response_cases != {"registered-client", "redirect", "oversized", "duplicate", "wrong-scope", "expired", "private-key"}:
                raise RuntimeError("TLS fixture did not execute every required response case")
            if "/redirect-target" in requests:
                raise RuntimeError("owner redirect was followed")
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=5)
        if worker.is_alive():
            raise RuntimeError("owned TLS fixture did not stop")
    # Let the shared CI positive-execution guard inspect the real sanitized
    # libtest summary, after the fixture teardown also succeeded.
    print(detail, end="")
    return {"test": CASE, "passed": 1, "ignored": 0, "tlsFixtureStopped": True,
            "temporaryTlsMaterialRemoved": not root.exists(), "redirectFollowed": False,
            "scope": "actual fixed-owner TLS transport against synthetic owner responses; not deployed owner, KMS, rootless installation or wallet acceptance"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-binary", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(qualify(args.test_binary)))
