"""Owned TLS response adapter for holder lifecycle qualification, not live PDP."""
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import http.server
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import tempfile
import threading
from urllib.parse import parse_qs, urlsplit
import uuid


@contextmanager
def serve(nonce: str):
    if re.fullmatch(r"[a-f0-9]{32,64}", nonce) is None:
        raise RuntimeError("owned TLS fixture marker required")
    with tempfile.TemporaryDirectory(prefix="holder-issuer-tls-") as directory:
        root = Path(directory)
        os.chmod(root, 0o700)
        ca, ca_key, leaf, leaf_key, csr = [root / name for name in ("ca.pem", "ca-key.pem", "leaf.pem", "leaf-key.pem", "leaf.csr")]

        def openssl(*arguments):
            subprocess.run(["openssl", *map(str, arguments)], check=True, timeout=30,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=Owned holder issuer response CA",
            "-addext", "basicConstraints=critical,CA:TRUE", "-keyout", ca_key, "-out", ca)
        openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=Owned holder response", "-keyout", leaf_key, "-out", csr)
        extensions = root / "leaf.ext"
        extensions.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n")
        openssl("x509", "-req", "-in", csr, "-CA", ca, "-CAkey", ca_key, "-CAcreateserial", "-days", "1", "-extfile", extensions, "-out", leaf)
        ca_key.chmod(0o600)
        leaf_key.chmod(0o600)
        selected = {}
        errors = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def reply(self, status, value):
                body = json.dumps(value).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                try:
                    url = urlsplit(self.path)
                    if self.headers.get("x-service-token") != nonce:
                        self.reply(401, {})
                        return
                    query = parse_qs(url.query)
                    if url.path == f"/fixture-bind/{nonce}" and not selected:
                        organization, user = query["organization_id"][0], query["user_id"][0]
                        uuid.UUID(organization)
                        if not user.startswith("user-"):
                            raise ValueError("invalid fixture user")
                        selected.update(organization=organization, user=user)
                        self.reply(200, {"nonce": nonce})
                        return
                    if not selected or self.headers.get("x-user-id") != selected["user"] or query.get("organization_id") != [selected["organization"]]:
                        self.reply(403, {})
                        return
                    profile = "11111111-2222-4333-8444-555555555555"
                    if url.path != f"/internal/v1/trust-profiles/{profile}/wallet-issuer-authority":
                        self.reply(404, {})
                        return
                    if self.headers.get("authorization"):
                        raise ValueError("bearer forwarded to fixture owner")
                    now = datetime.now(timezone.utc)
                    self.reply(200, {"contract": "marty.wallet/issuer-authority/v2", "organization_id": selected["organization"],
                        "trust_profile_id": profile, "revision": {"id": profile, "version": 1, "content_digest": "sha256:" + "a" * 64},
                        "generated_at": now.isoformat(), "expires_at": (now + timedelta(seconds=30)).isoformat(), "require_not_before": True,
                        "issuer_keys": [{"issuer": "did:web:fixture-issuer.example", "key_id": None, "algorithm": "EdDSA",
                            "public_jwk": {"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", "use": "sig"},
                            "credential_authorizations": [{"format": "SD_JWT_VC", "vct": "urn:fixture:holder-credential"}], "issuance_authorizations": []}]})
                except Exception as error:
                    errors.append(type(error).__name__)
                    self.reply(500, {})

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(leaf, leaf_key)

        class Server(http.server.ThreadingHTTPServer):
            def get_request(self):
                connection, address = self.socket.accept()
                connection.settimeout(5)
                try:
                    return context.wrap_socket(connection, server_side=True), address
                except BaseException:
                    connection.close()
                    raise

        server = Server(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            yield {"MARTY_TEST_HOLDER_TRUST_ORIGIN": f"https://127.0.0.1:{server.server_port}/", "MARTY_TEST_HOLDER_TRUST_CA": str(ca)}
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=5)
            if worker.is_alive():
                raise RuntimeError("owned issuer TLS fixture did not stop")
        if errors:
            raise RuntimeError("owned issuer response adapter failed: " + ",".join(errors))
