"""Owned synthetic HTTPS owner transport around a real signed Flow proof.

The disposable TLS leaf/CA keys are transport-test material, separate from the
non-exportable OpenBao request signing key. No deployed listener is qualified.
"""
from contextlib import contextmanager
import http.server
import json
import os
from pathlib import Path
import ssl
import subprocess
import threading


@contextmanager
def serve(private: Path, nonce: str, proof: dict, token: str):
    ca, ca_key = private / "owner-ca.pem", private / "owner-ca-key.pem"
    cert, key, csr = private / "owner-cert.pem", private / "owner-key.pem", private / "owner.csr"
    commands = [
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(ca_key),
         "-out", str(ca), "-days", "1", "-subj", "/CN=Owned Flow owner fixture CA", "-addext", "basicConstraints=critical,CA:TRUE"],
        ["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
         "-out", str(csr), "-subj", "/CN=Owned Flow owner fixture"],
    ]
    for command in commands:
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
    extensions = private / "owner-leaf.cnf"
    extensions.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n")
    subprocess.run(["openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca), "-CAkey", str(ca_key),
        "-CAcreateserial", "-days", "1", "-out", str(cert), "-extfile", str(extensions)],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
    os.chmod(ca_key, 0o600)
    os.chmod(key, 0o600)
    cases, errors = set(), []
    armed, pending, release = threading.Event(), threading.Event(), threading.Event()
    kinds = ["redirect", "oversized", "duplicate", "private", "media", "unknown"]
    identifiers = {f"00000000-0000-4000-8000-{index:012d}": kind for index, kind in enumerate(kinds, 1)}

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def respond(self, status, body, media="application/json", location=None):
            self.send_response(status)
            self.send_header("Content-Type", media)
            self.send_header("Content-Length", str(len(body)))
            if location:
                self.send_header("Location", location)
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                pass

        def do_GET(self):
            if self.path == "/redirect-target":
                cases.add("redirect-followed")
            if self.headers.get_all("x-fixture-token") != [token]:
                self.respond(401, b"{}")
                return
            prefix = f"/fixture/{nonce}/"
            operation = self.path.removeprefix(prefix) if self.path.startswith(prefix) else ""
            if operation == "guard":
                self.respond(200, json.dumps({"nonce": nonce}).encode())
            elif operation == "arm":
                pending.clear()
                release.clear()
                armed.set()
                self.respond(200, b"{}")
            elif operation == "pending":
                self.respond(200, json.dumps({"pending": pending.is_set()}).encode())
            elif operation == "release":
                release.set()
                self.respond(200, b"{}")
            else:
                self.respond(404, b"{}")

        def do_POST(self):
            try:
                self.owner()
            except Exception as error:
                errors.append(type(error).__name__)
                self.respond(500, b"{}")

        def owner(self):
            if self.headers.get_all("x-service-token") != [token]:
                cases.add("wrong-token")
                self.respond(401, b"{}")
                return
            prefix = "/internal/v1/wallet-verifier-requests/"
            identifier = self.path.removeprefix(prefix) if self.path.startswith(prefix) else ""
            kind = "valid" if identifier == proof["instance_id"] else identifiers.get(identifier)
            if kind is None:
                self.respond(404, b"{}")
                return
            cases.add(kind)
            if kind == "valid" and armed.is_set():
                armed.clear()
                pending.set()
                if not release.wait(10):
                    raise RuntimeError("native authority race did not release owned owner")
            if kind == "redirect":
                self.respond(302, b"{}", location="/redirect-target")
            elif kind == "oversized":
                self.respond(200, b" " * 65537)
            elif kind == "duplicate":
                encoded = json.dumps(proof)
                encoded = '{"contract":"first","con\\u0074ract":' + json.dumps(proof["contract"]) + ',' + encoded[1:]
                duplicates = []

                def inspect(pairs):
                    seen = set()
                    for name, _value in pairs:
                        if name in seen:
                            duplicates.append(name)
                        seen.add(name)
                    return dict(pairs)

                json.loads(encoded, object_pairs_hook=inspect)
                if duplicates != ["contract", "contract"]:
                    raise RuntimeError("escaped duplicate-member fixture is invalid")
                self.respond(200, encoded.encode())
            else:
                body = json.loads(json.dumps(proof))
                if kind == "private":
                    body["public_jwk"]["d"] = "forbidden-fixture-field"
                elif kind == "unknown":
                    body["unrecognized_authority"] = True
                self.respond(200, json.dumps(body).encode(), "text/plain" if kind == "media" else "application/json")

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield {
            "MARTY_TEST_WALLET_FLOW_OWNER_ORIGIN": f"https://127.0.0.1:{server.server_port}",
            "MARTY_TEST_WALLET_FLOW_OWNER_CA": str(ca),
            "MARTY_TEST_WALLET_FLOW_OWNER_TOKEN": token,
            "HTTPS_PROXY": "http://127.0.0.1:9", "https_proxy": "http://127.0.0.1:9",
        }
        if errors:
            raise RuntimeError("owned Flow TLS fixture handler failed: " + ",".join(errors))
        if cases != {"valid", "wrong-token", *kinds}:
            raise RuntimeError("owned Flow TLS vectors missing or redirect followed: " + ",".join(sorted(cases)))
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
        if worker.is_alive():
            raise RuntimeError("owned Flow TLS fixture did not stop")
