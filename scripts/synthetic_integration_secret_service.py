"""Disposable remote boundary for packaged startup tests; no key material.

This verifies that Issuance reaches a separate service and checks the bound
round trip. Live OpenBao tests qualify the actual Transit implementation.
"""

import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import secrets
import ssl
from urllib.parse import parse_qs, urlsplit


SCHEMA = "marty.integration-secret-envelope/v1"
PREFIX = "/internal/signing-keys/integration-secrets/"
store = {}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        route = urlsplit(self.path)
        if self.headers.get("X-API-Key") != os.environ["SYNTHETIC_API_KEY"]:
            return self.reply(401, {})
        if route.path not in (PREFIX + "encrypt", PREFIX + "decrypt"):
            return self.reply(404, {})
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 200000:
                return self.reply(422, {})
            request = json.loads(self.rfile.read(size))
            identity = tuple(request[key] for key in (
                "organization_id", "secret_id", "provider", "purpose"
            ))
            if not all(isinstance(value, str) and value for value in identity):
                return self.reply(422, {})
            if parse_qs(route.query).get("organization_id") != [identity[0]]:
                return self.reply(422, {})
            if route.path.endswith("/encrypt"):
                encoded = request["plaintext_b64"]
                base64.b64decode(encoded, validate=True)
                token = secrets.token_hex(24)
                store[token] = (identity, encoded)
                return self.reply(200, {
                    "schema": SCHEMA, "ciphertext": "vault:v1:" + token
                })
            envelope = request["envelope"]
            if envelope["schema"] != SCHEMA:
                return self.reply(422, {})
            prefix, token = envelope["ciphertext"].rsplit(":", 1)
            if prefix != "vault:v1" or token not in store:
                return self.reply(422, {})
            bound, encoded = store[token]
            if identity != bound:
                return self.reply(409, {})
            return self.reply(200, {"plaintext_b64": encoded})
        except (KeyError, ValueError, TypeError, json.JSONDecodeError):
            return self.reply(422, {})

    def reply(self, status, body):
        encoded = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, _format, *_args):
        pass


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", 8017), Handler)
    cert_file = os.environ.get("SYNTHETIC_TLS_CERT_FILE")
    key_file = os.environ.get("SYNTHETIC_TLS_KEY_FILE")
    if bool(cert_file) != bool(key_file):
        raise ValueError("synthetic TLS certificate and key must be paired")
    if cert_file:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_file, key_file)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
