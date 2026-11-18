"""Controlled HTTPS issuer for the joined real owner/Device/native contract.

Credential identity signing uses a fresh non-exportable Transit key on the
already marked disposable Bao. Only transport-test TLS keys exist in files.
This is not the deployed Issuance service or installed-wallet acceptance.
"""
from contextlib import contextmanager
import base64
import http.server
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import tempfile
import threading
from urllib.error import HTTPError
from urllib.parse import parse_qs
import uuid


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


@contextmanager
def serve(bao, nonce):
    require(re.fullmatch(r"[a-f0-9]{32,64}", nonce), "owned native receipt nonce required")
    require(bao.request("GET", "secret/data/marty-test-disposable-guard")["data"]["data"]["nonce"] == nonce,
            "refuse unmarked native receipt issuer")
    key = "joined-wallet-issuer-" + uuid.uuid4().hex
    bao.request("POST", "transit/keys/" + key,
                {"type": "ecdsa-p256", "exportable": False, "allow_plaintext_backup": False})
    metadata = bao.request("GET", "transit/keys/" + key)["data"]
    require(metadata["type"] == "ecdsa-p256" and metadata["exportable"] is False
            and metadata["allow_plaintext_backup"] is False, "joined issuer custody invalid")
    try:
        bao.request("GET", "transit/export/signing-key/" + key)
    except HTTPError as error:
        require(error.code in (400, 403), "unexpected issuer export refusal")
    else:
        raise RuntimeError("joined issuer key was exportable")
    result = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "DER"],
        input=metadata["keys"]["1"]["public_key"].encode(), capture_output=True, timeout=20, check=False)
    prefix = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")
    require(result.returncode == 0 and len(result.stdout) == len(prefix) + 65
            and result.stdout.startswith(prefix + b"\x04"), "joined issuer public key invalid")
    point = result.stdout[-65:]
    public = {"kty": "EC", "crv": "P-256", "x": b64(point[1:33]), "y": b64(point[33:]),
              "kid": "joined-issuer-key", "alg": "ES256", "use": "sig"}
    policy = "joined-wallet-issuer-" + uuid.uuid4().hex
    bao.request("PUT", "sys/policies/acl/" + policy, {"policy":
        f'path "transit/sign/{key}" {{ capabilities = ["update"] }}'})
    token = bao.request("POST", "auth/token/create",
        {"policies": [policy], "no_default_policy": True, "ttl": "10m"})["auth"]["client_token"]
    with tempfile.TemporaryDirectory(prefix="marty-joined-wallet-") as directory:
        private = Path(directory)
        os.chmod(private, 0o700)
        ca, ca_key, cert, tls_key, csr = [private / name for name in
            ("issuer-ca.pem", "issuer-ca-key.pem", "issuer.pem", "issuer-key.pem", "issuer.csr")]
        for command in [
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
             "-subj", "/CN=Owned joined issuer CA", "-addext", "basicConstraints=critical,CA:TRUE",
             "-keyout", str(ca_key), "-out", str(ca)],
            ["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=Owned joined issuer",
             "-keyout", str(tls_key), "-out", str(csr)],
        ]:
            made = subprocess.run(command, capture_output=True, timeout=20, check=False)
            require(made.returncode == 0, "owned issuer transport TLS unavailable")
        extensions = private / "issuer.ext"
        extensions.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n")
        made = subprocess.run(["openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca),
            "-CAkey", str(ca_key), "-CAcreateserial", "-days", "1", "-extfile", str(extensions),
            "-out", str(cert)], capture_output=True, timeout=20, check=False)
        require(made.returncode == 0, "owned issuer transport certificate unavailable")
        ca_key.chmod(0o600)
        tls_key.chmod(0o600)
        counts = {"token": 0, "nonce": 0, "credential": 0}
        errors = []
        signed_issuer = "did:web:joined-issuer.example"

        class Issuer(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def reply(self, value):
                body = json.dumps(value).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if self.path != "/.well-known/openid-credential-issuer":
                    self.send_error(404)
                    return
                origin = f"https://127.0.0.1:{self.server.server_port}"
                self.reply({"credential_issuer": origin, "credential_endpoint": origin + "/credential",
                    "nonce_endpoint": origin + "/nonce", "token_endpoint": origin + "/token",
                    "credential_configurations_supported": {"identity": {"format": "dc+sd-jwt",
                        "vct": "urn:elevenid:credential:identity", "cryptographic_binding_methods_supported": ["jwk"],
                        "proof_types_supported": {"jwt": {"proof_signing_alg_values_supported": ["ES256"]}}}}})

            def do_POST(self):
                try:
                    self.issuance()
                except Exception as error:
                    errors.append(type(error).__name__)
                    category = "encoding" if isinstance(error, (ValueError, base64.binascii.Error)) else "fixture"
                    print("joined_issuer_failure=" + category, flush=True)
                    self.send_error(400)

            def issuance(self):
                self.connection.settimeout(10)
                require(self.path in {"/token", "/nonce", "/credential"}, "unknown issuer path")
                size = int(self.headers.get("Content-Length", "0"))
                require(0 <= size <= 65536, "issuer request too large")
                raw = self.rfile.read(size)
                kind = self.path[1:]
                if kind == "token":
                    require(parse_qs(raw.decode(), strict_parsing=True) == {
                        "grant_type": ["urn:ietf:params:oauth:grant-type:pre-authorized_code"],
                        "pre-authorized_code": ["owned-joined-code"]}, "unbound owned token request")
                    reply = {"access_token": "owned-joined-token", "token_type": "Bearer", "expires_in": 120}
                elif kind == "nonce":
                    reply = {"c_nonce": "owned-joined-nonce", "c_nonce_expires_in": 120}
                else:
                    require(self.headers.get("Authorization") == "Bearer owned-joined-token", "owned token mismatch")
                    request = json.loads(raw)
                    require(set(request) == {"credential_configuration_id", "proofs"}
                        and request["credential_configuration_id"] == "identity" and set(request["proofs"]) == {"jwt"}
                        and len(request["proofs"]["jwt"]) == 1, "owned credential request mismatch")
                    holder = json.loads((private / "holder.json").read_text())
                    require(holder["nonce"] == nonce, "paired holder marker mismatch")
                    jwk = holder["public_jwk"]
                    require(set(jwk) == {"kty", "crv", "x", "y"} and jwk["crv"] == "P-256", "paired holder key invalid")
                    import time
                    now = int(time.time())
                    claims = {"iss": signed_issuer, "vct": "urn:elevenid:credential:identity", "iat": now,
                        "nbf": now - 1, "exp": now + 600, "cnf": {"jwk": jwk}, "_sd_alg": "sha-256"}
                    header = {"alg": "ES256", "typ": "dc+sd-jwt", "kid": public["kid"]}
                    data = b64(json.dumps(header).encode()) + "." + b64(json.dumps(claims).encode())
                    signature = bao.request("POST", "transit/sign/" + key,
                        {"input": base64.b64encode(data.encode()).decode(), "marshaling_algorithm": "jws", "key_version": 1}, token=token)["data"]["signature"]
                    require(signature.startswith("vault:v1:"), "issuer signing version mismatch")
                    # Transit JWS marshaling returns canonical base64url without
                    # padding, rather than the default ASN.1/base64 encoding.
                    encoded = signature.removeprefix("vault:v1:")
                    require(re.fullmatch(r"[A-Za-z0-9_-]{86}", encoded), "issuer JWS encoding invalid")
                    signature = base64.b64decode(encoded + "==", altchars=b"-_", validate=True)
                    require(len(signature) == 64 and b64(signature) == encoded, "issuer signature encoding mismatch")
                    reply = {"credentials": [{"credential": data + "." + b64(signature) + "~"}]}
                    (private / "issuer-proof.json").write_text(json.dumps({"proof": request["proofs"]["jwt"][0]}))
                counts[kind] += 1
                (private / "capture.json").write_text(json.dumps(counts))
                self.reply(reply)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, tls_key)

        class Server(http.server.HTTPServer):
            active = None

            def get_request(self):
                connection, address = self.socket.accept()
                connection.settimeout(10)
                try:
                    connection = context.wrap_socket(connection, server_side=True)
                except BaseException:
                    connection.close()
                    raise
                self.active = connection
                return connection, address

            def shutdown_request(self, request):
                super().shutdown_request(request)
                self.active = None

        server = Server(("127.0.0.1", 0), Issuer)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        config = private / "joined-fixture.json"
        config.write_text(json.dumps({"nonce": nonce, "issuer_origin": f"https://127.0.0.1:{server.server_port}",
            "issuer_ca_file": str(ca), "signed_issuer": signed_issuer, "issuer_public_jwk": public}))
        config.chmod(0o600)
        try:
            yield {"MARTY_TEST_JOINED_WALLET_CONFIG": str(config)}
            require(not errors and counts == {"token": 2, "nonce": 2, "credential": 2}, "joined issuer execution incomplete")
        finally:
            if server.active is not None:
                try:
                    server.active.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                server.active.close()
            stopper = threading.Thread(target=server.shutdown, daemon=True)
            stopper.start()
            stopper.join(timeout=15)
            server.server_close()
            thread.join(timeout=10)
            require(not stopper.is_alive() and not thread.is_alive(), "owned issuer thread did not stop")
