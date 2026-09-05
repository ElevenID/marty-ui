"""Own a synthetic TLS fixture and one child test; never alter machine trust."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading
from urllib.parse import parse_qs, urlsplit

AGS_SCOPE = "https://purl.imsglobal.org/spec/lti-ags/scope/result.readonly"
NRPS_SCOPE = "https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def respond(self, payload, status=200, headers=None):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        try:
            assert self.path == "/login/oauth2/token"
            assert self.headers["Accept"] == "application/json"
            assert self.headers["Content-Type"] == "application/x-www-form-urlencoded"
            form = parse_qs(
                self.rfile.read(int(self.headers["Content-Length"])).decode()
            )
            assert set(form) == {
                "grant_type",
                "client_assertion_type",
                "client_assertion",
                "client_id",
                "scope",
            }
            assert form["grant_type"] == ["client_credentials"]
            assert form["client_assertion_type"] == [
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            ]
            assert form["client_id"] == ["synthetic-client"]
            assert form["client_assertion"] == ["synthetic-lti-assertion"]
            scope = form["scope"][0]
            assert scope in {AGS_SCOPE, NRPS_SCOPE}
            self.server.scopes.append(scope)
            self.respond(
                {
                    "access_token": "synthetic-ags-token"
                    if scope == AGS_SCOPE
                    else "synthetic-nrps-token"
                }
            )
        except (AssertionError, KeyError, ValueError):
            self.server.failures.append("token request contract")
            self.respond({}, 500)

    def do_GET(self):
        try:
            url = urlsplit(self.path)
            query = parse_qs(url.query)
            if url.path.endswith("/memberships"):
                assert (
                    self.headers["Accept"]
                    == "application/vnd.ims.lti-nrps.v2.membershipcontainer+json"
                )
                assert self.headers["Authorization"] == "Bearer synthetic-nrps-token"
                self.server.membership_pages += 1
                if query.get("page") == ["2"]:
                    self.respond(
                        {
                            "members": [
                                {
                                    "userId": "subject-7",
                                    "status": "Active",
                                    "name": "SYNTHETIC_NO_RETENTION",
                                    "email": "synthetic@example.invalid",
                                }
                            ]
                        }
                    )
                else:
                    assert not query
                    self.respond(
                        {
                            "members": [
                                {"user_id": "inactive-subject", "status": "Inactive"}
                            ]
                        },
                        headers={
                            "Link": f'<https://127.0.0.1:{self.server.server_port}{url.path}?page=2>; rel="next"'
                        },
                    )
                return
            assert url.path.endswith("/results")
            assert (
                self.headers["Accept"]
                == "application/vnd.ims.lis.v2.resultcontainer+json"
            )
            assert self.headers["Authorization"] == "Bearer synthetic-ags-token"
            assert query == {"user_id": ["subject-7"]}
            self.server.result_reads += 1
            if "/rate/" in url.path:
                self.respond({}, 429, {"Retry-After": "37"})
            elif "/empty/" in url.path:
                self.respond([])
            else:
                self.respond(
                    [
                        {
                            "id": "result-7",
                            "userId": "subject-7",
                            "resultScore": 90,
                            "resultMaximum": 100,
                            "resultStatus": "FullyGraded",
                            "timestamp": "2026-09-01T00:00:00Z",
                            "name": "SYNTHETIC_NO_RETENTION",
                        }
                    ]
                )
        except (AssertionError, KeyError, ValueError):
            self.server.failures.append("collection request contract")
            self.respond({}, 500)


def run(executable):
    with tempfile.TemporaryDirectory(prefix="marty-lti-https-") as directory:
        root = Path(directory)
        cert, key = root / "ca.pem", root / "server.key"
        # A test-only self-signed leaf with an IP SAN; trusted solely by the child.
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=synthetic-canvas-test",
                "-addext",
                "subjectAltName=IP:127.0.0.1",
                "-addext",
                "basicConstraints=critical,CA:FALSE",
                "-keyout",
                str(key),
                "-out",
                str(cert),
            ],
            check=True,
            capture_output=True,
            timeout=30,
        )
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.scopes, server.failures = [], []
        server.membership_pages = server.result_reads = 0
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            environment = dict(os.environ)
            environment.pop("SSL_CERT_FILE", None)
            environment.pop("SSL_CERT_DIR", None)
            environment["MARTY_CANVAS_LTI_HTTPS_ORIGIN"] = (
                f"https://127.0.0.1:{server.server_port}"
            )
            environment["MARTY_CANVAS_LTI_HTTPS_UNTRUSTED"] = "1"
            command = [
                executable,
                "canvas_authoritative_https::https_child",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ]
            untrusted = subprocess.run(
                command, env=environment, capture_output=True, text=True, timeout=60
            )
            if untrusted.returncode:
                print(untrusted.stdout)
                print(untrusted.stderr)
            assert untrusted.returncode == 0, (
                "Native untrusted-certificate check failed"
            )
            assert (
                not server.scopes
                and server.result_reads == server.membership_pages == 0
            )
            environment.pop("MARTY_CANVAS_LTI_HTTPS_UNTRUSTED")
            cert_directory = root / "empty-cert-directory"
            cert_directory.mkdir()
            environment.update(
                {
                    "SSL_CERT_FILE": str(cert),
                    "SSL_CERT_DIR": str(cert_directory),
                    "MARTY_CANVAS_LTI_HTTPS_ORIGIN": f"https://127.0.0.1:{server.server_port}",
                }
            )
            result = subprocess.run(
                command,
                env=environment,
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.returncode:
                print(result.stdout)
                print(result.stderr)
            assert result.returncode == 0, "Native HTTPS child failed"
            assert not server.failures, "HTTPS request contract failed"
            assert server.scopes.count(AGS_SCOPE) == 3
            assert server.scopes.count(NRPS_SCOPE) == 1
            assert server.membership_pages == 2 and server.result_reads == 3
            print(
                "Actual native AGS/NRPS HTTPS gate passed: 4 token requests, 3 AGS reads, 2 NRPS pages"
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            assert not thread.is_alive(), "Owned HTTPS server did not stop"


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Expected the exact compiled OAuth test executable")
    run(sys.argv[1])
