import json
import os
from pathlib import Path
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "examples/protocol-consumer/client.py"


@pytest.fixture
def api():
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            requests.append((self.path, dict(self.headers), None))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"openapi":"3.1.0"}')

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            requests.append((self.path, dict(self.headers), body))
            if urlsplit(self.path).path.endswith("/issue"):
                result = {"verifiableCredential": "signed-test-credential"}
            else:
                result = {"verified": True}
            if body.get("verifiableCredential") == "redirect-test":
                self.send_response(307)
                self.send_header("Location", "/capture")
                self.end_headers()
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def run(base, *args):
    env = dict(os.environ)
    env.pop("MARTY_BEARER_TOKEN", None)
    env["MARTY_API_KEY"] = "example-test-credential"
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--base-url", base, *args],
        env=env,
        capture_output=True,
        text=True,
    )


def test_example_issues_by_did_and_verifies_with_tenant_policy(api, tmp_path):
    base, requests = api
    credential = tmp_path / "credential.json"
    credential.write_text(
        json.dumps(
            {
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "credentialSubject": {"id": "did:example:holder"},
            }
        )
    )
    issued = tmp_path / "issued.json"
    result = run(
        base,
        "--organization-id",
        "org-1",
        "--output",
        str(issued),
        "issue",
        "--template-id",
        "template-1",
        "--issuer-did",
        "did:web:issuer.example",
        "--credential",
        str(credential),
    )
    assert result.returncode == 0, result.stderr
    path, headers, body = requests[-1]
    assert urlsplit(path).path == "/v1/vc-api/credentials/issue"
    assert parse_qs(urlsplit(path).query) == {
        "organization_id": ["org-1"],
        "credential_template_id": ["template-1"],
        "issuer_did": ["did:web:issuer.example"],
    }
    assert headers["X-Api-Key"] == "example-test-credential"
    assert body == {"credential": json.loads(credential.read_text())}
    result = run(
        base,
        "--organization-id",
        "org-1",
        "verify",
        "--policy-id",
        "policy-1",
        "--credential",
        str(issued),
    )
    assert result.returncode == 0, result.stderr
    path, _, body = requests[-1]
    assert urlsplit(path).path == "/v1/vc-api/credentials/verify"
    assert parse_qs(urlsplit(path).query) == {
        "organization_id": ["org-1"],
        "presentation_policy_id": ["policy-1"],
    }
    assert body == {"verifiableCredential": "signed-test-credential"}
    assert json.loads(result.stdout) == {"verified": True}


def test_schema_example_does_not_send_authentication(api):
    base, requests = api
    result = run(base, "schema")
    assert result.returncode == 0
    assert requests[0][0] == "/openapi.json"
    assert not any(
        key.lower() in {"authorization", "x-api-key"} for key in requests[0][1]
    )


def test_example_does_not_forward_credentials_on_redirect(api, tmp_path):
    base, requests = api
    credential = tmp_path / "credential.json"
    credential.write_text(json.dumps("redirect-test"))
    result = run(
        base,
        "--organization-id",
        "org-1",
        "verify",
        "--policy-id",
        "policy-1",
        "--credential",
        str(credential),
    )
    assert result.returncode == 1
    assert "HTTP 307" in result.stderr
    assert len(requests) == 1
    assert "example-test-credential" not in result.stderr
