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
            path = urlsplit(self.path).path
            composition = {
                "/v1/trust-profiles/trust-1": {
                    "id": "trust-1",
                    "organization_id": "org-a",
                    "status": "ACTIVE",
                },
                "/v1/credential-templates/template-1": {
                    "id": "template-1",
                    "organization_id": "org-a",
                    "status": "ACTIVE",
                    "trust_profile_id": "trust-1",
                    "compliance_profile_id": "compliance-1",
                    "revocation_profile_id": "revocation-1",
                },
                "/v1/presentation-policies/policy-1": {
                    "id": "policy-1",
                    "organization_id": "org-a",
                    "status": "ACTIVE",
                    "trust_profile_id": "trust-1",
                },
                "/v1/deployment-profiles/deployment-1": {
                    "id": "deployment-1",
                    "organization_id": "org-a",
                    "status": "ACTIVE",
                    "trust_profile_id": "trust-1",
                    "credential_template_ids": ["template-1"],
                    "presentation_policy_ids": ["policy-1"],
                    "enabled_flow_ids": [
                        "issue-flow-1",
                        "verify-flow-1",
                        "verify-foreign",
                    ],
                },
                "/v1/flows/definitions/issue-flow-1": {
                    "id": "issue-flow-1",
                    "organization_id": "org-a",
                    "status": "ACTIVE",
                    "trust_profile_id": "trust-1",
                    "credential_template_id": "template-1",
                    "deployment_profile_ids": ["deployment-1"],
                },
                "/v1/flows/definitions/verify-flow-1": {
                    "id": "verify-flow-1",
                    "organization_id": "org-a",
                    "status": "ACTIVE",
                    "trust_profile_id": "trust-1",
                    "presentation_policy_id": "policy-1",
                    "deployment_profile_ids": ["deployment-1"],
                },
                "/v1/flows/definitions/verify-foreign": {
                    "id": "verify-foreign",
                    "organization_id": "org-b",
                    "status": "ACTIVE",
                    "trust_profile_id": "trust-1",
                    "presentation_policy_id": "policy-1",
                    "deployment_profile_ids": ["deployment-1"],
                },
                "/v1/compliance-profiles/compliance-1": {
                    "id": "compliance-1",
                    "organization_id": "org-a",
                    "status": "ACTIVE",
                },
                "/v1/revocation-profiles/revocation-1": {
                    "id": "revocation-1",
                    "organization_id": "org-a",
                    "status": "ACTIVE",
                },
                "/v1/organizations/org-a/runtime/status": {
                    "can_issue": True,
                    "can_verify": True,
                    "issuer_keys_valid": True,
                    "deployment_active": True,
                },
            }
            self.send_response(200)
            self.end_headers()
            if path == "/v1/protocol-support":
                example = SCRIPT.parents[2] / "contracts/protocol-support-catalog.json"
                self.wfile.write(example.read_bytes())
            elif path in composition:
                self.wfile.write(json.dumps(composition[path]).encode())
            elif path.endswith("/issuer-identities/inspection"):
                example = (
                    SCRIPT.parents[2]
                    / "contracts/issuer-identity-inspection-example.json"
                )
                self.wfile.write(example.read_bytes())
            elif path.endswith("/wallet-compatibility"):
                self.wfile.write(
                    (
                        SCRIPT.parents[2]
                        / "contracts/wallet-compatibility-example.json"
                    ).read_bytes()
                )
            else:
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


def test_example_inspects_an_exact_public_tuple_with_read_authority(api):
    base, requests = api
    result = run(
        base,
        "--organization-id",
        "org-a",
        "inspect",
        "--issuer-did",
        "did:web:issuer.example:orgs:acme",
        "--purpose",
        "vc_jwt_issuer",
        "--format",
        "SD_JWT_VC",
        "--algorithm",
        "ES256",
    )
    assert result.returncode == 0, result.stderr
    path, headers, body = requests[-1]
    assert urlsplit(path).path == "/v1/signing-keys/issuer-identities/inspection"
    assert parse_qs(urlsplit(path).query) == {
        "organization_id": ["org-a"],
        "issuer_did": ["did:web:issuer.example:orgs:acme"],
        "key_purpose": ["vc_jwt_issuer"],
        "credential_format": ["SD_JWT_VC"],
        "algorithm": ["ES256"],
    }
    assert headers["X-Api-Key"] == "example-test-credential"
    assert body is None
    assert (
        json.loads(result.stdout)["canonical_document_url"]
        == "https://issuer.example/orgs/acme/did.json"
    )


def test_example_reads_a_scoped_template_wallet_profile_without_a_credential_file(api):
    base, requests = api
    result = run(
        base,
        "--organization-id",
        "org-1",
        "wallet-profile",
        "--template-id",
        "template/with space",
    )
    assert result.returncode == 0, result.stderr
    path, headers, body = requests[-1]
    assert (
        urlsplit(path).path
        == "/v1/credential-templates/template%2Fwith%20space/wallet-compatibility"
    )
    assert parse_qs(urlsplit(path).query) == {"organization_id": ["org-1"]}
    assert headers["X-Api-Key"] == "example-test-credential"
    assert body is None
    assert json.loads(result.stdout)["derived_from"]["credential_format"] == "SD_JWT_VC"


def test_example_validates_a_complete_scoped_profile_composition(api):
    base, requests = api
    result = run(
        base,
        "--organization-id",
        "org-a",
        "composition",
        "--trust-profile-id",
        "trust-1",
        "--template-id",
        "template-1",
        "--policy-id",
        "policy-1",
        "--deployment-profile-id",
        "deployment-1",
        "--issuance-flow-id",
        "issue-flow-1",
        "--verification-flow-id",
        "verify-flow-1",
    )
    assert result.returncode == 0, result.stderr
    value = json.loads(result.stdout)
    assert value["consistent"] is True
    assert value["runtime_status"]["can_issue"] is True
    assert value["runtime_status"]["can_verify"] is True
    assert value["resources"]["revocation_profile"]["id"] == "revocation-1"
    paths = [urlsplit(request[0]).path for request in requests]
    assert paths == [
        "/v1/protocol-support",
        "/v1/trust-profiles/trust-1",
        "/v1/credential-templates/template-1",
        "/v1/presentation-policies/policy-1",
        "/v1/deployment-profiles/deployment-1",
        "/v1/flows/definitions/issue-flow-1",
        "/v1/flows/definitions/verify-flow-1",
        "/v1/compliance-profiles/compliance-1",
        "/v1/revocation-profiles/revocation-1",
        "/v1/organizations/org-a/runtime/status",
    ]
    assert not any(
        key.lower() in {"authorization", "x-api-key"} for key in requests[0][1]
    )
    assert all(
        request[1]["X-Api-Key"] == "example-test-credential" for request in requests[1:]
    )
    for path, _, _ in requests[1:-1]:
        assert parse_qs(urlsplit(path).query) == {"organization_id": ["org-a"]}


def test_example_rejects_a_foreign_resource_in_profile_composition(api):
    base, _ = api
    result = run(
        base,
        "--organization-id",
        "org-a",
        "composition",
        "--trust-profile-id",
        "trust-1",
        "--template-id",
        "template-1",
        "--policy-id",
        "policy-1",
        "--deployment-profile-id",
        "deployment-1",
        "--issuance-flow-id",
        "issue-flow-1",
        "--verification-flow-id",
        "verify-foreign",
    )
    assert result.returncode == 1
    assert "verification flow is outside the requested organization" in result.stderr
    assert result.stdout == ""


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
