"""The protected native batch probe must bind the selected Flow job itself."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from uuid import UUID

import pytest

from scripts.probe_passport_beta_batch import _job_commit
from scripts.probe_passport_beta_native_batch import (
    NativeBatchProbeError,
    ensure_private_state_available,
    exercise,
    request_private_batch,
    write_private_demo_handoff,
)


ORG = "beta-org"
KEY = "k" * 32
SERVICE = "s" * 32
TOKEN = "t" * 32
NATIVE = "a" * 64
SIMULATOR = "b" * 64
SELECTED_BUREAU = "76a7baef-368a-4722-95a4-df70ea1dfefa"
COMPANION_BUREAU = "ccdd126e-87e8-4fc0-8226-f63299ab839c"
COMPANION_FLOW_UUID = UUID("2ece31ce-039a-47ef-aed7-81145938fd12")
BATCH_UUID = UUID("f47ff5a5-1736-45f4-8e41-06c14896f725")
APPLICATION = {
    "organization_id": ORG,
    "issuer_did": "did:web:beta.example:issuer",
    "application_template_id": "app-template",
    "credential_template_id": "credential-template",
    "delivery_destination_profile_id": "destination-profile",
}
DOCUMENT = {"country_code": "USA", "document_type": "TD3",
            "applicant": {"name": "Synthetic"},
            "mrz": {"line_1": "P<UTOSYNTHETIC", "line_2": "123456789"},
            "data_groups": {"DG1": "YQ==", "DG2": "Yg=="}}


def model(private_state_path: Path, *, proof_status: str = "verified", wrong_receipt: bool = False,
          ambiguous_first: bool = False):
    calls = []
    companion_flow = "passport-native-batch-" + str(COMPANION_FLOW_UUID)

    def gateway(method, path, body, key):
        calls.append(("gateway", method, path))
        assert key == KEY
        if path == "/v1/passport/applications":
            assert method == "POST" and body == {**APPLICATION, **DOCUMENT,
                                                  "flow_execution_id": companion_flow}
            return 201, {"id": "companion-job", "application_id": "companion-app",
                         "organization_id": ORG, "issuer_did": APPLICATION["issuer_did"],
                         "flow_execution_id": companion_flow, "status": "DRAFT"}
        if path.endswith("/generate-data-groups"):
            status = "DATA_GENERATED"
        elif path.endswith("/generate-sod"):
            status = "SOD_SIGNED"
        elif path.endswith("/submit-personalization"):
            status = "SUBMITTED"
        elif path.endswith("/production-status"):
            status = "QUALITY_CHECK"
        elif path.endswith("/quality-verify"):
            status = "READY_FOR_ACTIVATION"
        else:
            assert path.endswith("/activate")
            status = "ACTIVE"
        return 200, {"id": "companion-job", "application_id": "companion-app",
                     "organization_id": ORG, "issuer_did": APPLICATION["issuer_did"],
                     "flow_execution_id": companion_flow, "status": status,
                     "sod_sha256": "c" * 64, "sod_signature_verified": True,
                     "bureau_job_id": COMPANION_BUREAU,
                     "completed_at": "2026-09-28T00:00:00Z" if status == "ACTIVE" else None}

    def private(container, batch_id, body, org, key, token, wire_key):
        calls.append(("private", batch_id, body.copy(), wire_key))
        assert (container, org, key, token) == (NATIVE, ORG, SERVICE, TOKEN)
        if ambiguous_first and len([call for call in calls if call[0] == "private"]) == 1:
            raise NativeBatchProbeError("synthetic transport timeout")
        return 200, {"batch_id": batch_id, "wire_evidence_status": proof_status,
                     "http_status": 202, "batch_status": "QUEUED",
                     "wire_commitments": {"request_commitment": "1" * 64,
                                          "response_commitment": "2" * 64},
                     "jobs": [
                         {"id": "selected-job", "application_id": "selected-app",
                          "organization_id": ORG, "issuer_did": APPLICATION["issuer_did"],
                          "flow_execution_id": "selected-flow", "status": "SUBMITTED",
                          "bureau_job_id": SELECTED_BUREAU},
                         {"id": "companion-job", "application_id": "companion-app",
                          "organization_id": ORG, "issuer_did": APPLICATION["issuer_did"],
                          "flow_execution_id": companion_flow, "status": "SUBMITTED",
                          "bureau_job_id": COMPANION_BUREAU},
                     ]}

    def receipt(org, source, bureau, sod, der, pem, key):
        calls.append(("receipt", source))
        assert (org, der, pem, key) == (ORG, "d" * 64, "e" * 64, KEY.encode())
        assert sod == ("f" * 64 if source == "selected-job" else "c" * 64)
        return {"verified": True, "evidence": {
            "tenant_and_job_binding": True,
            "first_accepted_sod_der_matches_native": True,
            "first_accepted_dsc_der_matches_selected_chain": True,
            "first_accepted_dsc_pem_wire_matches_selected_chain": True,
            "source_job_id_commitment": _job_commit(KEY, "source-job", source),
            "bureau_job_id_commitment": "0" * 64 if wrong_receipt else
            _job_commit(KEY, "bureau-job", bureau),
        }}

    def simulator(container, method, path):
        calls.append(("simulator", path))
        assert (container, method, path) == (
            SIMULATOR, "GET", "/v1/personalization/jobs/" + COMPANION_BUREAU)
        return 200, b"", {"status": "SHIPPED",
                           "tracking_number": "BETA-SIM-" + UUID(COMPANION_BUREAU).hex,
                           "callback_receipt_sha256": "7" * 64}

    uuids = iter((COMPANION_FLOW_UUID, BATCH_UUID))
    def run():
        return exercise(
            APPLICATION, DOCUMENT, KEY, SERVICE, TOKEN, NATIVE, SIMULATOR,
            "selected-flow", "selected-app", "selected-job", "f" * 64,
            "managed-profile", "d" * 64, "e" * 64, receipt, private_state_path,
            gateway_request=gateway, private_request=private,
            simulator_get=simulator, new_uuid=lambda: next(uuids),
            new_key=lambda count: b"K" * count,
            sleep=lambda seconds: calls.append(("sleep", seconds)),
        )

    return calls, run


def test_native_selected_pair_uses_stable_key_and_verifies_both_receipts(tmp_path: Path) -> None:
    private_state_path = tmp_path / "private" / "pending.json"
    calls, run = model(private_state_path)
    selected_bureau, result = run()
    assert selected_bureau == SELECTED_BUREAU
    private = [call for call in calls if call[0] == "private"]
    assert len(private) == 2
    assert private[0] == private[1]
    assert private[0][2] == {
        "selected_flow_instance_id": "selected-flow",
        "selected_application_id": "selected-app",
        "companion_application_id": "companion-app",
    }
    assert [call for call in calls if call[0] == "receipt"] == [
        ("receipt", "selected-job"), ("receipt", "companion-job")]
    assert result["verified"] is True
    assert result["evidence"]["selected_flow_in_two_job_batch"] is True
    pending = json.loads(private_state_path.read_text(encoding="utf-8"))
    assert pending["state"] == "dispatching"
    assert pending["batch_id"] == str(BATCH_UUID)
    assert pending["wire_key_b64"] == "S0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0s="
    if os.name == "posix":
        assert private_state_path.stat().st_mode & 0o077 == 0
    assert all(secret not in json.dumps(result) for secret in (
        KEY, TOKEN, "selected-job", "companion-job", SELECTED_BUREAU, COMPANION_BUREAU))


def test_unavailable_wire_proof_halts_before_receipt_or_flow_resume(tmp_path: Path) -> None:
    private_state_path = tmp_path / "private" / "pending.json"
    calls, run = model(private_state_path, proof_status="unavailable")
    with pytest.raises(NativeBatchProbeError, match="first-dispatch proof"):
        run()
    assert not any(call[0] == "receipt" for call in calls)
    assert private_state_path.exists()
    with pytest.raises(NativeBatchProbeError, match="Pending native batch"):
        ensure_private_state_available(private_state_path)


def test_ambiguous_first_send_reuses_uuid_and_key_but_cannot_qualify_proof(tmp_path: Path) -> None:
    calls, run = model(tmp_path / "private" / "pending.json", proof_status="unavailable", ambiguous_first=True)
    with pytest.raises(NativeBatchProbeError, match="first-dispatch proof"):
        run()
    private = [call for call in calls if call[0] == "private"]
    assert len(private) == 2 and private[0] == private[1]
    assert ("sleep", 131) in calls
    assert not any(call[0] == "receipt" for call in calls)


def test_wrong_first_accepted_receipt_halts_native_batch(tmp_path: Path) -> None:
    _, run = model(tmp_path / "private" / "pending.json", wrong_receipt=True)
    with pytest.raises(NativeBatchProbeError, match="receipt is unverified"):
        run()


def test_private_request_keeps_credentials_out_of_docker_argv() -> None:
    observed = []
    def runner(command, config):
        observed.append((command, config))
        return b'{"wire_evidence_status":"unavailable"}\n409'
    status, response = request_private_batch(
        NATIVE, str(BATCH_UUID), {
            "selected_flow_instance_id": "selected-flow",
            "selected_application_id": "selected-app",
            "companion_application_id": "companion-app",
        }, ORG, SERVICE, TOKEN, b"K" * 32, runner=runner,
    )
    assert status == 409 and response == {"wire_evidence_status": "unavailable"}
    command, config = observed[0]
    assert command == ["docker", "exec", "-i", NATIVE, "curl", "--config", "-"]
    assert SERVICE not in str(command) and TOKEN not in str(command)
    assert b"x-passport-reconciliation-token:" in config
    assert b"x-passport-batch-wire-key:" in config
    assert b"selected_flow_instance_id" in config


def test_private_demo_handoff_is_exclusive_and_protected(tmp_path: Path) -> None:
    path = tmp_path / "private" / "selected.json"
    record = {
        "schema": "marty.passport-beta-demo-private/v1",
        "source_commit": "a" * 40,
        "stack_manifest_sha256": "b" * 64,
        "organization_id": ORG,
        "flow_definition_id": "governed-flow",
        "flow_instance_id": "selected-flow",
        "application_id": "selected-app",
        "source_job_id": "selected-job",
        "bureau_job_id": SELECTED_BUREAU,
    }
    write_private_demo_handoff(path, record)
    assert json.loads(path.read_text(encoding="utf-8")) == record
    if os.name == "posix":
        assert path.stat().st_mode & 0o077 == 0
    with pytest.raises(NativeBatchProbeError, match="Pending native batch"):
        write_private_demo_handoff(path, record)


@pytest.mark.skipif(shutil.which("curl") is None, reason="curl is unavailable")
def test_private_curl_config_sends_only_identifiers_and_private_headers() -> None:
    observed = []
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            observed.append((self.path, dict(self.headers), json.loads(body)))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"wire_evidence_status":"verified"}')

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        def runner(command, config):
            assert command[:3] == ["docker", "exec", "-i"]
            local_config = config.replace(b"127.0.0.1:8005",
                                          f"127.0.0.1:{server.server_port}".encode())
            result = subprocess.run(["curl", "--config", "-"], input=local_config,
                                    capture_output=True, check=True, timeout=10)
            return result.stdout

        body = {"selected_flow_instance_id": "selected-flow",
                "selected_application_id": "selected-app",
                "companion_application_id": "companion-app"}
        status, response = request_private_batch(
            NATIVE, str(BATCH_UUID), body, ORG, SERVICE, TOKEN, b"K" * 32,
            runner=runner,
        )
        assert status == 200 and response["wire_evidence_status"] == "verified"
        path, headers, sent = observed[0]
        assert path == f"/internal/passport/beta-batches/{BATCH_UUID}/submit"
        assert sent == body
        assert headers["x-api-key"] == SERVICE
        assert headers["x-organization-id"] == ORG
        assert headers["x-passport-reconciliation-token"] == TOKEN
        assert headers["x-passport-batch-wire-key"] == "S0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0s="
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
