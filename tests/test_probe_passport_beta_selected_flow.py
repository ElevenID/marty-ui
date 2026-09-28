"""A selected beta Flow must create and complete one receipt-bound native job."""

from __future__ import annotations

import copy
import json

import pytest

from scripts import probe_passport_beta_selected_flow as selected_flow
from scripts.probe_passport_beta_flow import PHYSICAL_STEPS
from scripts.probe_passport_beta_selected_flow import SelectedFlowError, exercise

ORGANIZATION = "beta-org"
DEFINITION = "passport-flow"
ISSUER = "did:web:beta.example:issuer"
REFERENCES = {"application_template_id": "application-template",
              "credential_template_id": "credential-template",
              "delivery_destination_profile_id": "destination-profile"}
PHYSICAL = {"country_code": "USA", "document_type": "TD3",
            "applicant": {"given_name": "Synthetic"},
            "mrz": {"line_1": "P<UTOSYNTHETIC", "line_2": "123456789"},
            "data_groups": {"DG1": "YQ=="}}
COOKIE = "sessionId=governed-flow-operator"
KEY = "z" * 32
BUREAU = "c3ddfe4d-e67e-473e-a278-c95a27459344"
SOD = "f" * 64


def model(*, wrong_definition: bool = False, wrong_issuer: bool = False,
          wrong_submitted_sod: bool = False, wrong_final_steps: bool = False,
          failed_native_status: bool = False):
    calls = []
    finished = []

    def flow_request(method: str, path: str, body: dict | None, cookie: str) -> tuple[int, dict]:
        calls.append((method, path, body, cookie))
        assert cookie == COOKIE
        if method == "GET":
            return 200, {"id": DEFINITION, "organization_id": "foreign-org" if wrong_definition else ORGANIZATION,
                         "flow_type": "physical_document_issuance", "status": "ACTIVE",
                         "resolved_steps": list(PHYSICAL_STEPS), **REFERENCES}
        if path == "/v1/flows/instances":
            assert body == {"organization_id": ORGANIZATION, "flow_definition_id": DEFINITION,
                            "initial_context": {"physical_document": PHYSICAL}}
            index = -1
        else:
            index = len(finished)
            assert body == {"step_result": "success", "data": ({"passed": True, "failure_codes": []}
                                                              if PHYSICAL_STEPS[index] == "quality_verify" else {})}
            finished.append(PHYSICAL_STEPS[index])
        job = {"id": "job-1", "application_id": "app-1", "organization_id": ORGANIZATION,
               "flow_execution_id": "instance-1", "issuer_did": "did:example:wrong" if wrong_issuer else ISSUER,
               "status": "DRAFT"}
        if index >= 4:
            job.update(status="SOD_SIGNED", sod_sha256=SOD, sod_signature_verified=True)
        if index >= 5:
            job.update(status="SUBMITTED", bureau_job_id=BUREAU,
                       sod_sha256="e" * 64 if wrong_submitted_sod else SOD)
        if index >= 6:
            job["status"] = "QUALITY_CHECK"
        if index >= 7:
            job.update(status="READY_FOR_ACTIVATION", quality_result={"passed": True})
        if index >= 8:
            job.update(status="ACTIVE", completed_at="2026-09-28T00:00:00Z")
        results = {step: {"result": "success"} for step in finished}
        if wrong_final_steps and index == 8:
            results.pop("sign_sod")
        payload = {"id": "instance-1", "flow_id": DEFINITION, "organization_id": ORGANIZATION,
                   "flow_type": "physical_document_issuance",
                   "status": "COMPLETED" if index == 8 else "IN_PROGRESS",
                   "current_step": PHYSICAL_STEPS[index + 1] if index + 1 < len(PHYSICAL_STEPS) else PHYSICAL_STEPS[-1],
                   "context_data": {"application_id": "app-1", "physical_document_job": job},
                   "step_results": results}
        if index == 8:
            payload["completed_at"] = "2026-09-28T00:00:00Z"
        return 200, payload

    def native_request(method: str, path: str, body: dict | None, key: str) -> tuple[int, dict]:
        calls.append((method, path, body, key))
        assert key == KEY
        return 200, {"organization_id": ORGANIZATION, "application_id": "app-1",
                     "id": "job-1", "bureau_job_id": BUREAU,
                     "status": "FAILED" if failed_native_status else "QUALITY_CHECK"}

    def receipt(org: str, source: str, bureau: str, sod: str) -> dict:
        calls.append(("receipt", org, source, bureau, sod))
        return {"verified": True, "evidence": {
            "tenant_and_job_binding": True,
            "first_accepted_sod_der_matches_native": True,
            "first_accepted_dsc_der_matches_selected_chain": True,
            "first_accepted_dsc_pem_wire_matches_selected_chain": True,
            "source_job_id_commitment": "a" * 64,
            "bureau_job_id_commitment": "b" * 64}}

    return calls, flow_request, native_request, receipt


def probe(flow_request, native_request, receipt):
    return exercise(DEFINITION, ORGANIZATION, ISSUER, REFERENCES, PHYSICAL, COOKIE, KEY,
                    on_submission=receipt, request=flow_request,
                    passport_request=native_request, poll_interval_seconds=0)


def test_selected_flow_completes_nine_steps_on_one_receipt_bound_job() -> None:
    calls, flow_request, native_request, receipt = model()
    result = probe(flow_request, native_request, receipt)
    evidence = result["evidence"]
    assert result["verified"] is True
    assert evidence["completed_steps"] == 9
    assert evidence["ordered_steps"] == list(PHYSICAL_STEPS)
    assert (evidence["flow_instance_id"], evidence["job_id"], evidence["bureau_job_id"]) == (
        "instance-1", "job-1", BUREAU)
    assert evidence["sod_sha256"] == SOD
    assert evidence["source_job_commitment"] == "a" * 64
    assert "flow_owner" not in evidence
    assert [call[0] for call in calls].count("POST") == 10
    assert calls[0][0:2] == ("GET", f"/v1/flows/definitions/{DEFINITION}")
    assert ("GET", "/v1/passport/applications/app-1/production-status") in [call[:2] for call in calls]
    assert ("receipt", ORGANIZATION, "job-1", BUREAU, SOD) in calls
    assert all(private not in str(result) for private in ("Synthetic", "P<UTO", "123456789", COOKIE, KEY))


@pytest.mark.parametrize("defect", ["wrong_definition", "wrong_issuer", "wrong_submitted_sod",
                                     "wrong_final_steps", "failed_native_status"])
def test_selected_flow_rejects_false_job_or_step_proof(defect: str) -> None:
    calls, flow_request, native_request, receipt = model(**{defect: True})
    with pytest.raises(SelectedFlowError):
        probe(flow_request, native_request, receipt)
    if defect == "wrong_definition":
        assert len(calls) == 1


def test_selected_flow_rejects_missing_private_material_receipt() -> None:
    _, flow_request, native_request, receipt = model()

    def missing(*args):
        result = copy.deepcopy(receipt(*args))
        result["evidence"]["first_accepted_dsc_der_matches_selected_chain"] = False
        return result

    with pytest.raises(SelectedFlowError, match="receipt is unverified"):
        probe(flow_request, native_request, missing)


def test_selected_flow_requires_governed_inputs_before_start() -> None:
    calls, flow_request, native_request, receipt = model()
    with pytest.raises(SelectedFlowError, match="inputs are incomplete"):
        exercise(DEFINITION, ORGANIZATION, ISSUER, REFERENCES, PHYSICAL, "bad\nCookie", KEY,
                 on_submission=receipt, request=flow_request, passport_request=native_request)
    assert calls == []


def test_flow_http_request_keeps_operator_cookie_private_and_rejects_redirect(monkeypatch) -> None:
    seen = []

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def geturl(self):
            return seen[0].full_url

        def read(self, amount):
            return b'{"id":"instance-1"}'

    class Opener:
        def open(self, request, timeout):
            seen.append(request)
            return Response()

    monkeypatch.setattr(selected_flow, "build_opener", lambda *args: Opener())
    status, payload = selected_flow.request_flow("POST", "/v1/flows/instances", {"organization_id": ORGANIZATION}, COOKIE)
    assert (status, payload) == (200, {"id": "instance-1"})
    assert seen[0].full_url == "https://beta.elevenidllc.com/v1/flows/instances"
    assert seen[0].get_header("Cookie") == COOKIE
    assert seen[0].get_header("X-api-key") is None
    assert json.loads(seen[0].data) == {"organization_id": ORGANIZATION}
    with pytest.raises(SelectedFlowError, match="request is invalid"):
        selected_flow.request_flow("POST", "/v1/flows/instances", {}, "bad\rCookie")
