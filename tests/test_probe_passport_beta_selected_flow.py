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
CONTAINER = "a" * 12
CALLBACK_RECEIPT = "7" * 64


def model(*, wrong_definition: bool = False, wrong_issuer: bool = False,
          wrong_submitted_sod: bool = False, wrong_final_steps: bool = False,
          failed_native_status: bool = False, missing_callback_receipt: bool = False,
          wrong_native_identity: bool = False, wrong_terminal_identity: bool = False,
          wrong_terminal_status: bool = False, wrong_persisted_read: bool = False,
          wrong_tracking: bool = False, regressed_private_status: bool = False):
    calls = []
    finished = []
    last_projection = None
    private_polls = 0

    def flow_request(method: str, path: str, body: dict | None, cookie: str) -> tuple[int, dict]:
        nonlocal last_projection
        calls.append((method, path, body, cookie))
        assert cookie == COOKIE
        if method == "GET" and path.startswith("/v1/flows/definitions/"):
            return 200, {"id": DEFINITION, "organization_id": "foreign-org" if wrong_definition else ORGANIZATION,
                         "flow_type": "physical_document_issuance", "status": "ACTIVE",
                         "resolved_steps": list(PHYSICAL_STEPS), **REFERENCES}
        if method == "GET":
            assert path == "/v1/flows/instances/instance-1" and last_projection is not None
            persisted = copy.deepcopy(last_projection)
            if wrong_persisted_read:
                persisted["status"] = "COMPLETED"
            return 200, persisted
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
        last_projection = copy.deepcopy(payload)
        return 200, payload

    def native_request(method: str, path: str, body: dict | None, key: str) -> tuple[int, dict]:
        calls.append((method, path, body, key))
        assert key == KEY
        terminal = len(finished) == len(PHYSICAL_STEPS)
        return 200, {"organization_id": ORGANIZATION, "application_id": "app-1",
                     "id": "wrong-job" if (wrong_terminal_identity if terminal else wrong_native_identity)
                     else "job-1", "bureau_job_id": BUREAU,
                     "flow_execution_id": "instance-1", "issuer_did": ISSUER,
                     "tracking_number": "BETA-SIM-" + BUREAU.replace("-", ""),
                     "status": ("QUALITY_CHECK" if wrong_terminal_status else "ACTIVE") if terminal
                     else ("FAILED" if failed_native_status else "QUALITY_CHECK"),
                     "completed_at": "2026-09-28T00:00:00Z" if terminal else None}

    def simulator_request(container_id: str, method: str, path: str) -> tuple[int, bytes, dict]:
        nonlocal private_polls
        calls.append(("simulator", container_id, method, path))
        assert container_id == CONTAINER and method == "GET"
        assert path == "/v1/personalization/jobs/" + BUREAU
        private_polls += 1
        state = ("PRINTING" if private_polls == 1 else "QUEUED") if regressed_private_status else "SHIPPED"
        return 200, b"", {"status": state,
                          "tracking_number": "wrong" if wrong_tracking else "BETA-SIM-" + BUREAU.replace("-", ""),
                          "callback_receipt_sha256": None if missing_callback_receipt else CALLBACK_RECEIPT}

    def receipt(org: str, source: str, bureau: str, sod: str) -> dict:
        calls.append(("receipt", org, source, bureau, sod))
        return {"verified": True, "evidence": {
            "tenant_and_job_binding": True,
            "first_accepted_sod_der_matches_native": True,
            "first_accepted_dsc_der_matches_selected_chain": True,
            "first_accepted_dsc_pem_wire_matches_selected_chain": True,
            "source_job_id_commitment": "a" * 64,
            "bureau_job_id_commitment": "b" * 64}}

    return calls, flow_request, native_request, simulator_request, receipt


def probe(flow_request, native_request, simulator_request, receipt, *, max_polls: int = 90):
    return exercise(DEFINITION, ORGANIZATION, ISSUER, REFERENCES, PHYSICAL, COOKIE, KEY,
                    simulator_container_id=CONTAINER, on_submission=receipt, request=flow_request,
                    passport_request=native_request, simulator_request=simulator_request,
                    max_polls=max_polls, poll_interval_seconds=0)


def test_selected_flow_completes_nine_steps_on_one_receipt_bound_job() -> None:
    calls, flow_request, native_request, simulator_request, receipt = model()
    result = probe(flow_request, native_request, simulator_request, receipt)
    evidence = result["evidence"]
    assert result["verified"] is True
    assert evidence["completed_steps"] == 9
    assert evidence["ordered_steps"] == list(PHYSICAL_STEPS)
    assert (evidence["flow_instance_id"], evidence["job_id"], evidence["bureau_job_id"]) == (
        "instance-1", "job-1", BUREAU)
    assert evidence["sod_sha256"] == SOD
    assert evidence["source_job_commitment"] == "a" * 64
    assert evidence["callback_receipt_sha256"] == CALLBACK_RECEIPT
    assert evidence["terminal_native_status"] == "ACTIVE"
    assert evidence["signed_simulator_callback_verified"] is True
    assert "flow_owner" not in evidence
    assert [call[0] for call in calls].count("POST") == 10
    assert calls[0][0:2] == ("GET", f"/v1/flows/definitions/{DEFINITION}")
    assert ("GET", "/v1/passport/applications/app-1/production-status") in [call[:2] for call in calls]
    assert ("receipt", ORGANIZATION, "job-1", BUREAU, SOD) in calls
    assert [call[:2] for call in calls].count(("GET", "/v1/flows/instances/instance-1")) == 10
    assert ("simulator", CONTAINER, "GET", "/v1/personalization/jobs/" + BUREAU) in calls
    assert all(private not in str(result) for private in ("Synthetic", "P<UTO", "123456789", COOKIE, KEY))


def test_native_batch_is_inserted_after_durable_signed_sod_before_flow_submit() -> None:
    calls, flow_request, native_request, simulator_request, receipt = model()

    def native_batch(instance: str, application: str, source: str, sod: str) -> str:
        assert (instance, application, source, sod) == (
            "instance-1", "app-1", "job-1", SOD)
        calls.append(("native-batch", source))
        return BUREAU

    result = exercise(
        DEFINITION, ORGANIZATION, ISSUER, REFERENCES, PHYSICAL, COOKIE, KEY,
        simulator_container_id=CONTAINER, on_submission=receipt,
        on_signed_sod=native_batch, request=flow_request,
        passport_request=native_request, simulator_request=simulator_request,
        poll_interval_seconds=0,
    )
    assert result["verified"] is True
    batch_index = calls.index(("native-batch", "job-1"))
    assert calls[batch_index - 1][:2] == ("GET", "/v1/flows/instances/instance-1")
    assert calls[batch_index + 1][:2] == ("GET", "/v1/flows/instances/instance-1")
    assert all(call[0] != "native-batch" for call in calls[batch_index + 1:])


def test_native_batch_selected_bureau_mismatch_stops_flow() -> None:
    calls, flow_request, native_request, simulator_request, receipt = model()
    with pytest.raises(SelectedFlowError, match="submitted different"):
        exercise(
            DEFINITION, ORGANIZATION, ISSUER, REFERENCES, PHYSICAL, COOKIE, KEY,
            simulator_container_id=CONTAINER, on_submission=receipt,
            on_signed_sod=lambda *args: "b49974d5-af27-49ad-99a3-c433af3c3cb0",
            request=flow_request, passport_request=native_request,
            simulator_request=simulator_request, poll_interval_seconds=0,
        )
    assert ("receipt", ORGANIZATION, "job-1", BUREAU, SOD) not in calls


@pytest.mark.parametrize("defect", ["wrong_definition", "wrong_issuer", "wrong_submitted_sod",
                                     "wrong_final_steps", "failed_native_status",
                                     "missing_callback_receipt", "wrong_native_identity",
                                     "wrong_terminal_identity", "wrong_terminal_status",
                                     "wrong_persisted_read", "wrong_tracking",
                                     "regressed_private_status"])
def test_selected_flow_rejects_false_job_or_step_proof(defect: str) -> None:
    calls, flow_request, native_request, simulator_request, receipt = model(**{defect: True})
    with pytest.raises(SelectedFlowError):
        probe(flow_request, native_request, simulator_request, receipt,
              max_polls=2 if defect == "regressed_private_status" else 90)
    if defect == "wrong_definition":
        assert len(calls) == 1


def test_selected_flow_rejects_missing_private_material_receipt() -> None:
    _, flow_request, native_request, simulator_request, receipt = model()

    def missing(*args):
        result = copy.deepcopy(receipt(*args))
        result["evidence"]["first_accepted_dsc_der_matches_selected_chain"] = False
        return result

    with pytest.raises(SelectedFlowError, match="receipt is unverified"):
        probe(flow_request, native_request, simulator_request, missing)


def test_selected_flow_requires_governed_inputs_before_start() -> None:
    calls, flow_request, native_request, simulator_request, receipt = model()
    with pytest.raises(SelectedFlowError, match="inputs are incomplete"):
        exercise(DEFINITION, ORGANIZATION, ISSUER, REFERENCES, PHYSICAL, "bad\nCookie", KEY,
                 simulator_container_id=CONTAINER, on_submission=receipt, request=flow_request,
                 passport_request=native_request, simulator_request=simulator_request)
    assert calls == []


def test_selected_flow_rejects_profile_override_in_document_payload() -> None:
    calls, flow_request, native_request, simulator_request, receipt = model()
    physical = {**PHYSICAL, "issuer_did": "did:example:override"}
    with pytest.raises(SelectedFlowError, match="inputs are incomplete"):
        exercise(DEFINITION, ORGANIZATION, ISSUER, REFERENCES, physical, COOKIE, KEY,
                 simulator_container_id=CONTAINER, on_submission=receipt, request=flow_request,
                 passport_request=native_request, simulator_request=simulator_request)
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

    handlers = []

    def opener(*args):
        handlers.extend(args)
        return Opener()

    monkeypatch.setattr(selected_flow, "build_opener", opener)
    status, payload = selected_flow.request_flow("POST", "/v1/flows/instances", {"organization_id": ORGANIZATION}, COOKIE)
    assert (status, payload) == (200, {"id": "instance-1"})
    assert seen[0].full_url == "https://beta.elevenidllc.com/v1/flows/instances"
    assert seen[0].get_header("Cookie") == COOKIE
    assert seen[0].get_header("X-api-key") is None
    assert json.loads(seen[0].data) == {"organization_id": ORGANIZATION}
    assert any(isinstance(handler, selected_flow.ProxyHandler)
               and handler.proxies == {} for handler in handlers)
    with pytest.raises(SelectedFlowError, match="request is invalid"):
        selected_flow.request_flow("POST", "/v1/flows/instances", {}, "bad\rCookie")
