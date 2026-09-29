"""The same simulator job must carry the signed callback route evidence."""

from copy import deepcopy
import json
from pathlib import Path
import uuid

import pytest

from scripts.probe_passport_supported_routes import (
    SupportedRouteProbeError, exercise,
)


APPLICATION = {
    "organization_id": "disposable-org", "issuer_did": "did:web:localhost%3A29877:orgs:marty",
    "flow_execution_id": "synthetic-flow", "application_template_id": "template",
    "credential_template_id": "credential", "delivery_destination_profile_id": "destination",
    "country_code": "USA", "applicant": {}, "mrz": {},
    "data_groups": {"DG1": "YQ==", "DG2": "Yg=="},
}
KEY = "a" * 64
BUREAU_ID = "be6bccf4-51eb-4985-a079-6424bf5c5685"


def responses(*, wrong_job: bool = False, denied_status: int = 422,
              capability: bool = True):
    calls = []
    states = iter(("DRAFT", "DATA_GENERATED", "SOD_SIGNED", "SUBMITTED",
                   "QUALITY_CHECK", "READY_FOR_ACTIVATION", "ACTIVE"))

    def request(method: str, path: str, body: dict | None, key: str):
        calls.append((method, path, body, key))
        if path == "/v1/passport/capabilities":
            return 200, {"supported": capability, "blockers": [],
                         "bureau_configured": True, "encrypted_artifact_store": True,
                         "signer": {"mode": "MANAGED_ISSUER_PROFILE"}}
        if path == "/v1/passport/webhooks/personalization":
            return denied_status, {}
        state = next(states)
        job = BUREAU_ID if state in ("SUBMITTED", "QUALITY_CHECK",
                                      "READY_FOR_ACTIVATION", "ACTIVE") else None
        if wrong_job and state == "QUALITY_CHECK":
            job = str(uuid.uuid4())
        payload = {"id": "job-1", "application_id": "application-1",
                   "organization_id": "disposable-org", "status": state,
                   "bureau_job_id": job}
        if state == "SOD_SIGNED":
            payload.update(sod_sha256="f" * 64, sod_signature_verified=True)
        if state == "SUBMITTED":
            payload["sod_sha256"] = "f" * 64
        if state == "READY_FOR_ACTIVATION":
            payload["quality_result"] = {"passed": True}
        if state == "ACTIVE":
            payload["completed_at"] = "2026-09-28T00:00:00Z"
        return (201 if state == "DRAFT" else 200), payload

    return calls, request


def poll(bureau_id: str):
    assert bureau_id == BUREAU_ID
    return 200, {"status": "QUALITY_CHECK", "tracking_number": None,
                 "callback_receipt_sha256": "b" * 64}


def test_frozen_routes_and_same_job_signed_receipt_are_sanitized() -> None:
    calls, request = responses()
    report = exercise(APPLICATION, KEY, request=request, private_poll=poll,
                      callback_via_gateway=True,
                      poll_interval_seconds=0)
    routes = report["evidence"]["routes"]
    contract = json.loads((Path(__file__).resolve().parents[1]
                           / "contracts/passport-supported-consumer-routing.json").read_text())
    assert {(entry["method"], entry["route"]) for entry in routes} == {
        (entry["method"], entry["path"]) for entry in contract["routes"]}
    assert contract["software_route_acceptance"]["callback_result"] == (
        "gateway_routed_native_accepted_signed_receipt_for_same_bureau_job")
    assert len(routes) == 9
    assert report["verified"] is True
    assert report["flow_execution_verified"] is False
    assert report["evidence"]["callback_receipt_sha256"] == "b" * 64
    assert report["evidence"]["signed_callback_path"] == "simulator-to-gateway-to-native"
    assert report["evidence"]["signed_gateway_callback_verified"] is True
    assert routes[-1]["positive_gateway_path_verified"] is True
    assert report["evidence"]["physical_claim"] == "not_claimed"
    serialized = json.dumps(report)
    assert BUREAU_ID not in serialized and KEY not in serialized
    assert "data_groups" not in serialized and "mrz" not in serialized
    assert calls[-1][:2] == ("POST", "/v1/passport/webhooks/personalization")
    assert calls[-1][3] == ""


@pytest.mark.parametrize("defect", ["wrong_job", "missing_receipt", "foreign_tracking",
                                      "unsigned_accepted", "unsigned_authenticated",
                                      "capability", "gateway_not_selected"])
def test_rejects_broken_route_or_callback_evidence(defect: str) -> None:
    calls, request = responses(
        wrong_job=defect == "wrong_job",
        denied_status=(200 if defect == "unsigned_accepted" else
                       401 if defect == "unsigned_authenticated" else 422),
        capability=defect != "capability",
    )
    def private(bureau_id: str):
        status, body = poll(bureau_id)
        body = deepcopy(body)
        if defect == "missing_receipt":
            body["callback_receipt_sha256"] = None
        if defect == "foreign_tracking":
            body["status"] = "SHIPPED"
            body["tracking_number"] = "BETA-SIM-other"
        return status, body

    with pytest.raises(SupportedRouteProbeError):
        exercise(APPLICATION, KEY, request=request, private_poll=private,
                 callback_via_gateway=defect != "gateway_not_selected",
                 poll_interval_seconds=0)
    assert calls
