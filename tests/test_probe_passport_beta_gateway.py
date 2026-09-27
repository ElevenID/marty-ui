"""Gate the actual Gateway probe on persisted transitions and stable tenancy."""

from __future__ import annotations

import copy

import pytest

from scripts.probe_passport_beta_gateway import ProbeError, exercise


APPLICATION = {"organization_id": "beta-org", "issuer_did": "did:example:issuer",
               "flow_execution_id": "acceptance-flow", "application_template_id": "test-template",
               "credential_template_id": "test-credential", "delivery_destination_profile_id": "test-destination",
               "country_code": "USA", "applicant": {}, "mrz": {},
               "data_groups": {"DG1": "YQ==", "DG2": "Yg=="}}
KEY = "a" * 32


def gateway(*, wrong_tenant: bool = False, no_quality: bool = False,
            wrong_job: bool = False, missing_sod: bool = False,
            failed_bureau: bool = False):
    calls = []
    states = ["DRAFT", "DATA_GENERATED", "SOD_SIGNED", "SUBMITTED",
              "IN_PRODUCTION" if no_quality else "QUALITY_CHECK", "READY_FOR_ACTIVATION", "ACTIVE"]

    def request(method: str, path: str, body: dict | None, api_key: str) -> tuple[int, dict]:
        calls.append((method, path, body, api_key))
        state = states[min(len(calls) - 1, len(states) - 1)]
        if failed_bureau and len(calls) == 5:
            state = "FAILED"
        payload = {"id": "job-other" if wrong_job and len(calls) > 1 else "job-1",
                   "application_id": "application-1",
                   "organization_id": "foreign-org" if wrong_tenant else "beta-org",
                   "status": state, "bureau_job_id": "bureau-1" if len(calls) >= 4 else None}
        if state == "SOD_SIGNED" and not missing_sod:
            payload["sod_sha256"] = "f" * 64
        if state == "READY_FOR_ACTIVATION":
            payload["quality_result"] = {"passed": True}
        if state == "ACTIVE":
            payload["completed_at"] = "2026-09-27T00:00:00Z"
        return (201 if len(calls) == 1 else 200), payload

    return calls, request


def test_exercises_lifecycle_but_does_not_claim_nine_routes_or_physical_booklet() -> None:
    calls, request = gateway()
    result = exercise(APPLICATION, KEY, request=request, poll_interval_seconds=0)
    assert result["verified"] is True
    assert len(calls) == 7
    assert [call[0] for call in calls] == ["POST", "POST", "POST", "POST", "GET", "POST", "POST"]
    assert calls[0][2] == APPLICATION
    assert calls[5][2] == {"passed": True, "failure_codes": []}
    assert result["evidence"]["sod_sha256"] == "f" * 64
    assert result["evidence"]["routes"][-1]["job_status"] == "ACTIVE"
    assert "physical_booklet_verified" not in result
    assert "nine_route_gateway_flow" not in result
    assert KEY not in str(result)
    assert "data_groups" not in str(result)


def test_rejects_cross_tenant_response_and_never_submits_to_provider() -> None:
    calls, request = gateway(wrong_tenant=True)
    with pytest.raises(ProbeError, match="organization"):
        exercise(APPLICATION, KEY, request=request, poll_interval_seconds=0)
    assert len(calls) == 1


def test_rejects_unfinished_bureau_lifecycle() -> None:
    calls, request = gateway(no_quality=True)
    with pytest.raises(ProbeError, match="before the bound"):
        exercise(APPLICATION, KEY, request=request, max_polls=1, poll_interval_seconds=0)
    assert len(calls) == 5


@pytest.mark.parametrize("defect", ["wrong_job", "missing_sod", "failed_bureau"])
def test_rejects_missing_or_inconsistent_runtime_outcome(defect: str) -> None:
    calls, request = gateway(**{defect: True})
    with pytest.raises(ProbeError):
        exercise(APPLICATION, KEY, request=request, max_polls=1, poll_interval_seconds=0)
    assert len(calls) < 7


def test_rejects_missing_managed_profile_did_before_mutation() -> None:
    calls, request = gateway()
    application = copy.deepcopy(APPLICATION)
    application.pop("issuer_did")
    with pytest.raises(ProbeError, match="managed issuer DID"):
        exercise(application, KEY, request=request)
    assert calls == []
