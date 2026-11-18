"""The physical Flow probe proves execution without claiming callback origin."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from scripts.probe_passport_beta_flow import PHYSICAL_STEPS
from scripts import probe_passport_beta_physical_flow as probe
from scripts.probe_passport_beta_physical_flow import (
    PhysicalFlowProbeError, exercise as live_exercise, validate_plan,
)

CONTAINER = "a" * 12
BUREAU = "00000000-0000-0000-0000-000000000001"


def test_flow_http_request_uses_direct_beta_origin(monkeypatch) -> None:
    handlers = []
    requests = []

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def geturl(self):
            return requests[0].full_url

        def read(self, amount):
            return b'{"id":"flow-1"}'

    class Opener:
        def open(self, request, timeout):
            requests.append(request)
            return Response()

    def opener(*args):
        handlers.extend(args)
        return Opener()

    monkeypatch.setattr(probe, "build_opener", opener)
    assert probe.request_beta("GET", "/v1/flows/instances/flow-1", None, "sessionId=operator") == (
        200, {"id": "flow-1"},
    )
    assert requests[0].full_url == "https://beta.elevenidllc.com/v1/flows/instances/flow-1"
    assert any(isinstance(handler, probe.ProxyHandler)
               and handler.proxies == {} for handler in handlers)


def simulator_request(container: str, method: str, path: str) -> tuple[int, bytes, dict]:
    assert container == CONTAINER and method == "GET"
    assert path == "/v1/personalization/jobs/" + BUREAU
    return 200, b"", {"status": "SHIPPED", "tracking_number": "BETA-SIM-" + "0" * 31 + "1",
                      "callback_receipt_sha256": "e" * 64}


def exercise(plan, release, deployment, session, api_key, **kwargs):
    original_status = kwargs.pop("status_request", ready_status)
    calls = 0

    def status(*args):
        nonlocal calls
        calls += 1
        code, payload = original_status(*args)
        if (original_status is ready_status and calls > 1 and code == 200
                and payload.get("flow_execution_id") == "instance-1"):
            payload = {**payload, "status": "ACTIVE", "completed_at": "2026-09-28T00:00:00Z"}
        return code, payload

    return live_exercise(plan, release, deployment, CONTAINER, session, api_key,
                         status_request=status, simulator_request=simulator_request, **kwargs)


def inputs() -> tuple[dict, dict, dict]:
    source = "a" * 40
    manifest = "b" * 64
    plan = {"source_commit": source, "stack_manifest_sha256": manifest,
            "organization_id": "org-beta", "flow_definition_id": "flow-physical",
            "issuer_did": "did:example:issuer",
            "physical_document": {"country_code": "USA", "applicant": {"name": "Test"},
                                  "mrz": {"line_1": "P<USA"},
                                  "data_groups": {"DG1": "MQ==", "DG2": "Mg=="}}}
    release = {"source_commit": source, "stack_manifest_sha256": manifest,
               "signed_manifest_verified": True}
    deployment = {"provider_mode": "simulator"}
    return plan, release, deployment


class FakeFlow:
    def __init__(self, *, wrong_step: bool = False, stale_job: bool = False,
                 late_bureau: bool = False) -> None:
        self.calls: list[tuple[str, str]] = []
        self.index = 0
        self.reference = ""
        self.wrong_step = wrong_step
        self.stale_job = stale_job
        self.late_bureau = late_bureau

    def payload(self) -> dict:
        step = PHYSICAL_STEPS[min(self.index, len(PHYSICAL_STEPS) - 1)]
        if self.wrong_step and self.index == 2:
            step = "issue_credential"
        return {"id": "instance-1", "organization_id": "org-beta", "flow_id": "flow-physical",
                "flow_type": "physical_document_issuance", "current_step": step,
                "status": "COMPLETED" if self.index == len(PHYSICAL_STEPS) else "IN_PROGRESS",
                "metadata": {"external_reference": self.reference},
                "context_data": {"physical_document_job": {"application_id": "application-1",
                                                          "organization_id": "org-beta",
                                                          "flow_execution_id": "instance-1",
                                                          "issuer_did": "did:example:issuer",
                                                          "sod_sha256": "f" * 64,
                                                          "sod_signature_verified": True,
                                                          "id": "job-1", "bureau_job_id": (
                                                              None if self.late_bureau and self.index < 6
                                                              else BUREAU),
                    "status": "SUBMITTED" if self.stale_job else "QUALITY_CHECK"}}}

    def __call__(self, method: str, path: str, body: dict | None, session: str) -> tuple[int, dict]:
        assert session == "operator-session"
        self.calls.append((method, path))
        if path == "/v1/flows/instances":
            assert method == "POST" and body is not None
            assert body["flow_definition_id"] == "flow-physical"
            assert body["initial_context"]["physical_document"]["country_code"] == "USA"
            self.reference = body["external_reference"]
            return 200, self.payload()
        assert path.startswith("/v1/flows/instances/instance-1")
        if method == "POST":
            assert body is not None and body["step_result"] == "success"
            if self.index == 7:
                assert body["data"] == {"passed": True, "failure_codes": []}
            self.index += 1
        return 200, self.payload()


def test_executed_flow_binds_managed_sod_and_simulator_receipt() -> None:
    contract = json.loads((Path(__file__).resolve().parents[1] / "contracts/flow-service-behavior.json").read_text())
    assert list(PHYSICAL_STEPS) == contract["flow_types"]["physical_document_issuance"]["steps"]
    physical_contract = json.loads((Path(__file__).resolve().parents[1] / "contracts/issuance-physical-passport-native.json").read_text())
    assert set(physical_contract["application_validation_base_input"]["data_groups"]) == {"DG1", "DG2"}
    plan, release, deployment = inputs()
    fake = FakeFlow()
    result = exercise(plan, release, deployment, "operator-session", "k" * 32,
                      request=fake, status_request=ready_status, nonce=lambda: "c" * 32,
                      source_checker=lambda source: source == "a" * 40 or pytest.fail("source drift"))
    assert result["verified"] is True
    assert result["evidence"]["steps"] == list(PHYSICAL_STEPS)
    assert result["evidence"]["source_commit"] == release["source_commit"]
    assert result["evidence"]["signed_simulator_callback_verified"] is True
    assert result["evidence"]["callback_receipt_sha256"] == "e" * 64
    assert result["evidence"]["sod_signature_verified"] is True
    assert result["evidence"]["execution_relationship"] == "not_compared_to_gateway_lifecycle"
    for field in ("application_id_sha256", "job_id_sha256", "bureau_job_id_sha256"):
        assert len(result["evidence"][field]) == 64
    assert result["evidence"]["terminal_native_status"] == "ACTIVE"
    assert len(fake.calls) == 2 + 2 * len(PHYSICAL_STEPS)
    assert "operator-session" not in str(result)
    assert "Test" not in str(result)


def test_bureau_job_can_bind_when_submission_completes() -> None:
    plan, release, deployment = inputs()
    result = exercise(plan, release, deployment, "operator-session", "k" * 32,
                      request=FakeFlow(late_bureau=True), status_request=ready_status,
                      nonce=lambda: "c" * 32, source_checker=lambda source: None)
    assert result["verified"] is True
    assert len(result["evidence"]["bureau_job_id_sha256"]) == 64


@pytest.mark.parametrize("field,value", [
    ("source_commit", "d" * 40), ("stack_manifest_sha256", "d" * 64),
])
def test_source_drift_fails_before_any_request(field: str, value: str) -> None:
    plan, release, deployment = inputs()
    plan[field] = value
    with pytest.raises(PhysicalFlowProbeError, match="signed simulator release"):
        exercise(plan, release, deployment, "operator-session",
                 "k" * 32, request=lambda *args: pytest.fail("no request before source binding"))


def test_unsigned_or_physical_provider_release_fails_before_mutation() -> None:
    plan, release, deployment = inputs()
    for changed_release, changed_deployment in [
        ({**release, "signed_manifest_verified": False}, deployment),
        (release, {"provider_mode": "physical"}),
    ]:
        with pytest.raises(PhysicalFlowProbeError, match="signed simulator release"):
            validate_plan(plan, changed_release, changed_deployment)


@pytest.mark.parametrize("field", ["applicant", "mrz"])
def test_empty_required_document_objects_fail_before_mutation(field: str) -> None:
    plan, release, deployment = inputs()
    plan["physical_document"][field] = {}
    with pytest.raises(PhysicalFlowProbeError, match="inputs are incomplete"):
        exercise(plan, release, deployment, "operator-session", "k" * 32,
                 request=lambda *args: pytest.fail("invalid plan must not mutate beta"))


@pytest.mark.parametrize("fake", [FakeFlow(wrong_step=True), FakeFlow(stale_job=True)])
def test_wrong_step_or_unready_provider_state_fails_closed(fake: FakeFlow) -> None:
    plan, release, deployment = inputs()
    with pytest.raises(PhysicalFlowProbeError):
        exercise(copy.deepcopy(plan), release, deployment, "operator-session",
                 "k" * 32, request=fake, status_request=ready_status, nonce=lambda: "c" * 32,
                 source_checker=lambda source: None)


def ready_status(method: str, path: str, body: dict | None, api_key: str) -> tuple[int, dict]:
    assert method == "GET" and path == "/v1/passport/applications/application-1/production-status"
    assert body is None and api_key == "k" * 32
    return 200, {"organization_id": "org-beta", "application_id": "application-1",
                 "flow_execution_id": "instance-1", "id": "job-1",
                 "bureau_job_id": BUREAU, "issuer_did": "did:example:issuer",
                 "tracking_number": "BETA-SIM-" + "0" * 31 + "1",
                 "status": "QUALITY_CHECK"}


@pytest.mark.parametrize("head,status", [("f" * 40, ""), ("a" * 40, " M scripts/probe.py")])
def test_checkout_drift_blocks_before_any_flow_call(monkeypatch, head: str, status: str) -> None:
    class Completed:
        def __init__(self, stdout: str) -> None:
            self.stdout = stdout

    def git(command, **kwargs):
        return Completed(head if "rev-parse" in command else status)

    monkeypatch.setattr(probe.subprocess, "run", git)
    plan, release, deployment = inputs()
    with pytest.raises(PhysicalFlowProbeError, match="checkout drifted"):
        exercise(plan, release, deployment, "operator-session", "k" * 32,
                 request=lambda *args: pytest.fail("checkout drift must precede mutation"))


def test_foreign_provider_job_cannot_qualify_callback_progress() -> None:
    plan, release, deployment = inputs()
    fake = FakeFlow()

    def foreign(*args):
        status, body = ready_status(*args)
        body["flow_execution_id"] = "foreign-instance"
        return status, body

    with pytest.raises(PhysicalFlowProbeError, match="identity drifted"):
        exercise(plan, release, deployment, "operator-session", "k" * 32,
                 request=fake, status_request=foreign, nonce=lambda: "c" * 32,
                 source_checker=lambda source: None)


def test_different_bureau_job_cannot_qualify_callback_progress() -> None:
    plan, release, deployment = inputs()
    fake = FakeFlow()

    def wrong_bureau(*args):
        status, body = ready_status(*args)
        body["bureau_job_id"] = "bureau-foreign"
        return status, body

    with pytest.raises(PhysicalFlowProbeError, match="identity drifted"):
        exercise(plan, release, deployment, "operator-session", "k" * 32,
                 request=fake, status_request=wrong_bureau, nonce=lambda: "c" * 32,
                 source_checker=lambda source: None)


@pytest.mark.parametrize("drift_index", [1, 4, 6, 7, 8, 9])
@pytest.mark.parametrize("field", ["application_id", "id", "bureau_job_id"])
def test_durable_job_binding_survives_quality_activation_and_final_read(
    drift_index: int, field: str,
) -> None:
    plan, release, deployment = inputs()
    fake = FakeFlow()

    def swapped(method: str, path: str, body: dict | None, session: str) -> tuple[int, dict]:
        status, payload = fake(method, path, body, session)
        if fake.index >= drift_index:
            payload["context_data"]["physical_document_job"][field] = "foreign-job"
        return status, payload

    with pytest.raises(PhysicalFlowProbeError, match="durable job identity drifted"):
        exercise(plan, release, deployment, "operator-session", "k" * 32,
                 request=swapped, status_request=ready_status, nonce=lambda: "c" * 32,
                 source_checker=lambda source: None)


def test_missing_callback_times_out_without_advancing_track_step() -> None:
    plan, release, deployment = inputs()
    fake = FakeFlow()

    def pending(*args):
        status, body = ready_status(*args)
        body["status"] = "SUBMITTED"
        return status, body

    with pytest.raises(PhysicalFlowProbeError, match="did not reach quality check"):
        exercise(plan, release, deployment, "operator-session", "k" * 32,
                 request=fake, status_request=pending, nonce=lambda: "c" * 32,
                 source_checker=lambda source: None, max_polls=2,
                 poll_interval_seconds=0, sleep=lambda seconds: None)
    assert fake.index == PHYSICAL_STEPS.index("track_production")
