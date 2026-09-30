"""Nine Flow transitions must bind one native job and durable ordered history."""

from copy import deepcopy

import pytest

from scripts.passport_supported_flow_advance import (
    FlowAdvanceError, advance_physical_passport_flow,
)
from scripts.passport_supported_flow_start import STEPS


ORG = "00000000-0000-0000-0000-000000000001"
ISSUER = "did:web:issuer.acceptance.invalid"
IDS = [f"d0000000-0000-4000-8000-{number:012x}" for number in range(1, 19)]
REFERENCES = {
    "credential_template_id": IDS[0],
    "application_template_id": IDS[1],
    "delivery_destination_profile_id": IDS[2],
}
STARTED = {"flow_definition_id": IDS[3], "flow_instance_id": IDS[4],
           "native_job_id": IDS[5], "application_id": IDS[6]}
BUREAU = IDS[7]


class Fixture:
    def __init__(self):
        self.completed = 0
        self.job_status = "DRAFT"
        self.bureau = None
        self.callback = False
        self.history_corrupt = False
        self.requests = []

    def job(self):
        job = {
            "id": STARTED["native_job_id"],
            "application_id": STARTED["application_id"],
            "flow_execution_id": STARTED["flow_instance_id"],
            "organization_id": ORG,
            "credential_template_id": REFERENCES["credential_template_id"],
            "delivery_destination_profile_id": REFERENCES["delivery_destination_profile_id"],
            "country_code": "USA", "document_type": "TD3",
            "issuer_did": ISSUER, "status": self.job_status,
            "bureau_job_id": self.bureau,
        }
        if self.completed >= 5:
            job.update(sod_sha256="a" * 64, sod_signature_verified=True)
        if self.completed >= 8:
            job["quality_result"] = {"passed": True}
        if self.completed >= 9:
            job["completed_at"] = "2026-09-28T18:00:00Z"
        return job

    def instance(self):
        return {
            "id": STARTED["flow_instance_id"],
            "organization_id": ORG,
            "flow_id": STARTED["flow_definition_id"],
            "flow_type": "physical_document_issuance",
            "status": "COMPLETED" if self.completed == 9 else "IN_PROGRESS",
            "current_step": STEPS[min(self.completed, 8)],
            "current_step_index": min(self.completed, 8),
            "context_data": {"application_id": STARTED["application_id"],
                             "physical_document_job": self.job()},
            "step_results": {step: {"result": "success",
                                    "completed_at": "2026-09-28T18:00:00Z"}
                             for step in STEPS[:self.completed]},
        }

    def request(self, method, path, body):
        self.requests.append((method, path, body))
        if method == "GET":
            return 200, deepcopy(self.instance())
        assert method == "POST" and path.endswith("/advance")
        assert body["step_result"] == "success"
        step = STEPS[self.completed]
        if step == "quality_verify":
            assert body["data"] == {"passed": True, "failure_codes": []}
        else:
            assert body["data"] == {}
        self.completed += 1
        if step == "generate_data_groups":
            self.job_status = "DATA_GENERATED"
        elif step == "sign_sod":
            self.job_status = "SOD_SIGNED"
        elif step == "submit_to_personalization":
            self.job_status = "SUBMITTED"
            self.bureau = BUREAU
        elif step == "track_production":
            assert self.callback
        elif step == "quality_verify":
            self.job_status = "READY_FOR_ACTIVATION"
        elif step == "activate_credential":
            self.job_status = "ACTIVE"
        return 200, deepcopy(self.instance())

    def native(self, method, path, body):
        assert (method, path, body) == (
            "GET", f"/v1/passport/applications/{STARTED['application_id']}/production-status",
            None,
        )
        return 200, deepcopy(self.job())

    def private(self, bureau_job_id):
        assert bureau_job_id == BUREAU
        self.callback = True
        self.job_status = "QUALITY_CHECK"
        return 200, {"status": "QUALITY_CHECK", "tracking_number": None,
                     "callback_receipt_sha256": "b" * 64}

    def history(self, instance_id, definition_id):
        assert (instance_id, definition_id) == (
            STARTED["flow_instance_id"], STARTED["flow_definition_id"])
        steps = [{"id": IDS[index + 8], "config": {"protocol_step": step}}
                 for index, step in enumerate(STEPS)]
        entries = [{"step_id": step["id"], "status": "entered",
                    "result": "success", "entered_at": "2026-09-28T17:00:00Z",
                    "completed_at": "2026-09-28T18:00:00Z"}
                   for step in steps]
        if self.history_corrupt:
            entries[4]["step_id"] = IDS[8]
        return {"organization_id": ORG,
                "flow_definition_id": STARTED["flow_definition_id"],
                "status": "completed", "steps": steps, "step_history": entries}


def test_nine_advances_require_same_job_callback_and_durable_history():
    fixture = Fixture()
    proof = advance_physical_passport_flow(
        fixture.request, fixture.native, fixture.private, fixture.history,
        ORG, REFERENCES, STARTED, ISSUER, poll_interval_seconds=0)
    assert proof == {"flow_step_count": 9, "native_effect_count": 6,
                     "durable_history_verified": True,
                     "restart_resume_verified": False,
                     "signed_callback_receipt_sha256": "b" * 64,
                     "bureau_job_id": BUREAU, "sod_sha256": "a" * 64}
    assert [item[0] for item in fixture.requests].count("POST") == 9
    assert fixture.callback is True


def test_missing_signed_callback_stops_before_track():
    fixture = Fixture()

    def missing(bureau_job_id):
        return 200, {"status": "QUALITY_CHECK", "callback_receipt_sha256": None}

    with pytest.raises(FlowAdvanceError, match="signed callback"):
        advance_physical_passport_flow(
            fixture.request, fixture.native, missing, fixture.history,
            ORG, REFERENCES, STARTED, ISSUER, max_polls=1,
            poll_interval_seconds=0)
    assert fixture.completed == 6


def test_corrupt_durable_history_is_rejected():
    fixture = Fixture()
    fixture.history_corrupt = True
    with pytest.raises(FlowAdvanceError, match="out of order"):
        advance_physical_passport_flow(
            fixture.request, fixture.native, fixture.private, fixture.history,
            ORG, REFERENCES, STARTED, ISSUER, poll_interval_seconds=0)


def test_foreign_native_job_is_rejected_before_advance():
    fixture = Fixture()

    def native(method, path, body):
        status, job = fixture.native(method, path, body)
        job["organization_id"] = IDS[15]
        return status, job

    with pytest.raises(ValueError, match="changed identity"):
        advance_physical_passport_flow(
            fixture.request, native, fixture.private, fixture.history,
            ORG, REFERENCES, STARTED, ISSUER, poll_interval_seconds=0)
    assert fixture.completed == 0


def test_restart_resumes_same_persisted_flow_and_native_job():
    fixture = Fixture()
    restarts = []

    def restart():
        assert fixture.completed == 5
        restarts.append(fixture.completed)
        return True

    proof = advance_physical_passport_flow(
        fixture.request, fixture.native, fixture.private, fixture.history,
        ORG, REFERENCES, STARTED, ISSUER, poll_interval_seconds=0,
        restart=restart)
    assert restarts == [5]
    assert fixture.completed == 9
    assert proof["restart_resume_verified"] is True


def test_restart_checkpoint_drift_stops_before_bureau_submission():
    fixture = Fixture()
    original_request = fixture.request
    restarted = False

    def request(method, path, body):
        status, value = original_request(method, path, body)
        if restarted and method == "GET" and fixture.completed == 5:
            value["step_results"].pop("sign_sod")
        return status, value

    def restart():
        nonlocal restarted
        restarted = True
        return True

    with pytest.raises(FlowAdvanceError, match="step results drifted"):
        advance_physical_passport_flow(
            request, fixture.native, fixture.private, fixture.history,
            ORG, REFERENCES, STARTED, ISSUER, poll_interval_seconds=0,
            restart=restart)
    assert fixture.completed == 5


def test_native_batch_runs_after_restart_and_binds_flow_submission():
    fixture = Fixture()
    calls = []

    def restart():
        calls.append("restart")
        assert fixture.completed == 5
        return True

    def before_submit(started, sod_sha256):
        calls.append("batch")
        assert fixture.completed == 5
        assert started == STARTED and sod_sha256 == "a" * 64
        return BUREAU

    proof = advance_physical_passport_flow(
        fixture.request, fixture.native, fixture.private, fixture.history,
        ORG, REFERENCES, STARTED, ISSUER, poll_interval_seconds=0,
        restart=restart, before_submit=before_submit)
    assert calls == ["restart", "batch"]
    assert proof["bureau_job_id"] == BUREAU


def test_native_batch_bureau_identity_must_match_flow_submission():
    fixture = Fixture()
    with pytest.raises(FlowAdvanceError, match="submission changed job"):
        advance_physical_passport_flow(
            fixture.request, fixture.native, fixture.private, fixture.history,
            ORG, REFERENCES, STARTED, ISSUER, poll_interval_seconds=0,
            before_submit=lambda started, sod: IDS[8])
    assert fixture.completed == 6


@pytest.mark.parametrize("field,value", [
    ("sod_sha256", "c" * 64),
    ("sod_signature_verified", False),
])
def test_native_batch_submission_keeps_signed_sod_material(field, value):
    fixture = Fixture()

    def native(method, path, body):
        status, job = fixture.native(method, path, body)
        if fixture.completed == 6:
            job[field] = value
        return status, job

    with pytest.raises(FlowAdvanceError, match="submission changed job"):
        advance_physical_passport_flow(
            fixture.request, native, fixture.private, fixture.history,
            ORG, REFERENCES, STARTED, ISSUER, poll_interval_seconds=0,
            before_submit=lambda started, sod: BUREAU)
    assert fixture.completed == 6
