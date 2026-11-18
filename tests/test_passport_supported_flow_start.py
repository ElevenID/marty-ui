"""Real Flow start proof must bind persisted tenant, references, and native job."""

from __future__ import annotations

from copy import deepcopy

import pytest

from scripts.passport_supported_flow_start import (
    FlowStartError, STEPS, start_physical_passport_flow,
)


ORG = "00000000-0000-0000-0000-000000000001"
DEFINITION = "d0000000-0000-4000-8000-000000000001"
INSTANCE = "d0000000-0000-4000-8000-000000000002"
APPLICATION = "d0000000-0000-4000-8000-000000000003"
JOB = "d0000000-0000-4000-8000-000000000004"
REFERENCES = {
    "credential_template_id": "credential-1",
    "application_template_id": "application-1",
    "delivery_destination_profile_id": "destination-1",
}
PHYSICAL = {
    "country_code": "USA", "applicant": {"name": "Synthetic"},
    "mrz": {"document_number": "TEST123"},
    "data_groups": {"DG1": "YQ==", "DG2": "Yg=="},
}


def responses() -> list[dict]:
    definition = {
        "id": DEFINITION, "organization_id": ORG, "name": "Disposable passport",
        "flow_type": "physical_document_issuance",
        "resolved_steps": list(STEPS), "status": "DRAFT", **REFERENCES,
    }
    active = {**definition, "status": "ACTIVE"}
    instance = {
        "id": INSTANCE, "organization_id": ORG, "flow_id": DEFINITION,
        "flow_type": "physical_document_issuance", "status": "IN_PROGRESS",
        "current_step": STEPS[0], "current_step_index": 0,
        "context_data": {
            "application_id": APPLICATION,
            "physical_document_job": {
                "id": JOB, "organization_id": ORG,
                "application_id": APPLICATION, "flow_execution_id": INSTANCE,
                "credential_template_id": REFERENCES["credential_template_id"],
                "delivery_destination_profile_id":
                    REFERENCES["delivery_destination_profile_id"],
                "country_code": "USA", "document_type": "TD3",
                "issuer_did": "did:web:issuer.acceptance.invalid",
            },
        },
    }
    return [deepcopy(value) for value in (
        definition, definition, active, active, instance, instance,
        instance["context_data"]["physical_document_job"],
    )]


def test_start_uses_persisted_flow_and_native_same_job_binding() -> None:
    queue = responses()
    calls = []

    def request(method: str, path: str, body: dict | None):
        calls.append((method, path, body))
        return 200, deepcopy(queue.pop(0))

    def native_request(method: str, path: str, body: dict | None):
        calls.append((method, path, body))
        return 200, deepcopy(queue.pop(0))

    proof = start_physical_passport_flow(
        request, ORG, "Disposable passport", REFERENCES, PHYSICAL,
        native_request,
    )
    assert proof == {
        "flow_definition_id": DEFINITION,
        "flow_instance_id": INSTANCE,
        "native_job_id": JOB,
        "application_id": APPLICATION,
    }
    assert not queue
    assert [(method, path) for method, path, _ in calls] == [
        ("POST", "/v1/flows/definitions"),
        ("GET", f"/v1/flows/definitions/{DEFINITION}"),
        ("POST", f"/v1/flows/definitions/{DEFINITION}/activate"),
        ("GET", f"/v1/flows/definitions/{DEFINITION}"),
        ("POST", "/v1/flows/instances"),
        ("GET", f"/v1/flows/instances/{INSTANCE}"),
        ("GET", f"/v1/passport/applications/{APPLICATION}/production-status"),
    ]
    assert calls[0][2]["credential_template_id"] == REFERENCES["credential_template_id"]
    assert calls[4][2]["initial_context"] == {"physical_document": PHYSICAL}
    assert "flow_execution_id" not in calls[4][2]["initial_context"]


@pytest.mark.parametrize("index,mutation", [
    (1, lambda value: value.update({"credential_template_id": "foreign"})),
    (3, lambda value: value.update({"status": "DRAFT"})),
    (4, lambda value: value["context_data"]["physical_document_job"].update(
        {"flow_execution_id": "disposable-producer-synthetic-flow"})),
    (4, lambda value: value["context_data"]["physical_document_job"].update(
        {"organization_id": "foreign"})),
    (4, lambda value: value["context_data"]["physical_document_job"].update(
        {"credential_template_id": "foreign"})),
    (5, lambda value: value["context_data"]["physical_document_job"].update(
        {"id": "d0000000-0000-4000-8000-000000000005"})),
    (5, lambda value: value["context_data"].update(
        {"application_id": "d0000000-0000-4000-8000-000000000004"})),
    (6, lambda value: value.update({"id": "d0000000-0000-4000-8000-000000000005"})),
])
def test_start_rejects_foreign_or_unpersisted_proof(index: int, mutation) -> None:
    queue = responses()
    mutation(queue[index])

    def request(method: str, path: str, body: dict | None):
        return 200, deepcopy(queue.pop(0))

    with pytest.raises(FlowStartError):
        start_physical_passport_flow(
            request, ORG, "Disposable passport", REFERENCES, PHYSICAL,
            request,
        )
