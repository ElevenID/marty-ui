#!/usr/bin/env python3
"""Start one tenant-bound physical passport Flow through the disposable Gateway."""

from __future__ import annotations

from typing import Any, Callable
from uuid import UUID


STEPS = (
    "accept_application", "validate_evidence", "approval_decision",
    "generate_data_groups", "sign_sod", "submit_to_personalization",
    "track_production", "quality_verify", "activate_credential",
)
REFERENCES = (
    "credential_template_id", "application_template_id",
    "delivery_destination_profile_id",
)
Request = Callable[[str, str, dict[str, Any] | None], tuple[int, dict[str, Any]]]


class FlowStartError(ValueError):
    pass


def _require(ok: bool, message: str) -> None:
    if not ok:
        raise FlowStartError(message)


def _uuid(value: Any) -> str:
    _require(isinstance(value, str), "Flow response ID is missing")
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError) as error:
        raise FlowStartError("Flow response ID is invalid") from error
    _require(str(parsed) == value, "Flow response ID is not canonical")
    return value


def _response(
    request: Request, method: str, path: str, body: dict[str, Any] | None,
) -> dict[str, Any]:
    status, result = request(method, path, body)
    _require(status == 200 and isinstance(result, dict),
             "Disposable Flow request did not succeed")
    return result


def _definition(
    result: dict[str, Any], organization_id: str, name: str,
    references: dict[str, str], status: str, expected_id: str | None = None,
) -> str:
    identifier = _uuid(result.get("id"))
    _require(expected_id is None or identifier == expected_id,
             "Flow definition changed identity")
    _require(result.get("organization_id") == organization_id
             and result.get("name") == name
             and result.get("flow_type") == "physical_document_issuance"
             and result.get("status") == status
             and result.get("resolved_steps") == list(STEPS),
             "Flow definition identity or steps drifted")
    _require(all(result.get(field) == references[field] for field in REFERENCES),
             "Flow definition references drifted")
    return identifier


def _instance(
    result: dict[str, Any], organization_id: str, definition_id: str,
    references: dict[str, str], physical_document: dict[str, Any],
    expected_id: str | None = None, expected_application_id: str | None = None,
    expected_job_id: str | None = None,
) -> tuple[str, str, str]:
    identifier = _uuid(result.get("id"))
    _require(expected_id is None or identifier == expected_id,
             "Flow instance changed identity")
    _require(result.get("organization_id") == organization_id
             and result.get("flow_id") == definition_id
             and result.get("flow_type") == "physical_document_issuance"
             and result.get("status") == "IN_PROGRESS"
             and result.get("current_step") == STEPS[0]
             and result.get("current_step_index") == 0,
             "Flow instance identity or initial step drifted")
    context = result.get("context_data")
    _require(isinstance(context, dict), "Flow instance context is missing")
    job = context.get("physical_document_job")
    _require(isinstance(job, dict), "Native passport job is missing")
    application_id, job_id = _job(
        job, organization_id, identifier, references, physical_document,
        expected_application_id, expected_job_id,
    )
    _require(context.get("application_id") == application_id,
             "Flow context application changed identity")
    return identifier, application_id, job_id


def _job(
    job: dict[str, Any], organization_id: str, instance_id: str,
    references: dict[str, str], physical_document: dict[str, Any],
    expected_application_id: str | None = None,
    expected_job_id: str | None = None,
) -> tuple[str, str]:
    job_id = _uuid(job.get("id"))
    application_id = _uuid(job.get("application_id"))
    _require(job.get("flow_execution_id") == instance_id
             and (expected_application_id is None
                  or application_id == expected_application_id)
             and (expected_job_id is None or job_id == expected_job_id)
             and job.get("organization_id") == organization_id
             and job.get("credential_template_id")
                 == references["credential_template_id"]
             and job.get("delivery_destination_profile_id")
                 == references["delivery_destination_profile_id"]
             and job.get("country_code") == physical_document["country_code"]
             and job.get("document_type")
                 == physical_document.get("document_type", "TD3")
             and isinstance(job.get("issuer_did"), str)
             and job["issuer_did"].startswith("did:"),
             "Native passport job or application changed identity")
    return application_id, job_id


def create_physical_passport_definition(
    request: Request, organization_id: str, name: str,
    references: dict[str, str], *, resume: bool = False,
) -> str:
    """Create and activate the same physical Flow definition used by acceptance."""
    _require(isinstance(organization_id, str) and organization_id.strip()
             and isinstance(name, str) and name.strip(),
             "Flow organization and name are required")
    _require(isinstance(references, dict)
             and all(isinstance(references.get(field), str)
                     and references[field].strip() for field in REFERENCES),
             "Flow references must be present")
    definition_body = {
        "organization_id": organization_id,
        "name": name,
        "flow_type": "physical_document_issuance",
        "approval_strategy": "AUTO",
        **{field: references[field] for field in REFERENCES},
    }
    draft = _response(request, "POST", "/v1/flows/definitions", definition_body)
    definition_status = draft.get("status") if resume else "DRAFT"
    _require(definition_status in ("DRAFT", "ACTIVE"),
             "Flow definition status is invalid")
    definition_id = _definition(draft, organization_id, name, references,
                                definition_status)
    definition_path = f"/v1/flows/definitions/{definition_id}"
    persisted_draft = _response(request, "GET", definition_path, None)
    _definition(persisted_draft, organization_id, name, references, definition_status,
                definition_id)
    if definition_status == "DRAFT":
        active = _response(request, "POST", f"{definition_path}/activate", None)
        _definition(active, organization_id, name, references, "ACTIVE", definition_id)
    persisted_active = _response(request, "GET", definition_path, None)
    _definition(persisted_active, organization_id, name, references, "ACTIVE",
                definition_id)
    return definition_id


def start_physical_passport_flow(
    request: Request, organization_id: str, name: str,
    references: dict[str, str], physical_document: dict[str, Any],
    native_request: Request,
) -> dict[str, str]:
    """Create, activate, start, and read back a real Flow and same-job native ID."""
    _require(isinstance(physical_document, dict)
             and all(physical_document.get(field)
                     for field in ("country_code", "applicant", "mrz", "data_groups")),
             "Flow physical document is incomplete")
    definition_id = create_physical_passport_definition(
        request, organization_id, name, references,
    )
    started = _response(request, "POST", "/v1/flows/instances", {
        "organization_id": organization_id,
        "flow_definition_id": definition_id,
        "subject_type": "applicant",
        "initial_context": {"physical_document": physical_document},
    })
    instance_id, application_id, job_id = _instance(
        started, organization_id, definition_id, references, physical_document,
    )
    persisted = _response(request, "GET", f"/v1/flows/instances/{instance_id}", None)
    _instance(persisted, organization_id, definition_id, references, physical_document,
              instance_id, application_id, job_id)
    native = _response(
        native_request, "GET",
        f"/v1/passport/applications/{application_id}/production-status", None,
    )
    _job(native, organization_id, instance_id, references, physical_document,
         application_id, job_id)
    return {
        "flow_definition_id": definition_id,
        "flow_instance_id": instance_id,
        "native_job_id": job_id,
        "application_id": application_id,
    }
