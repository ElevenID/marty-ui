#!/usr/bin/env python3
"""Create the three owned references required by a disposable passport Flow."""

from __future__ import annotations

from typing import Any, Callable
from uuid import UUID


Request = Callable[[str, str, dict[str, Any] | None, dict[str, str]],
                   tuple[int, dict[str, Any]]]
DISPOSABLE_ORGANIZATION_ID = "00000000-0000-0000-0000-000000000001"
PASSPORT_COMPLIANCE_PROFILE_ID = "10000000-0000-0000-0000-000000000005"


class FlowReferenceError(ValueError):
    pass


def _require(ok: bool, message: str) -> None:
    if not ok:
        raise FlowReferenceError(message)


def _uuid(value: Any) -> str:
    _require(isinstance(value, str), "Disposable reference ID is missing")
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError) as error:
        raise FlowReferenceError("Disposable reference ID is invalid") from error
    _require(str(parsed) == value, "Disposable reference ID is not canonical")
    return value


def _response(
    request: Request, method: str, path: str,
    body: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    *, operation: str, status: int = 200,
) -> dict[str, Any]:
    actual, result = request(method, path, body, headers or {})
    safe_status = actual if type(actual) is int and 100 <= actual <= 599 else "invalid"
    _require(actual == status,
             f"Disposable reference request failed: {operation} HTTP {safe_status} expected {status}")
    _require(isinstance(result, dict),
             f"Disposable reference request failed: {operation} invalid response")
    return result


def _credential_template(
    result: dict[str, Any], organization_id: str, name: str,
    issuer_did: str, status: str, expected_id: str | None = None,
) -> str:
    identifier = _uuid(result.get("id"))
    _require(expected_id is None or identifier == expected_id,
             "Credential template changed identity")
    _require(result.get("organization_id") == organization_id
             and result.get("name") == name
             and result.get("status") == status
             and result.get("credential_type") == "Passport"
             and result.get("credential_payload_format") == "ICAO_EMRTD"
             and result.get("issuance_protocol") == "PHYSICAL_DOCUMENT"
             and result.get("doctype") == "TD3"
             and result.get("revocation_profile_id") is None
             and result.get("issuer_did") == issuer_did,
             "Credential template binding drifted")
    return identifier


def _application_template(
    result: dict[str, Any], organization_id: str, name: str,
    credential_template_id: str, status: str,
    expected_id: str | None = None,
) -> str:
    identifier = _uuid(result.get("id"))
    _require(expected_id is None or identifier == expected_id,
             "Application template changed identity")
    _require(result.get("organization_id") == organization_id
             and result.get("name") == name
             and result.get("status") == status
             and result.get("credential_template_id") == credential_template_id
             and result.get("approval_strategy") == "AUTO",
             "Application template binding drifted")
    return identifier


def _destination(
    result: dict[str, Any], organization_id: str, name: str,
    expected_id: str | None = None,
) -> str:
    identifier = _uuid(result.get("id"))
    _require(expected_id is None or identifier == expected_id,
             "Delivery destination changed identity")
    _require(result.get("organization_id") == organization_id
             and result.get("is_system") is False
             and result.get("name") == name
             and result.get("provider") == "physical_document_bureau"
             and result.get("mode") == "physical_document"
             and result.get("setup_actor") == "system"
             and result.get("delivery_target") == "physical_document"
             and result.get("credential_format") == "ICAO_EMRTD"
             and result.get("issuance_protocol") == "PHYSICAL_DOCUMENT"
             and result.get("is_enabled") is True,
             "Delivery destination binding drifted")
    return identifier


def provision_physical_passport_references(
    request: Request, organization_id: str, name_prefix: str,
    issuer_did: str, idempotency_key: str,
) -> dict[str, str]:
    """Provision and read back owned references; caller destroys the project."""
    _require(organization_id == DISPOSABLE_ORGANIZATION_ID
             and isinstance(name_prefix, str) and name_prefix.strip()
             and isinstance(issuer_did, str) and issuer_did.startswith("did:")
             and isinstance(idempotency_key, str) and idempotency_key.strip(),
             "Disposable reference context is invalid")
    credential_name = f"{name_prefix} credential"
    application_name = f"{name_prefix} application"
    destination_name = f"{name_prefix} bureau"
    credential = _response(request, "POST", "/v1/credential-templates", {
        "organization_id": organization_id,
        "name": credential_name,
        "credential_type": "Passport",
        "doctype": "TD3",
        "claims": [{"name": "document_number", "display_name": "Document Number",
                    "selectively_disclosable": False}],
        "supported_formats": ["ICAO_EMRTD"],
        "credential_payload_format": "ICAO_EMRTD",
        "issuance_protocol": "PHYSICAL_DOCUMENT",
        "compliance_profile_id": PASSPORT_COMPLIANCE_PROFILE_ID,
        "issuer_did": issuer_did,
    }, operation="POST /v1/credential-templates")
    credential_id = _credential_template(
        credential, organization_id, credential_name, issuer_did, "DRAFT",
    )
    credential_path = f"/v1/credential-templates/{credential_id}"
    _credential_template(_response(request, "GET", credential_path,
                                   operation="GET /v1/credential-templates/{id}"),
                         organization_id, credential_name, issuer_did, "DRAFT",
                         credential_id)
    _credential_template(_response(request, "POST", f"{credential_path}/activate",
                                   operation="POST /v1/credential-templates/{id}/activate"),
                         organization_id, credential_name, issuer_did, "ACTIVE",
                         credential_id)
    _credential_template(_response(request, "GET", credential_path,
                                   operation="GET /v1/credential-templates/{id}"),
                         organization_id, credential_name, issuer_did, "ACTIVE",
                         credential_id)

    application = _response(
        request, "POST", "/v1/application-templates", {
            "organization_id": organization_id,
            "name": application_name,
            "credential_template_id": credential_id,
            "approval_strategy": "AUTO",
            "form_fields": [{"field_id": "document_number",
                             "label": "Document number", "field_type": "TEXT",
                             "required": True,
                             "claim_mapping": "document_number"}],
        }, {"idempotency-key": idempotency_key},
        operation="POST /v1/application-templates",
    )
    application_id = _application_template(
        application, organization_id, application_name, credential_id, "DRAFT",
    )
    application_path = f"/v1/application-templates/{application_id}"
    _application_template(_response(request, "GET", application_path,
                                    operation="GET /v1/application-templates/{id}"),
                          organization_id, application_name, credential_id, "DRAFT",
                          application_id)
    validation = _response(request, "POST", f"{application_path}/validate",
                           operation="POST /v1/application-templates/{id}/validate")
    _require(validation.get("valid") is True and validation.get("errors") == [],
             "Application template validation failed")
    _application_template(_response(request, "POST", f"{application_path}/activate",
                                    operation="POST /v1/application-templates/{id}/activate"),
                          organization_id, application_name, credential_id, "ACTIVE",
                          application_id)
    _application_template(_response(request, "GET", application_path,
                                    operation="GET /v1/application-templates/{id}"),
                          organization_id, application_name, credential_id, "ACTIVE",
                          application_id)

    destination = _response(request, "POST", "/v1/delivery-destinations", {
        "organization_id": organization_id,
        "name": destination_name,
        "provider": "physical_document_bureau",
        "mode": "physical_document",
        "setup_actor": "system",
        "delivery_target": "physical_document",
        "credential_format": "ICAO_EMRTD",
        "issuance_protocol": "PHYSICAL_DOCUMENT",
        "is_enabled": True,
    }, operation="POST /v1/delivery-destinations", status=201)
    destination_id = _destination(
        destination, organization_id, destination_name,
    )
    _destination(_response(request, "GET", f"/v1/delivery-destinations/{destination_id}",
                           operation="GET /v1/delivery-destinations/{id}"),
                 organization_id, destination_name, destination_id)
    return {
        "credential_template_id": credential_id,
        "application_template_id": application_id,
        "delivery_destination_profile_id": destination_id,
    }
