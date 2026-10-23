"""Disposable Flow references must be active and bound to Marty issuance."""

from __future__ import annotations

from copy import deepcopy

import pytest

from scripts.passport_supported_flow_references import (
    PASSPORT_COMPLIANCE_PROFILE_ID,
    FlowReferenceError,
    provision_beta_physical_passport_references,
    provision_physical_passport_references,
)


ORG = "00000000-0000-0000-0000-000000000001"
ISSUER = "did:web:issuer.acceptance.invalid"
PREFIX = "Disposable passport 123456"
CREDENTIAL = "d0000000-0000-4000-8000-000000000001"
APPLICATION = "d0000000-0000-4000-8000-000000000002"
DESTINATION = "d0000000-0000-4000-8000-000000000003"


def responses() -> list[tuple[int, dict]]:
    credential = {
        "id": CREDENTIAL, "organization_id": ORG,
        "name": PREFIX + " credential", "status": "DRAFT",
        "credential_type": "Passport", "credential_payload_format": "ICAO_EMRTD",
        "issuance_protocol": "PHYSICAL_DOCUMENT", "doctype": "TD3",
        "revocation_profile_id": None,
        "compliance_profile_id": PASSPORT_COMPLIANCE_PROFILE_ID,
        "issuer_did": ISSUER,
    }
    application = {
        "id": APPLICATION, "organization_id": ORG,
        "name": PREFIX + " application", "status": "DRAFT",
        "credential_template_id": CREDENTIAL, "approval_strategy": "AUTO",
    }
    destination = {
        "id": DESTINATION, "organization_id": ORG,
        "is_system": False, "name": PREFIX + " bureau",
        "provider": "physical_document_bureau", "mode": "physical_document",
        "setup_actor": "system", "delivery_target": "physical_document",
        "credential_format": "ICAO_EMRTD",
        "issuance_protocol": "PHYSICAL_DOCUMENT", "is_enabled": True,
    }
    return [(status, deepcopy(value)) for status, value in (
        (200, credential), (200, credential),
        (200, {**credential, "status": "ACTIVE"}),
        (200, {**credential, "status": "ACTIVE"}),
        (200, application), (200, application),
        (200, {"valid": True, "errors": []}),
        (200, {**application, "status": "ACTIVE"}),
        (200, {**application, "status": "ACTIVE"}),
        (201, destination), (200, destination),
    )]


def test_reference_setup_uses_real_activated_tenant_resources() -> None:
    queue = responses()
    calls = []

    def request(method, path, body, headers):
        calls.append((method, path, body, headers))
        return queue.pop(0)

    refs = provision_physical_passport_references(
        request, ORG, PREFIX, ISSUER, "acceptance-123456-template",
    )
    assert refs == {
        "credential_template_id": CREDENTIAL,
        "application_template_id": APPLICATION,
        "delivery_destination_profile_id": DESTINATION,
    }
    assert not queue
    assert calls[0][0:2] == ("POST", "/v1/credential-templates")
    assert calls[0][2]["supported_formats"] == ["ICAO_EMRTD"]
    assert calls[0][2]["issuer_did"] == ISSUER
    assert "revocation_profile_id" not in calls[0][2]
    assert calls[0][2]["compliance_profile_id"] == PASSPORT_COMPLIANCE_PROFILE_ID
    assert calls[4][2]["form_fields"][0]["claim_mapping"] == "document_number"
    assert calls[6][0:2] == ("POST", f"/v1/application-templates/{APPLICATION}/validate")
    assert calls[4][3] == {"idempotency-key": "acceptance-123456-template"}
    assert calls[9][0:2] == ("POST", "/v1/delivery-destinations")
    assert calls[9][2]["provider"] == "physical_document_bureau"


@pytest.mark.parametrize("index,field,value", [
    (1, "issuer_did", "did:web:foreign.invalid"),
    (2, "revocation_profile_id", "foreign"),
    (3, "compliance_profile_id", "foreign"),
    (3, "status", "DRAFT"),
    (5, "credential_template_id", "foreign"),
    (6, "valid", False),
    (8, "organization_id", "foreign"),
    (9, "provider", "external_api"),
    (10, "is_enabled", False),
])
def test_reference_setup_rejects_drift(index: int, field: str, value) -> None:
    queue = responses()
    queue[index][1][field] = value

    def request(method, path, body, headers):
        return queue.pop(0)

    with pytest.raises(FlowReferenceError):
        provision_physical_passport_references(
            request, ORG, PREFIX, ISSUER, "acceptance-123456-template",
        )


def test_reference_setup_rejects_another_organization_before_writes() -> None:
    def request(method, path, body, headers):
        raise AssertionError("no request should be sent")

    with pytest.raises(FlowReferenceError):
        provision_physical_passport_references(
            request, "00000000-0000-0000-0000-000000000002",
            PREFIX, ISSUER, "acceptance-123456-template",
        )


def test_beta_reference_setup_reuses_the_frozen_physical_contract_for_pilot() -> None:
    pilot = "00000000-0000-0000-0000-000000000019"
    queue = responses()
    calls = []

    def request(method, path, body, headers):
        calls.append((method, path, body, headers))
        status, result = queue.pop(0)
        if "organization_id" in result:
            result["organization_id"] = pilot
        return status, result

    refs = provision_beta_physical_passport_references(
        request, pilot, PREFIX, ISSUER, "pilot-key",
        PASSPORT_COMPLIANCE_PROFILE_ID,
    )
    assert refs["credential_template_id"] == CREDENTIAL
    assert calls[0][2]["organization_id"] == pilot
    assert calls[0][2]["compliance_profile_id"] == PASSPORT_COMPLIANCE_PROFILE_ID
    assert not queue


@pytest.mark.parametrize("index,operation,expected", [
    (0, "POST /v1/credential-templates", 200),
    (1, "GET /v1/credential-templates/{id}", 200),
    (2, "POST /v1/credential-templates/{id}/activate", 200),
    (3, "GET /v1/credential-templates/{id}", 200),
    (4, "POST /v1/application-templates", 200),
    (5, "GET /v1/application-templates/{id}", 200),
    (6, "POST /v1/application-templates/{id}/validate", 200),
    (7, "POST /v1/application-templates/{id}/activate", 200),
    (8, "GET /v1/application-templates/{id}", 200),
    (9, "POST /v1/delivery-destinations", 201),
    (10, "GET /v1/delivery-destinations/{id}", 200),
])
def test_reference_failure_identifies_only_fixed_operation_and_http_status(
    index: int, operation: str, expected: int,
) -> None:
    queue = responses()
    queue[index] = (404, {"detail": "sensitive response marker"})
    calls = []

    def request(method, path, body, headers):
        calls.append((method, path))
        return queue.pop(0)

    with pytest.raises(FlowReferenceError) as exc:
        provision_physical_passport_references(
            request, ORG, PREFIX, ISSUER, "sensitive-idempotency-key",
        )
    assert str(exc.value) == (
        f"Disposable reference request failed: {operation} HTTP 404 expected {expected}"
    )
    assert len(calls) == index + 1
    for private in (PREFIX, ORG, ISSUER, CREDENTIAL, APPLICATION,
                    DESTINATION, "sensitive", "idempotency"):
        assert private not in str(exc.value)


def test_reference_failure_rejects_non_object_without_echoing_it() -> None:
    def request(method, path, body, headers):
        return 200, "sensitive response marker"

    with pytest.raises(FlowReferenceError) as exc:
        provision_physical_passport_references(
            request, ORG, PREFIX, ISSUER, "sensitive-idempotency-key",
        )
    assert str(exc.value) == (
        "Disposable reference request failed: "
        "POST /v1/credential-templates invalid response"
    )
