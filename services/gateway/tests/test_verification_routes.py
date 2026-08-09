"""Presentation-policy gateway authority-boundary tests."""

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import Response
from pydantic import ValidationError

from gateway.models import (
    EvaluateInlineRequest,
    PresentationPolicyCreate,
    PresentationPolicyUpdate,
)
from gateway.routes import verification


class JsonRequest:
    def __init__(self, payload: dict) -> None:
        self.payload = payload

    async def json(self) -> dict:
        return self.payload


def _policy_payload() -> dict:
    return {
        "organization_id": "org-1",
        "name": "Verify DTC",
        "credential_requirements": [
            {
                "credential_template_id": "template-dtc",
                "display_name": "Digital Travel Credential",
                "credential_payload_format": "caller-controlled-wrong-format",
                "requested_claims": [
                    {
                        "claim_name": "document_number",
                        "display_name": "Document Number",
                        "required": True,
                    }
                ],
            }
        ],
    }


def _inline_payload() -> dict:
    return {
        "organization_id": "org-1",
        "vp_token": "header.payload.signature",
        "credential_requirements": [
            {
                "credential_template_id": "template-vc",
                "credential_payload_format": "jwt_vc_json",
                "requested_claims": [{"claim_name": "name"}],
            }
        ],
    }


def test_inline_evaluation_requires_organization_scope() -> None:
    payload = _inline_payload()
    payload.pop("organization_id")

    with pytest.raises(ValidationError, match="organization_id"):
        EvaluateInlineRequest.model_validate(payload)


def test_inline_evaluation_rejects_private_signing_selectors() -> None:
    payload = _inline_payload()
    payload["issuer_profile_id"] = "attacker-profile"

    with pytest.raises(ValidationError, match="issuer_profile_id"):
        EvaluateInlineRequest.model_validate(payload)


@pytest.mark.asyncio
async def test_policy_format_comes_from_authoritative_template(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _policy_payload()
    request = JsonRequest(payload)
    body = PresentationPolicyCreate.model_validate(payload)
    monkeypatch.setattr(
        verification,
        "_load_credential_template",
        AsyncMock(
            return_value={
                "id": "template-dtc",
                "organization_id": "org-1",
                "credential_payload_format": "MDOC",
            }
        ),
    )

    encoded = await verification._authoritative_policy_body(body, request)
    forwarded = json.loads(encoded)

    assert (
        forwarded["credential_requirements"][0]["credential_payload_format"] == "MDOC"
    )


@pytest.mark.asyncio
async def test_policy_rejects_template_from_another_organization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _policy_payload()
    request = JsonRequest(payload)
    body = PresentationPolicyCreate.model_validate(payload)
    monkeypatch.setattr(
        verification,
        "_load_credential_template",
        AsyncMock(
            return_value={
                "id": "template-dtc",
                "organization_id": "org-2",
                "credential_payload_format": "MDOC",
            }
        ),
    )

    with pytest.raises(verification.HTTPException) as exc_info:
        await verification._authoritative_policy_body(body, request)

    assert exc_info.value.status_code == 422
    assert "policy organization" in exc_info.value.detail


@pytest.mark.asyncio
async def test_create_policy_proxies_only_enriched_format(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _policy_payload()
    request = JsonRequest(payload)
    body = PresentationPolicyCreate.model_validate(payload)
    monkeypatch.setattr(
        verification,
        "_load_credential_template",
        AsyncMock(
            return_value={
                "id": "template-dtc",
                "organization_id": "org-1",
                "credential_payload_format": "MDOC",
            }
        ),
    )
    monkeypatch.setattr(
        verification,
        "get_registry",
        lambda: SimpleNamespace(
            get_service_url=lambda service: "http://presentation-policy:8000"
        ),
    )
    expected_response = SimpleNamespace(status_code=201)
    proxy = AsyncMock(return_value=expected_response)
    monkeypatch.setattr(verification, "proxy_request", proxy)

    def sanitizer(response):
        return response

    monkeypatch.setattr(
        verification,
        "_sanitize_presentation_policy_response",
        sanitizer,
    )

    response = await verification.create_presentation_policy(body, request)

    assert response is expected_response
    body_override = proxy.await_args.kwargs["body_override"]
    assert (
        json.loads(body_override)["credential_requirements"][0][
            "credential_payload_format"
        ]
        == "MDOC"
    )


def test_policy_request_rejects_unmodeled_raw_fields() -> None:
    payload = _policy_payload()
    payload["issuer_profile_id"] = "private-selector"

    with pytest.raises(ValidationError, match="issuer_profile_id"):
        PresentationPolicyCreate.model_validate(payload)


def test_disabled_holder_binding_serializes_to_canonical_shape() -> None:
    body = PresentationPolicyCreate.model_validate(
        {
            **_policy_payload(),
            "holder_binding": {"required": False},
        }
    )

    payload = verification._validated_policy_payload(body)

    assert payload["holder_binding"] == {"required": False}


@pytest.mark.asyncio
async def test_authoritative_body_is_serialized_from_validated_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _policy_payload()
    body = PresentationPolicyCreate.model_validate(payload)
    request = JsonRequest({**payload, "unvalidated_field": "must-not-forward"})
    monkeypatch.setattr(
        verification,
        "_load_credential_template",
        AsyncMock(
            return_value={
                "id": "template-dtc",
                "organization_id": "org-1",
                "credential_payload_format": "MDOC",
            }
        ),
    )

    forwarded = json.loads(await verification._authoritative_policy_body(body, request))

    assert "unvalidated_field" not in forwarded


def _policy_response_payload() -> dict:
    return {
        "id": "policy-1",
        "organization_id": "org-1",
        "name": "Verify DTC",
        "status": "draft",
        "required_claims": [
            {
                "claim_name": "document_number",
                "credential_type": "DigitalTravelCredential",
            }
        ],
        "accepted_credential_types": ["DigitalTravelCredential"],
        "display_metadata": {
            "title": "Verify DTC",
            "description": "",
            "purpose": "identity_verification",
            "purpose_description": None,
            "verifier_name": "",
            "verifier_logo_url": None,
            "privacy_policy_url": None,
            "terms_of_service_url": None,
        },
        "credential_requirements": [],
        "alternative_requirements": [],
        "holder_binding": {"required": False},
        "prefer_predicates": False,
        "supported_circuits": [],
        "credential_ranking_strategy": "FRESHEST_FIRST",
        "version": 1,
        "created_at": "2026-07-30T00:00:00Z",
        "updated_at": "2026-07-30T00:00:00Z",
    }


def test_policy_response_removes_internal_fields_and_validates_contract() -> None:
    payload = {
        **_policy_response_payload(),
        "issuer_profile_id": "private-selector",
        "signing_service_id": "private-selector",
    }

    response = verification._sanitize_presentation_policy_response(
        Response(content=json.dumps(payload), media_type="application/json")
    )
    public = json.loads(response.body)

    assert "issuer_profile_id" not in public
    assert "signing_service_id" not in public
    assert public["organization_id"] == "org-1"
    assert public["version"] == 1


def test_policy_response_fails_closed_when_service_breaks_contract() -> None:
    payload = _policy_response_payload()
    payload.pop("organization_id")

    with pytest.raises(verification.HTTPException) as exc_info:
        verification._sanitize_presentation_policy_response(
            Response(content=json.dumps(payload), media_type="application/json")
        )

    assert exc_info.value.status_code == 502


@pytest.mark.asyncio
async def test_update_policy_rejects_cross_tenant_resource_substitution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = PresentationPolicyUpdate(
        organization_id="org-1",
        name="Updated policy",
    )
    monkeypatch.setattr(
        verification,
        "_resource_org_id",
        AsyncMock(return_value="org-2"),
    )
    proxy = AsyncMock()
    monkeypatch.setattr(verification, "proxy_request", proxy)

    with pytest.raises(verification.HTTPException) as exc_info:
        await verification.update_presentation_policy(
            "policy-from-org-2",
            body,
            JsonRequest(body.model_dump()),
        )

    assert exc_info.value.status_code == 404
    proxy.assert_not_awaited()


def test_gateway_exposes_patch_not_put_for_policy_updates() -> None:
    update_route = next(
        route
        for route in verification.presentation_policy_router.routes
        if route.path.endswith("/{policy_id}") and "PATCH" in (route.methods or set())
    )

    assert update_route.methods == {"PATCH"}
    assert not any(
        route.path.endswith("/{policy_id}") and "PUT" in (route.methods or set())
        for route in verification.presentation_policy_router.routes
    )
