"""Presentation-policy gateway authority-boundary tests."""

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from pydantic import ValidationError

from gateway.models import EvaluateInlineRequest, PresentationPolicyCreate
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

    response = await verification.create_presentation_policy(body, request)

    assert response is expected_response
    body_override = proxy.await_args.kwargs["body_override"]
    assert (
        json.loads(body_override)["credential_requirements"][0][
            "credential_payload_format"
        ]
        == "MDOC"
    )
