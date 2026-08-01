from __future__ import annotations

import json

import pytest
from fastapi import Response
from pydantic import ValidationError

from gateway.models import (
    IssuerEntityCreate,
    IssuerEntityResponse,
    IssuerEntityUpdate,
    IssuerIdentityListResponse,
)
from gateway.routes import trust


ORG_ID = "20000000-0000-4000-8000-000000000001"
ENTITY_ID = "10000000-0000-4000-8000-000000000001"


def _entity_payload() -> dict:
    return {
        "id": ENTITY_ID,
        "organization_id": ORG_ID,
        "issuer_id": "did:web:issuer.example",
        "issuer_type": "ORGANIZATION",
        "display_name": "Example Issuer",
        "description": "Tenant trust-registry entry",
        "is_system_issuer": False,
        "compliance_status": "COMPLIANT",
        "accreditation_body": None,
        "accreditation_date": None,
        "valid_from": "2026-08-01T00:00:00Z",
        "valid_until": None,
        "trust_anchor_id": None,
        "revoked_at": None,
        "revocation_reason": None,
        "revoked_by": None,
        "metadata": {"jurisdiction": "US"},
        "created_at": "2026-08-01T00:00:00Z",
        "updated_at": "2026-08-01T00:00:00Z",
    }


def test_create_rejects_system_authority_and_private_metadata() -> None:
    base = {
        "organization_id": ORG_ID,
        "issuer_id": "did:web:issuer.example",
        "display_name": "Example Issuer",
    }
    for field, value in (
        ("is_system_issuer", True),
        ("revoked_by", "forged-operator"),
        ("issuer_profile_id", "private-profile"),
    ):
        with pytest.raises(ValidationError):
            IssuerEntityCreate.model_validate({**base, field: value})

    with pytest.raises(ValidationError):
        IssuerEntityCreate.model_validate(
            {
                **base,
                "metadata": {"public": [{"signing_service_id": "private"}]},
            }
        )


def test_update_is_tenant_bound_partial_and_server_attributed() -> None:
    with pytest.raises(ValidationError):
        IssuerEntityUpdate.model_validate({"organization_id": ORG_ID})
    with pytest.raises(ValidationError):
        IssuerEntityUpdate.model_validate(
            {
                "organization_id": ORG_ID,
                "compliance_status": "REVOKED",
            }
        )
    with pytest.raises(ValidationError):
        IssuerEntityUpdate.model_validate(
            {
                "organization_id": ORG_ID,
                "compliance_status": "REVOKED",
                "revocation_reason": "Compromise",
                "revoked_by": "forged-operator",
            }
        )

    body = IssuerEntityUpdate.model_validate(
        {
            "organization_id": ORG_ID,
            "description": None,
        }
    )
    assert json.loads(trust._validated_issuer_entity_payload(body)) == {
        "description": None,
        "organization_id": ORG_ID,
    }


def test_success_response_validation_fails_closed_on_private_state() -> None:
    valid = trust._sanitize_issuer_entity_response(
        Response(content=json.dumps(_entity_payload()), media_type="application/json")
    )
    assert valid.status_code == 200
    IssuerEntityResponse.model_validate(json.loads(bytes(valid.body)))

    private = _entity_payload()
    private["metadata"] = {"nested": {"key_reference": "private-key"}}
    rejected = trust._sanitize_issuer_entity_response(
        Response(content=json.dumps(private), media_type="application/json")
    )
    assert rejected.status_code == 502
    assert b"private-key" not in rejected.body


def test_success_list_requires_public_resource_array() -> None:
    valid = trust._sanitize_issuer_entity_response(
        Response(content=json.dumps([_entity_payload()]), media_type="application/json"),
        many=True,
    )
    assert valid.status_code == 200

    rejected = trust._sanitize_issuer_entity_response(
        Response(content=json.dumps(_entity_payload()), media_type="application/json"),
        many=True,
    )
    assert rejected.status_code == 502


def test_public_identity_projection_is_did_only() -> None:
    response = IssuerIdentityListResponse.model_validate(
        {
            "identities": [
                {
                    "issuer_did": "did:web:issuer.example",
                    "key_purpose": "vc_jwt_issuer",
                    "algorithm": "ES256",
                    "status": "active",
                }
            ]
        }
    )
    assert response.identities[0].issuer_did == "did:web:issuer.example"

    with pytest.raises(ValidationError):
        IssuerIdentityListResponse.model_validate(
            {
                "identities": [
                    {
                        "issuer_did": "did:web:issuer.example",
                        "key_purpose": "vc_jwt_issuer",
                        "algorithm": "ES256",
                        "status": "active",
                        "issuer_profile_id": "private-profile",
                    }
                ]
            }
        )


def test_issuer_entity_partial_update_is_patch_only() -> None:
    methods = {
        method
        for route in trust.issuer_entity_router.routes
        if getattr(route, "path", None) == "/v1/issuer-entities/{issuer_entity_id}"
        for method in (getattr(route, "methods", None) or set())
    }
    assert "PATCH" in methods
    assert "PUT" not in methods
