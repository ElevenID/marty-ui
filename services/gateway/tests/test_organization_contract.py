from __future__ import annotations

import json

import pytest
from fastapi import Response
from pydantic import ValidationError
from starlette.requests import Request

from gateway.models import OrganizationCreate, OrganizationResponse, OrganizationUpdate
from gateway.routes import organizations


ORG_ID = "20000000-0000-4000-8000-000000000001"


def _organization_payload() -> dict:
    return {
        "id": ORG_ID,
        "name": "example-issuer",
        "display_name": "Example Issuer",
        "description": "Example tenant",
        "join_code": None,
        "visibility": "PUBLIC",
        "owner_id": "owner-subject",
        "status": "active",
        "org_type": "enterprise",
        "join_mechanism": "open",
        "requires_approval": True,
        "is_discoverable": True,
        "contact_email": "operator@example.com",
        "contact_phone": None,
        "website": "https://example.com",
        "membership": None,
        "created_at": "2026-07-31T00:00:00Z",
        "updated_at": "2026-07-31T00:00:00Z",
    }


def _request(method: str = "PATCH") -> Request:
    return Request(
        {
            "type": "http",
            "method": method,
            "path": f"/v1/organizations/{ORG_ID}",
            "headers": [],
            "query_string": b"",
            "server": ("test", 80),
            "client": ("test", 1),
            "scheme": "http",
        }
    )


def test_create_rejects_unmodeled_and_legacy_noop_fields() -> None:
    for field in ("jurisdiction", "membership_mode", "settings", "issuer_profile_id"):
        with pytest.raises(ValidationError):
            OrganizationCreate.model_validate(
                {
                    "name": "example-issuer",
                    "display_name": "Example Issuer",
                    field: "must-not-pass",
                }
            )


def test_validated_create_payload_contains_only_canonical_fields() -> None:
    body = OrganizationCreate.model_validate(
        {
            "name": "example-issuer",
            "display_name": "Example Issuer",
            "org_type": "healthcare",
            "visibility": "PUBLIC",
            "join_mechanism": "open",
            "requires_approval": True,
        }
    )

    payload = json.loads(organizations._validated_organization_payload(body))

    assert payload == {
        "contact_email": None,
        "description": None,
        "display_name": "Example Issuer",
        "join_mechanism": "open",
        "name": "example-issuer",
        "org_type": "healthcare",
        "requires_approval": True,
        "visibility": "PUBLIC",
    }


def test_update_payload_is_partial_and_strips_tenant_routing() -> None:
    body = OrganizationUpdate.model_validate(
        {
            "organization_id": ORG_ID,
            "display_name": "Updated Issuer",
            "contact_email": None,
        }
    )

    payload = json.loads(
        organizations._validated_organization_payload(
            body,
            include_organization_id=False,
        )
    )

    assert payload == {"contact_email": None, "display_name": "Updated Issuer"}


def test_success_response_is_validated_and_private_fields_fail_closed() -> None:
    valid = organizations._sanitize_organization_response(
        Response(
            content=json.dumps(_organization_payload()), media_type="application/json"
        )
    )
    assert valid.status_code == 200
    OrganizationResponse.model_validate(json.loads(bytes(valid.body)))

    malformed = _organization_payload()
    malformed["settings"] = {"private": True}
    rejected = organizations._sanitize_organization_response(
        Response(content=json.dumps(malformed), media_type="application/json")
    )
    assert rejected.status_code == 502
    assert b"settings" not in rejected.body


def test_success_list_requires_a_list_of_public_resources() -> None:
    valid = organizations._sanitize_organization_response(
        Response(
            content=json.dumps([_organization_payload()]), media_type="application/json"
        ),
        many=True,
    )
    assert valid.status_code == 200
    assert len(json.loads(bytes(valid.body))) == 1

    rejected = organizations._sanitize_organization_response(
        Response(
            content=json.dumps(_organization_payload()), media_type="application/json"
        ),
        many=True,
    )
    assert rejected.status_code == 502


def test_membership_response_rejects_internal_identity_fields() -> None:
    payload = _organization_payload()
    payload["membership"] = {
        "roles": [
            {"id": "role-1", "name": "owner", "display_name": "Owner"}
        ],
        "status": "active",
        "permissions": ["organization:read"],
        "has_org_console_access": True,
        "is_owner": True,
        "joined_at": "2026-07-31T00:00:00Z",
    }
    valid = organizations._sanitize_organization_response(
        Response(content=json.dumps([payload]), media_type="application/json"),
        many=True,
    )
    assert valid.status_code == 200

    payload["membership"]["user_id"] = "private-user-id"
    rejected = organizations._sanitize_organization_response(
        Response(content=json.dumps([payload]), media_type="application/json"),
        many=True,
    )
    assert rejected.status_code == 502
    assert b"private-user-id" not in rejected.body


@pytest.mark.asyncio
async def test_cross_tenant_update_fails_before_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    async def fail_if_called(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("cross-tenant update must not proxy")

    monkeypatch.setattr(organizations, "proxy_request", fail_if_called)
    body = OrganizationUpdate(
        organization_id="20000000-0000-4000-8000-000000000002",
        display_name="Wrong tenant",
    )

    response = await organizations.update_organization(ORG_ID, body, _request())

    assert response.status_code == 404
    assert called is False


def test_only_patch_exposes_the_organization_update_operation() -> None:
    methods_by_path = {
        method
        for route in organizations.organization_router.routes
        if getattr(route, "path", None) == "/v1/organizations/{org_id}"
        for method in (getattr(route, "methods", None) or set())
    }

    assert "PATCH" in methods_by_path
    assert "PUT" not in methods_by_path
    assert "DELETE" not in methods_by_path
