from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from services.organization.infrastructure.adapters import http_adapter
from services.organization.infrastructure.adapters.http_adapter import (
    CreateOrganizationRequest,
    UpdateOrganizationRequest,
    create_organization,
)
from services.organization.domain.entities import JoinMechanism, OrganizationType


class _FakeOrganization:
    id = "org-1"
    name = "acme"
    display_name = "Acme"
    description = None
    join_code = None
    visibility = "PRIVATE"
    org_type = OrganizationType.STARTUP
    join_mechanism = JoinMechanism.INVITE
    requires_approval = False
    is_discoverable = False
    contact_email = None
    contact_phone = None
    website = None
    owner_id = "user-1"
    status = type("Status", (), {"value": "active"})()
    created_at = datetime(2026, 5, 12, tzinfo=timezone.utc)
    updated_at = None


class _FakeOrganizationUseCase:
    def __init__(self) -> None:
        self.commands = []

    async def create_organization(self, command):
        self.commands.append(command)
        return _FakeOrganization()


class _FakeMembership:
    id = "membership-internal-id"
    organization_id = "org-1"
    user_id = "user-1"
    email = "private-membership@example.com"
    roles = [
        type(
            "Role",
            (),
            {"id": "role-1", "name": "owner", "display_name": "Owner"},
        )()
    ]
    status = type("Status", (), {"value": "active"})()
    effective_permissions = {"organization:read", "organization:update"}
    has_org_console_access = True
    is_owner = True
    joined_at = datetime(2026, 5, 12, tzinfo=timezone.utc)


@pytest.mark.asyncio
async def test_create_organization_rejects_when_disabled(monkeypatch):
    monkeypatch.setenv("ORGANIZATION_CREATION_ENABLED", "false")
    use_case = _FakeOrganizationUseCase()

    with pytest.raises(HTTPException) as exc_info:
        await create_organization(
            CreateOrganizationRequest(name="acme", display_name="Acme"),
            user_id="user-1",
            use_case=use_case,
        )

    assert exc_info.value.status_code == 403
    assert "disabled" in str(exc_info.value.detail)
    assert use_case.commands == []


@pytest.mark.asyncio
async def test_create_organization_allows_when_enabled(monkeypatch):
    monkeypatch.setenv("ORGANIZATION_CREATION_ENABLED", "true")
    use_case = _FakeOrganizationUseCase()

    response = await create_organization(
        CreateOrganizationRequest(name="acme", display_name="Acme"),
        user_id="user-1",
        use_case=use_case,
    )

    assert response.id == "org-1"
    assert len(use_case.commands) == 1
    assert use_case.commands[0].owner_id == "user-1"


@pytest.mark.asyncio
async def test_create_organization_preserves_discovery_and_admission(monkeypatch):
    monkeypatch.setenv("ORGANIZATION_CREATION_ENABLED", "true")
    use_case = _FakeOrganizationUseCase()

    await create_organization(
        CreateOrganizationRequest(
            name="health-issuer",
            display_name="Health Issuer",
            org_type="healthcare",
            visibility="PUBLIC",
            join_mechanism="open",
            requires_approval=True,
        ),
        user_id="user-1",
        use_case=use_case,
    )

    command = use_case.commands[0]
    assert command.org_type is OrganizationType.HEALTHCARE
    assert command.visibility == "PUBLIC"
    assert command.join_mechanism is JoinMechanism.OPEN
    assert command.requires_approval is True


def test_organization_requests_reject_noop_and_internal_fields():
    with pytest.raises(ValidationError):
        CreateOrganizationRequest.model_validate(
            {
                "name": "acme",
                "display_name": "Acme",
                "jurisdiction": "US",
            }
        )

    with pytest.raises(ValidationError):
        UpdateOrganizationRequest.model_validate({"settings": {"private": True}})


def test_open_admission_requires_public_visibility():
    with pytest.raises(ValidationError):
        CreateOrganizationRequest(
            name="acme",
            display_name="Acme",
            visibility="PRIVATE",
            join_mechanism="open",
        )


def test_membership_summary_exposes_only_the_public_protocol_shape():
    response = http_adapter._org_to_response(
        _FakeOrganization(), membership=_FakeMembership()
    )

    assert response.membership == {
        "roles": [
            {"id": "role-1", "name": "owner", "display_name": "Owner"}
        ],
        "status": "active",
        "permissions": ["organization:read", "organization:update"],
        "has_org_console_access": True,
        "is_owner": True,
        "joined_at": "2026-05-12T00:00:00+00:00",
    }
    assert "email" not in response.membership
    assert "user_id" not in response.membership


def test_organization_creation_enabled_defaults_true(monkeypatch):
    monkeypatch.delenv("ORGANIZATION_CREATION_ENABLED", raising=False)

    assert http_adapter._organization_creation_enabled() is True
