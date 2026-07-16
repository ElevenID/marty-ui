from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi import HTTPException
from fastapi.testclient import TestClient

from services.organization.domain.entities import MemberStatus
from services.organization.infrastructure.adapters.http_adapter import (
    UpdateOrganizationEnvironmentRequest,
    get_organization_environment,
    get_org_use_case,
    get_team_snapshot,
    require_org_membership,
    router,
    update_organization_environment,
)


def _role(name: str, display_name: str | None = None):
    return SimpleNamespace(id=f"role-{name}", name=name, display_name=display_name or name.title())


def _member(member_id: str, status: MemberStatus, roles: list[object], *, owner: bool = False):
    return SimpleNamespace(
        id=member_id,
        organization_id="org-1",
        user_id=f"user-{member_id}" if status != MemberStatus.INVITED else None,
        email=f"{member_id}@example.com",
        roles=roles,
        status=status,
        effective_permissions=set(),
        has_org_console_access=any(role.name in {"owner", "admin", "access_admin", "developer"} for role in roles),
        is_owner=owner,
        invited_at=datetime(2026, 7, 9, tzinfo=timezone.utc) if status == MemberStatus.INVITED else None,
        joined_at=datetime(2026, 7, 9, tzinfo=timezone.utc) if status == MemberStatus.ACTIVE else None,
    )


class _MemberUseCase:
    def __init__(self, members):
        self.members = members

    async def list_members(self, org_id: str):
        assert org_id == "org-1"
        return self.members


class _OrgUseCase:
    def __init__(self, settings=None):
        self.updated_commands = []
        self.org = SimpleNamespace(id="org-1", settings=settings or {})

    async def get_organization(self, org_id: str):
        assert org_id == "org-1"
        return self.org

    async def update_organization(self, command):
        self.updated_commands.append(command)
        self.org.settings.update(command.settings or {})
        return self.org


@pytest.mark.asyncio
async def test_team_snapshot_uses_real_memberships_and_role_buckets():
    members = [
        _member("owner", MemberStatus.ACTIVE, [_role("owner")], owner=True),
        _member("dev", MemberStatus.ACTIVE, [_role("developer")]),
        _member("invited", MemberStatus.INVITED, [_role("operator")]),
    ]

    response = await get_team_snapshot(
        "org-1",
        org_ctx=object(),
        use_case=_MemberUseCase(members),
    )

    assert [member["email"] for member in response.members] == ["owner@example.com", "dev@example.com"]
    assert [member["email"] for member in response.pending_invites] == ["invited@example.com"]
    assert response.role_distribution["admin"] == 1
    assert response.role_distribution["developer"] == 1
    assert response.role_distribution["operator"] == 0


@pytest.mark.asyncio
async def test_environment_read_returns_stored_value_without_defaulting():
    response = await get_organization_environment(
        "org-1",
        org_ctx=object(),
        use_case=_OrgUseCase({"environment": "staging"}),
    )

    assert response.organization_id == "org-1"
    assert response.environment == "staging"


@pytest.mark.asyncio
async def test_environment_read_returns_null_when_unset_or_unknown():
    response = await get_organization_environment(
        "org-1",
        org_ctx=object(),
        use_case=_OrgUseCase({"environment": "sandbox"}),
    )

    assert response.environment is None


def test_environment_http_response_includes_null_environment_field():
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_org_use_case] = lambda: _OrgUseCase({"environment": "sandbox"})
    app.dependency_overrides[require_org_membership] = lambda: object()

    response = TestClient(app).get("/v1/organizations/org-1/environment")

    assert response.status_code == 200
    assert response.json() == {"organization_id": "org-1", "environment": None}


@pytest.mark.asyncio
async def test_environment_update_persists_allowed_value():
    use_case = _OrgUseCase()

    response = await update_organization_environment(
        "org-1",
        UpdateOrganizationEnvironmentRequest(environment="production"),
        org_ctx=object(),
        use_case=use_case,
    )

    assert response.environment == "production"
    assert len(use_case.updated_commands) == 1
    assert use_case.updated_commands[0].settings == {"environment": "production"}


@pytest.mark.asyncio
async def test_environment_update_rejects_unknown_value():
    with pytest.raises(HTTPException) as exc_info:
        await update_organization_environment(
            "org-1",
            UpdateOrganizationEnvironmentRequest(environment="sandbox"),
            org_ctx=object(),
            use_case=_OrgUseCase(),
        )

    assert exc_info.value.status_code == 400
