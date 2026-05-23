from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi import HTTPException

from services.organization.infrastructure.adapters import http_adapter
from services.organization.infrastructure.adapters.http_adapter import (
    CreateOrganizationRequest,
    create_organization,
)


class _FakeOrganization:
    id = "org-1"
    name = "acme"
    display_name = "Acme"
    description = None
    join_code = None
    visibility = "PRIVATE"
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


def test_organization_creation_enabled_defaults_true(monkeypatch):
    monkeypatch.delenv("ORGANIZATION_CREATION_ENABLED", raising=False)

    assert http_adapter._organization_creation_enabled() is True
