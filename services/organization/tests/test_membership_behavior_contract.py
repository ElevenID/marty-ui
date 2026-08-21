import json
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from services.organization.application import use_cases as use_cases_module
from services.organization.application.use_cases import JoinUseCase, MemberUseCase
from services.organization.domain.entities import JoinCode, Role


def _fixture() -> dict:
    root = Path(__file__).resolve().parents[3]
    return json.loads(
        (root / "contracts" / "organization-membership-behavior.json").read_text(
            encoding="utf-8"
        )
    )


def _role(name: str, organization_id: str) -> Role:
    return Role(
        id=f"role-{name}",
        organization_id=organization_id,
        name=name,
        is_default_for_new_members=name == "applicant",
    )


@pytest.mark.asyncio
async def test_direct_role_resolution_uses_shared_behavior(monkeypatch) -> None:
    organization_id = "00000000-0000-0000-0000-000000000001"
    monkeypatch.setattr(use_cases_module, "MARTY_ORG_ID", organization_id)
    monkeypatch.setattr(use_cases_module, "MARTY_ORG_ADMIN_EMAIL", "admin@example.com")
    monkeypatch.setattr(use_cases_module, "CANVAS_DEMO_ADMIN_ENABLED", "false")
    roles = {
        name: _role(name, organization_id)
        for name in ["admin", "applicant", "reviewer", "viewer"]
    }
    role_use_case = SimpleNamespace(list_roles=AsyncMock(return_value=list(roles.values())))
    use_case = MemberUseCase(
        member_repo=SimpleNamespace(),
        organization_repo=SimpleNamespace(),
        event_publisher=SimpleNamespace(),
        role_use_case=role_use_case,
    )

    fixture = _fixture()
    assert fixture["schema_version"] == 1
    for case in fixture["direct_role_cases"]:
        requested = (
            [roles[name].id for name in case["requested"]]
            if case["requested"] is not None
            else None
        )
        current = [roles[name] for name in case["current"]]
        resolved = await use_case._resolve_direct_member_role_ids(
            organization_id=organization_id,
            email="admin@example.com" if case["grants_marty_admin"] else "user@example.com",
            requested_role_ids=requested,
            current_roles=current,
        )
        expected = [roles[name].id for name in case["expected"]]
        assert resolved == expected, case["name"]


@pytest.mark.asyncio
async def test_join_code_status_precedence_uses_shared_behavior() -> None:
    organization = SimpleNamespace(id="org-1", name="Behavior Organization")
    for case in _fixture()["join_code_cases"]:
        join_code = JoinCode(
            organization_id=organization.id,
            code="MARTY123",
            is_active=case["is_active"],
            expires_at=(
                datetime.fromisoformat(case["expires_at"].replace("Z", "+00:00"))
                if case["expires_at"]
                else None
            ),
            max_uses=case["max_uses"],
            use_count=case["use_count"],
        )
        use_case = JoinUseCase(
            join_code_repo=SimpleNamespace(get_by_code=AsyncMock(return_value=join_code)),
            organization_repo=SimpleNamespace(get_by_id=AsyncMock(return_value=organization)),
            member_repo=SimpleNamespace(),
            event_publisher=SimpleNamespace(),
        )
        valid, _organization, message, expired = await use_case.validate_join_code(
            join_code.code
        )
        assert valid is (case["state"] == "valid"), case["name"]
        if not valid:
            assert message == case["message"], case["name"]
        assert expired is case["expired"], case["name"]
