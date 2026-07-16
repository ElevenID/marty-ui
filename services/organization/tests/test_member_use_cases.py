from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from services.organization.application import use_cases as use_cases_module
from services.organization.application.use_cases import MemberUseCase
from services.organization.domain.entities import Member, MemberStatus, Role


@pytest.mark.asyncio
async def test_add_member_direct_promotes_existing_marty_admin_email_membership(monkeypatch):
    monkeypatch.setattr(use_cases_module, "MARTY_ORG_ADMIN_EMAIL", "admin@example.com")
    monkeypatch.setattr(use_cases_module, "MARTY_ORG_ID", "00000000-0000-0000-0000-000000000001")

    applicant_role = Role(
        id="role-applicant",
        organization_id=use_cases_module.MARTY_ORG_ID,
        name="applicant",
        display_name="Applicant",
    )
    admin_role = Role(
        id="role-admin",
        organization_id=use_cases_module.MARTY_ORG_ID,
        name="admin",
        display_name="Administrator",
    )
    existing_member = Member(
        id="member-1",
        organization_id=use_cases_module.MARTY_ORG_ID,
        user_id="user-1",
        email="admin@example.com",
        status=MemberStatus.ACTIVE,
        roles=[applicant_role],
    )

    member_repo = SimpleNamespace(
        get_by_user_and_org=AsyncMock(return_value=existing_member),
        get_by_email_and_org=AsyncMock(),
        save=AsyncMock(),
    )
    role_use_case = SimpleNamespace(
        list_roles=AsyncMock(return_value=[admin_role, applicant_role]),
        set_member_roles=AsyncMock(return_value=[admin_role]),
    )
    event_publisher = SimpleNamespace(publish=AsyncMock())
    use_case = MemberUseCase(
        member_repo=member_repo,
        organization_repo=SimpleNamespace(),
        event_publisher=event_publisher,
        role_use_case=role_use_case,
    )

    member = await use_case.add_member_direct(
        organization_id=use_cases_module.MARTY_ORG_ID,
        user_id="user-1",
        email="admin@example.com",
    )

    command = role_use_case.set_member_roles.await_args.args[0]
    assert command.member_id == "member-1"
    assert command.organization_id == use_cases_module.MARTY_ORG_ID
    assert command.role_ids == ["role-admin"]
    assert {role.name for role in member.roles} == {"admin"}
    member_repo.save.assert_awaited()


@pytest.mark.asyncio
async def test_add_member_direct_assigns_admin_role_to_new_marty_admin_email(monkeypatch):
    monkeypatch.setattr(use_cases_module, "MARTY_ORG_ADMIN_EMAIL", "admin@example.com")
    monkeypatch.setattr(use_cases_module, "MARTY_ORG_ID", "00000000-0000-0000-0000-000000000001")

    admin_role = Role(
        id="role-admin",
        organization_id=use_cases_module.MARTY_ORG_ID,
        name="admin",
        display_name="Administrator",
    )
    applicant_role = Role(
        id="role-applicant",
        organization_id=use_cases_module.MARTY_ORG_ID,
        name="applicant",
        display_name="Applicant",
    )

    member_repo = SimpleNamespace(
        get_by_user_and_org=AsyncMock(return_value=None),
        get_by_email_and_org=AsyncMock(return_value=None),
        save=AsyncMock(),
    )
    role_use_case = SimpleNamespace(
        list_roles=AsyncMock(return_value=[admin_role, applicant_role]),
        set_member_roles=AsyncMock(return_value=[admin_role]),
    )
    event_publisher = SimpleNamespace(publish=AsyncMock())
    use_case = MemberUseCase(
        member_repo=member_repo,
        organization_repo=SimpleNamespace(),
        event_publisher=event_publisher,
        role_use_case=role_use_case,
    )

    member = await use_case.add_member_direct(
        organization_id=use_cases_module.MARTY_ORG_ID,
        user_id="user-2",
        email="admin@example.com",
    )

    command = role_use_case.set_member_roles.await_args.args[0]
    assert command.organization_id == use_cases_module.MARTY_ORG_ID
    assert command.role_ids == ["role-admin"]
    assert {role.name for role in member.roles} == {"admin"}
    event_publisher.publish.assert_awaited_once()


@pytest.mark.asyncio
async def test_add_member_direct_assigns_admin_role_to_canvas_demo_admin_email(monkeypatch):
    monkeypatch.setattr(use_cases_module, "MARTY_ORG_ADMIN_EMAIL", "")
    monkeypatch.setattr(use_cases_module, "CANVAS_DEMO_ADMIN_ENABLED", "true")
    monkeypatch.setattr(use_cases_module, "CANVAS_DEMO_ADMIN_EMAIL", "canvas.admin@marty.demo")
    monkeypatch.setattr(use_cases_module, "MARTY_ORG_ID", "00000000-0000-0000-0000-000000000001")

    admin_role = Role(
        id="role-admin",
        organization_id=use_cases_module.MARTY_ORG_ID,
        name="admin",
        display_name="Administrator",
    )
    applicant_role = Role(
        id="role-applicant",
        organization_id=use_cases_module.MARTY_ORG_ID,
        name="applicant",
        display_name="Applicant",
    )

    member_repo = SimpleNamespace(
        get_by_user_and_org=AsyncMock(return_value=None),
        get_by_email_and_org=AsyncMock(return_value=None),
        save=AsyncMock(),
    )
    role_use_case = SimpleNamespace(
        list_roles=AsyncMock(return_value=[admin_role, applicant_role]),
        set_member_roles=AsyncMock(return_value=[admin_role]),
    )
    event_publisher = SimpleNamespace(publish=AsyncMock())
    use_case = MemberUseCase(
        member_repo=member_repo,
        organization_repo=SimpleNamespace(),
        event_publisher=event_publisher,
        role_use_case=role_use_case,
    )

    member = await use_case.add_member_direct(
        organization_id=use_cases_module.MARTY_ORG_ID,
        user_id="canvas-admin-user",
        email="canvas.admin@marty.demo",
    )

    command = role_use_case.set_member_roles.await_args.args[0]
    assert command.organization_id == use_cases_module.MARTY_ORG_ID
    assert command.role_ids == ["role-admin"]
    assert {role.name for role in member.roles} == {"admin"}
