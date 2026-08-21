import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from services.organization.application.ports import DeleteRoleCommand
from services.organization.application.rbac_use_cases import RoleUseCase
from services.organization.domain.entities import Role


def _fixture() -> dict:
    root = Path(__file__).resolve().parents[3]
    return json.loads(
        (root / "contracts" / "organization-rbac-behavior.json").read_text(
            encoding="utf-8"
        )
    )


def _classify_error(error: ValueError) -> str:
    message = str(error)
    if "not found" in message:
        return "role_not_found"
    if "replacement" in message.lower():
        return "replacement_role_required"
    raise AssertionError(f"unrecognized RBAC error: {message}")


@pytest.mark.asyncio
async def test_role_replacement_uses_shared_behavior() -> None:
    fixture = _fixture()
    assert fixture["schema_version"] == 1
    role_catalog = {item["id"]: item for item in fixture["roles"]}

    def build_role(role_id: str) -> Role:
        item = role_catalog[role_id]
        return Role(
            id=item["id"],
            organization_id=fixture["organization_id"],
            name=item["name"],
            display_name=item["name"],
            is_default_for_new_members=item["is_default"],
        )

    for case in fixture["cases"]:
        roles = [build_role(role_id) for role_id in case["available_role_ids"]]
        deleted = next(role for role in roles if role.id == case["deleted_role_id"])
        affected_member_ids = ["member-1"] if case["has_affected_members"] else []
        repository = SimpleNamespace(
            get_by_id=AsyncMock(return_value=deleted),
            list_by_organization=AsyncMock(return_value=roles),
            get_members_with_role=AsyncMock(return_value=affected_member_ids),
            get_member_roles=AsyncMock(return_value=[deleted]),
            add_member_role=AsyncMock(),
            save=AsyncMock(),
            delete=AsyncMock(),
        )
        use_case = RoleUseCase(
            role_repo=repository,
            permission_repo=SimpleNamespace(),
            member_repo=SimpleNamespace(),
            event_publisher=SimpleNamespace(publish=AsyncMock()),
        )
        command = DeleteRoleCommand(
            role_id=deleted.id,
            organization_id=fixture["organization_id"],
            deleted_by="contract-actor",
            replacement_role_id=case["requested_replacement_id"],
        )

        if case["expected_error"]:
            try:
                await use_case.delete_role(command)
            except ValueError as error:
                assert _classify_error(error) == case["expected_error"], case["name"]
            else:
                pytest.fail(f"{case['name']}: expected {case['expected_error']}")
            repository.delete.assert_not_awaited()
            continue

        await use_case.delete_role(command)
        repository.delete.assert_awaited_once_with(deleted.id)
        expected_replacement = case["expected_replacement_id"]
        if case["has_affected_members"]:
            repository.add_member_role.assert_awaited_once_with(
                "member-1", expected_replacement
            )
        else:
            repository.add_member_role.assert_not_awaited()
        if deleted.is_default_for_new_members:
            saved_roles = [call.args[0] for call in repository.save.await_args_list]
            assert any(
                role.id == expected_replacement and role.is_default_for_new_members
                for role in saved_roles
            ), case["name"]
