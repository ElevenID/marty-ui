import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from marty_common import OrganizationMembership, require_org_membership, require_permission
from starlette.requests import Request


def _fixture() -> dict:
    root = Path(__file__).resolve().parents[3]
    return json.loads(
        (root / "contracts" / "organization-authorization-behavior.json").read_text(
            encoding="utf-8"
        )
    )


def _classify(error: HTTPException) -> str:
    if error.status_code == 401:
        return "authentication_required"
    detail = str(error.detail).lower()
    if "not a member" in detail:
        return "membership_required"
    if "membership is" in detail:
        return "membership_inactive"
    return "action_not_authorized"


@pytest.mark.asyncio
async def test_forwarded_user_and_api_key_context_uses_shared_behavior(monkeypatch) -> None:
    fixture = _fixture()
    assert fixture["schema_version"] == 1
    import marty_common.org_authorization as authorization

    for case in fixture["cases"]:
        membership = None
        if case["member_present"]:
            membership = OrganizationMembership(
                user_id=case["member_user_id"],
                organization_id=case["member_organization_id"],
                status=case["member_status"],
                permissions=set(case["member_permissions"]),
                is_owner="owner" in case["member_roles"],
            )
        client = SimpleNamespace(
            get_membership=lambda _user_id, _organization_id: None
        )

        async def get_membership(_user_id, _organization_id, value=membership):
            return value

        client.get_membership = get_membership

        async def get_client(_request, value=client):
            return value

        monkeypatch.setattr(authorization, "get_organization_client", get_client)
        headers = []
        if case["principal"] == "api_key":
            headers.extend(
                [
                    (b"x-api-key-id", case["api_key_id"].encode()),
                    (
                        b"x-organization-id",
                        case["principal_organization_id"].encode(),
                    ),
                    (
                        b"x-required-permission",
                        case["authorized_permission"].encode(),
                    ),
                ]
            )
        request = Request({"type": "http", "headers": headers, "app": SimpleNamespace()})
        try:
            context = await require_org_membership(
                fixture["organization_id"],
                request,
                x_user_id=case["user_id"] or None,
                x_organization_id=case["principal_organization_id"],
                x_api_key_id=case["api_key_id"],
                x_required_permission=case["authorized_permission"],
            )
        except HTTPException as error:
            membership_actual = _classify(error)
            actual = membership_actual
        else:
            membership_actual = "allow"
            try:
                if case["owner_only"]:
                    if not context.is_owner:
                        raise HTTPException(status_code=403, detail="owner required")
                else:
                    resource, action = case["required_permission"].split(":", 1)
                    checker = require_permission(resource, action)
                    await checker(request, context)
                actual = "allow"
            except HTTPException as error:
                actual = _classify(error)
        assert membership_actual == case["membership_expected"], (
            f'{case["name"]} membership-only'
        )
        assert actual == case["expected"], case["name"]
