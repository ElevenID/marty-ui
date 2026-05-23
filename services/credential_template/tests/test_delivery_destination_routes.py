from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

from fastapi import FastAPI
from fastapi.testclient import TestClient
from marty_common.org_authorization import OrganizationMembership, OrganizationRoleSummary

from services.credential_template import main as credential_template


def _build_client(
    repo: credential_template.InMemoryDeliveryDestinationRepository | None = None,
    *,
    has_org_console_access: bool = True,
) -> tuple[TestClient, AsyncMock]:
    app = FastAPI()
    app.include_router(credential_template.delivery_destination_router)

    credential_template._delivery_destination_repo = (
        repo or credential_template.InMemoryDeliveryDestinationRepository()
    )
    get_membership = AsyncMock(
        return_value=OrganizationMembership(
            user_id="user-1",
            organization_id="org-1",
            status="active",
            roles=[OrganizationRoleSummary(id="role-admin", name="admin", display_name="Admin")],
            permissions=set(),
            has_org_console_access=has_org_console_access,
        )
    )
    app.state.org_client = SimpleNamespace(get_membership=get_membership)
    return TestClient(app), get_membership


def test_list_delivery_destinations_includes_canvas_credentials_as_org_managed_destination():
    client, get_membership = _build_client()

    response = client.get(
        "/v1/delivery-destinations",
        headers={"x-user-id": "user-1"},
        params={"organization_id": "org-1"},
    )

    assert response.status_code == 200
    body = response.json()
    canvas = next(item for item in body if item["id"] == "dd-canvas-credentials-institutional")
    assert canvas["provider"] == "canvas_credentials"
    assert canvas["mode"] == "organization_mirror"
    assert canvas["setup_actor"] == "org_admin"
    assert canvas["delivery_target"] == "canvas_credentials"
    assert canvas["requires_consent"] is True
    assert canvas["claim_projection_policy"]["mode"] == "public_badge"
    assert canvas["capabilities"]["org_managed"] is True
    get_membership.assert_awaited_once_with("user-1", "org-1")


def test_create_delivery_destination_requires_org_console_access():
    client, _ = _build_client(has_org_console_access=False)

    response = client.post(
        "/v1/delivery-destinations",
        headers={"x-user-id": "user-1"},
        json={
            "organization_id": "org-1",
            "name": "Org Mirror",
            "provider": "custom",
            "mode": "organization_mirror",
            "setup_actor": "org_admin",
            "delivery_target": "external_api",
        },
    )

    assert response.status_code == 403


def test_create_and_update_org_delivery_destination():
    repo = credential_template.InMemoryDeliveryDestinationRepository()
    client, _ = _build_client(repo)

    create = client.post(
        "/v1/delivery-destinations",
        headers={"x-user-id": "user-1"},
        json={
            "organization_id": "org-1",
            "id": "dd-org-canvas",
            "name": "Org Canvas Credentials",
            "provider": "canvas_credentials",
            "mode": "organization_mirror",
            "setup_actor": "org_admin",
            "delivery_target": "canvas_credentials",
            "connector_type": "canvas_platform",
            "connector_id": "canvas-platform-1",
            "requires_consent": True,
            "claim_projection_policy": {"mode": "public_badge"},
        },
    )

    assert create.status_code == 201
    body = create.json()
    assert body["is_system"] is False
    assert body["organization_id"] == "org-1"
    assert body["connector_id"] == "canvas-platform-1"

    update = client.patch(
        "/v1/delivery-destinations/dd-org-canvas",
        headers={"x-user-id": "user-1"},
        json={"is_enabled": False, "claim_projection_policy": {"mode": "allow_list", "allowed_claims": ["achievement"]}},
    )

    assert update.status_code == 200
    updated = update.json()
    assert updated["is_enabled"] is False
    assert updated["claim_projection_policy"] == {
        "mode": "allow_list",
        "allowed_claims": ["achievement"],
    }


def test_system_delivery_destinations_are_read_only():
    client, _ = _build_client()

    response = client.patch(
        "/v1/delivery-destinations/dd-canvas-credentials-institutional",
        headers={"x-user-id": "user-1"},
        json={"name": "Changed"},
    )

    assert response.status_code == 403


def test_student_cannot_create_institutional_canvas_destination_from_learner_context():
    client, _ = _build_client(has_org_console_access=False)

    response = client.post(
        "/v1/delivery-destinations",
        headers={"x-user-id": "user-1"},
        json={
            "organization_id": "org-1",
            "name": "Student Canvas Mirror",
            "provider": "canvas_credentials",
            "mode": "organization_mirror",
            "setup_actor": "org_admin",
            "delivery_target": "canvas_credentials",
            "connector_type": "canvas_platform",
        },
    )

    assert response.status_code == 403
