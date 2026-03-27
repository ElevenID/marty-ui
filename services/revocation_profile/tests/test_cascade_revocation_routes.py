from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

from fastapi import FastAPI
from fastapi.testclient import TestClient

from marty_common.org_authorization import OrgRole, OrganizationMembership
from services.revocation_profile import main as revocation_profile


def _membership(*, role: str = "admin") -> OrganizationMembership:
    return OrganizationMembership(
        user_id="user-1",
        organization_id="org-1",
        role=OrgRole(role),
        status="active",
    )


def _build_client(
    repo: revocation_profile.InMemoryRevocationProfileRepository,
    membership: OrganizationMembership | None = None,
) -> tuple[TestClient, AsyncMock]:
    app = FastAPI()
    app.include_router(revocation_profile.cascade_router)

    revocation_profile._repo = repo
    get_membership = AsyncMock(return_value=membership or _membership())
    app.state.org_client = SimpleNamespace(get_membership=get_membership)
    revocation_profile.app.state.org_client = SimpleNamespace(get_membership=get_membership)
    return TestClient(app), get_membership


def test_create_cascade_revocation_uses_circuit_breaker_pending_state():
    repo = revocation_profile.InMemoryRevocationProfileRepository()
    client, get_membership = _build_client(repo)

    response = client.post(
        "/v1/cascade-revocations",
        headers={"x-user-id": "user-1"},
        json={
            "organization_id": "org-1",
            "operation_type": "ISSUER_REVOCATION",
            "trigger_entity_type": "ISSUER",
            "trigger_entity_id": "issuer-1",
            "affected_credential_count": 1500,
            "affected_credential_ids": ["cred-1", "cred-2"],
            "circuit_breaker_threshold": 1000,
            "can_rollback": True,
            "metadata": {"source": "test"},
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["organization_id"] == "org-1"
    assert body["status"] == "PENDING_CONFIRMATION"
    assert body["requires_confirmation"] is True
    assert body["circuit_breaker_triggered"] is True
    assert body["affected_credential_count"] == 1500
    assert body["rollback_snapshot"] == {
        "affected_credential_ids": ["cred-1", "cred-2"],
        "affected_credential_count": 1500,
        "trigger_entity_id": "issuer-1",
    }
    get_membership.assert_awaited_once_with("user-1", "org-1")

    saved = asyncio.run(repo.get_cascade_operation(body["id"]))
    assert saved is not None
    assert saved.status == revocation_profile.CascadeStatus.PENDING_CONFIRMATION


def test_confirm_cascade_revocation_requires_admin_and_completes_operation():
    repo = revocation_profile.InMemoryRevocationProfileRepository()
    operation = revocation_profile.CascadeRevocationOperation(
        organization_id="org-1",
        operation_type=revocation_profile.CascadeOperationType.ISSUER_REVOCATION,
        trigger_entity_type=revocation_profile.TriggerEntityType.ISSUER,
        trigger_entity_id="issuer-1",
        status=revocation_profile.CascadeStatus.PENDING_CONFIRMATION,
        requires_confirmation=True,
        can_rollback=True,
        rollback_snapshot={"affected_credential_ids": ["cred-1"]},
    )
    asyncio.run(repo.save_cascade_operation(operation))
    client, _ = _build_client(repo)

    response = client.post(
        f"/v1/cascade-revocations/{operation.id}/confirm",
        headers={"x-user-id": "admin-1"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "COMPLETED"
    assert body["confirmed_by"] == "admin-1"
    assert body["confirmed_at"] is not None

    saved = asyncio.run(repo.get_cascade_operation(operation.id))
    assert saved is not None
    assert saved.status == revocation_profile.CascadeStatus.COMPLETED
    assert saved.completed_at is not None


def test_rollback_cascade_revocation_marks_terminal_state_and_clears_snapshot():
    repo = revocation_profile.InMemoryRevocationProfileRepository()
    operation = revocation_profile.CascadeRevocationOperation(
        organization_id="org-1",
        operation_type=revocation_profile.CascadeOperationType.ISSUER_REVOCATION,
        trigger_entity_type=revocation_profile.TriggerEntityType.ISSUER,
        trigger_entity_id="issuer-1",
        status=revocation_profile.CascadeStatus.COMPLETED,
        can_rollback=True,
        rollback_snapshot={"affected_credential_ids": ["cred-1"]},
        completed_at=datetime.now(timezone.utc),
    )
    asyncio.run(repo.save_cascade_operation(operation))
    client, _ = _build_client(repo)

    response = client.post(
        f"/v1/cascade-revocations/{operation.id}/rollback",
        headers={"x-user-id": "admin-1"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ROLLED_BACK"
    assert body["rolled_back_by"] == "admin-1"
    assert body["rolled_back_at"] is not None
    # rollback_snapshot is None → excluded by exclude_none
    assert "rollback_snapshot" not in body


def test_delete_cascade_revocation_rejects_completed_operation():
    repo = revocation_profile.InMemoryRevocationProfileRepository()
    operation = revocation_profile.CascadeRevocationOperation(
        organization_id="org-1",
        operation_type=revocation_profile.CascadeOperationType.ANCHOR_REVOCATION,
        trigger_entity_type=revocation_profile.TriggerEntityType.TRUST_ANCHOR,
        trigger_entity_id="anchor-1",
        status=revocation_profile.CascadeStatus.COMPLETED,
    )
    asyncio.run(repo.save_cascade_operation(operation))
    client, _ = _build_client(repo)

    response = client.delete(
        f"/v1/cascade-revocations/{operation.id}",
        headers={"x-user-id": "admin-1"},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Only pending cascade operations can be cancelled"


def test_list_cascade_revocations_filters_by_status():
    repo = revocation_profile.InMemoryRevocationProfileRepository()
    pending_operation = revocation_profile.CascadeRevocationOperation(
        organization_id="org-1",
        operation_type=revocation_profile.CascadeOperationType.ISSUER_REVOCATION,
        trigger_entity_type=revocation_profile.TriggerEntityType.ISSUER,
        trigger_entity_id="issuer-1",
        status=revocation_profile.CascadeStatus.PENDING_CONFIRMATION,
        requires_confirmation=True,
    )
    completed_operation = revocation_profile.CascadeRevocationOperation(
        organization_id="org-1",
        operation_type=revocation_profile.CascadeOperationType.ISSUER_REVOCATION,
        trigger_entity_type=revocation_profile.TriggerEntityType.ISSUER,
        trigger_entity_id="issuer-2",
        status=revocation_profile.CascadeStatus.COMPLETED,
        completed_at=datetime.now(timezone.utc),
    )
    asyncio.run(repo.save_cascade_operation(pending_operation))
    asyncio.run(repo.save_cascade_operation(completed_operation))
    client, get_membership = _build_client(repo)

    response = client.get(
        "/v1/cascade-revocations",
        headers={"x-user-id": "user-1"},
        params={"organization_id": "org-1", "status": "PENDING_CONFIRMATION"},
    )

    assert response.status_code == 200
    body = response.json()
    assert [operation["id"] for operation in body] == [pending_operation.id]
    get_membership.assert_awaited_once_with("user-1", "org-1")
