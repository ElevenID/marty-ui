"""Owned authorization tests for presentation-policy REST principals."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from services.presentation_policy import main as pp


def _build_client() -> tuple[TestClient, pp.PresentationPolicy, AsyncMock]:
    repo = pp.InMemoryPresentationPolicyRepository()
    policy = pp.PresentationPolicy(
        organization_id="org-1",
        name="Explicit principal policy",
    )
    asyncio.run(repo.save(policy))

    membership = AsyncMock(return_value=None)
    org_client = SimpleNamespace(get_membership=membership)
    app = FastAPI()
    app.include_router(pp.router)
    pp._repo = repo
    pp.app.state.org_client = org_client
    return TestClient(app), policy, membership


@pytest.mark.parametrize("principal", ["auth-service", "flow", "not-a-uuid"])
def test_non_uuid_labels_do_not_bypass_user_membership(principal: str) -> None:
    client, policy, membership = _build_client()

    response = client.get(
        f"/v1/presentation-policies/{policy.id}",
        headers={"x-user-id": principal},
    )

    assert response.status_code == 403
    membership.assert_awaited_once_with(principal, "org-1")


def test_complete_organization_bound_api_key_context_can_read_policy() -> None:
    client, policy, membership = _build_client()

    response = client.get(
        f"/v1/presentation-policies/{policy.id}",
        headers={
            "x-user-id": "api_key:key-1",
            "x-api-key-id": "key-1",
            "x-api-key-scopes": "trust:read",
            "x-organization-id": "org-1",
            "x-required-permission": "presentation-policy:view",
        },
    )

    assert response.status_code == 200
    assert response.json()["id"] == policy.id
    membership.assert_not_awaited()


@pytest.mark.parametrize(
    "headers",
    [
        {"x-user-id": "api_key:key-1"},
        {
            "x-user-id": "api_key:key-2",
            "x-api-key-id": "key-1",
            "x-api-key-scopes": "trust:read",
            "x-organization-id": "org-1",
            "x-required-permission": "presentation-policy:view",
        },
        {
            "x-user-id": "api_key:key-1",
            "x-api-key-id": "key-1",
            "x-api-key-scopes": "trust:read",
            "x-organization-id": "org-2",
            "x-required-permission": "presentation-policy:view",
        },
        {
            "x-user-id": "api_key:key-1",
            "x-api-key-id": "key-1",
            "x-api-key-scopes": "credentials:read",
            "x-organization-id": "org-1",
            "x-required-permission": "presentation-policy:view",
        },
        {
            "x-user-id": "api_key:key-1",
            "x-api-key-id": "key-1",
            "x-api-key-scopes": "trust:read",
            "x-organization-id": "org-1",
            "x-required-permission": "verification:execute",
        },
    ],
)
def test_partial_or_inconsistent_api_key_context_fails_closed(
    headers: dict[str, str],
) -> None:
    client, policy, membership = _build_client()

    response = client.get(
        f"/v1/presentation-policies/{policy.id}",
        headers=headers,
    )

    assert response.status_code == 403
    membership.assert_not_awaited()
