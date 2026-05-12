from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

from fastapi import FastAPI
from fastapi.testclient import TestClient
from marty_common.org_authorization import OrganizationMembership, OrganizationRoleSummary

from services.deployment_profile import main as deployment_profile


def _build_client(
    repo: deployment_profile.InMemoryDeploymentProfileRepository,
    lane_repo: deployment_profile.InMemoryLaneRepository | None = None,
) -> tuple[TestClient, AsyncMock]:
    app = FastAPI()
    app.include_router(deployment_profile.router)

    deployment_profile._repo = repo
    deployment_profile._lane_repo = lane_repo or deployment_profile.InMemoryLaneRepository()

    get_membership = AsyncMock(
        return_value=OrganizationMembership(
            user_id="user-1",
            organization_id="org-1",
            status="active",
            roles=[OrganizationRoleSummary(id="role-admin", name="admin", display_name="Admin")],
            permissions={
                "deployment-profile:view",
                "deployment-profile:create",
                "deployment-profile:edit",
                "deployment-profile:delete",
                "deployment-profile:activate",
                "deployment-profile:suspend",
                "api-key:create",
            },
            has_org_console_access=True,
        )
    )
    org_client = SimpleNamespace(get_membership=get_membership)
    app.state.org_client = org_client
    deployment_profile.app.state.org_client = org_client
    return TestClient(app), get_membership


async def _save_profile(
    repo: deployment_profile.InMemoryDeploymentProfileRepository,
) -> deployment_profile.DeploymentProfile:
    profile = deployment_profile.DeploymentProfile(
        organization_id="org-1",
        name="Airport kiosk",
        trust_profile_id="trust-1",
        presentation_policy_ids=["policy-1"],
        default_policy_id="policy-1",
        default_presentation_policy_id="policy-1",
        enabled_flow_ids=["flow-1"],
        network_mode="ONLINE",
        key_access_mode="KEY_VAULT",
        update_channel="stable",
        update_policy={"channel": "stable", "auto_update": True},
        environment_config={"language": "en-US", "offline_cache_ttl_seconds": 86400},
        ux_config={"language": "en-US"},
    )
    await repo.save(profile)
    return profile


async def _save_lane(
    lane_repo: deployment_profile.InMemoryLaneRepository,
    profile_id: str,
) -> deployment_profile.Lane:
    lane = deployment_profile.Lane(
        deployment_profile_id=profile_id,
        name="Lane A",
        default_policy_id="policy-1",
    )
    await lane_repo.save(lane)
    return lane


def test_get_deployment_profile_includes_lanes() -> None:
    repo = deployment_profile.InMemoryDeploymentProfileRepository()
    lane_repo = deployment_profile.InMemoryLaneRepository()
    profile = asyncio.run(_save_profile(repo))
    lane = asyncio.run(_save_lane(lane_repo, profile.id))
    client, get_membership = _build_client(repo, lane_repo)

    response = client.get(
        f"/v1/deployment-profiles/{profile.id}",
        headers={"x-user-id": "user-1"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["lanes"] == [
        {
            "id": lane.id,
            "name": "Lane A",
            "deployment_profile_id": profile.id,
            "default_policy_id": "policy-1",
            "device_ids": [],
            "metadata": {},
        }
    ]
    get_membership.assert_awaited_once_with("user-1", "org-1")


def test_get_deployment_profile_exposes_protocol_aligned_shape_only() -> None:
    repo = deployment_profile.InMemoryDeploymentProfileRepository()
    profile = asyncio.run(_save_profile(repo))
    profile.callbacks = deployment_profile.CallbackConfiguration(
        issuance_complete_url="https://example.com/issued",
    )
    profile.api_auth = deployment_profile.ApiAuthConfiguration(
        auth_method=deployment_profile.AuthMethod.JWT,
    )
    profile.rate_limits = deployment_profile.RateLimitConfiguration(requests_per_minute=42)
    profile.feature_flags = deployment_profile.FeatureFlags(enable_batch_issuance=True)
    profile.branding = deployment_profile.BrandingConfiguration(organization_name="Example Org")
    profile.default_compliance_profile_id = "compliance-1"
    profile.api_key = "mk_live_secret"
    profile.api_key_prefix = "mk_live_deadbeef..."
    asyncio.run(repo.save(profile))

    client, _ = _build_client(repo)

    response = client.get(
        f"/v1/deployment-profiles/{profile.id}",
        headers={"x-user-id": "user-1"},
    )

    assert response.status_code == 200
    body = response.json()
    assert set(body) == {
        "id",
        "organization_id",
        "name",
        "trust_profile_id",
        "presentation_policy_ids",
        "credential_template_ids",
        "default_policy_id",
        "default_presentation_policy_id",
        "network_mode",
        "key_access_mode",
        "environment_config",
        "ux_config",
        "enabled_flow_ids",
        "update_channel",
        "update_policy",
        "offline_cache_ttl_hours",
        "biometric_required",
        "audit_all_events",
        "lanes",
        "created_at",
        "updated_at",
    }
    # description and site_id are None for this fixture → excluded by exclude_none
    assert "description" not in body
    assert "site_id" not in body
    for removed_key in {
        "status",
        "environment",
        "callbacks",
        "api_auth",
        "rate_limits",
        "feature_flags",
        "branding",
        "default_trust_profile_id",
        "default_compliance_profile_id",
        "api_key_prefix",
    }:
        assert removed_key not in body


def test_update_channel_keeps_update_policy_channel_in_sync() -> None:
    repo = deployment_profile.InMemoryDeploymentProfileRepository()
    profile = asyncio.run(_save_profile(repo))
    client, _ = _build_client(repo)

    response = client.patch(
        f"/v1/deployment-profiles/{profile.id}",
        headers={"x-user-id": "user-1"},
        json={"update_channel": "beta"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["update_channel"] == "beta"
    assert body["update_policy"]["channel"] == "beta"
    assert body["update_policy"]["auto_update"] is True


def test_offline_cache_ttl_hours_preserves_existing_environment_config_seconds() -> None:
    repo = deployment_profile.InMemoryDeploymentProfileRepository()
    profile = asyncio.run(_save_profile(repo))
    client, _ = _build_client(repo)

    response = client.patch(
        f"/v1/deployment-profiles/{profile.id}",
        headers={"x-user-id": "user-1"},
        json={"offline_cache_ttl_hours": 12},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["offline_cache_ttl_hours"] == 12
    assert body["environment_config"]["offline_cache_ttl_seconds"] == 86400
