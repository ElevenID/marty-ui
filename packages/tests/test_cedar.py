"""Unit tests for marty_common Cedar authorization modules.

Tests cedar_engine, cedar_entities, cedar_actions, and cedar_middleware
without requiring a running gateway or database.
"""

from __future__ import annotations

import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from marty_common.cedar_actions import (
    RESOURCE_ACTION_MAP,
    extract_org_id,
    resolve_action,
    resolve_action_and_resource,
)
from marty_common.cedar_engine import AuthzDecision, CedarEngine
from marty_common.cedar_entities import (
    build_apikey_entities,
    build_request_context,
    build_user_entities,
)


# ============================================================================
# cedar_actions tests
# ============================================================================


class TestResolveAction:
    def test_get_credentials(self):
        assert resolve_action("GET", "/v1/organizations/00000000-0000-0000-0000-000000000001/credentials") == "credentials:read"

    def test_post_credentials(self):
        assert resolve_action("POST", "/v1/organizations/00000000-0000-0000-0000-000000000001/credentials") == "credentials:issue"

    def test_delete_credentials(self):
        assert resolve_action("DELETE", "/v1/organizations/00000000-0000-0000-0000-000000000001/credentials/123") == "credentials:revoke"

    def test_get_members(self):
        assert resolve_action("GET", "/v1/organizations/00000000-0000-0000-0000-000000000001/members") == "users:read"

    def test_post_invitations(self):
        assert resolve_action("POST", "/v1/organizations/00000000-0000-0000-0000-000000000001/invitations") == "users:invite"

    def test_settings_always_admin(self):
        for method in ("GET", "POST", "PUT", "DELETE"):
            assert resolve_action(method, "/v1/organizations/00000000-0000-0000-0000-000000000001/settings") == "admin:full"

    def test_unknown_resource_defaults_admin(self):
        assert resolve_action("GET", "/v1/organizations/00000000-0000-0000-0000-000000000001/unknown-thing") == "admin:full"

    def test_non_org_path_returns_none(self):
        assert resolve_action("GET", "/health") is None
        assert resolve_action("GET", "/v1/auth/login") is None

    def test_head_options_count_as_read(self):
        assert resolve_action("HEAD", "/v1/organizations/00000000-0000-0000-0000-000000000001/flows") == "flows:read"
        assert resolve_action("OPTIONS", "/v1/organizations/00000000-0000-0000-0000-000000000001/flows") == "flows:read"

    def test_all_resource_segments_mapped(self):
        org_prefix = "/v1/organizations/00000000-0000-0000-0000-000000000001/"
        for segment in RESOURCE_ACTION_MAP:
            action = resolve_action("GET", org_prefix + segment)
            assert action is not None, f"GET {segment} returned None"

    def test_policy_sets(self):
        assert resolve_action("GET", "/v1/organizations/00000000-0000-0000-0000-000000000001/policy-sets") == "trust:read"
        assert resolve_action("POST", "/v1/organizations/00000000-0000-0000-0000-000000000001/policy-sets") == "trust:admin"


class TestResolveActionAndResource:
    ORG_PREFIX = "/v1/organizations/00000000-0000-0000-0000-000000000001/"

    def test_credentials_returns_credential_type(self):
        result = resolve_action_and_resource("GET", self.ORG_PREFIX + "credentials")
        assert result == ("credentials:read", "Credential")

    def test_trust_profiles_returns_trust_profile_type(self):
        result = resolve_action_and_resource("POST", self.ORG_PREFIX + "trust-profiles")
        assert result == ("trust:write", "TrustProfile")

    def test_members_returns_user_type(self):
        result = resolve_action_and_resource("GET", self.ORG_PREFIX + "members")
        assert result == ("users:read", "User")

    def test_settings_returns_organization_type(self):
        result = resolve_action_and_resource("PUT", self.ORG_PREFIX + "settings")
        assert result == ("admin:full", "Organization")

    def test_unknown_defaults_to_organization(self):
        result = resolve_action_and_resource("GET", self.ORG_PREFIX + "unknown-thing")
        assert result == ("admin:full", "Organization")

    def test_non_org_path_returns_none(self):
        assert resolve_action_and_resource("GET", "/health") is None

    def test_all_segments_have_resource_type(self):
        for segment, actions in RESOURCE_ACTION_MAP.items():
            assert len(actions) == 4, f"{segment} tuple should have 4 elements"
            assert actions[3], f"{segment} has empty resource type"

    def test_flows_returns_flow_type(self):
        result = resolve_action_and_resource("POST", self.ORG_PREFIX + "flows")
        assert result == ("flows:write", "Flow")

    def test_delete_credentials(self):
        result = resolve_action_and_resource("DELETE", self.ORG_PREFIX + "credentials/123")
        assert result == ("credentials:revoke", "Credential")


class TestExtractOrgId:
    def test_extracts_uuid(self):
        org_id = extract_org_id("/v1/organizations/00000000-0000-0000-0000-000000000001/members")
        assert org_id == "00000000-0000-0000-0000-000000000001"

    def test_non_org_path(self):
        assert extract_org_id("/health") is None
        assert extract_org_id("/v1/auth/login") is None


# ============================================================================
# cedar_entities tests
# ============================================================================


class TestBuildUserEntities:
    def test_basic_user(self):
        entities = build_user_entities(
            user_id="u-1",
            email="alice@test.com",
            status="ACTIVE",
            org_id="org-1",
            role="member",
        )
        assert len(entities) == 3  # User, Organization, Role

        user = next(e for e in entities if e["uid"]["type"] == "MIP::User")
        assert user["uid"]["id"] == "u-1"
        assert user["attrs"]["email"] == "alice@test.com"
        assert user["attrs"]["status"] == "ACTIVE"
        assert {"type": "MIP::Organization", "id": "org-1"} in user["parents"]
        assert {"type": "MIP::Role", "id": "member"} in user["parents"]

    def test_org_entity_present(self):
        entities = build_user_entities("u", "e", "ACTIVE", "org-1", "admin")
        org = next(e for e in entities if e["uid"]["type"] == "MIP::Organization")
        assert org["uid"]["id"] == "org-1"
        assert org["parents"] == []

    def test_role_entity_present(self):
        entities = build_user_entities("u", "e", "ACTIVE", "org-1", "Owner")
        role = next(e for e in entities if e["uid"]["type"] == "MIP::Role")
        assert role["uid"]["id"] == "owner"  # lowercased
        assert role["attrs"]["is_system_role"] is True


class TestBuildApiKeyEntities:
    def test_org_scoped_key(self):
        entities = build_apikey_entities(
            api_key_id="key-1",
            org_id="org-1",
            scope_type="ORGANIZATION",
            enabled=True,
        )
        assert len(entities) == 2  # ApiKey, Organization

        key = next(e for e in entities if e["uid"]["type"] == "MIP::ApiKey")
        assert key["uid"]["id"] == "key-1"
        assert key["attrs"]["scope_type"] == "ORGANIZATION"
        assert key["attrs"]["enabled"] is True

    def test_deployment_scoped_key(self):
        entities = build_apikey_entities(
            api_key_id="key-2",
            org_id="org-1",
            scope_type="DEPLOYMENT",
            enabled=True,
            deployment_profile_id="dp-1",
        )
        assert len(entities) == 3  # ApiKey, Organization, DeploymentProfile

        dp = next(e for e in entities if e["uid"]["type"] == "MIP::DeploymentProfile")
        assert dp["uid"]["id"] == "dp-1"

        key = next(e for e in entities if e["uid"]["type"] == "MIP::ApiKey")
        assert {"type": "MIP::DeploymentProfile", "id": "dp-1"} in key["parents"]

    def test_disabled_key(self):
        entities = build_apikey_entities("k", "o", "ORGANIZATION", enabled=False)
        key = next(e for e in entities if e["uid"]["type"] == "MIP::ApiKey")
        assert key["attrs"]["enabled"] is False


class TestBuildRequestContext:
    def test_minimal(self):
        ctx = build_request_context(ip_address="10.0.0.1")
        assert ctx["ip_address"] == {"__extn": {"fn": "ip", "arg": "10.0.0.1"}}
        assert isinstance(ctx["timestamp"], int)
        assert ctx["mfa_authenticated"] is False
        assert "session_id" not in ctx
        assert "user_agent" not in ctx

    def test_full(self):
        ctx = build_request_context(
            ip_address="192.168.1.1",
            mfa_authenticated=True,
            session_id="sess-1",
            user_agent="TestAgent/1.0",
        )
        assert ctx["mfa_authenticated"] is True
        assert ctx["session_id"] == "sess-1"
        assert ctx["user_agent"] == "TestAgent/1.0"

    def test_timestamp_is_recent(self):
        before = int(time.time())
        ctx = build_request_context(ip_address="127.0.0.1")
        after = int(time.time())
        assert before <= ctx["timestamp"] <= after


# ============================================================================
# cedar_engine tests
# ============================================================================


class TestAuthzDecision:
    def test_allowed(self):
        d = AuthzDecision(allowed=True, reasons=["policy-1"])
        assert d.allowed is True
        assert d.reasons == ["policy-1"]

    def test_denied(self):
        d = AuthzDecision(allowed=False, errors=["boom"])
        assert d.allowed is False

    def test_defaults(self):
        d = AuthzDecision(allowed=True)
        assert d.reasons == []
        assert d.errors == []

    def test_immutable(self):
        d = AuthzDecision(allowed=True)
        with pytest.raises(AttributeError):
            d.allowed = False  # type: ignore[misc]


class TestCedarEngine:
    def test_init(self):
        engine = CedarEngine(schema="s", policies="p")
        assert engine._schema == "s"
        assert engine._policies == "p"

    def test_policies_property(self):
        engine = CedarEngine(schema="s", policies="p1")
        assert engine.policies == "p1"
        engine.policies = "p2"
        assert engine.policies == "p2"

    def test_append_policies(self):
        engine = CedarEngine(schema="s", policies="first")
        engine.append_policies("second")
        assert "first" in engine.policies
        assert "second" in engine.policies

    @patch("marty_common.cedar_engine.cedarpy")
    def test_is_authorized_allowed(self, mock_cedar):
        mock_result = MagicMock()
        mock_result.allowed = True
        mock_result.diagnostics.reasons = ["policy-1"]
        mock_result.diagnostics.errors = []
        mock_cedar.is_authorized.return_value = mock_result

        engine = CedarEngine(schema="schema", policies="policies")
        decision = engine.is_authorized(
            principal='MIP::User::"u-1"',
            action='MIP::Action::"credentials:read"',
            resource='MIP::Organization::"org-1"',
            context={"ip_address": {"__extn": {"fn": "ip", "arg": "10.0.0.1"}}},
            entities=[],
        )
        assert decision.allowed is True
        assert decision.reasons == ["policy-1"]

    @patch("marty_common.cedar_engine.cedarpy")
    def test_is_authorized_denied(self, mock_cedar):
        mock_result = MagicMock()
        mock_result.allowed = False
        mock_result.diagnostics.reasons = []
        mock_result.diagnostics.errors = []
        mock_cedar.is_authorized.return_value = mock_result

        engine = CedarEngine(schema="schema", policies="policies")
        decision = engine.is_authorized(
            principal='MIP::User::"u-1"',
            action='MIP::Action::"admin:full"',
            resource='MIP::Organization::"org-1"',
            context={},
            entities=[],
        )
        assert decision.allowed is False

    @patch("marty_common.cedar_engine.cedarpy")
    def test_is_authorized_error_returns_denied(self, mock_cedar):
        mock_cedar.is_authorized.side_effect = RuntimeError("engine fail")

        engine = CedarEngine(schema="schema", policies="policies")
        decision = engine.is_authorized(
            principal='MIP::User::"u-1"',
            action='MIP::Action::"x"',
            resource='MIP::Organization::"o"',
            context={},
            entities=[],
        )
        assert decision.allowed is False
        assert "engine fail" in decision.errors[0]

    @patch("marty_common.cedar_engine.cedarpy")
    def test_entities_serialized_as_json(self, mock_cedar):
        mock_result = MagicMock()
        mock_result.allowed = True
        mock_result.diagnostics.reasons = []
        mock_result.diagnostics.errors = []
        mock_cedar.is_authorized.return_value = mock_result

        entities = [
            {"uid": {"type": "MIP::User", "id": "u-1"}, "attrs": {}, "parents": []}
        ]
        engine = CedarEngine(schema="s", policies="p")
        engine.is_authorized(
            principal='MIP::User::"u-1"',
            action='MIP::Action::"x"',
            resource='MIP::Organization::"o"',
            context={},
            entities=entities,
        )

        # Verify entities were JSON-serialized
        call_args = mock_cedar.is_authorized.call_args[0]
        entities_arg = call_args[2]  # 3rd positional arg
        assert json.loads(entities_arg) == entities
