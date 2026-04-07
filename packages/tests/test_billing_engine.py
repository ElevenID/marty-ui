"""Unit tests for marty_common billing Cedar engine and middleware.

Tests the billing Cedar schema, policies, and engine without requiring
a running gateway or database.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from marty_common.billing_engine import BillingCedarEngine


# ============================================================================
# BillingCedarEngine tests
# ============================================================================


class TestBillingCedarEngineInit:
    def test_with_defaults_creates_engine(self):
        """with_defaults() should load billing schema and policies without error."""
        engine = BillingCedarEngine.with_defaults()
        assert engine is not None
        assert engine._engine is not None


class TestBillingCedarEngineGetBillingAction:
    """Test the static mapping from MIP actions/routes to billing actions."""

    def test_webhooks_read_is_gated(self):
        assert BillingCedarEngine.get_billing_action("webhooks:read", "/v1/organizations/org-1/webhooks") == "webhooks:read"

    def test_webhooks_write_is_gated(self):
        assert BillingCedarEngine.get_billing_action("webhooks:write", "/v1/organizations/org-1/webhooks") == "webhooks:write"

    def test_audit_read_is_gated(self):
        assert BillingCedarEngine.get_billing_action("audit:read", "/v1/organizations/org-1/audit") == "audit:read"

    def test_deployment_write_is_gated(self):
        assert BillingCedarEngine.get_billing_action("deployment:write", "/v1/organizations/org-1/deployment-profiles") == "deployment:write"

    def test_policy_sets_route_gated(self):
        assert BillingCedarEngine.get_billing_action("trust:read", "/v1/policy-sets/123") == "custom_cedar_policies:access"

    def test_devices_route_gated(self):
        assert BillingCedarEngine.get_billing_action("admin:full", "/v1/devices/register") == "device_registration:access"

    def test_credentials_read_not_gated(self):
        assert BillingCedarEngine.get_billing_action("credentials:read", "/v1/organizations/org-1/credentials") is None

    def test_flows_write_not_gated(self):
        assert BillingCedarEngine.get_billing_action("flows:write", "/v1/organizations/org-1/flows") is None

    def test_empty_action(self):
        assert BillingCedarEngine.get_billing_action("", "/v1/organizations/org-1/credentials") is None


class TestBillingCedarEnginePolicies:
    """Test billing Cedar policy evaluation via mocked cedarpy."""

    @patch("marty_common.cedar_engine.cedarpy")
    def test_enterprise_allows_all(self, mock_cedar):
        mock_result = MagicMock()
        mock_result.allowed = True
        mock_result.diagnostics.reasons = ["billing-default-permit"]
        mock_result.diagnostics.errors = []
        mock_cedar.is_authorized.return_value = mock_result

        engine = BillingCedarEngine.with_defaults()
        decision = engine.is_plan_allowed(
            plan_tier="enterprise",
            action_name="webhooks:read",
            org_id="org-1",
            principal_id="u-1",
        )
        assert decision.allowed is True

    @patch("marty_common.cedar_engine.cedarpy")
    def test_free_denies_webhooks(self, mock_cedar):
        mock_result = MagicMock()
        mock_result.allowed = False
        mock_result.diagnostics.reasons = ["billing-deny-webhooks-free"]
        mock_result.diagnostics.errors = []
        mock_cedar.is_authorized.return_value = mock_result

        engine = BillingCedarEngine.with_defaults()
        decision = engine.is_plan_allowed(
            plan_tier="free",
            action_name="webhooks:read",
            org_id="org-1",
            principal_id="u-1",
        )
        assert decision.allowed is False

    @patch("marty_common.cedar_engine.cedarpy")
    def test_passes_correct_entities(self, mock_cedar):
        mock_result = MagicMock()
        mock_result.allowed = True
        mock_result.diagnostics.reasons = []
        mock_result.diagnostics.errors = []
        mock_cedar.is_authorized.return_value = mock_result

        engine = BillingCedarEngine.with_defaults()
        engine.is_plan_allowed(
            plan_tier="starter",
            action_name="audit:read",
            org_id="org-42",
            principal_id="u-7",
            principal_type="ApiKey",
        )

        # Verify the request passed to cedarpy
        call_args = mock_cedar.is_authorized.call_args[0]
        request = call_args[0]
        assert request["principal"] == 'Billing::ApiKey::"u-7"'
        assert request["action"] == 'Billing::Action::"audit:read"'
        assert request["resource"] == 'Billing::Organization::"org-42"'
        assert request["context"] == {"plan_tier": "starter"}

    @patch("marty_common.cedar_engine.cedarpy")
    def test_free_denies_custom_cedar_policies(self, mock_cedar):
        mock_result = MagicMock()
        mock_result.allowed = False
        mock_result.diagnostics.reasons = ["billing-deny-custom-cedar-low-tier"]
        mock_result.diagnostics.errors = []
        mock_cedar.is_authorized.return_value = mock_result

        engine = BillingCedarEngine.with_defaults()
        decision = engine.is_plan_allowed(
            plan_tier="free",
            action_name="custom_cedar_policies:access",
            org_id="org-1",
            principal_id="u-1",
        )
        assert decision.allowed is False

    @patch("marty_common.cedar_engine.cedarpy")
    def test_starter_denies_device_registration(self, mock_cedar):
        mock_result = MagicMock()
        mock_result.allowed = False
        mock_result.diagnostics.reasons = ["billing-deny-device-reg-low-tier"]
        mock_result.diagnostics.errors = []
        mock_cedar.is_authorized.return_value = mock_result

        engine = BillingCedarEngine.with_defaults()
        decision = engine.is_plan_allowed(
            plan_tier="starter",
            action_name="device_registration:access",
            org_id="org-1",
            principal_id="u-1",
        )
        assert decision.allowed is False
