"""Billing Cedar policy engine for plan-tier feature gating.

Evaluates billing-specific Cedar policies using a separate schema and
policy set from the MIP RBAC engine. This keeps payment/plan concerns
out of the protocol-standard MIP Cedar schema.

Internal to the Marty platform — not part of the MIP specification.
"""

import logging
from pathlib import Path
from typing import Any

from .cedar_engine import AuthzDecision, CedarEngine

logger = logging.getLogger(__name__)

_CEDAR_DIR = Path(__file__).parent / "cedar"

# MIP actions that have billing gates (must match billing_policies.cedar)
_BILLING_GATED_ACTIONS: set[str] = {
    "webhooks:read",
    "webhooks:write",
    "audit:read",
    "deployment:write",
}

# Route-prefix → billing action for features that don't map to MIP actions
_ROUTE_BILLING_ACTIONS: dict[str, str] = {
    "/v1/policy-sets": "custom_cedar_policies:access",
    "/v1/devices": "device_registration:access",
    "/v1/webhooks": "webhooks:read",
    "/v1/audit": "audit:read",
    "/v1/audit-logs": "audit:read",
}


class BillingCedarEngine:
    """Cedar engine for plan-tier feature gating.

    Wraps a CedarEngine loaded with the Billing namespace schema and
    billing forbid policies. Provides a simplified interface for checking
    whether a plan tier allows a specific action.
    """

    def __init__(self, engine: CedarEngine):
        self._engine = engine

    @classmethod
    def with_defaults(cls) -> "BillingCedarEngine":
        """Create engine with bundled billing schema and default billing policies."""
        schema = (_CEDAR_DIR / "billing.cedarschema").read_text()
        policies = (_CEDAR_DIR / "billing_policies.cedar").read_text()
        return cls(engine=CedarEngine(schema=schema, policies=policies))

    @classmethod
    def from_files(
        cls,
        schema_path: str | Path,
        policy_paths: list[str | Path],
    ) -> "BillingCedarEngine":
        """Create engine from custom schema and policy files."""
        engine = CedarEngine.from_files(schema_path, policy_paths)
        return cls(engine=engine)

    def is_plan_allowed(
        self,
        plan_tier: str,
        action_name: str,
        org_id: str,
        principal_id: str,
        principal_type: str = "User",
    ) -> AuthzDecision:
        """Check whether a plan tier permits a billing-gated action.

        Args:
            plan_tier: The org's plan tier (free, starter, professional, enterprise).
            action_name: The billing action to check (e.g. "webhooks:read").
            org_id: Organization ID.
            principal_id: User or API key ID.
            principal_type: "User", "ApiKey", or "ServiceAccount".
        """
        entities = [
            {
                "uid": {"type": f"Billing::{principal_type}", "id": principal_id},
                "attrs": {},
                "parents": [{"type": "Billing::Organization", "id": org_id}],
            },
            {
                "uid": {"type": "Billing::Organization", "id": org_id},
                "attrs": {"plan_tier": plan_tier},
                "parents": [],
            },
        ]

        context = {"plan_tier": plan_tier}

        return self._engine.is_authorized(
            principal=f'Billing::{principal_type}::"{principal_id}"',
            action=f'Billing::Action::"{action_name}"',
            resource=f'Billing::Organization::"{org_id}"',
            context=context,
            entities=entities,
        )

    @staticmethod
    def get_billing_action(mip_action: str, path: str) -> str | None:
        """Map an MIP action or route to a billing action, if plan-gated.

        Returns the billing action name if the action/route is gated,
        or None if no billing check is needed.
        """
        # Check if the MIP action itself is billing-gated
        if mip_action in _BILLING_GATED_ACTIONS:
            return mip_action

        # Check if the route maps to a billing-only action
        for prefix, billing_action in _ROUTE_BILLING_ACTIONS.items():
            if path.startswith(prefix):
                return billing_action

        return None
