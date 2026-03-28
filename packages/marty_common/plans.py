"""
Plan definitions and usage limits for ElevenID.

Single source of truth for plan tiers, feature gates, and usage limits.
Used by gateway middleware (enforcement), organization service (plan field),
and mirrored in the UI PricingPage.

Metric philosophy: track verifications, issued credentials, and active flows
as the primary billable units — aligned with the protocol, not raw API calls.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Literal


class PlanTier(str, Enum):
    """Available plan tiers."""
    FREE = "free"
    STARTER = "starter"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"


@dataclass(frozen=True)
class PlanLimits:
    """Usage limits for a plan tier."""

    # Primary metrics (protocol-aligned)
    verifications_per_month: int | None  # None = unlimited
    issued_credentials_per_month: int | None
    active_flows: int | None  # concurrent OID4VP/SIOP flows

    # Organization limits
    members: int | None
    credential_templates: int | None
    deployment_profiles: int | None

    # Feature gates (bool = included or not)
    custom_branding: bool = False
    webhooks: bool = False
    audit_logs: bool = False
    multi_environment: bool = False
    custom_cedar_policies: bool = False
    scim_provisioning: bool = False
    self_hosted: bool = False
    priority_support: bool = False
    dedicated_support: bool = False
    zkp_verification: bool = False
    device_registration: bool = False  # kiosk


# ── Plan definitions ─────────────────────────────────────────────────────

PLAN_LIMITS: dict[PlanTier, PlanLimits] = {
    PlanTier.FREE: PlanLimits(
        verifications_per_month=500,
        issued_credentials_per_month=50,
        active_flows=5,
        members=5,
        credential_templates=3,
        deployment_profiles=1,
        custom_branding=False,
        webhooks=False,
        audit_logs=False,
        zkp_verification=True,  # all protocol features unlocked
    ),
    PlanTier.STARTER: PlanLimits(
        verifications_per_month=1_000,
        issued_credentials_per_month=500,
        active_flows=25,
        members=25,
        credential_templates=None,  # unlimited
        deployment_profiles=2,
        custom_branding=True,
        webhooks=True,
        audit_logs=True,
        zkp_verification=True,
        priority_support=True,
    ),
    PlanTier.PROFESSIONAL: PlanLimits(
        verifications_per_month=10_000,
        issued_credentials_per_month=5_000,
        active_flows=100,
        members=100,
        credential_templates=None,
        deployment_profiles=5,
        custom_branding=True,
        webhooks=True,
        audit_logs=True,
        multi_environment=True,
        custom_cedar_policies=True,
        zkp_verification=True,
        device_registration=True,
        priority_support=True,
    ),
    PlanTier.ENTERPRISE: PlanLimits(
        verifications_per_month=None,
        issued_credentials_per_month=None,
        active_flows=None,
        members=None,
        credential_templates=None,
        deployment_profiles=None,
        custom_branding=True,
        webhooks=True,
        audit_logs=True,
        multi_environment=True,
        custom_cedar_policies=True,
        scim_provisioning=True,
        self_hosted=True,
        zkp_verification=True,
        device_registration=True,
        priority_support=True,
        dedicated_support=True,
    ),
}


# ── Plan metadata (for display) ─────────────────────────────────────────

@dataclass(frozen=True)
class PlanInfo:
    """Display metadata for a plan tier."""
    tier: PlanTier
    name: str
    tagline: str
    headline: str
    price_monthly: int | None  # None = custom
    differentiator: str


PLAN_INFO: dict[PlanTier, PlanInfo] = {
    PlanTier.FREE: PlanInfo(
        tier=PlanTier.FREE,
        name="The Sandbox",
        tagline="Experiment with Standards",
        headline="$0",
        price_monthly=0,
        differentiator="All OID4VCI / OID4VP features enabled. No protocol gating.",
    ),
    PlanTier.STARTER: PlanInfo(
        tier=PlanTier.STARTER,
        name="The Launchpad",
        tagline="First Production App",
        headline="$99/mo",
        price_monthly=99,
        differentiator="Custom branding and presentation policies. Stop paying $1.50 per check.",
    ),
    PlanTier.PROFESSIONAL: PlanInfo(
        tier=PlanTier.PROFESSIONAL,
        name="The Trust Fabric",
        tagline="Multi-App Orchestration",
        headline="$399/mo",
        price_monthly=399,
        differentiator="Audit-ready logs and multi-environment management. Built for scale.",
    ),
    PlanTier.ENTERPRISE: PlanInfo(
        tier=PlanTier.ENTERPRISE,
        name="The Sovereign Choice",
        tagline="Your Trust, Your Infrastructure",
        headline="Custom",
        price_monthly=None,
        differentiator="Air-gapped deployments, dedicated data residency, and 24/7 support.",
    ),
}


# ── Usage metric keys (for Redis counters) ───────────────────────────────

USAGE_METRICS = [
    "verifications",
    "issued_credentials",
    "active_flows",
    "api_calls",  # tracked for analytics, not billed
]


def get_plan_limits(tier: PlanTier | str) -> PlanLimits:
    """Get limits for a plan tier."""
    if isinstance(tier, str):
        tier = PlanTier(tier)
    return PLAN_LIMITS[tier]


def check_limit(limits: PlanLimits, metric: str, current_value: int) -> bool:
    """Check if current usage is within plan limits. Returns True if allowed."""
    limit_map = {
        "verifications": limits.verifications_per_month,
        "issued_credentials": limits.issued_credentials_per_month,
        "active_flows": limits.active_flows,
        "members": limits.members,
        "credential_templates": limits.credential_templates,
        "deployment_profiles": limits.deployment_profiles,
    }
    cap = limit_map.get(metric)
    if cap is None:
        return True  # unlimited
    return current_value < cap


def check_feature(limits: PlanLimits, feature: str) -> bool:
    """Check if a feature is enabled for the plan. Returns True if allowed."""
    return getattr(limits, feature, False)
