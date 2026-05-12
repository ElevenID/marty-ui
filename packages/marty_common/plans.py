"""
Plan definitions and infrastructure limits for ElevenID.

Reads from plan_catalog.json — the single source of truth shared by backend,
middleware, and UI.

Philosophy: ElevenID is credentialing infrastructure for education. You pay
for deployments, governance, and orchestration capacity — not per-verification
or per-issuance fees. Protocol activity is unlimited on paid plans.

Sandbox has fair-use limits (5,000 combined events/month) and is
non-production only.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any


# ── Load catalog ─────────────────────────────────────────────────────────

_CATALOG_PATH = Path(__file__).parent / "plan_catalog.json"

with open(_CATALOG_PATH, encoding="utf-8") as _f:
    PLAN_CATALOG: dict[str, Any] = json.load(_f)


# ── Plan IDs ─────────────────────────────────────────────────────────────

class PlanTier(str, Enum):
    """Stable internal plan IDs."""
    SANDBOX = "sandbox"
    PROGRAM = "program"
    INSTITUTION = "institution"
    SYSTEM = "system"


def normalize_plan_identifier(tier: PlanTier | str | None) -> str | None:
    """Normalize a plan identifier without forcing it into an internal tier."""
    if tier is None:
        return None
    if isinstance(tier, PlanTier):
        return tier.value

    normalized = str(tier).strip().lower()
    return normalized or None


# ── Entitlements ─────────────────────────────────────────────────────────

@dataclass(frozen=True)
class PlanLimits:
    """Infrastructure entitlements for a plan tier.

    -1 means unlimited. None for audit_retention_days means custom/negotiated.
    """

    # Infrastructure capacity
    deployments: int | None          # -1 = unlimited
    verifier_instances: int | None
    active_flows: int | None         # "Programs / workflows" in education UI
    badge_templates: int | None      # "Badge templates" in education UI
    admin_seats: int | None          # "Admin seats" in education UI

    # Audit & retention
    audit_retention_days: int | None  # None = custom / unlimited

    # Protocol activity mode
    verifications_mode: str           # "fair_use" | "unlimited"
    issuances_mode: str               # "fair_use" | "unlimited"
    sandbox_monthly_activity_limit: int | None  # only applies when mode=fair_use

    # Key management
    key_management: tuple[str, ...]

    # Support tier
    support_tier: str                 # community | standard | priority | dedicated

    # Feature gates
    open_badge_issuance: bool
    badge_verification_page: bool
    criteria_evidence_fields: bool
    learner_share_pages: bool
    custom_branding: bool
    webhooks: bool
    audit_logs: bool
    csv_roster_import: bool
    approval_workflow: bool
    multi_environment: bool
    custom_cedar_policies: bool
    remote_signing: bool
    scim_provisioning: bool
    self_hosted: bool
    trust_registry_federation: bool
    byok_hsm: bool
    zk_verification: bool


def _build_limits(plan: dict) -> PlanLimits:
    """Build a PlanLimits from a catalog plan entry."""
    ent = plan["entitlements"]
    flags = plan["feature_flags"]
    return PlanLimits(
        deployments=ent["deployments"],
        verifier_instances=ent["verifier_instances"],
        active_flows=ent["active_flows"],
        badge_templates=ent["badge_templates"],
        admin_seats=ent["admin_seats"],
        audit_retention_days=ent["audit_retention_days"],
        verifications_mode=ent.get("verifications_mode", "unlimited"),
        issuances_mode=ent.get("issuances_mode", "unlimited"),
        sandbox_monthly_activity_limit=ent.get("sandbox_monthly_activity_limit"),
        key_management=tuple(plan.get("key_management", [])),
        support_tier=plan.get("support_tier", "community"),
        open_badge_issuance=flags.get("open_badge_issuance", True),
        badge_verification_page=flags.get("badge_verification_page", True),
        criteria_evidence_fields=flags.get("criteria_evidence_fields", True),
        learner_share_pages=flags.get("learner_share_pages", True),
        custom_branding=flags.get("custom_branding", False),
        webhooks=flags.get("webhooks", False),
        audit_logs=flags.get("audit_logs", False),
        csv_roster_import=flags.get("csv_roster_import", False),
        approval_workflow=flags.get("approval_workflow", False),
        multi_environment=flags.get("multi_environment", False),
        custom_cedar_policies=flags.get("custom_cedar_policies", False),
        remote_signing=flags.get("remote_signing", False),
        scim_provisioning=flags.get("scim_provisioning", False),
        self_hosted=flags.get("self_hosted", False),
        trust_registry_federation=flags.get("trust_registry_federation", False),
        byok_hsm=flags.get("byok_hsm", False),
        zk_verification=flags.get("zk_verification", True),
    )


# Build the lookup table from catalog
PLAN_LIMITS: dict[PlanTier, PlanLimits] = {}
for _plan_entry in PLAN_CATALOG["plans"]:
    _tier = PlanTier(_plan_entry["plan_id"])
    PLAN_LIMITS[_tier] = _build_limits(_plan_entry)


# ── Billing ──────────────────────────────────────────────────────────────

BILLING_INTERVALS: dict[str, dict] = PLAN_CATALOG["billing_intervals"]


def price_for_interval(annual_price: int, interval: str) -> int:
    """Calculate the total contract price for a billing interval.

    Annual price is the base. Multi-year intervals get discounts.
    Monthly is a premium on Program only (monthly_price is explicit in catalog).
    """
    info = BILLING_INTERVALS.get(interval)
    if not info:
        return annual_price
    discount = info.get("discount_pct", 0)
    years = info["months"] / 12
    return round(annual_price * years * (1 - discount / 100))


# ── Plan metadata (for display) ─────────────────────────────────────────

@dataclass(frozen=True)
class PlanInfo:
    """Display metadata for a plan tier."""
    plan_id: str
    display_name: str
    tagline: str
    annual_price: int | None  # None = custom
    monthly_price: int | None
    starting_annual_price: int | None


PLAN_INFO: dict[PlanTier, PlanInfo] = {}
for _plan_entry in PLAN_CATALOG["plans"]:
    _tier = PlanTier(_plan_entry["plan_id"])
    _billing = _plan_entry["billing"]
    PLAN_INFO[_tier] = PlanInfo(
        plan_id=_plan_entry["plan_id"],
        display_name=_plan_entry["display_name"],
        tagline=_plan_entry["tagline"],
        annual_price=_billing.get("annual_price"),
        monthly_price=_billing.get("monthly_price"),
        starting_annual_price=_billing.get("starting_annual_price"),
    )


_COMMERCIAL_PLAN_INFO: dict[str, PlanInfo] = {
    "free": PlanInfo(
        plan_id="free",
        display_name="Developer Sandbox",
        tagline="Free shared cloud for developer testing only.",
        annual_price=0,
        monthly_price=0,
        starting_annual_price=0,
    ),
    "starter": PlanInfo(
        plan_id="starter",
        display_name="Hosted Pilot",
        tagline="Managed pilot with automatic 30-day purge.",
        annual_price=None,
        monthly_price=299,
        starting_annual_price=None,
    ),
    "hosted_pilot": PlanInfo(
        plan_id="starter",
        display_name="Hosted Pilot",
        tagline="Managed pilot with automatic 30-day purge.",
        annual_price=None,
        monthly_price=299,
        starting_annual_price=None,
    ),
    "pilot": PlanInfo(
        plan_id="starter",
        display_name="Hosted Pilot",
        tagline="Managed pilot with automatic 30-day purge.",
        annual_price=None,
        monthly_price=299,
        starting_annual_price=None,
    ),
    "professional": PlanInfo(
        plan_id="professional",
        display_name="Self-Hosted Production",
        tagline="Customer-managed production deployment.",
        annual_price=12000,
        monthly_price=None,
        starting_annual_price=12000,
    ),
    "self_hosted_production": PlanInfo(
        plan_id="professional",
        display_name="Self-Hosted Production",
        tagline="Customer-managed production deployment.",
        annual_price=12000,
        monthly_price=None,
        starting_annual_price=12000,
    ),
    "self-hosted-production": PlanInfo(
        plan_id="professional",
        display_name="Self-Hosted Production",
        tagline="Customer-managed production deployment.",
        annual_price=12000,
        monthly_price=None,
        starting_annual_price=12000,
    ),
    "production": PlanInfo(
        plan_id="professional",
        display_name="Self-Hosted Production",
        tagline="Customer-managed production deployment.",
        annual_price=12000,
        monthly_price=None,
        starting_annual_price=12000,
    ),
    "enterprise": PlanInfo(
        plan_id="enterprise",
        display_name="Enterprise",
        tagline="Custom deployment and support package.",
        annual_price=None,
        monthly_price=None,
        starting_annual_price=60000,
    ),
}


_PLAN_TIER_ALIASES: dict[str, PlanTier] = {
    PlanTier.SANDBOX.value: PlanTier.SANDBOX,
    PlanTier.PROGRAM.value: PlanTier.PROGRAM,
    PlanTier.INSTITUTION.value: PlanTier.INSTITUTION,
    PlanTier.SYSTEM.value: PlanTier.SYSTEM,
    "free": PlanTier.SANDBOX,
    "starter": PlanTier.PROGRAM,
    "hosted_pilot": PlanTier.PROGRAM,
    "pilot": PlanTier.PROGRAM,
    "professional": PlanTier.PROGRAM,
    "self_hosted_production": PlanTier.PROGRAM,
    "self-hosted-production": PlanTier.PROGRAM,
    "production": PlanTier.PROGRAM,
    "enterprise": PlanTier.SYSTEM,
    "sovereign_plus": PlanTier.SYSTEM,
    "sovereign+": PlanTier.SYSTEM,
}


# ── Display labels (education market) ───────────────────────────────────

DISPLAY_LABELS: dict[str, str] = PLAN_CATALOG["display_labels"]


# ── Enforcement categories ───────────────────────────────────────────────

ENFORCEMENT = PLAN_CATALOG["enforcement"]

HARD_ENFORCED = ENFORCEMENT["hard_enforced"]

ANALYTICS_ONLY = ENFORCEMENT["analytics_only"]

SANDBOX_FAIR_USE = ENFORCEMENT["sandbox_fair_use"]

# Legacy compat aliases
USAGE_METRICS = ANALYTICS_ONLY
RESOURCE_GAUGES = HARD_ENFORCED


# ── Add-ons & onboarding ────────────────────────────────────────────────

ADDONS = PLAN_CATALOG["addons"]
ONBOARDING_SKUS = PLAN_CATALOG["onboarding_skus"]


# ── Helpers ──────────────────────────────────────────────────────────────

def get_plan_limits(tier: PlanTier | str) -> PlanLimits:
    """Get limits for a plan tier."""
    if isinstance(tier, str):
        tier = resolve_plan_tier(tier)
    return PLAN_LIMITS[tier]


def resolve_plan_tier(tier: PlanTier | str | None, *, default: PlanTier = PlanTier.SANDBOX) -> PlanTier:
    """Resolve a plan identifier to an internal entitlement tier."""
    if isinstance(tier, PlanTier):
        return tier

    normalized = normalize_plan_identifier(tier)
    if not normalized:
        return default

    return _PLAN_TIER_ALIASES.get(normalized, default)


def resolve_plan_info(tier: PlanTier | str | None) -> PlanInfo:
    """Resolve user-facing plan metadata for internal or commercial plan IDs."""
    if isinstance(tier, PlanTier):
        return PLAN_INFO[tier]

    normalized = normalize_plan_identifier(tier)
    if not normalized:
        return PLAN_INFO[PlanTier.SANDBOX]

    commercial_info = _COMMERCIAL_PLAN_INFO.get(normalized)
    if commercial_info is not None:
        return commercial_info

    return PLAN_INFO[resolve_plan_tier(normalized)]


def check_limit(limits: PlanLimits, metric: str, current_value: int) -> bool:
    """Check if current usage is within plan limits.

    Returns True if allowed. -1 means unlimited.
    """
    limit_map = {
        "active_flows": limits.active_flows,
        "badge_templates": limits.badge_templates,
        "deployments": limits.deployments,
        "verifier_instances": limits.verifier_instances,
        "admin_seats": limits.admin_seats,
    }
    cap = limit_map.get(metric)
    if cap is None or cap == -1:
        return True  # unlimited
    return current_value < cap


def check_sandbox_fair_use(
    limits: PlanLimits,
    current_monthly_events: int,
) -> bool:
    """Check if sandbox fair-use activity limit is exceeded.

    Returns True if allowed.
    """
    if limits.verifications_mode != "fair_use":
        return True  # paid plans are unlimited
    cap = limits.sandbox_monthly_activity_limit
    if cap is None:
        return True
    return current_monthly_events < cap


def check_feature(limits: PlanLimits, feature: str) -> bool:
    """Check if a feature is enabled for the plan. Returns True if allowed."""
    return getattr(limits, feature, False)
