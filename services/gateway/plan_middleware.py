"""
Usage tracking middleware for the API gateway.

Tracks metered usage (verifications, issued credentials, active flows) in
Redis for billing analytics. Enforces monthly usage limits based on the
organization's plan tier.

Feature gates (webhooks, audit, deployment writes, etc.) are enforced by
Cedar forbid policies in plan_policies.cedar. This middleware only handles
numeric metering and the remaining feature gates that don't map cleanly
to Cedar actions (custom_cedar_policies, device_registration).

Execution order: MIPVersion → RateLimit → Auth → ContentType → Cedar → UsageTracking → route
"""

from __future__ import annotations

import logging

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from marty_common.plans import PlanTier, get_plan_limits, check_feature, check_limit
from marty_common.usage import UsageTracker

logger = logging.getLogger(__name__)


# ── Route → metric mapping ──────────────────────────────────────────────
# Which routes count toward which metered usage.

ROUTE_METRIC_MAP: dict[str, str] = {
    # Verification endpoints → count verifications
    "/v1/verify": "verifications",
    "/v1/verify/zkp": "verifications",
    # Flow completion counts as verification (OID4VP)
    "/v1/flows/siop/submit": "verifications",
    # Issuance endpoints → count issued credentials
    "/v1/issuance": "issued_credentials",
    # Flow creation → active flow gauge
    "/v1/flows": "active_flows",
}

# ── Route → feature gate mapping (non-Cedar) ────────────────────────────
# Features that don't map cleanly to Cedar actions. Cedar handles webhooks,
# audit_logs, and deployment writes; these remain here.

ROUTE_FEATURE_GATE: dict[str, str] = {
    "/v1/policy-sets": "custom_cedar_policies",
    "/v1/devices": "device_registration",
}

# Routes that should only increment metrics on write operations
WRITE_METHODS = {"POST", "PUT", "PATCH"}

# Paths that skip usage tracking entirely (public, health, auth)
SKIP_PREFIXES = (
    "/health",
    "/v1/auth",
    "/.well-known",
    "/openapi.json",
    "/docs",
    "/v1/issuance/offers",
    "/v1/issuance/token",
    "/v1/issuance/nonce",
    "/v1/issuance/authorize",
    "/v1/issuance/notification",
    "/v1/issuance/deferred-credential",
    "/v1/flows/instances/",  # wallet-facing OID4VP
    "/v1/trust-registry",
    "/v1/plans",
    "/v1/usage",
    "/v1/billing",
)


class UsageTrackingMiddleware(BaseHTTPMiddleware):
    """
    Tracks metered usage and enforces monthly limits by plan tier.
    Also enforces remaining feature gates not handled by Cedar.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path

        # Skip non-org-scoped or public routes
        if any(path.startswith(p) for p in SKIP_PREFIXES):
            return await call_next(request)

        # Need authenticated org context (set by Cedar middleware)
        org_id = getattr(request.state, "organization_id", None)
        if not org_id:
            return await call_next(request)

        # Use plan from Cedar middleware (already resolved from Redis)
        plan_str = getattr(request.state, "org_plan", "free")
        try:
            plan = PlanTier(plan_str)
        except ValueError:
            plan = PlanTier.FREE
        limits = get_plan_limits(plan)

        # ── Feature gates (non-Cedar) ───────────────────────────────
        for prefix, feature in ROUTE_FEATURE_GATE.items():
            if path.startswith(prefix) and not check_feature(limits, feature):
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "plan_feature_unavailable",
                        "message": f"This feature requires the {_min_plan_for_feature(feature)} plan or higher.",
                        "feature": feature,
                        "current_plan": plan.value,
                        "upgrade_url": "/pricing",
                    },
                )

        # ── Usage limit checks (pre-request) ────────────────────────
        tracker: UsageTracker | None = getattr(request.app.state, "usage_tracker", None)
        if tracker and request.method in WRITE_METHODS:
            metric = _resolve_metric(path)
            if metric:
                if metric == "active_flows":
                    # Check concurrent flow gauge against limit
                    current = await tracker.get(org_id, "active_flows")
                    if not check_limit(limits, metric, current):
                        limit_val = getattr(limits, metric, None)
                        return JSONResponse(
                            status_code=429,
                            content={
                                "error": "plan_limit_exceeded",
                                "message": f"Concurrent active flows limit reached ({limit_val}).",
                                "metric": metric,
                                "current": current,
                                "limit": limit_val,
                                "current_plan": plan.value,
                                "upgrade_url": "/pricing",
                            },
                        )
                else:
                    current = await tracker.get(org_id, metric)
                    if not check_limit(limits, metric, current):
                        limit_val = getattr(limits, f"{metric}_per_month", None)
                        return JSONResponse(
                            status_code=429,
                            content={
                                "error": "plan_limit_exceeded",
                                "message": f"Monthly {metric.replace('_', ' ')} limit reached ({limit_val}).",
                                "metric": metric,
                                "current": current,
                                "limit": limit_val,
                                "current_plan": plan.value,
                                "upgrade_url": "/pricing",
                            },
                        )

        # ── Execute request ──────────────────────────────────────────
        response = await call_next(request)

        # ── Post-request usage tracking (only on success) ────────────
        if tracker and response.status_code < 400 and request.method in WRITE_METHODS:
            metric = _resolve_metric(path)
            if metric:
                if metric == "active_flows":
                    await tracker.increment_gauge(org_id, "active_flows")
                else:
                    await tracker.increment(org_id, metric)
            # Always increment API calls counter (for analytics)
            await tracker.increment(org_id, "api_calls")

        return response


def _resolve_metric(path: str) -> str | None:
    """Find the usage metric for a given path."""
    for prefix, metric in ROUTE_METRIC_MAP.items():
        if path.startswith(prefix):
            return metric
    return None


def _min_plan_for_feature(feature: str) -> str:
    """Return the minimum plan tier name that includes a feature."""
    for tier in [PlanTier.STARTER, PlanTier.PROFESSIONAL, PlanTier.ENTERPRISE]:
        if check_feature(get_plan_limits(tier), feature):
            return tier.value.capitalize()
    return "Enterprise"
