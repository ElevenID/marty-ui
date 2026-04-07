"""
Usage tracking middleware for the API gateway.

Tracks protocol activity (verifications, issued credentials) in Redis for
analytics only — these are never rejected on paid plans. Infrastructure
resource gauges (active flows, deployments, verifier instances, badge
templates, admin seats) are hard-enforced against the organization's plan tier.

Sandbox plans have fair-use enforcement: combined issuance + verification
events are capped at 5,000/month. When exceeded, an upgrade banner is shown
but requests are still processed (soft cap with warning header).

Feature gates (webhooks, audit, custom_cedar_policies, etc.) are enforced
by BillingAuthMiddleware using Cedar billing policies. This middleware handles
resource gauge enforcement, sandbox fair-use tracking, and analytics counters.

Execution order: MIPVersion → RateLimit → Auth → ContentType → Cedar → Billing → UsageTracking → route
"""

from __future__ import annotations

import logging

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from marty_common.plans import PlanTier, get_plan_limits, check_limit, check_sandbox_fair_use
from marty_common.usage import UsageTracker

logger = logging.getLogger(__name__)


# ── Route → metric mapping ──────────────────────────────────────────────
# Analytics counters: tracked but never enforced on paid plans.
ANALYTICS_METRIC_MAP: dict[str, str] = {
    "/v1/verify": "verifications",
    "/v1/verify/zkp": "verifications",
    "/v1/flows/siop/submit": "verifications",
    "/v1/issuance": "issued_credentials",
}

# Enforced resource gauges: creation is blocked when the plan limit is reached.
ENFORCED_GAUGE_MAP: dict[str, str] = {
    "/v1/flows": "active_flows",
    "/v1/badge-templates": "badge_templates",
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
    "/v1/issuance/par",
    "/v1/issuance/notification",
    "/v1/issuance/deferred-credential",
    "/v1/flows/instances/",  # wallet-facing OID4VP
)


class UsageTrackingMiddleware(BaseHTTPMiddleware):
    """
    Enforces infrastructure resource gauges and sandbox fair-use limits.
    Tracks protocol activity for analytics on all plans.
    Feature gates are handled by BillingAuthMiddleware (Cedar billing policies).
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

        # Resolve plan tier
        plan_str = getattr(request.state, "org_plan", "sandbox")
        try:
            plan = PlanTier(plan_str)
        except ValueError:
            plan = PlanTier.SANDBOX
        limits = get_plan_limits(plan)

        tracker: UsageTracker | None = getattr(request.app.state, "usage_tracker", None)

        if tracker and request.method in WRITE_METHODS:
            # ── Hard-enforced resource gauge checks ──────────────────
            gauge_metric = _resolve_gauge(path)
            if gauge_metric:
                current = await tracker.get(org_id, gauge_metric)
                if not check_limit(limits, gauge_metric, current):
                    limit_val = getattr(limits, gauge_metric, None)
                    return JSONResponse(
                        status_code=429,
                        content={
                            "error": "plan_limit_exceeded",
                            "message": f"Resource limit reached: {gauge_metric.replace('_', ' ')} ({limit_val}).",
                            "metric": gauge_metric,
                            "current": current,
                            "limit": limit_val,
                            "current_plan": plan.value,
                            "upgrade_url": "/pricing",
                        },
                    )

            # ── Sandbox fair-use check ───────────────────────────────
            analytics_metric = _resolve_analytics(path)
            if analytics_metric and plan == PlanTier.SANDBOX:
                combined = await tracker.get(org_id, "sandbox_monthly_activity")
                if not check_sandbox_fair_use(limits, combined):
                    return JSONResponse(
                        status_code=429,
                        content={
                            "error": "sandbox_fair_use_exceeded",
                            "message": "Sandbox monthly activity limit reached. Upgrade to a paid plan for unlimited usage.",
                            "current": combined,
                            "limit": limits.sandbox_monthly_activity_limit,
                            "current_plan": plan.value,
                            "upgrade_url": "/pricing",
                        },
                    )

        # ── Execute request ──────────────────────────────────────────
        response = await call_next(request)

        # ── Post-request tracking (only on success) ──────────────────
        if tracker and response.status_code < 400 and request.method in WRITE_METHODS:
            # Increment enforced gauges
            gauge_metric = _resolve_gauge(path)
            if gauge_metric:
                await tracker.increment_gauge(org_id, gauge_metric)

            # Increment analytics counters
            analytics_metric = _resolve_analytics(path)
            if analytics_metric:
                await tracker.increment(org_id, analytics_metric)
                # Also increment sandbox combined activity counter
                if plan == PlanTier.SANDBOX:
                    await tracker.increment(org_id, "sandbox_monthly_activity")

            # Always increment API calls counter (for analytics)
            await tracker.increment(org_id, "api_calls")

        return response


def _resolve_gauge(path: str) -> str | None:
    """Find the enforced resource gauge for a given path."""
    for prefix, metric in ENFORCED_GAUGE_MAP.items():
        if path.startswith(prefix):
            return metric
    return None


def _resolve_analytics(path: str) -> str | None:
    """Find the analytics counter for a given path."""
    for prefix, metric in ANALYTICS_METRIC_MAP.items():
        if path.startswith(prefix):
            return metric
    return None
