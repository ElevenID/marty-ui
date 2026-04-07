"""Billing authorization middleware for the Marty API gateway.

Evaluates plan-tier feature gates using a separate Cedar engine with the
Billing namespace. Runs AFTER CedarAuthMiddleware (MIP RBAC) and BEFORE
UsageTrackingMiddleware (numeric metering).

This keeps payment/plan concerns out of the MIP protocol Cedar schema.
"""

import logging

from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from .billing_engine import BillingCedarEngine
from .plans import PlanTier, get_plan_limits

logger = logging.getLogger(__name__)


def _min_plan_for_feature(feature: str) -> str:
    """Return the minimum plan tier name that includes a feature."""
    from .plans import check_feature

    for tier in [PlanTier.PROGRAM, PlanTier.INSTITUTION, PlanTier.SYSTEM]:
        if check_feature(get_plan_limits(tier), feature):
            return tier.value.capitalize()
    return "Enterprise"


class BillingAuthMiddleware(BaseHTTPMiddleware):
    """Middleware that evaluates billing Cedar policies for plan-gated features.

    Only evaluates for org-scoped requests where CedarAuthMiddleware has
    already set request.state.organization_id and request.state.cedar_action.
    If the action is not billing-gated, passes through immediately.

    Sets request.state.org_plan for downstream UsageTrackingMiddleware.
    """

    async def dispatch(self, request: Request, call_next):
        # Only evaluate if CedarAuthMiddleware already ran
        org_id = getattr(request.state, "organization_id", None)
        if not org_id:
            return await call_next(request)

        # Get billing engine from app state
        billing_engine: BillingCedarEngine | None = getattr(
            request.app.state, "billing_engine", None
        )
        if not billing_engine:
            # No billing engine configured — pass through (no plan gating)
            return await call_next(request)

        # Resolve org plan tier from Redis
        plan_tier = None
        redis_client = getattr(request.app.state, "redis_client", None)
        if redis_client:
            try:
                cached = await redis_client.get(f"org:{org_id}:plan")
                if cached:
                    plan_tier = cached if isinstance(cached, str) else cached.decode()
            except Exception:
                logger.error(
                    "Failed to read plan for org %s from Redis — denying request",
                    org_id,
                )
                return JSONResponse(
                    status_code=503,
                    content={"detail": "Billing service temporarily unavailable"},
                )

        if plan_tier is None:
            plan_tier = "free"

        # Set org_plan for downstream UsageTrackingMiddleware
        request.state.org_plan = plan_tier

        # Check whether this action is billing-gated
        mip_action = getattr(request.state, "cedar_action", None) or ""
        path = request.url.path
        billing_action = billing_engine.get_billing_action(mip_action, path)

        if not billing_action:
            # Not a plan-gated action — pass through
            return await call_next(request)

        # Evaluate billing Cedar policy
        user_id = getattr(request.state, "user_id", "unknown")
        decision = billing_engine.is_plan_allowed(
            plan_tier=plan_tier,
            action_name=billing_action,
            org_id=org_id,
            principal_id=user_id,
            principal_type="User",
        )

        if not decision.allowed:
            # Map billing action to a human-readable feature name
            feature_name = billing_action.replace(":", "_").replace("_access", "")
            logger.info(
                f"Billing DENY: user={user_id} action={billing_action} "
                f"org={org_id} plan={plan_tier} reasons={decision.reasons}"
            )
            return JSONResponse(
                status_code=403,
                content={
                    "error": "plan_feature_unavailable",
                    "message": (
                        f"This feature requires the "
                        f"{_min_plan_for_feature(feature_name)} plan or higher."
                    ),
                    "feature": feature_name,
                    "current_plan": plan_tier,
                    "upgrade_url": "/pricing",
                },
            )

        return await call_next(request)
