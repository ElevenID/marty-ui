"""Cedar authorization middleware for the Marty API gateway.

Replaces OrgAuthMiddleware with Cedar policy-based authorization.
Evaluates MIP Cedar policies for all org-scoped routes, checking both
organization membership and action-level permissions.
"""

import logging
import re

from fastapi import HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from .cedar_actions import extract_org_id, resolve_action_and_resource
from .cedar_engine import CedarEngine
from .cedar_entities import build_request_context, build_user_entities
from .org_authorization import OrganizationClient

logger = logging.getLogger(__name__)


class CedarAuthMiddleware(BaseHTTPMiddleware):
    """Middleware that evaluates Cedar policies for org-scoped routes.

    Replaces OrgAuthMiddleware with formal policy evaluation. Requires
    CedarEngine and OrganizationClient on app.state (set during lifespan).

    Flow:
        1. Skip allowlisted paths (join flows, health, etc.)
        2. Extract org_id from path — pass through non-org routes
        3. Verify org membership via OrganizationClient
        4. Resolve Cedar action from HTTP method + path
        5. Build Cedar entities and context
        6. Evaluate via CedarEngine.is_authorized()
        7. Deny (403) or allow and inject org_role for downstream services
    """

    SKIP_PATTERNS = [
        r"^/v1/organizations$",
        r"^/v1/organizations/mine$",
        r"^/v1/organizations/discover",
        r"^/v1/organizations/join/",
        r"^/v1/organizations/[^/]+/join$",
        r"^/v1/organizations/invitations/",
        r"^/health",
        r"^/.well-known/",
    ]

    def __init__(self, app):
        super().__init__(app)
        self._skip_patterns = [re.compile(p) for p in self.SKIP_PATTERNS]

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Skip allowlisted paths
        if any(p.match(path) for p in self._skip_patterns):
            return await call_next(request)

        # Only evaluate Cedar for org-scoped routes
        org_id = extract_org_id(path)
        if not org_id:
            return await call_next(request)

        # Require authenticated user (set by AuthMiddleware)
        user_id = getattr(request.state, "user_id", None)
        if not user_id:
            return JSONResponse(
                status_code=401,
                content={"detail": "Authentication required"},
            )

        # Get Cedar engine from app state
        cedar_engine: CedarEngine | None = getattr(
            request.app.state, "cedar_engine", None
        )
        if not cedar_engine:
            logger.error("CedarEngine not configured in app state")
            return JSONResponse(
                status_code=500,
                content={"detail": "Authorization engine not configured"},
            )

        # Get org client from app state
        org_client: OrganizationClient | None = getattr(
            request.app.state, "org_client", None
        )
        if not org_client:
            logger.error("OrganizationClient not configured in app state")
            return JSONResponse(
                status_code=500,
                content={"detail": "Organization client not configured"},
            )

        # Resolve Cedar action and resource type from HTTP method + path
        resolved = resolve_action_and_resource(request.method, path)
        if not resolved:
            logger.warning(
                f"Could not resolve Cedar action for {request.method} {path}"
            )
            return JSONResponse(
                status_code=403,
                content={"detail": "Action not authorized"},
            )
        action_name, resource_type = resolved

        # Verify org membership
        try:
            membership = await org_client.get_membership(user_id, org_id)
        except HTTPException as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"detail": e.detail},
            )
        except Exception as e:
            logger.error(f"Error fetching membership: {e}", exc_info=True)
            return JSONResponse(
                status_code=500,
                content={"detail": "Internal server error"},
            )

        if not membership:
            return JSONResponse(
                status_code=403,
                content={"detail": "Not a member of this organization"},
            )

        if not membership.is_active():
            return JSONResponse(
                status_code=403,
                content={
                    "detail": f"Organization membership is {membership.status}"
                },
            )

        # Build Cedar entities
        user_email = getattr(request.state, "user_email", "") or ""
        entities = build_user_entities(
            user_id=user_id,
            email=user_email,
            status="ACTIVE",
            org_id=org_id,
            role=membership.role.value,
        )

        # Add typed resource entity so Cedar schema validation passes
        entities.append(
            {
                "uid": {"type": f"MIP::{resource_type}", "id": org_id},
                "attrs": {},
                "parents": [{"type": "MIP::Organization", "id": org_id}],
            }
        )

        # Build Cedar request context
        client_ip = request.client.host if request.client else "0.0.0.0"
        session_id = request.cookies.get("sessionId")
        user_agent = request.headers.get("user-agent")
        mfa_verified = getattr(request.state, "mfa_verified", False)
        context = build_request_context(
            ip_address=client_ip,
            mfa_authenticated=bool(mfa_verified),
            session_id=session_id,
            user_agent=user_agent,
        )

        # Evaluate Cedar policy
        decision = cedar_engine.is_authorized(
            principal=f'MIP::User::"{user_id}"',
            action=f'MIP::Action::"{action_name}"',
            resource=f'MIP::{resource_type}::"{org_id}"',
            context=context,
            entities=entities,
        )

        if not decision.allowed:
            logger.warning(
                f"Cedar DENY: user={user_id} action={action_name} "
                f"org={org_id} role={membership.role.value} "
                f"reasons={decision.reasons} errors={decision.errors}"
            )
            return JSONResponse(
                status_code=403,
                content={"detail": "Action not authorized by policy"},
            )

        logger.debug(
            f"Cedar ALLOW: user={user_id} action={action_name} "
            f"org={org_id} role={membership.role.value} "
            f"reasons={decision.reasons}"
        )

        # Inject org role for downstream services
        request.state.org_role = membership.role.value

        return await call_next(request)
