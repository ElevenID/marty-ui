"""Cedar authorization middleware for the Marty API gateway.

Replaces OrgAuthMiddleware with Cedar policy-based authorization.
Evaluates MIP Cedar policies for all org-scoped routes, checking both
organization membership and action-level permissions.
"""

import os
import logging
import re

from fastapi import HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from .cedar_actions import extract_org_id, resolve_action_and_resource, resolve_resource_lookup
from .cedar_engine import CedarEngine
from .cedar_entities import build_request_context, build_user_entities
from .org_authorization import OrganizationClient

logger = logging.getLogger(__name__)

# Default attribute values for Cedar entity types that have required attrs
# in mip.cedarschema.  These are used only for the synthetic resource entity
# created during policy evaluation (the real resource attrs are irrelevant
# to RBAC — only type and hierarchy matter).
_DEFAULT_RESOURCE_ATTRS: dict[str, dict] = {
    "ComplianceProfile": {"is_system": False, "compliance_code": ""},
    "Application": {"risk_score": 0, "status": "PENDING"},
    "Credential": {
        "format": "",
        "status": "ACTIVE",
        "compliance_code": "",
        "issuer_id": "",
        "trust_level": 0,
    },
    "CredentialTemplate": {"credential_format": ""},
    "Flow": {"flow_type": "", "status": ""},
    "FlowExecution": {"status": ""},
}


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

    @staticmethod
    def _forward_headers(request: Request, service_name: str | None = None) -> dict[str, str]:
        """Forward user context headers for internal authorization lookups."""
        headers: dict[str, str] = {}
        user_id = getattr(request.state, "user_id", None)
        user_email = getattr(request.state, "user_email", None)
        user_domain = getattr(request.state, "user_domain", None)
        if user_id:
            headers["X-User-Id"] = user_id
        if user_email:
            headers["X-User-Email"] = user_email
        if user_domain:
            headers["X-User-Domain"] = user_domain

        auth = request.headers.get("authorization")
        if auth:
            headers["Authorization"] = auth

        if service_name == "issuance":
            issuance_api_key = os.environ.get("ISSUANCE_API_KEY", "")
            if issuance_api_key:
                headers["X-API-Key"] = issuance_api_key

        return headers

    async def _extract_body_org_id(self, request: Request) -> str | None:
        """Extract organization_id from a JSON request body when present."""
        if request.method.upper() not in {"POST", "PUT", "PATCH"}:
            return None

        content_type = (request.headers.get("content-type") or "").split(";", 1)[0].strip().lower()
        if content_type not in {"application/json", "application/scim+json"}:
            return None

        try:
            payload = await request.json()
        except Exception:
            return None

        if not isinstance(payload, dict):
            return None

        org_id = payload.get("organization_id")
        return org_id if isinstance(org_id, str) and org_id else None

    async def _lookup_resource_org_id(self, request: Request, path: str) -> str | None:
        """Look up resource ownership for top-level detail routes."""
        lookup = resolve_resource_lookup(path)
        if not lookup:
            return None

        service_registry = getattr(request.app.state, "service_registry", None)
        http_client = getattr(request.app.state, "http_client", None)
        if service_registry is None or http_client is None:
            return None

        service_name, lookup_path = lookup
        service_url = service_registry.get_service_url(service_name)
        if not service_url:
            return None

        try:
            response = await http_client.get(
                f"{service_url}{lookup_path}",
                timeout=10.0,
                headers=self._forward_headers(request, service_name),
            )
        except Exception:
            return None

        if response.status_code >= 400:
            return None

        try:
            payload = response.json()
        except Exception:
            return None

        org_id = payload.get("organization_id") if isinstance(payload, dict) else None
        return org_id if isinstance(org_id, str) and org_id else None

    async def _resolve_request_org_id(self, request: Request, path: str) -> str | None:
        """Resolve org scope from path, owned resource, query, or body."""
        org_id = extract_org_id(path)
        if org_id:
            return org_id

        org_id = await self._lookup_resource_org_id(request, path)
        if org_id:
            return org_id

        query_org_id = request.query_params.get("organization_id")
        if query_org_id:
            return query_org_id

        return await self._extract_body_org_id(request)

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Skip allowlisted paths
        if any(p.match(path) for p in self._skip_patterns):
            return await call_next(request)

        # Only evaluate Cedar for routes we know how to authorize.
        resolved = resolve_action_and_resource(request.method, path)
        if not resolved:
            return await call_next(request)

        org_id = await self._resolve_request_org_id(request, path)
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

        # Build Cedar entities (no plan_tier — billing is a separate engine)
        user_email = getattr(request.state, "user_email", "") or ""
        entities = build_user_entities(
            user_id=user_id,
            email=user_email,
            status="ACTIVE",
            org_id=org_id,
            role=membership.role.value,
        )

        # Add typed resource entity so Cedar schema validation passes
        default_attrs = _DEFAULT_RESOURCE_ATTRS.get(resource_type, {})
        entities.append(
            {
                "uid": {"type": f"MIP::{resource_type}", "id": org_id},
                "attrs": default_attrs,
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

        # Inject org context for downstream middleware and services
        request.state.org_role = membership.role.value
        request.state.organization_id = org_id
        request.state.cedar_action = action_name

        return await call_next(request)
