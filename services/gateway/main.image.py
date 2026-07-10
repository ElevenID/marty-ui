"""
Marty API Gateway

Central API gateway that routes requests to microservices.
All services follow the Digital Identity model architecture.

Services:
- Auth (8001) - Authentication
- Organization (8002) - Organization management
- Credential Template (8003) - Credential blueprints
- Trust Profile (8004) - Trust configuration
- Issuance (8005) - Credential issuance
- Notification (8007) - Notifications
- Compliance Profile (8008) - Regulatory rules
- Presentation Policy (8009) - Verification policies + stateless evaluation
- Deployment Profile (8010) - Runtime configuration
- Flow (8011) - Orchestration + async verification flows

Port: 8000
"""

from __future__ import annotations

import logging
import os
from typing import Any, AsyncGenerator

import httpx
from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import redis.asyncio as aioredis
from marty_common import CedarEngine, CedarAuthMiddleware
from marty_common.billing_engine import BillingCedarEngine
from marty_common.billing_middleware import BillingAuthMiddleware
from marty_common.middleware import ETagMiddleware, IdempotencyMiddleware
from marty_common.usage import UsageTracker
from marty_common.plans import PlanTier, get_plan_limits, PLAN_LIMITS, PLAN_INFO
from .plan_middleware import UsageTrackingMiddleware

import gateway.proxy as _proxy_mod
from gateway.registry import ServiceRegistry
from gateway.middleware import (
    AuthMiddleware,
    ContentTypeEnforcementMiddleware,
    MIPVersionMiddleware,
    RateLimitMiddleware,
    SessionCache,
    mip_error_response,
)
from gateway.proxy import get_http_client, get_registry, get_session_cache, proxy_request

# Route modules
from gateway.routes.applicants import applicant_router
from gateway.routes.credentials import (
    compliance_profile_router,
    credential_template_router,
    delivery_destination_router,
    wallet_registry_router,
)
from gateway.routes.deployment import deployment_profile_router
from gateway.routes.devices import device_router
from gateway.routes.flows import flow_router
from gateway.routes.issuance import (
    application_router,
    application_template_router,
    issuance_router,
    issued_credential_router,
)
from gateway.routes.notifications import (
    notification_router,
    policy_set_router,
    subscription_router,
    webhook_router,
)
from gateway.routes.organizations import organization_router, preferences_router
from gateway.routes.revocation import cascade_revocation_router, revocation_profile_router, status_list_router
from gateway.routes.signing_keys import signing_key_router
from gateway.routes.trust import (
    api_key_router,
    issuer_entity_router,
    organization_trust_profile_router,
    trust_framework_router,
    trust_profile_router,
    trust_registry_router,
)
from gateway.routes.verification import presentation_policy_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

SERVICE_NAME = "api-gateway"
SERVICE_PORT = int(os.environ.get("GATEWAY_PORT", "8000"))

_DEFAULT_READY_SERVICES = (
    "auth",
    "organizations",
    "credential-templates",
    "trust-profiles",
    "presentation-policies",
    "deployment-profiles",
    "signing-keys",
    "flows",
    "issuance",
)


def _required_ready_services() -> tuple[str, ...]:
    configured = os.environ.get("GATEWAY_REQUIRED_READY_SERVICES")
    if configured is None:
        return _DEFAULT_READY_SERVICES
    return tuple(service.strip() for service in configured.split(",") if service.strip())


# =============================================================================
# Application Lifecycle
# =============================================================================

async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    logger.info(f"Starting {SERVICE_NAME}...")
    _proxy_mod._registry = ServiceRegistry()
    _proxy_mod._http_client = httpx.AsyncClient(timeout=httpx.Timeout(30.0))
    _proxy_mod._session_cache = SessionCache(ttl_seconds=60)
    app.state.service_registry = _proxy_mod._registry
    app.state.http_client = _proxy_mod._http_client

    # Initialize Redis for membership caching
    redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")
    redis_db = int(os.environ.get("REDIS_DB_GATEWAY", "2"))  # Use DB 2 for gateway
    logger.info(f"Connecting to Redis at {redis_url}/{redis_db}")
    redis_client = aioredis.from_url(
        f"{redis_url}/{redis_db}",
        encoding="utf-8",
        decode_responses=True
    )

    # Initialize OrganizationClient for membership verification
    from common.grpc_factory import create_grpc_channel
    from common.di import setup_org_client, teardown_org_client
    from marty_proto.v1.auth_service_pb2_grpc import AuthServiceStub

    auth_grpc_target = os.environ.get("AUTH_GRPC_TARGET", "localhost:9001")

    auth_grpc_channel = create_grpc_channel(auth_grpc_target, service_name="gateway")
    auth_grpc_stub = AuthServiceStub(auth_grpc_channel)
    await setup_org_client(app, "gateway", redis_client=redis_client, cache_ttl=120)
    grpc_tls_enabled = bool(os.environ.get("GRPC_TLS_CA_CERT"))
    org_grpc_target = os.environ.get("ORG_GRPC_TARGET", "organization:9002")
    logger.info(
        "Gateway gRPC: auth\u2192%s  org\u2192%s  tls=%s",
        auth_grpc_target, org_grpc_target, grpc_tls_enabled,
    )

    # Event-stream gRPC channel for SSE bridging
    es_grpc_target = os.environ.get("ES_GRPC_TARGET", "event-stream:9015")
    es_grpc_channel = create_grpc_channel(es_grpc_target, service_name="gateway")
    app.state.es_grpc_channel = es_grpc_channel
    logger.info("Gateway gRPC: event-stream\u2192%s", es_grpc_target)

    app.state.redis_client = redis_client
    app.state.usage_tracker = UsageTracker(redis_client)
    app.state.auth_grpc_stub = auth_grpc_stub

    # Initialize Cedar policy engine (MIP RBAC \u2014 protocol-standard)
    cedar_schema_path = os.environ.get("CEDAR_SCHEMA_PATH")
    cedar_policies_dir = os.environ.get("CEDAR_POLICIES_DIR")
    if cedar_schema_path and cedar_policies_dir:
        cedar_engine = CedarEngine.from_files(cedar_schema_path, [cedar_policies_dir])
        logger.info(f"Cedar engine loaded from {cedar_schema_path}")
    else:
        cedar_engine = CedarEngine.with_defaults()
        logger.info("Cedar engine loaded with default MIP schema and gateway policies")
    app.state.cedar_engine = cedar_engine

    # Initialize billing Cedar engine (internal plan-tier feature gating)
    billing_schema_path = os.environ.get("BILLING_SCHEMA_PATH")
    billing_policies_dir = os.environ.get("BILLING_POLICIES_DIR")
    if billing_schema_path and billing_policies_dir:
        billing_engine = BillingCedarEngine.from_files(
            billing_schema_path, [billing_policies_dir]
        )
        logger.info(f"Billing engine loaded from {billing_schema_path}")
    else:
        billing_engine = BillingCedarEngine.with_defaults()
        logger.info("Billing engine loaded with default billing schema and policies")
    app.state.billing_engine = billing_engine

    logger.info(f"{SERVICE_NAME} started successfully")
    yield

    logger.info(f"Shutting down {SERVICE_NAME}...")
    await teardown_org_client(app)
    await auth_grpc_channel.close()
    await es_grpc_channel.close()
    await redis_client.aclose()
    await _proxy_mod._http_client.aclose()


def create_app() -> FastAPI:
    app = FastAPI(
        title="Marty API Gateway",
        description="""
## Digital Identity Management API

The Marty API provides a complete platform for digital identity credential management,
following the Digital Identity model architecture.

### Configuration Resources

- **Trust Profiles** - Define who is trusted and how validation happens
- **Revocation Profiles** - Format-agnostic revocation configuration
- **Credential Templates** - Blueprint for credential structure and claims
- **Compliance Profiles** - Regulatory and policy rules
- **Presentation Policies** - Define what credentials to request for verification
- **Deployment Profiles** - Runtime configuration for different environments (including Lanes)

### Operational Resources

- **Flows** - Orchestrate multi-step credential operations (issuance and verification)
- **Issuance** - Issue credentials to holders
- **Applications** - Manage Application Templates and Application instances
- **Audit Events** - Track actions within Organizations

### Verification

Verification is handled through two complementary approaches:

- **Stateless Evaluation**: Use `POST /v1/presentation-policies/{id}/evaluate` to immediately verify a VP token against a policy
- **Async Wallet Flows**: Use `POST /v1/flows/verify` to start a verification flow with QR code / request_uri for wallet interactions

### Getting Started

1. Create an Organization
2. Configure a Trust Profile (who you trust)
3. Create a Credential Template (what to issue)
4. Create an Application Template and instance Application
5. Issue credentials (via Application or direct issuance)
6. Create a Presentation Policy and use `/evaluate` or start a Flow to verify
        """,
        version="1.0.0",
        lifespan=lifespan,
    )

    # CORS configuration: Use specific origins when credentials are enabled
    # Cannot use wildcard "*" with credentials per CORS spec
    allowed_origins = os.environ.get(
        "CORS_ORIGINS",
        "http://localhost:3000,https://beta.elevenidllc.com,http://localhost:5173"
    ).split(",")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=[origin.strip() for origin in allowed_origins],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["*"],
    )

    # NOTE: create_app() runs at import time, before lifespan() initializes globals.
    # So we bootstrap defaults here and let lifespan() refresh them at startup.
    if _proxy_mod._registry is None:
        _proxy_mod._registry = ServiceRegistry()
    if _proxy_mod._session_cache is None:
        _proxy_mod._session_cache = SessionCache(ttl_seconds=60)

    session_cache = _proxy_mod._session_cache

    # Starlette executes middleware in reverse registration order, so keep
    # idempotency inside current authz checks. A replay should still pass
    # current Cedar/billing authorization before a cached response is returned.
    app.add_middleware(UsageTrackingMiddleware)
    app.add_middleware(IdempotencyMiddleware)
    app.add_middleware(BillingAuthMiddleware)
    app.add_middleware(CedarAuthMiddleware)
    app.add_middleware(ETagMiddleware)
    app.add_middleware(ContentTypeEnforcementMiddleware)
    app.add_middleware(AuthMiddleware, session_cache=session_cache)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(MIPVersionMiddleware)

    # Include all routers
    app.include_router(trust_profile_router)
    app.include_router(organization_trust_profile_router)
    app.include_router(issuer_entity_router)
    app.include_router(trust_framework_router)
    app.include_router(trust_registry_router)
    app.include_router(api_key_router)
    app.include_router(signing_key_router)
    app.include_router(revocation_profile_router)
    app.include_router(cascade_revocation_router)
    app.include_router(status_list_router)
    app.include_router(credential_template_router)
    app.include_router(wallet_registry_router)
    app.include_router(delivery_destination_router)
    app.include_router(compliance_profile_router)
    app.include_router(device_router)
    app.include_router(presentation_policy_router)
    app.include_router(deployment_profile_router)
    app.include_router(flow_router)
    app.include_router(issued_credential_router)
    app.include_router(issuance_router)
    app.include_router(application_template_router)
    app.include_router(application_router)
    app.include_router(subscription_router)
    app.include_router(webhook_router)
    app.include_router(notification_router)
    app.include_router(policy_set_router)
    app.include_router(applicant_router)
    app.include_router(organization_router)
    app.include_router(preferences_router)

    # Auth service proxy - forward all /v1/auth/* requests to auth service
    @app.api_route("/v1/auth/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
    async def proxy_auth_requests(request: Request, path: str) -> Response:
        """Proxy auth requests to the auth service.

        This handles login/logout redirects and session management.
        """
        registry = get_registry()
        auth_url = registry.get_service_url("auth")
        if not auth_url:
            return mip_error_response(status_code=503, error="service_unavailable", message="Auth service unavailable")

        # Clear session cache on logout to prevent stale sessions
        if path.startswith("logout"):
            session_id = request.cookies.get("sessionId")
            if session_id:
                try:
                    get_session_cache().clear(session_id)
                except RuntimeError:
                    pass

        client = get_http_client()
        target_url = f"{auth_url}/v1/auth/{path}"

        # Forward query parameters
        if request.url.query:
            target_url += f"?{request.url.query}"

        # Get request body if present
        body = None
        if request.method in ["POST", "PUT", "PATCH"]:
            body = await request.body()

        # Forward headers (excluding hop-by-hop headers)
        headers = {
            k: v for k, v in request.headers.items()
            if k.lower() not in ("host", "connection", "keep-alive", "transfer-encoding")
        }

        try:
            # Forward request without following redirects (auth handles redirects)
            response = await client.request(
                method=request.method,
                url=target_url,
                headers=headers,
                content=body,
                follow_redirects=False,
                timeout=30.0,
            )

            # Return proxied response with all headers including Set-Cookie
            return Response(
                content=response.content,
                status_code=response.status_code,
                headers={
                    k: v for k, v in response.headers.items()
                    if k.lower() not in ("content-encoding", "transfer-encoding")
                },
                media_type=response.headers.get("content-type"),
            )
        except httpx.ConnectError:
            logger.error(f"Auth service unavailable at {auth_url}")
            return mip_error_response(status_code=503, error="service_unavailable", message="Auth service unavailable")
        except httpx.TimeoutException:
            logger.error(f"Auth service timeout at {auth_url}")
            return mip_error_response(status_code=504, error="service_timeout", message="Auth service timeout")
        except Exception as e:
            logger.error(f"Error proxying auth request: {e}")
            return mip_error_response(status_code=502, error="auth_service_error", message="Auth service error")

    @app.get("/health")
    async def health_check() -> dict:
        return {"status": "healthy", "service": SERVICE_NAME}

    async def signing_keys_local_readiness(client: httpx.AsyncClient) -> dict:
        details = {"status": "healthy", "mode": "gateway-local"}
        redis_client = getattr(app.state, "redis_client", None)
        if redis_client is None:
            return {"status": "unhealthy", "mode": "gateway-local", "error": "redis storage is not configured"}
        try:
            await redis_client.ping()
        except Exception as exc:
            return {"status": "unreachable", "mode": "gateway-local", "error": str(exc)}

        bao_addr = os.environ.get("BAO_ADDR")
        if bao_addr:
            headers = {}
            bao_token = os.environ.get("BAO_TOKEN")
            bao_token_file = os.environ.get("BAO_TOKEN_FILE")
            if not bao_token and bao_token_file:
                try:
                    with open(bao_token_file, encoding="utf-8") as handle:
                        bao_token = handle.read().strip()
                except OSError:
                    bao_token = None
            if bao_token:
                headers["X-Vault-Token"] = bao_token
            try:
                response = await client.get(f"{bao_addr.rstrip('/')}/v1/sys/health", headers=headers, timeout=3.0)
                details["openbao_status_code"] = response.status_code
                if response.status_code not in {200, 429, 472, 473}:
                    details["status"] = "unhealthy"
            except Exception as exc:
                return {"status": "unreachable", "mode": "gateway-local", "error": f"openbao: {exc}"}
        return details

    async def readiness_check():
        registry = get_registry()
        client = get_http_client()
        services = {}

        for service in _required_ready_services():
            if service == "signing-keys":
                services[service] = await signing_keys_local_readiness(client)
                continue
            url = registry.get_service_url(service)
            if not url:
                services[service] = {"status": "missing", "url": None}
                continue

            try:
                response = await client.get(f"{url}/health", timeout=3.0)
                services[service] = {
                    "status": "healthy" if response.status_code == 200 else "unhealthy",
                    "url": url,
                    "status_code": response.status_code,
                }
            except Exception as exc:
                services[service] = {
                    "status": "unreachable",
                    "url": url,
                    "error": str(exc),
                }

        unhealthy = {
            service: details
            for service, details in services.items()
            if details["status"] != "healthy"
        }
        payload = {
            "status": "ready" if not unhealthy else "not_ready",
            "service": SERVICE_NAME,
            "services": services,
        }
        if unhealthy:
            return JSONResponse(status_code=503, content=payload)
        return payload

    app.add_api_route("/ready", readiness_check, methods=["GET"])
    app.add_api_route("/health/ready", readiness_check, methods=["GET"])

    # \u2500\u2500 Usage & billing analytics \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500

    @app.get("/v1/usage")
    async def get_usage(request: Request, month: str | None = None) -> dict:
        """Get usage metrics for the authenticated user's organization."""
        org_id = getattr(request.state, "organization_id", None)
        if not org_id:
            return JSONResponse(status_code=401, content={"error": "Not authenticated"})
        tracker: UsageTracker | None = getattr(request.app.state, "usage_tracker", None)
        if not tracker:
            return {"metrics": {}, "plan": "sandbox", "limits": {}}
        metrics = await tracker.get_all(org_id, month)
        plan_str = "sandbox"
        redis_client = getattr(request.app.state, "redis_client", None)
        if redis_client:
            cached = await redis_client.get(f"org:{org_id}:plan")
            if cached:
                plan_str = cached
        try:
            plan = PlanTier(plan_str)
        except ValueError:
            plan = PlanTier.SANDBOX
        limits = get_plan_limits(plan)
        info = PLAN_INFO[plan]
        return {
            "plan": plan.value,
            "plan_name": info.display_name,
            "plan_tagline": info.tagline,
            "metrics": metrics,
            "limits": {
                "deployments": limits.deployments,
                "verifier_instances": limits.verifier_instances,
                "active_flows": limits.active_flows,
                "badge_templates": limits.badge_templates,
                "admin_seats": limits.admin_seats,
                "audit_retention_days": limits.audit_retention_days,
                "sandbox_monthly_activity_limit": limits.sandbox_monthly_activity_limit,
            },
        }

    @app.get("/v1/usage/history")
    async def get_usage_history(request: Request, metric: str = "verifications", months: int = 6) -> dict:
        """Get historical usage for a metric over the last N months."""
        org_id = getattr(request.state, "organization_id", None)
        if not org_id:
            return JSONResponse(status_code=401, content={"error": "Not authenticated"})
        tracker: UsageTracker | None = getattr(request.app.state, "usage_tracker", None)
        if not tracker:
            return {"metric": metric, "history": {}}
        allowed_metrics = {"verifications", "issued_credentials", "api_calls", "active_flows"}
        if metric not in allowed_metrics:
            return JSONResponse(status_code=400, content={"error": f"Invalid metric. Use one of: {allowed_metrics}"})
        history = await tracker.get_history(org_id, metric, min(months, 12))
        return {"metric": metric, "history": history}

    @app.get("/v1/plans")
    async def list_plans() -> dict:
        """Return available plan tiers and their limits (public endpoint)."""
        plans = []
        for tier in PlanTier:
            info = PLAN_INFO[tier]
            limits = get_plan_limits(tier)
            plans.append({
                "tier": tier.value,
                "name": info.name,
                "tagline": info.tagline,
                "headline": info.headline,
                "price_monthly": info.price_monthly,
                "differentiator": info.differentiator,
                "limits": {
                    "verifications_per_month": limits.verifications_per_month,
                    "issued_credentials_per_month": limits.issued_credentials_per_month,
                    "active_flows": limits.active_flows,
                    "members": limits.members,
                    "credential_templates": limits.credential_templates,
                    "deployment_profiles": limits.deployment_profiles,
                },
                "features": {
                    "custom_branding": limits.custom_branding,
                    "webhooks": limits.webhooks,
                    "audit_logs": limits.audit_logs,
                    "multi_environment": limits.multi_environment,
                    "custom_cedar_policies": limits.custom_cedar_policies,
                    "scim_provisioning": limits.scim_provisioning,
                    "self_hosted": limits.self_hosted,
                    "zkp_verification": limits.zkp_verification,
                    "device_registration": limits.device_registration,
                },
            })
        return {"plans": plans}

    # \u2500\u2500 Billing proxy routes \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500

    @app.api_route(
        "/v1/billing/{path:path}",
        methods=["GET", "POST", "PUT", "DELETE"],
        tags=["Billing"],
    )
    async def proxy_billing(request: Request, path: str) -> Response:
        """Proxy billing requests to the billing service."""
        service_url = get_registry().get_service_url("billing")
        if not service_url:
            return mip_error_response(
                status_code=503,
                error="service_unavailable",
                message="Billing service not configured",
            )
        return await proxy_request(request, service_url, f"/v1/billing/{path}")

    async def _proxy_to_issuance_well_known(path: str) -> Response:
        """Proxy a well-known request to the issuance service.

        The issuance service is the source of truth for OID4VCI metadata.
        Keeping gateway endpoints as a proxy avoids drift and ensures that
        per-org discovery (OID4VCI v1 \u00a712.2.2 insertion rule) works end-to-end.
        """
        registry = get_registry()
        issuance_url = registry.get_service_url("issuance")
        if not issuance_url:
            raise HTTPException(status_code=503, detail="Issuance service unavailable")

        client = get_http_client()
        try:
            upstream = await client.get(f"{issuance_url}{path}", timeout=10.0)
        except httpx.TimeoutException:
            raise HTTPException(status_code=504, detail="Issuance service timeout")
        except Exception as exc:
            logger.error("Error proxying well-known to issuance (%s): %s", path, exc)
            raise HTTPException(status_code=502, detail="Issuance service error")

        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            media_type=upstream.headers.get("content-type"),
            headers={
                k: v
                for k, v in upstream.headers.items()
                if k.lower() not in ("content-encoding", "transfer-encoding")
            },
        )

    # OID4VCI v1 per-org discovery (insertion rule paths)

    @app.get("/.well-known/openid-credential-issuer/org/{org_id}")
    async def get_org_issuer_metadata(org_id: str) -> Response:
        return await _proxy_to_issuance_well_known(f"/.well-known/openid-credential-issuer/org/{org_id}")

    @app.get("/.well-known/oauth-authorization-server/org/{org_id}")
    async def get_org_oauth_authorization_server_metadata(org_id: str) -> Response:
        return await _proxy_to_issuance_well_known(f"/.well-known/oauth-authorization-server/org/{org_id}")

    # SpruceID / SpruceKit wallet variants

    @app.get("/.well-known/openid-credential-issuer/org/{org_id}/spruce")
    async def get_org_spruce_issuer_metadata(org_id: str) -> Response:
        return await _proxy_to_issuance_well_known(f"/.well-known/openid-credential-issuer/org/{org_id}/spruce")

    @app.get("/org/{org_id}/spruce/.well-known/openid-credential-issuer")
    async def get_org_spruce_issuer_metadata_appended(org_id: str) -> Response:
        return await _proxy_to_issuance_well_known(f"/.well-known/openid-credential-issuer/org/{org_id}/spruce")

    @app.get("/.well-known/oauth-authorization-server/org/{org_id}/spruce")
    async def get_org_spruce_as_metadata(org_id: str) -> Response:
        return await _proxy_to_issuance_well_known(f"/.well-known/oauth-authorization-server/org/{org_id}/spruce")

    @app.get("/org/{org_id}/spruce/.well-known/oauth-authorization-server")
    async def get_org_spruce_as_metadata_appended(org_id: str) -> Response:
        return await _proxy_to_issuance_well_known(f"/.well-known/oauth-authorization-server/org/{org_id}/spruce")

    # Google Wallet CredentialManager API variants

    @app.get("/.well-known/openid-credential-issuer/org/{org_id}/credential-manager")
    async def get_org_credential_manager_issuer_metadata(org_id: str) -> Response:
        return await _proxy_to_issuance_well_known(f"/.well-known/openid-credential-issuer/org/{org_id}/credential-manager")

    @app.get("/org/{org_id}/credential-manager/.well-known/openid-credential-issuer")
    async def get_org_credential_manager_issuer_metadata_appended(org_id: str) -> Response:
        return await _proxy_to_issuance_well_known(f"/.well-known/openid-credential-issuer/org/{org_id}/credential-manager")

    @app.get("/.well-known/oauth-authorization-server/org/{org_id}/credential-manager")
    async def get_org_credential_manager_as_metadata(org_id: str) -> Response:
        return await _proxy_to_issuance_well_known(f"/.well-known/oauth-authorization-server/org/{org_id}/credential-manager")

    @app.get("/org/{org_id}/credential-manager/.well-known/oauth-authorization-server")
    async def get_org_credential_manager_as_metadata_appended(org_id: str) -> Response:
        return await _proxy_to_issuance_well_known(f"/.well-known/oauth-authorization-server/org/{org_id}/credential-manager")
    # Apple Wallet variants

    @app.get("/.well-known/openid-credential-issuer/org/{org_id}/apple-wallet")
    async def get_org_apple_wallet_issuer_metadata(org_id: str) -> Response:
        return await _proxy_to_issuance_well_known(f"/.well-known/openid-credential-issuer/org/{org_id}/apple-wallet")

    @app.get("/org/{org_id}/apple-wallet/.well-known/openid-credential-issuer")
    async def get_org_apple_wallet_issuer_metadata_appended(org_id: str) -> Response:
        return await _proxy_to_issuance_well_known(f"/.well-known/openid-credential-issuer/org/{org_id}/apple-wallet")

    @app.get("/.well-known/oauth-authorization-server/org/{org_id}/apple-wallet")
    async def get_org_apple_wallet_as_metadata(org_id: str) -> Response:
        return await _proxy_to_issuance_well_known(f"/.well-known/oauth-authorization-server/org/{org_id}/apple-wallet")

    @app.get("/org/{org_id}/apple-wallet/.well-known/oauth-authorization-server")
    async def get_org_apple_wallet_as_metadata_appended(org_id: str) -> Response:
        return await _proxy_to_issuance_well_known(f"/.well-known/oauth-authorization-server/org/{org_id}/apple-wallet")
    # OID4VCI \u00a711.2.2 appended-form discovery

    @app.get("/org/{org_id}/.well-known/openid-credential-issuer")
    async def get_org_issuer_metadata_oid4vci_style(org_id: str) -> Response:
        return await _proxy_to_issuance_well_known(f"/.well-known/openid-credential-issuer/org/{org_id}")

    @app.get("/org/{org_id}/.well-known/oauth-authorization-server")
    async def get_org_oauth_metadata_oid4vci_style(org_id: str) -> Response:
        return await _proxy_to_issuance_well_known(f"/.well-known/oauth-authorization-server/org/{org_id}")

    @app.get("/.well-known/openid-credential-issuer")
    async def get_issuer_metadata() -> Response:
        """OID4VCI Issuer Metadata."""
        return await _proxy_to_issuance_well_known("/.well-known/openid-credential-issuer")

    @app.get("/.well-known//openid-credential-issuer")
    async def get_issuer_metadata_double_slash() -> Response:
        """OID4VCI Issuer Metadata (double-slash compat for EUDI wallet tester)."""
        return await _proxy_to_issuance_well_known("/.well-known/openid-credential-issuer")

    @app.get("/.well-known/oauth-authorization-server")
    async def get_oauth_authorization_server_metadata() -> Response:
        """OAuth Authorization Server Metadata."""
        return await _proxy_to_issuance_well_known("/.well-known/oauth-authorization-server")

    @app.get("/.well-known/openid-configuration")
    async def get_openid_configuration() -> dict:
        """OIDC Discovery metadata (compatibility endpoint used by some wallets)."""
        issuer_url = os.environ.get("ISSUER_BASE_URL", "http://localhost:8000")
        return {
            "issuer": issuer_url,
            "authorization_endpoint": f"{issuer_url}/v1/issuance/authorize",
            "token_endpoint": f"{issuer_url}/v1/issuance/token",
            "pushed_authorization_request_endpoint": f"{issuer_url}/v1/issuance/par",
            "credential_endpoint": f"{issuer_url}/v1/issuance/credential",
            "nonce_endpoint": f"{issuer_url}/v1/issuance/nonce",
            "deferred_credential_endpoint": f"{issuer_url}/v1/issuance/deferred-credential",
            "notification_endpoint": f"{issuer_url}/v1/issuance/notification",
            "jwks_uri": f"{issuer_url}/.well-known/jwks.json",
            "response_types_supported": ["code", "token", "id_token"],
            "subject_types_supported": ["public", "pairwise"],
            "subject_syntax_types_supported": [
                "urn:ietf:params:oauth:jwk-thumbprint",
                "did:key",
                "did:jwk",
            ],
            "id_token_signing_alg_values_supported": ["EdDSA", "ES256"],
            "grant_types_supported": [
                "authorization_code",
                "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            ],
            "token_endpoint_auth_methods_supported": ["none"],
        }

    @app.get("/.well-known/jwks.json")
    async def get_jwks() -> Response:
        """JWKS endpoint."""
        return await _proxy_to_issuance_well_known("/.well-known/jwks.json")

    @app.get("/.well-known/mip-configuration")
    async def get_mip_configuration() -> dict:
        """MIP \u00a710 \u2014 Every MIP implementation MUST expose this discovery endpoint."""
        issuer_url = os.environ.get("ISSUER_BASE_URL", "http://localhost:8000")
        registry = get_registry()

        # Gather active compliance profile codes from the compliance-profiles service
        active_profiles: list[dict] = []
        compliance_url = registry.get_service_url("compliance-profiles")
        if compliance_url:
            client = get_http_client()
            try:
                resp = await client.get(
                    f"{compliance_url}/v1/compliance-profiles",
                    params={"status": "active"},
                    timeout=5.0,
                )
                if resp.status_code == 200:
                    profiles_data = resp.json()
                    items = profiles_data if isinstance(profiles_data, list) else profiles_data.get("items", [])
                    for p in items:
                        entry: dict[str, Any] = {
                            "compliance_code": p.get("compliance_code"),
                            "credential_format": p.get("credential_format"),
                            "issuance_protocol": p.get("issuance_protocol"),
                        }
                        if p.get("api_surface"):
                            entry["api_surface"] = p["api_surface"]
                        active_profiles.append(entry)
            except Exception as exc:
                logger.warning("Failed to fetch compliance profiles for MIP config: %s", exc)

        return {
            "mip_version": "0.1",
            "supported_versions": ["0.1"],
            "issuer": issuer_url,
            "api_base_url": f"{issuer_url}/v1",
            "active_compliance_profiles": active_profiles,
            "supported_credential_formats": [
                "MDOC", "SD_JWT_VC", "VC_JWT", "JSON_LD", "ZK_MDOC",
            ],
            "supported_issuance_protocols": [
                "OID4VCI_PRE_AUTH", "OID4VCI_AUTH_CODE", "DIRECT",
            ],
            "endpoints": {
                "trust_profiles": f"{issuer_url}/v1/trust-profiles",
                "credential_templates": f"{issuer_url}/v1/credential-templates",
                "presentation_policies": f"{issuer_url}/v1/presentation-policies",
                "deployment_profiles": f"{issuer_url}/v1/deployment-profiles",
                "flows": f"{issuer_url}/v1/flows",
                "compliance_profiles": f"{issuer_url}/v1/compliance-profiles",
                "revocation_profiles": f"{issuer_url}/v1/revocation-profiles",
                "issued_credentials": f"{issuer_url}/v1/issued-credentials",
                "trust_registry": f"{issuer_url}/v1/trust-registry",
                "organizations": f"{issuer_url}/v1/organizations",
                "devices": f"{issuer_url}/v1/devices",
                "policy_sets": f"{issuer_url}/v1/policy-sets",
                "wallet_registry": f"{issuer_url}/v1/wallet-registry",
                "notifications": f"{issuer_url}/v1/notifications",
                "scim": f"{issuer_url}/v1/organizations/{{org_id}}/scim/v2",
            },
            "wallet_facing_endpoints": {
                "credential_offer": f"{issuer_url}/v1/issuance/offers/{{tx_id}}",
                "token": f"{issuer_url}/v1/issuance/token",
                "credential": f"{issuer_url}/v1/issuance/credential",
                "nonce": f"{issuer_url}/v1/issuance/nonce",
                "deferred_credential": f"{issuer_url}/v1/issuance/deferred-credential",
                "notification": f"{issuer_url}/v1/issuance/notification",
                "verification_request": f"{issuer_url}/v1/flows/instances/{{id}}/request",
                "verification_submit": f"{issuer_url}/v1/flows/instances/{{id}}/submit",
                "siop_request": f"{issuer_url}/v1/flows/siop/{{id}}/request",
                "siop_submit": f"{issuer_url}/v1/flows/siop/submit",
            },
            "authorization": {
                "policy_language": "cedar",
                "cedar_schema_version": "MIP/1.0",
            },
        }

    @app.get("/health/services")
    async def services_health() -> dict:
        """Check health of all backend services."""
        registry = get_registry()
        client = get_http_client()

        results = {}
        for service, url in registry.get_all_services().items():
            try:
                response = await client.get(f"{url}/health", timeout=5.0)
                results[service] = {
                    "status": "healthy" if response.status_code == 200 else "unhealthy",
                    "url": url,
                }
            except Exception as e:
                results[service] = {
                    "status": "unreachable",
                    "url": url,
                    "error": str(e),
                }

        return {"services": results}

    # \u2500\u2500 MIP \u00a717.7 \u2014 Global exception handlers \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
    from marty_common.errors import MartyError

    @app.exception_handler(MartyError)
    async def _marty_error_handler(request: Request, exc: MartyError):
        """Wrap MartyError subclasses in MIP error envelope."""
        return mip_error_response(
            status_code=exc.http_status,
            error=exc.code.lower(),
            message=exc.user_message or exc.message,
            details=[
                {"field": d.field, "message": d.message}
                for d in exc.details
            ] if exc.details else None,
        )

    @app.exception_handler(HTTPException)
    async def _http_exception_handler(request: Request, exc: HTTPException):
        """Wrap FastAPI HTTPException in MIP error envelope."""
        detail = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
        error_key = {
            400: "bad_request",
            401: "unauthorized",
            403: "forbidden",
            404: "not_found",
            409: "conflict",
            415: "unsupported_media_type",
            422: "validation_error",
            429: "rate_limit_exceeded",
            500: "server_error",
            502: "bad_gateway",
            503: "service_unavailable",
            504: "gateway_timeout",
        }.get(exc.status_code, "error")
        return mip_error_response(
            status_code=exc.status_code,
            error=error_key,
            message=detail,
        )

    @app.exception_handler(RequestValidationError)
    async def _request_validation_error_handler(request: Request, exc: RequestValidationError):
        """Wrap Pydantic/FastAPI validation errors in MIP error envelope."""
        details = []
        for err in exc.errors():
            field = ".".join(str(loc) for loc in err.get("loc", []))
            details.append({"field": field, "message": err.get("msg", "")})
        return mip_error_response(
            status_code=422,
            error="validation_error",
            message="Request validation failed",
            extra={"details": details},
        )

    @app.exception_handler(Exception)
    async def _unhandled_exception_handler(request: Request, exc: Exception):
        """Catch-all: return 500 in MIP envelope, never leak stack traces."""
        logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
        return mip_error_response(
            status_code=500,
            error="server_error",
            message="An unexpected error occurred",
        )

    from common.metrics import init_otel_tracing, mount_metrics
    init_otel_tracing(SERVICE_NAME)
    mount_metrics(app)

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("gateway.main:app", host="0.0.0.0", port=SERVICE_PORT, reload=True)
