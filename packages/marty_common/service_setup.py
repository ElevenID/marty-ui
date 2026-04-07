"""
Service Setup Helpers

Eliminates copy-pasted middleware and initialization boilerplate
across Marty microservices.

Usage::

    from marty_common.service_setup import create_service_app

    app = create_service_app(
        title="Credential Template Service",
        service_name="credential-template-service",
        version="1.0.0",
        lifespan=lifespan,
        routers=[router, wallet_router],
    )
"""

from __future__ import annotations

import logging
import os
from typing import Any, Sequence

from fastapi import APIRouter, FastAPI
from fastapi.middleware.cors import CORSMiddleware

logger = logging.getLogger(__name__)


def create_service_app(
    *,
    title: str,
    service_name: str,
    description: str = "",
    version: str = "1.0.0",
    lifespan: Any = None,
    routers: Sequence[APIRouter] = (),
    cors_origins: list[str] | None = None,
    enable_otel: bool = True,
    **fastapi_kwargs: Any,
) -> FastAPI:
    """Create a FastAPI app with the standard Marty middleware stack.

    This wires up, in correct Starlette execution order (outermost first):

    1. ``CORSMiddleware``
    2. ``RequestIdMiddleware``   — injects / forwards ``X-Request-ID``
    3. ``RequestLoggingMiddleware`` — structured request/response logging
    4. ``/health`` endpoint
    5. ``/metrics`` + OpenTelemetry tracing (opt-in, default on)

    Parameters
    ----------
    title:
        FastAPI ``title``.
    service_name:
        Used for logging middleware, OTel service name, and health endpoint.
    description:
        FastAPI ``description``.
    version:
        FastAPI ``version``.
    lifespan:
        Async context-manager for startup/shutdown (``lifespan`` protocol).
    routers:
        Sequence of ``APIRouter`` instances to include.
    cors_origins:
        Allowed origins.  Defaults to ``CORS_ORIGINS`` env var or ``["*"]``.
    enable_otel:
        If ``True`` (default), initialise OTel tracing and mount ``/metrics``.
    **fastapi_kwargs:
        Extra keyword arguments forwarded to ``FastAPI()``, e.g.
        ``docs_url``, ``redoc_url``, ``openapi_url``.
    """
    app = FastAPI(
        title=title,
        description=description,
        version=version,
        lifespan=lifespan,
        **fastapi_kwargs,
    )

    # ── CORS ──────────────────────────────────────────────────────────
    if cors_origins is None:
        env_origins = os.environ.get("CORS_ORIGINS")
        cors_origins = (
            [o.strip() for o in env_origins.split(",")]
            if env_origins
            else ["*"]
        )

    # Warn if CORS_ORIGINS is not explicitly configured in production-like envs.
    if cors_origins == ["*"]:
        _env = os.environ.get("ENVIRONMENT", "production")
        if _env not in ("development", "test"):
            import logging as _logging
            _logging.getLogger("marty_common.service_setup").warning(
                "CORS_ORIGINS not set — defaulting to wildcard. "
                "Set CORS_ORIGINS env var for production deployments."
            )

    # When origins is ["*"], browsers reject Access-Control-Allow-Credentials
    # with wildcard origin.  Disable credentials in that case to avoid a
    # misleading (and potentially exploitable) CORS configuration.
    allow_creds = cors_origins != ["*"]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=allow_creds,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Request middleware ─────────────────────────────────────────────
    # Starlette runs middleware in reverse registration order, so register
    # logging first and request-id second ⇒ request-id runs outermost.
    from marty_common.middleware import RequestIdMiddleware, RequestLoggingMiddleware

    app.add_middleware(RequestLoggingMiddleware, service_name=service_name)
    app.add_middleware(RequestIdMiddleware)

    # ── Security headers ──────────────────────────────────────────────
    from marty_common.middleware import SecurityHeadersMiddleware

    app.add_middleware(SecurityHeadersMiddleware)

    # ── Routers ───────────────────────────────────────────────────────
    for router in routers:
        app.include_router(router)

    # ── Health / readiness / startup ─────────────────────────────────
    @app.get("/health")
    async def health_check() -> dict:
        return {"status": "healthy", "service": service_name}

    @app.get("/ready")
    async def readiness_check() -> dict:
        """Readiness probe — returns 200 once the service can accept traffic.

        Because all routers are registered synchronously before the app
        starts serving, reaching this handler already implies the
        FastAPI app is fully wired.  Services that need deeper checks
        (e.g. DB connectivity) can override via a custom router.
        """
        return {"status": "ready", "service": service_name}

    @app.get("/startup")
    async def startup_check() -> dict:
        """Startup probe — returns 200 once initial boot is complete."""
        return {"status": "started", "service": service_name}

    # ── Observability ─────────────────────────────────────────────────
    if enable_otel:
        try:
            from common.metrics import init_otel_tracing, mount_metrics

            init_otel_tracing(service_name)
            mount_metrics(app)
        except ImportError:
            logger.debug("common.metrics not available; OTel/metrics disabled")

    return app
