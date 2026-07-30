"""Notification, Subscription, Webhook, SSE, and Policy Set routes."""

from __future__ import annotations

import json
import logging

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import StreamingResponse

from gateway.proxy import get_registry, proxy_request

logger = logging.getLogger(__name__)

notification_router = APIRouter(prefix="/v1/notifications", tags=["Notifications"])
subscription_router = APIRouter(prefix="/v1/subscriptions", tags=["Subscriptions"])
webhook_router = APIRouter(prefix="/v1/webhooks", tags=["Webhooks"])
policy_set_router = APIRouter(prefix="/v1/policy-sets", tags=["PolicySets"])


# ── SSE Real-time Events ────────────────────────────────────────────


async def _authorized_organization_id(
    request: Request,
    *,
    require_query: bool = False,
) -> str:
    """Bind every forwarded organization selector to the Cedar-approved tenant."""
    authorized = str(getattr(request.state, "organization_id", None) or "").strip()
    if not authorized:
        raise HTTPException(
            status_code=403,
            detail="Organization authorization context is required",
        )

    query_org = str(request.query_params.get("organization_id") or "").strip()
    if require_query and not query_org:
        raise HTTPException(
            status_code=422,
            detail="organization_id query parameter is required",
        )
    if query_org and query_org != authorized:
        raise HTTPException(
            status_code=403,
            detail="Organization scope does not match authorized organization",
        )

    if request.method.upper() in {"POST", "PUT", "PATCH"}:
        content_type = (
            (request.headers.get("content-type") or "").split(";", 1)[0].strip().lower()
        )
        if content_type == "application/json":
            try:
                payload = await request.json()
            except Exception:
                payload = None
            if isinstance(payload, dict):
                body_orgs = [payload.get("organization_id")]
                target = payload.get("target")
                if isinstance(target, dict):
                    body_orgs.append(target.get("organization_id"))
                if any(
                    isinstance(body_org, str) and body_org and body_org != authorized
                    for body_org in body_orgs
                ):
                    raise HTTPException(
                        status_code=403,
                        detail=(
                            "Organization scope does not match authorized organization"
                        ),
                    )

    return authorized


@notification_router.get("/events/push", summary="SSE Real-time Events")
async def sse_events(
    request: Request,
    organization_id: str | None = None,
    tenant_id: str | None = None,
    user_id: str | None = None,
    subscriptions: str | None = None,
) -> Response:
    """
    Server-Sent Events endpoint that bridges browser clients to the
    event-stream gRPC Subscribe RPC.  Filters by organization (tenant_id)
    and optional event_types.
    """
    authorized_org = await _authorized_organization_id(request)
    requested_orgs = {
        value.strip()
        for value in (organization_id, tenant_id)
        if isinstance(value, str) and value.strip()
    }
    if len(requested_orgs) > 1 or (
        requested_orgs and authorized_org not in requested_orgs
    ):
        raise HTTPException(
            status_code=403,
            detail="Organization scope does not match authorized organization",
        )

    authenticated_user = str(getattr(request.state, "user_id", None) or "").strip()
    if user_id and user_id != authenticated_user:
        raise HTTPException(
            status_code=403,
            detail="User scope does not match authenticated user",
        )

    from marty_proto.v1 import (
        event_stream_service_pb2,
        event_stream_service_pb2_grpc,
    )

    requested_types = (
        [s.strip() for s in subscriptions.split(",") if s.strip()]
        if subscriptions
        else []
    )

    async def generate():
        try:
            channel = request.app.state.es_grpc_channel
            stub = event_stream_service_pb2_grpc.EventStreamServiceStub(channel)
            sub_req = event_stream_service_pb2.EventSubscription(
                event_types=requested_types,
                organization_id=authorized_org,
            )
            # Send initial connection confirmation
            yield 'data: {"type": "connected"}\n\n'
            async for event in stub.Subscribe(sub_req):
                if await request.is_disconnected():
                    break
                payload = {
                    "event_id": event.event_id,
                    "aggregate_id": event.aggregate_id,
                    "aggregate_type": event.aggregate_type,
                    "organization_id": event.organization_id,
                    "data": dict(event.data),
                    "timestamp": event.timestamp,
                }
                yield f"event: {event.event_type}\ndata: {json.dumps(payload)}\n\n"
        except Exception as exc:
            logger.warning(
                "SSE stream error for tenant %s: %s",
                authorized_org,
                exc,
            )
            yield 'data: {"error": "stream_error"}\n\n'

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


# ── Notification catch-all proxy ─────────────────────────────────────


@notification_router.api_route(
    "", methods=["GET", "POST", "PUT", "PATCH", "DELETE"], summary="Notifications"
)
@notification_router.api_route(
    "/{subpath:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    summary="Notifications",
)
async def proxy_notifications(request: Request, subpath: str = "") -> Response:
    """Proxy all notification routes to notification service."""
    organization_id = await _authorized_organization_id(request)
    registry = get_registry()
    service_url = registry.get_service_url("notifications")
    target_path = "/v1/notifications"
    if subpath:
        target_path = f"{target_path}/{subpath}"
    return await proxy_request(
        request,
        service_url,
        target_path,
        inject_params={"organization_id": organization_id},
    )


# ── Subscriptions ────────────────────────────────────────────────────


@subscription_router.api_route("", methods=["GET", "POST"], summary="Subscriptions")
@subscription_router.api_route(
    "/{subpath:path}",
    methods=["GET", "PUT", "PATCH", "DELETE"],
    summary="Subscriptions",
)
async def proxy_subscriptions(request: Request, subpath: str = "") -> Response:
    """Proxy protocol subscription routes to notification service."""
    organization_id = await _authorized_organization_id(
        request,
        require_query=bool(subpath) or request.method.upper() == "GET",
    )
    registry = get_registry()
    service_url = registry.get_service_url("notifications")
    target_path = "/v1/subscriptions"
    if subpath:
        target_path = f"{target_path}/{subpath}"
    return await proxy_request(
        request,
        service_url,
        target_path,
        inject_params={"organization_id": organization_id},
    )


# ── Webhooks ─────────────────────────────────────────────────────────


@webhook_router.api_route("", methods=["GET", "POST"], summary="Webhooks")
@webhook_router.api_route(
    "/{subpath:path}",
    methods=["GET", "PUT", "PATCH", "DELETE", "POST"],
    summary="Webhooks",
)
async def proxy_webhooks(request: Request, subpath: str = "") -> Response:
    """Proxy protocol webhook routes to notification service."""
    organization_id = await _authorized_organization_id(
        request,
        require_query=bool(subpath) or request.method.upper() == "GET",
    )
    registry = get_registry()
    service_url = registry.get_service_url("notifications")
    target_path = "/v1/webhooks"
    if subpath:
        target_path = f"{target_path}/{subpath}"
    return await proxy_request(
        request,
        service_url,
        target_path,
        inject_params={"organization_id": organization_id},
    )


# ── Policy Sets (Cedar) ─────────────────────────────────────────────


@policy_set_router.api_route("", methods=["GET", "POST"], summary="Policy Sets")
@policy_set_router.api_route(
    "/{subpath:path}", methods=["GET", "PATCH", "DELETE", "POST"], summary="Policy Sets"
)
async def proxy_policy_sets(request: Request, subpath: str = "") -> Response:
    """Proxy MIP Policy Set operations to the organization-scoped service API."""
    organization_id = str(request.query_params.get("organization_id") or "").strip()
    if not organization_id:
        raise HTTPException(
            status_code=422, detail="organization_id query parameter is required"
        )
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    target_path = f"/v1/organizations/{organization_id}/policy-sets"
    if subpath:
        target_path = f"{target_path}/{subpath}"
    return await proxy_request(request, service_url, target_path)
