"""Notification, Subscription, Webhook, SSE, and Policy Set routes."""
from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Request, Response
from fastapi.responses import StreamingResponse

from gateway.proxy import get_registry, proxy_request

logger = logging.getLogger(__name__)

notification_router = APIRouter(prefix="/v1/notifications", tags=["Notifications"])
subscription_router = APIRouter(prefix="/v1/subscriptions", tags=["Subscriptions"])
webhook_router = APIRouter(prefix="/v1/webhooks", tags=["Webhooks"])
policy_set_router = APIRouter(prefix="/v1/policy-sets", tags=["PolicySets"])


# ── SSE Real-time Events ────────────────────────────────────────────

@notification_router.get("/events/push", summary="SSE Real-time Events")
async def sse_events(
    request: Request,
    tenant_id: str | None = None,
    user_id: str | None = None,
    subscriptions: str | None = None,
) -> Response:
    """
    Server-Sent Events endpoint that bridges browser clients to the
    event-stream gRPC Subscribe RPC.  Filters by organization (tenant_id)
    and optional event_types.
    """
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
                organization_id=tenant_id or "",
            )
            # Send initial connection confirmation
            yield "data: {\"type\": \"connected\"}\n\n"
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
            logger.warning("SSE stream error for tenant %s: %s", tenant_id, exc)
            yield f"data: {{\"error\": \"stream_error\"}}\n\n"

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

@notification_router.api_route("", methods=["GET", "POST", "PUT", "PATCH", "DELETE"], summary="Notifications")
@notification_router.api_route("/{subpath:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"], summary="Notifications")
async def proxy_notifications(request: Request, subpath: str = "") -> Response:
    """Proxy all notification routes to notification service."""
    registry = get_registry()
    service_url = registry.get_service_url("notifications")
    target_path = "/v1/notifications"
    if subpath:
        target_path = f"{target_path}/{subpath}"
    return await proxy_request(request, service_url, target_path)


# ── Subscriptions ────────────────────────────────────────────────────

@subscription_router.api_route("", methods=["GET", "POST"], summary="Subscriptions")
@subscription_router.api_route("/{subpath:path}", methods=["GET", "PUT", "DELETE"], summary="Subscriptions")
async def proxy_subscriptions(request: Request, subpath: str = "") -> Response:
    """Proxy protocol subscription routes to notification service."""
    registry = get_registry()
    service_url = registry.get_service_url("notifications")
    target_path = "/v1/subscriptions"
    if subpath:
        target_path = f"{target_path}/{subpath}"
    return await proxy_request(request, service_url, target_path)


# ── Webhooks ─────────────────────────────────────────────────────────

@webhook_router.api_route("", methods=["GET", "POST"], summary="Webhooks")
@webhook_router.api_route("/{subpath:path}", methods=["GET", "PUT", "DELETE"], summary="Webhooks")
async def proxy_webhooks(request: Request, subpath: str = "") -> Response:
    """Proxy protocol webhook routes to notification service."""
    registry = get_registry()
    service_url = registry.get_service_url("notifications")
    target_path = "/v1/webhooks"
    if subpath:
        target_path = f"{target_path}/{subpath}"
    return await proxy_request(request, service_url, target_path)


# ── Policy Sets (Cedar) ─────────────────────────────────────────────

@policy_set_router.api_route("", methods=["GET", "POST"], summary="Policy Sets")
@policy_set_router.api_route("/{subpath:path}", methods=["GET", "PATCH", "DELETE", "POST"], summary="Policy Sets")
async def proxy_policy_sets(request: Request, subpath: str = "") -> Response:
    """Proxy policy-set CRUD (including /activate, /archive, /validate) to organization service."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    target_path = "/v1/policy-sets"
    if subpath:
        target_path = f"{target_path}/{subpath}"
    return await proxy_request(request, service_url, target_path)
