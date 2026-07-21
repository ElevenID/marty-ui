"""Tests for the Flow Service gRPC adapter."""

from __future__ import annotations

import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import grpc
import pytest

# Pre-inject a lightweight stub for flow.main so the deferred import inside
# the gRPC adapter doesn't pull in the entire flow service (and its heavy
# deps like jose, httpx, etc.).
_flow_main_stub = SimpleNamespace(
    StartVerificationFlowRequest=type(
        "StartVerificationFlowRequest",
        (),
        {"__init__": lambda self, **kw: self.__dict__.update(kw)},
    ),
    ApplicationApprovedWebhook=type(
        "ApplicationApprovedWebhook",
        (),
        {"__init__": lambda self, **kw: self.__dict__.update(kw)},
    ),
)
sys.modules.setdefault("flow.main", _flow_main_stub)

from flow.infrastructure.adapters.grpc_adapter import FlowServiceGrpc
from marty_proto.v1 import flow_service_pb2


def _build_servicer(**overrides) -> FlowServiceGrpc:
    defaults = dict(
        start_verification_fn=AsyncMock(),
        application_approved_fn=AsyncMock(),
        get_repo_fn=MagicMock(return_value=MagicMock()),
    )
    defaults.update(overrides)
    return FlowServiceGrpc(**defaults)


# ── StartVerification ────────────────────────────────────────────────


class TestStartVerification:
    async def test_success(self, ctx):
        result = SimpleNamespace(
            instance_id="inst-1",
            flow_definition_id="fdef-1",
            request_uri="https://example.com/request",
            qr_code_data="openid4vp://...",
            presentation_policy_id="pp-1",
            nonce="nonce-abc",
            expires_at="2026-03-15T00:00:00Z",
            status="pending",
        )
        start_verification = AsyncMock(return_value=result)
        servicer = _build_servicer(start_verification_fn=start_verification)

        req = flow_service_pb2.StartVerificationRequest(
            presentation_policy_id="pp-1",
            organization_id="org-1",
            trust_profile_id="trust-1",
            user_id="user-1",
            callback_url="https://example.com/callback",
        )
        resp = await servicer.StartVerification(req, ctx)

        assert resp.instance_id == "inst-1"
        assert resp.request_uri == "https://example.com/request"
        assert resp.nonce == "nonce-abc"
        assert resp.status == "pending"
        assert ctx.code is None
        forwarded = start_verification.call_args.kwargs["request"]
        assert forwarded.trust_profile_id == "trust-1"

    async def test_internal_http_callback_is_allowed_for_grpc(self, ctx):
        result = SimpleNamespace(
            instance_id="inst-1",
            flow_definition_id="fdef-1",
            request_uri="https://example.com/request",
            qr_code_data="openid4vp://...",
            presentation_policy_id="pp-1",
            nonce="nonce-abc",
            expires_at="2026-03-15T00:00:00Z",
            status="pending",
        )
        start_verification = AsyncMock(return_value=result)
        servicer = _build_servicer(start_verification_fn=start_verification)

        req = flow_service_pb2.StartVerificationRequest(
            presentation_policy_id="pp-1",
            organization_id="org-1",
            user_id="auth-service",
            callback_url="http://auth:8001/internal/v1/auth/credential-verified?nonce=abc",
        )
        resp = await servicer.StartVerification(req, ctx)

        assert resp.instance_id == "inst-1"
        assert ctx.code is None
        forwarded = start_verification.call_args.kwargs["request"]
        assert forwarded.callback_url == "http://auth:8001/internal/v1/auth/credential-verified?nonce=abc"

    async def test_external_http_callback_is_rejected_for_grpc(self, ctx):
        start_verification = AsyncMock()
        servicer = _build_servicer(start_verification_fn=start_verification)

        req = flow_service_pb2.StartVerificationRequest(
            presentation_policy_id="pp-1",
            organization_id="org-1",
            user_id="auth-service",
            callback_url="http://example.com/callback",
        )
        resp = await servicer.StartVerification(req, ctx)

        assert resp.instance_id == ""
        assert ctx.code == grpc.StatusCode.INVALID_ARGUMENT
        assert "callback_url" in ctx.details
        start_verification.assert_not_called()

    async def test_not_found_error(self, ctx):
        servicer = _build_servicer(
            start_verification_fn=AsyncMock(side_effect=Exception("Policy not found"))
        )

        req = flow_service_pb2.StartVerificationRequest(
            presentation_policy_id="missing",
            organization_id="org-1",
            user_id="user-1",
        )
        resp = await servicer.StartVerification(req, ctx)

        assert ctx.code == grpc.StatusCode.NOT_FOUND
        assert "not found" in ctx.details.lower()

    async def test_invalid_request_error(self, ctx):
        servicer = _build_servicer(
            start_verification_fn=AsyncMock(
                side_effect=Exception("invalid_request: missing required fields")
            )
        )

        req = flow_service_pb2.StartVerificationRequest(
            organization_id="org-1",
            user_id="user-1",
        )
        resp = await servicer.StartVerification(req, ctx)

        assert ctx.code == grpc.StatusCode.INVALID_ARGUMENT

    async def test_internal_error(self, ctx):
        servicer = _build_servicer(
            start_verification_fn=AsyncMock(side_effect=RuntimeError("database down"))
        )

        req = flow_service_pb2.StartVerificationRequest(
            presentation_policy_id="pp-1",
            organization_id="org-1",
            user_id="user-1",
        )
        resp = await servicer.StartVerification(req, ctx)

        assert ctx.code == grpc.StatusCode.INTERNAL


# ── ApplicationApproved ──────────────────────────────────────────────


class TestApplicationApproved:
    async def test_success(self, ctx):
        servicer = _build_servicer(
            application_approved_fn=AsyncMock(
                return_value={"success": True, "flows_triggered": 2}
            )
        )

        req = flow_service_pb2.ApplicationApprovedEvent(
            event_type="application.approved",
            aggregate_id="app-1",
            aggregate_type="Application",
            organization_id="org-1",
            data={"applicant_id": "a-1", "credential_type": "MemberCredential"},
            timestamp="2026-03-14T00:00:00Z",
        )
        resp = await servicer.ApplicationApproved(req, ctx)

        assert resp.success is True
        assert resp.flows_triggered == 2
        assert ctx.code is None

    async def test_handler_error(self, ctx):
        servicer = _build_servicer(
            application_approved_fn=AsyncMock(side_effect=RuntimeError("boom"))
        )

        req = flow_service_pb2.ApplicationApprovedEvent(
            event_type="application.approved",
            aggregate_id="app-2",
            aggregate_type="Application",
            organization_id="org-1",
            data={},
            timestamp="2026-03-14T00:00:00Z",
        )
        resp = await servicer.ApplicationApproved(req, ctx)

        assert ctx.code == grpc.StatusCode.INTERNAL
        assert "boom" in ctx.details


# ── HealthCheck ──────────────────────────────────────────────────────


class TestHealthCheck:
    async def test_returns_serving(self, ctx):
        servicer = _build_servicer()
        req = flow_service_pb2.HealthCheckRequest()
        resp = await servicer.HealthCheck(req, ctx)
        assert resp.status == "serving"
