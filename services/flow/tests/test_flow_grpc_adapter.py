"""Tests for the Flow Service gRPC adapter."""

from __future__ import annotations

import sys
from enum import Enum
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import grpc
from common.application_event_auth import ApplicationEventAuthError


class _FlowInstanceStatus(str, Enum):
    IN_PROGRESS = "in_progress"
    AWAITING_WALLET = "awaiting_wallet"


class _StepType(str, Enum):
    APPROVAL = "approval"


class _TransitionCondition(str, Enum):
    SUCCESS = "success"


async def _check_preconditions(preconditions, _context):
    return False, list(preconditions)


class _ApplicationApprovedWebhook:
    def __init__(self, **values):
        if values.get("event_type") != "application.approved":
            raise ValueError("event_type must be application.approved")
        if values.get("aggregate_type") != "application":
            raise ValueError("aggregate_type must be application")
        self.__dict__.update(values)


class _VerificationStartPrincipal:
    def __init__(self, workload_identity: str):
        self.workload_identity = workload_identity

    @classmethod
    def workload(cls, identity: str):
        return cls(identity)


# Pre-inject a lightweight stub for flow.main so the deferred import inside
# the gRPC adapter doesn't pull in the entire flow service (and its heavy
# deps like jose, httpx, etc.).
_flow_main_stub = SimpleNamespace(
    AUTH_WORKLOAD_IDENTITY="spiffe://marty.internal/service/auth",
    StartVerificationFlowRequest=type(
        "StartVerificationFlowRequest",
        (),
        {"__init__": lambda self, **kw: self.__dict__.update(kw)},
    ),
    VerificationStartPrincipal=_VerificationStartPrincipal,
    ApplicationApprovedWebhook=_ApplicationApprovedWebhook,
    _private_flow_context_path=lambda value: next(
        (str(key) for key in value if str(key).lower().startswith("_marty_")),
        None,
    ),
    FlowInstanceStatus=_FlowInstanceStatus,
    StepType=_StepType,
    TransitionCondition=_TransitionCondition,
    check_preconditions=_check_preconditions,
)
sys.modules.setdefault("flow.main", _flow_main_stub)

from flow.infrastructure.adapters.grpc_adapter import FlowServiceGrpc  # noqa: E402
from marty_proto.v1 import flow_service_pb2  # noqa: E402


def _build_servicer(**overrides) -> FlowServiceGrpc:
    defaults = dict(
        start_verification_fn=AsyncMock(),
        application_approved_fn=AsyncMock(),
        authenticate_application_approved_fn=AsyncMock(
            return_value=SimpleNamespace(as_dict=lambda: {})
        ),
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
            issuer_did="did:web:verifier.example:orgs:org-1",
            trust_profile_id="trust-1",
            user_id="user-1",
            callback_url="https://example.com/callback",
            request_transport="url_query",
        )
        resp = await servicer.StartVerification(req, ctx)

        assert resp.instance_id == "inst-1"
        assert resp.request_uri == "https://example.com/request"
        assert resp.nonce == "nonce-abc"
        assert resp.status == "pending"
        assert ctx.code is None
        forwarded = start_verification.call_args.kwargs["request"]
        assert forwarded.trust_profile_id == "trust-1"
        assert forwarded.request_transport == "url_query"
        principal = start_verification.call_args.kwargs["principal"]
        assert principal.workload_identity == "spiffe://marty.internal/service/auth"
        assert "user_id" not in start_verification.call_args.kwargs

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
            issuer_did="did:web:verifier.example:orgs:org-1",
            user_id="auth-service",
            callback_url="http://auth:8001/internal/v1/auth/credential-verified?nonce=abc",
        )
        resp = await servicer.StartVerification(req, ctx)

        assert resp.instance_id == "inst-1"
        assert ctx.code is None
        forwarded = start_verification.call_args.kwargs["request"]
        assert (
            forwarded.callback_url
            == "http://auth:8001/internal/v1/auth/credential-verified?nonce=abc"
        )

    async def test_external_http_callback_is_rejected_for_grpc(self, ctx):
        start_verification = AsyncMock()
        servicer = _build_servicer(start_verification_fn=start_verification)

        req = flow_service_pb2.StartVerificationRequest(
            presentation_policy_id="pp-1",
            organization_id="org-1",
            issuer_did="did:web:verifier.example:orgs:org-1",
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
            issuer_did="did:web:verifier.example:orgs:org-1",
            user_id="user-1",
        )
        await servicer.StartVerification(req, ctx)

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
        await servicer.StartVerification(req, ctx)

        assert ctx.code == grpc.StatusCode.INVALID_ARGUMENT

    async def test_internal_error(self, ctx):
        servicer = _build_servicer(
            start_verification_fn=AsyncMock(side_effect=RuntimeError("database down"))
        )

        req = flow_service_pb2.StartVerificationRequest(
            presentation_policy_id="pp-1",
            organization_id="org-1",
            issuer_did="did:web:verifier.example:orgs:org-1",
            user_id="user-1",
        )
        await servicer.StartVerification(req, ctx)

        assert ctx.code == grpc.StatusCode.INTERNAL


# ── ApplicationApproved ──────────────────────────────────────────────


class TestPrivateFlowContext:
    async def test_start_rejects_reserved_context_before_repository_access(self, ctx):
        repo = MagicMock()
        servicer = _build_servicer(get_repo_fn=MagicMock(return_value=repo))
        response = await servicer.StartFlowInstance(
            flow_service_pb2.StartFlowRequest(
                flow_definition_id="flow-1",
                initial_context={"_marty_precondition_evidence_v1": "forged"},
            ),
            ctx,
        )
        assert response.id == ""
        assert ctx.code == grpc.StatusCode.INVALID_ARGUMENT
        repo.get_definition.assert_not_called()

    async def test_advance_rejects_reserved_context_before_repository_access(self, ctx):
        repo = MagicMock()
        servicer = _build_servicer(get_repo_fn=MagicMock(return_value=repo))
        response = await servicer.AdvanceFlowInstance(
            flow_service_pb2.AdvanceFlowRequest(
                instance_id="instance-1",
                data={"_marty_precondition_evidence_v1": "forged"},
            ),
            ctx,
        )
        assert response.id == ""
        assert ctx.code == grpc.StatusCode.INVALID_ARGUMENT
        repo.get_instance.assert_not_called()

    async def test_advance_enforces_preconditions_before_context_update(self, ctx):
        instance = SimpleNamespace(
            id="instance-1",
            flow_definition_id="flow-1",
            current_step_id="approval-step",
            status=_FlowInstanceStatus.IN_PROGRESS,
            context={"application_status": "approved"},
        )
        flow_def = SimpleNamespace(
            preconditions=["application_approved"],
            steps=[
                SimpleNamespace(
                    id="approval-step",
                    step_type=_StepType.APPROVAL,
                    config={},
                )
            ],
        )
        repo = MagicMock()
        repo.get_instance = AsyncMock(return_value=instance)
        repo.get_definition = AsyncMock(return_value=flow_def)
        repo.save_instance = AsyncMock()
        servicer = _build_servicer(get_repo_fn=MagicMock(return_value=repo))

        await servicer.AdvanceFlowInstance(
            flow_service_pb2.AdvanceFlowRequest(
                instance_id="instance-1",
                step_result="success",
                data={"application_status": "approved"},
            ),
            ctx,
        )

        assert ctx.code == grpc.StatusCode.FAILED_PRECONDITION
        assert "application_approved" in ctx.details
        assert instance.context == {"application_status": "approved"}
        repo.save_instance.assert_not_awaited()


class TestApplicationApproved:
    async def test_success(self, ctx):
        evidence = SimpleNamespace(as_dict=lambda: {"authenticated": "yes"})
        authenticate = AsyncMock(return_value=evidence)
        handler = AsyncMock(return_value={"success": True, "flows_triggered": 2})
        servicer = _build_servicer(
            application_approved_fn=handler,
            authenticate_application_approved_fn=authenticate,
        )

        req = flow_service_pb2.ApplicationApprovedEvent(
            event_type="application.approved",
            aggregate_id="app-1",
            aggregate_type="application",
            organization_id="org-1",
            data={
                "applicant_id": '"a-1"',
                "claims": '{"given_name":"Ada","roles":["member"]}',
            },
            timestamp="2026-03-14T00:00:00Z",
        )
        resp = await servicer.ApplicationApproved(req, ctx)

        assert resp.success is True
        assert resp.flows_triggered == 2
        assert ctx.code is None
        authenticated_event = authenticate.call_args.kwargs["event"]
        assert authenticated_event["data"] == {
            "applicant_id": "a-1",
            "claims": {"given_name": "Ada", "roles": ["member"]},
        }
        handler.assert_awaited_once()
        assert handler.call_args.kwargs["auth_evidence"] is evidence

    async def test_missing_authentication_never_reaches_handler(self, ctx):
        handler = AsyncMock()
        servicer = _build_servicer(
            application_approved_fn=handler,
            authenticate_application_approved_fn=AsyncMock(
                side_effect=ApplicationEventAuthError(
                    "missing_authentication", "authentication required"
                )
            ),
        )

        await servicer.ApplicationApproved(
            flow_service_pb2.ApplicationApprovedEvent(
                event_type="application.approved",
                aggregate_id="app-unauthenticated",
                aggregate_type="application",
                organization_id="org-1",
                data={"applicant_id": '"a-1"'},
                timestamp="2026-03-14T00:00:00Z",
            ),
            ctx,
        )

        assert ctx.code == grpc.StatusCode.UNAUTHENTICATED
        handler.assert_not_awaited()

    async def test_wrong_event_type_is_rejected_before_authentication(self, ctx):
        authenticate = AsyncMock()
        handler = AsyncMock()
        servicer = _build_servicer(
            application_approved_fn=handler,
            authenticate_application_approved_fn=authenticate,
        )

        await servicer.ApplicationApproved(
            flow_service_pb2.ApplicationApprovedEvent(
                event_type="application.rejected",
                aggregate_id="app-wrong-event",
                aggregate_type="application",
                organization_id="org-1",
                timestamp="2026-03-14T00:00:00Z",
            ),
            ctx,
        )

        assert ctx.code == grpc.StatusCode.INVALID_ARGUMENT
        authenticate.assert_awaited_once()
        handler.assert_not_awaited()

    async def test_replay_maps_to_already_exists(self, ctx):
        servicer = _build_servicer(
            authenticate_application_approved_fn=AsyncMock(
                side_effect=ApplicationEventAuthError(
                    "replayed_event", "already consumed"
                )
            )
        )
        await servicer.ApplicationApproved(
            flow_service_pb2.ApplicationApprovedEvent(
                event_type="application.approved",
                aggregate_id="app-replayed",
                aggregate_type="application",
                organization_id="org-1",
                timestamp="2026-03-14T00:00:00Z",
            ),
            ctx,
        )
        assert ctx.code == grpc.StatusCode.ALREADY_EXISTS

    async def test_handler_error(self, ctx):
        servicer = _build_servicer(
            application_approved_fn=AsyncMock(side_effect=RuntimeError("boom"))
        )

        req = flow_service_pb2.ApplicationApprovedEvent(
            event_type="application.approved",
            aggregate_id="app-2",
            aggregate_type="application",
            organization_id="org-1",
            data={},
            timestamp="2026-03-14T00:00:00Z",
        )
        await servicer.ApplicationApproved(req, ctx)

        assert ctx.code == grpc.StatusCode.INTERNAL
        assert "boom" in ctx.details


# ── HealthCheck ──────────────────────────────────────────────────────


class TestHealthCheck:
    async def test_returns_serving(self, ctx):
        servicer = _build_servicer()
        req = flow_service_pb2.HealthCheckRequest()
        resp = await servicer.HealthCheck(req, ctx)
        assert resp.status == "serving"
