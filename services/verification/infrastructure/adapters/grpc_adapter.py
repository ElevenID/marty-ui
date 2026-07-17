"""
Verification Service gRPC Adapter (Inbound)

Implements the VerificationService gRPC servicer, delegating to the same
session store and evaluation logic that backs the REST endpoints.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import grpc

from marty_proto.v1 import (
    verification_service_pb2 as vs_pb2,
    verification_service_pb2_grpc,
)

logger = logging.getLogger(__name__)


def _session_to_pb(s: Any) -> vs_pb2.VerificationSession:
    from verification.main import _protocol_status_for_session

    return vs_pb2.VerificationSession(
        session_id=s.session_id,
        organization_id=s.organization_id,
        presentation_policy_id=s.presentation_policy_id or "",
        response_type=s.response_type,
        status=_protocol_status_for_session(s),
        request_uri=s.request_uri(),
        qr_code_data=s.qr_code_data(),
        nonce=s.nonce,
        expires_at=s.expires_at.isoformat(),
        created_at=s.created_at.isoformat(),
        external_reference=s.external_reference or "",
        result=s.result or "",
        decision=s.decision or "",
        verified_claims_json=json.dumps(s.verified_claims) if s.verified_claims else "",
    )


class VerificationServiceGrpc(
    verification_service_pb2_grpc.VerificationServiceServicer,
):
    """gRPC inbound adapter for the verification service."""

    def __init__(self, get_store_fn: Any) -> None:
        self._get_store = get_store_fn

    # -- StartVerification ---------------------------------------------------

    async def StartVerification(self, request, context):
        from verification.main import SessionStatus, VerificationSession

        if request.response_type in ("vp_token", "") and not request.presentation_policy_id:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("presentation_policy_id is required for vp_token")
            return vs_pb2.VerificationSession()

        session = VerificationSession(
            organization_id=request.organization_id,
            presentation_policy_id=request.presentation_policy_id or None,
            response_type=request.response_type or "vp_token",
            trust_profile_id=request.trust_profile_id or None,
            deployment_profile_id=request.deployment_profile_id or None,
            external_reference=request.external_reference or None,
            callback_url=request.callback_url or None,
            expiry_minutes=request.expiry_minutes or 15,
            purpose=request.purpose or "",
        )
        store = self._get_store()
        store.save(session, touch_updated_at=False)
        logger.info("gRPC StartVerification: %s", session.session_id)
        return _session_to_pb(session)

    # -- GetSession ----------------------------------------------------------

    async def GetSession(self, request, context):
        store = self._get_store()
        session = store.get(request.session_id)
        if not session:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details(f"Session {request.session_id} not found")
            return vs_pb2.VerificationSession()
        return _session_to_pb(session)

    # -- SubmitPresentation --------------------------------------------------

    async def SubmitPresentation(self, request, context):
        from verification.main import (
            SessionStatus,
            _evaluate_via_grpc,
            _inspect_via_grpc,
            INSPECTION_SYSTEM_TARGET,
        )
        from datetime import datetime, timezone

        store = self._get_store()
        session = store.get(request.session_id)
        if not session:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details(f"Session {request.session_id} not found")
            return vs_pb2.VerificationResult()

        if session.status != SessionStatus.PENDING:
            context.set_code(grpc.StatusCode.FAILED_PRECONDITION)
            context.set_details(f"Session is {session.status.value}")
            return vs_pb2.VerificationResult()

        session.vp_token = request.vp_token
        try:
            eval_result = await _evaluate_via_grpc(
                policy_id=session.presentation_policy_id or "",
                vp_token=request.vp_token,
                nonce=session.nonce,
                context_json=json.dumps({"session_id": request.session_id}),
            )
            session.result = eval_result.get("result", "failed")
            session.decision = eval_result.get("decision", "deny")
            session.decision_reason = eval_result.get("decision_reason", "")
            session.verified_claims = eval_result.get("verified_claims", {})
            session.credential_results = eval_result.get("credential_results", [])
        except Exception as exc:
            session.result = "failed"
            session.decision = "deny"
            session.decision_reason = str(exc)
            eval_result = {"credential_results": [], "total_requirements": 0, "satisfied_requirements": 0}

        if INSPECTION_SYSTEM_TARGET and session.result != "failed":
            inspection_result = await _inspect_via_grpc(request.vp_token)
            if inspection_result:
                session.inspection_performed = True
                session.inspection_result = inspection_result

        session.status = SessionStatus.COMPLETED if session.result == "passed" else SessionStatus.FAILED
        session.completed_at = datetime.now(timezone.utc)
        session.updated_at = session.completed_at
        store.save(session, touch_updated_at=False)

        return vs_pb2.VerificationResult(
            session_id=request.session_id,
            result=session.result or "",
            decision=session.decision or "",
            decision_reason=session.decision_reason,
            verified_claims_json=json.dumps(session.verified_claims),
            credential_results_json=json.dumps(session.credential_results),
            total_requirements=eval_result.get("total_requirements", 0),
            satisfied_requirements=eval_result.get("satisfied_requirements", 0),
            evaluation_timestamp=session.completed_at.isoformat(),
            nonce=session.nonce,
            inspection_performed=session.inspection_performed,
            inspection_result=session.inspection_result,
        )

    # -- EvaluatePresentation ------------------------------------------------

    async def EvaluatePresentation(self, request, context):
        from verification.main import _evaluate_via_grpc

        try:
            eval_result = await _evaluate_via_grpc(
                policy_id=request.presentation_policy_id,
                vp_token=request.vp_token,
                nonce=request.nonce or None,
                context_json=request.context_json or "{}",
            )
        except Exception as exc:
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(exc))
            return vs_pb2.VerificationResult()

        return vs_pb2.VerificationResult(
            result=eval_result.get("result", ""),
            decision=eval_result.get("decision", ""),
            decision_reason=eval_result.get("decision_reason", ""),
            verified_claims_json=json.dumps(eval_result.get("verified_claims", {})),
            credential_results_json=json.dumps(eval_result.get("credential_results", [])),
            total_requirements=eval_result.get("total_requirements", 0),
            satisfied_requirements=eval_result.get("satisfied_requirements", 0),
            evaluation_timestamp=eval_result.get("evaluation_timestamp", ""),
            nonce=eval_result.get("nonce", ""),
        )

    # -- ListSessions --------------------------------------------------------

    async def ListSessions(self, request, context):
        store = self._get_store()
        sessions = store.list_by_org(
            request.organization_id,
            request.status or None,
        )
        limit = request.limit or 50
        offset = request.offset or 0
        page = sessions[offset: offset + limit]
        return vs_pb2.ListSessionsResponse(
            sessions=[_session_to_pb(s) for s in page],
            total=len(sessions),
        )

    # -- GetInspectionResult -------------------------------------------------

    async def GetInspectionResult(self, request, context):
        store = self._get_store()
        session = store.get(request.session_id)
        if not session:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details(f"Session {request.session_id} not found")
            return vs_pb2.InspectionResultResponse()

        return vs_pb2.InspectionResultResponse(
            session_id=session.session_id,
            performed=session.inspection_performed,
            result=session.inspection_result,
            detail_json="{}",
            timestamp=session.completed_at.isoformat() if session.completed_at else "",
        )

    # -- HealthCheck ---------------------------------------------------------

    async def HealthCheck(self, request, context):
        return vs_pb2.HealthCheckResponse(status="serving")
