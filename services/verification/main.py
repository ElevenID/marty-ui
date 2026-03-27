"""
Verification Service

Manages standalone credential verification sessions using OID4VP and SIOPv2.
Delegates policy evaluation to the Presentation Policy service via gRPC and,
when configured, calls the Marty InspectionSystem for deep document inspection
(ISO 18013-5 mDoc, passport CHIP, etc.).

Session lifecycle:
  1. POST /v1/verify          — create session with request_uri / QR code
  2. GET  /v1/verify/{id}/request — wallet fetches OID4VP request object
  3. POST /v1/verify/{id}/submit  — wallet POSTs VP token
  4. GET  /v1/verify/{id}         — relying-party polls for result

Stateless shortcut:
  POST /v1/verify/evaluate — evaluate any VP token against a policy in one call

Port: 8012  |  gRPC: 9017
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, AsyncGenerator

import grpc
import grpc.aio as grpc_aio
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SERVICE_NAME = "verification"
SERVICE_PORT = int(os.environ.get("VERIFICATION_SERVICE_PORT", "8012"))
GRPC_ENABLED = os.environ.get("VERIF_GRPC_ENABLED", "true").lower() == "true"
GRPC_PORT = int(os.environ.get("VERIF_GRPC_PORT", "9017"))

# Downstream gRPC targets
PP_GRPC_TARGET = os.environ.get("PP_GRPC_TARGET", "presentation-policy:9009")
INSPECTION_SYSTEM_TARGET = os.environ.get("INSPECTION_SYSTEM_TARGET", "")  # optional

PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "http://localhost:8012")

# ---------------------------------------------------------------------------
# Domain models
# ---------------------------------------------------------------------------

class SessionStatus(str, Enum):
    PENDING = "pending"
    COMPLETED = "completed"
    EXPIRED = "expired"
    FAILED = "failed"


class VerificationSession:
    def __init__(
        self,
        organization_id: str,
        presentation_policy_id: str | None = None,
        response_type: str = "vp_token",
        trust_profile_id: str | None = None,
        deployment_profile_id: str | None = None,
        external_reference: str | None = None,
        callback_url: str | None = None,
        expiry_minutes: int = 15,
        purpose: str = "",
    ) -> None:
        self.session_id = str(uuid.uuid4())
        self.flow_id = str(uuid.uuid4())
        self.flow_instance_id = self.session_id
        self.organization_id = organization_id
        self.presentation_policy_id = presentation_policy_id
        self.response_type = response_type
        self.trust_profile_id = trust_profile_id
        self.deployment_profile_id = deployment_profile_id
        self.external_reference = external_reference
        self.callback_url = callback_url
        self.purpose = purpose
        self.nonce = secrets.token_urlsafe(16)
        self.holder_id: str | None = None
        self.status = SessionStatus.PENDING
        self.created_at = datetime.now(timezone.utc)
        self.updated_at = self.created_at
        self.expires_at = self.created_at + timedelta(minutes=expiry_minutes)
        # Set on completion
        self.result: str | None = None
        self.decision: str | None = None
        self.decision_reason: str = ""
        self.verified_claims: dict[str, Any] = {}
        self.credential_results: list[dict] = []
        self.inspection_performed: bool = False
        self.inspection_result: str = ""
        self.vp_token: str | None = None
        self.completed_at: datetime | None = None
        self.error: str | None = None

    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.expires_at

    def request_uri(self) -> str:
        return f"{PUBLIC_BASE_URL}/v1/verify/{self.session_id}/request"

    def qr_code_data(self) -> str:
        return f"openid4vp://authorize?request_uri={self.request_uri()}"


# ---------------------------------------------------------------------------
# In-memory session store (replace with Redis/DB for production)
# ---------------------------------------------------------------------------

class SessionStore:
    def __init__(self) -> None:
        self._sessions: dict[str, VerificationSession] = {}

    def save(self, session: VerificationSession) -> None:
        self._sessions[session.session_id] = session

    def get(self, session_id: str) -> VerificationSession | None:
        session = self._sessions.get(session_id)
        if session and session.is_expired() and session.status == SessionStatus.PENDING:
            session.status = SessionStatus.EXPIRED
            session.error = "Session expired before presentation was submitted"
            session.updated_at = datetime.now(timezone.utc)
        return session

    def list_by_org(self, org_id: str, status: str | None = None) -> list[VerificationSession]:
        sessions = [s for s in self._sessions.values() if s.organization_id == org_id]
        if status:
            sessions = [s for s in sessions if s.status.value == status]
        return sorted(sessions, key=lambda s: s.created_at, reverse=True)


_store = SessionStore()


def get_store() -> SessionStore:
    return _store


# ---------------------------------------------------------------------------
# gRPC helper — policy evaluation via PP service
# ---------------------------------------------------------------------------

async def _evaluate_via_grpc(
    policy_id: str,
    vp_token: str,
    nonce: str | None,
    context_json: str = "{}",
) -> dict[str, Any]:
    """Call PresentationPolicyService.EvaluatePresentation via gRPC."""
    try:
        from marty_proto.v1 import (
            presentation_policy_service_pb2,
            presentation_policy_service_pb2_grpc,
        )

        channel = grpc_aio.insecure_channel(PP_GRPC_TARGET)
        stub = presentation_policy_service_pb2_grpc.PresentationPolicyServiceStub(channel)
        req = presentation_policy_service_pb2.EvaluatePresentationRequest(
            policy_id=policy_id,
            vp_token=vp_token,
            nonce=nonce or "",
            context_json=context_json,
        )
        resp = await stub.EvaluatePresentation(req)
        await channel.close()
        return {
            "result": resp.result,
            "decision": resp.decision,
            "decision_reason": resp.decision_reason,
            "verified_claims": json.loads(resp.verified_claims_json) if resp.verified_claims_json else {},
            "credential_results": json.loads(resp.credential_results_json) if resp.credential_results_json else [],
            "total_requirements": resp.total_requirements,
            "satisfied_requirements": resp.satisfied_requirements,
            "evaluation_timestamp": resp.evaluation_timestamp,
            "nonce": resp.nonce,
        }
    except Exception as exc:
        logger.warning("PP gRPC evaluation failed: %s", exc)
        raise


async def _inspect_via_grpc(item: str) -> str:
    """Call Marty InspectionSystem.Inspect via gRPC (optional)."""
    if not INSPECTION_SYSTEM_TARGET:
        return ""
    try:
        from marty_proto.v1 import inspection_system_pb2, inspection_system_pb2_grpc  # type: ignore

        channel = grpc_aio.insecure_channel(INSPECTION_SYSTEM_TARGET)
        stub = inspection_system_pb2_grpc.InspectionSystemStub(channel)
        resp = await stub.Inspect(inspection_system_pb2.InspectRequest(item=item))
        await channel.close()
        return resp.result
    except Exception as exc:
        logger.warning("InspectionSystem gRPC call failed: %s", exc)
        return ""


# ---------------------------------------------------------------------------
# REST API – request/response models
# ---------------------------------------------------------------------------

class StartVerificationRequest(BaseModel):
    organization_id: str
    presentation_policy_id: str | None = None
    response_type: str = "vp_token"
    trust_profile_id: str | None = None
    deployment_profile_id: str | None = None
    external_reference: str | None = None
    callback_url: str | None = None
    expiry_minutes: int = 15
    purpose: str = ""


class SubmitVerificationRequest(BaseModel):
    vp_token: str
    presentation_submission: dict | None = None


class EvaluateRequest(BaseModel):
    vp_token: str
    presentation_policy_id: str
    nonce: str | None = None
    audience: str | None = None
    context: dict | None = None


def _protocol_status_for_session(session: VerificationSession) -> str:
    if session.status == SessionStatus.EXPIRED:
        return "EXPIRED"
    if session.status == SessionStatus.FAILED:
        return "FAILED"
    if session.status == SessionStatus.COMPLETED:
        return "PASSED"
    return "PENDING"


def _collect_claims_missing(credential_results: list[dict[str, Any]]) -> list[str]:
    missing: list[str] = []
    for credential_result in credential_results:
        for key in ("claims_missing", "missing_claims", "unsatisfied_claims"):
            values = credential_result.get(key)
            if isinstance(values, list):
                missing.extend(str(value) for value in values)
    return sorted(dict.fromkeys(missing))


def _derive_revocation_checked(credential_results: list[dict[str, Any]]) -> bool | None:
    for credential_result in credential_results:
        for key in (
            "revocation_checked",
            "revocation_validated",
            "revocation_status_checked",
        ):
            if key in credential_result:
                return bool(credential_result[key])
    return None


def _protocol_result_for_session(session: VerificationSession) -> dict[str, Any] | None:
    if not session.completed_at and not session.result:
        return None

    passed = session.result == "passed" and session.status != SessionStatus.FAILED
    result: dict[str, Any] = {"passed": passed}

    claims_satisfied = sorted(str(claim_name) for claim_name in session.verified_claims.keys())
    if claims_satisfied:
        result["claims_satisfied"] = claims_satisfied

    claims_missing = _collect_claims_missing(session.credential_results)
    if claims_missing:
        result["claims_missing"] = claims_missing

    if session.decision is not None:
        result["trust_validated"] = session.decision == "allow"

    revocation_checked = _derive_revocation_checked(session.credential_results)
    if revocation_checked is not None:
        result["revocation_checked"] = revocation_checked

    failure_reason = session.decision_reason or session.error
    if failure_reason and not passed:
        result["failure_reason"] = failure_reason

    return result


def _session_to_protocol_dict(s: VerificationSession) -> dict:
    """Protocol-compliant verification-session.json shape."""
    protocol_status = _protocol_status_for_session(s)
    d: dict[str, Any] = {
        "id": s.session_id,
        "flow_id": s.flow_id,
        "flow_instance_id": s.flow_instance_id,
        "presentation_policy_id": s.presentation_policy_id,
        "deployment_profile_id": s.deployment_profile_id,
        "verifier_nonce": s.nonce,
        "holder_id": s.holder_id,
        "status": protocol_status,
        "result": _protocol_result_for_session(s),
        "expires_at": s.expires_at.isoformat(),
        "created_at": s.created_at.isoformat(),
        "completed_at": s.completed_at.isoformat() if s.completed_at else None,
        "updated_at": s.updated_at.isoformat() if s.updated_at else None,
        "error": s.error,
    }
    return {k: v for k, v in d.items() if v is not None}


def _session_to_dict(s: VerificationSession) -> dict:
    """Full dict with legacy fields — used for callbacks and internal gRPC."""
    protocol_status = _protocol_status_for_session(s)
    return {
        "id": s.session_id,
        "flow_id": s.flow_id,
        "flow_instance_id": s.flow_instance_id,
        "presentation_policy_id": s.presentation_policy_id,
        "deployment_profile_id": s.deployment_profile_id,
        "verifier_nonce": s.nonce,
        "holder_id": s.holder_id,
        "status": protocol_status,
        "result": _protocol_result_for_session(s),
        "expires_at": s.expires_at.isoformat(),
        "created_at": s.created_at.isoformat(),
        "completed_at": s.completed_at.isoformat() if s.completed_at else None,
        "updated_at": s.updated_at.isoformat() if s.updated_at else None,
        "error": s.error,
        "session_id": s.session_id,
        "organization_id": s.organization_id,
        "response_type": s.response_type,
        "request_uri": s.request_uri(),
        "qr_code_data": s.qr_code_data(),
        "nonce": s.nonce,
        "external_reference": s.external_reference,
        "purpose": s.purpose,
        "result_code": s.result,
        "decision": s.decision,
        "decision_reason": s.decision_reason,
        "verified_claims": s.verified_claims,
        "credential_results": s.credential_results,
        "inspection_performed": s.inspection_performed,
        "inspection_result": s.inspection_result,
        "runtime_status": s.status.value,
    }


# ---------------------------------------------------------------------------
# REST router
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/v1/verify", tags=["Verification"])


@router.post("", summary="Start Verification Session")
async def start_verification(
    body: StartVerificationRequest,
    store: SessionStore = Depends(get_store),
) -> dict:
    """Create a verification session and return a request_uri for the wallet."""
    if body.response_type == "vp_token" and not body.presentation_policy_id:
        raise HTTPException(
            status_code=400,
            detail="presentation_policy_id is required for vp_token response_type",
        )

    session = VerificationSession(
        organization_id=body.organization_id,
        presentation_policy_id=body.presentation_policy_id,
        response_type=body.response_type,
        trust_profile_id=body.trust_profile_id,
        deployment_profile_id=body.deployment_profile_id,
        external_reference=body.external_reference,
        callback_url=body.callback_url,
        expiry_minutes=body.expiry_minutes,
        purpose=body.purpose,
    )
    store.save(session)
    logger.info("Created verification session %s (org=%s)", session.session_id, body.organization_id)
    resp = _session_to_protocol_dict(session)
    # Include operational fields the wallet / UI needs to display QR and deep-link
    resp["request_uri"] = session.request_uri()
    resp["qr_code_data"] = session.qr_code_data()
    return resp


@router.get("/sessions", summary="List Verification Sessions")
async def list_sessions(
    organization_id: str,
    status: str | None = None,
    limit: int = 50,
    offset: int = 0,
    store: SessionStore = Depends(get_store),
) -> dict:
    """List verification sessions for an organization."""
    sessions = store.list_by_org(organization_id, status)
    page = sessions[offset: offset + limit]
    return {"sessions": [_session_to_protocol_dict(s) for s in page], "total": len(sessions)}


@router.get("/{session_id}/request", summary="OID4VP Request Object")
async def get_request_object(
    session_id: str,
    store: SessionStore = Depends(get_store),
) -> dict:
    """Return the OID4VP request object for a pending session (fetched by wallet)."""
    session = store.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    if session.status == SessionStatus.EXPIRED:
        raise HTTPException(status_code=410, detail="Session expired")

    return {
        "response_type": session.response_type,
        "client_id": PUBLIC_BASE_URL,
        "nonce": session.nonce,
        "response_uri": f"{PUBLIC_BASE_URL}/v1/verify/{session_id}/submit",
        "presentation_definition": {
            "id": session.presentation_policy_id or "adhoc",
        },
    }


@router.get("/{session_id}", summary="Get Verification Session")
async def get_session(
    session_id: str,
    store: SessionStore = Depends(get_store),
) -> dict:
    """Retrieve the current state of a verification session (poll)."""
    session = store.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return _session_to_protocol_dict(session)


@router.post("/{session_id}/submit", summary="Submit VP Token")
async def submit_presentation(
    session_id: str,
    body: SubmitVerificationRequest,
    store: SessionStore = Depends(get_store),
) -> dict:
    """
    Receive a VP token from a wallet and evaluate it against the session policy.
    Optionally calls the Marty InspectionSystem for credential inspection.
    """
    session = store.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    if session.status != SessionStatus.PENDING:
        raise HTTPException(status_code=409, detail=f"Session is {session.status.value}")
    if session.is_expired():
        session.status = SessionStatus.EXPIRED
        session.error = "Session expired before presentation was submitted"
        session.updated_at = datetime.now(timezone.utc)
        raise HTTPException(status_code=410, detail="Session expired")

    session.vp_token = body.vp_token
    session.updated_at = datetime.now(timezone.utc)

    try:
        eval_result = await _evaluate_via_grpc(
            policy_id=session.presentation_policy_id or "",
            vp_token=body.vp_token,
            nonce=session.nonce,
            context_json=json.dumps({"session_id": session_id}),
        )
        session.result = eval_result.get("result", "failed")
        session.decision = eval_result.get("decision", "deny")
        session.decision_reason = eval_result.get("decision_reason", "")
        session.verified_claims = eval_result.get("verified_claims", {})
        session.credential_results = eval_result.get("credential_results", [])
        session.error = None
    except Exception as exc:
        logger.error("Evaluation failed for session %s: %s", session_id, exc)
        session.result = "failed"
        session.decision = "deny"
        session.decision_reason = str(exc)
        session.error = None

    # Optionally call InspectionSystem for deep document verification
    if INSPECTION_SYSTEM_TARGET and session.result != "failed":
        inspection_result = await _inspect_via_grpc(body.vp_token)
        if inspection_result:
            session.inspection_performed = True
            session.inspection_result = inspection_result

    session.status = SessionStatus.COMPLETED if session.result == "passed" else SessionStatus.FAILED
    session.completed_at = datetime.now(timezone.utc)
    session.updated_at = session.completed_at
    store.save(session)

    # Fire callback if configured
    if session.callback_url:
        import httpx
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                await client.post(session.callback_url, json=_session_to_dict(session))
        except Exception as cb_exc:
            logger.warning("Callback POST to %s failed: %s", session.callback_url, cb_exc)

    logger.info(
        "Verification session %s completed: result=%s decision=%s",
        session_id, session.result, session.decision,
    )
    return _session_to_protocol_dict(session)


@router.post("/evaluate", summary="Stateless Evaluation")
async def evaluate_presentation(body: EvaluateRequest) -> dict:
    """
    Evaluate a VP token against a presentation policy without creating a session.
    Useful for server-side verification where session state is not needed.
    """
    try:
        result = await _evaluate_via_grpc(
            policy_id=body.presentation_policy_id,
            vp_token=body.vp_token,
            nonce=body.nonce,
            context_json=json.dumps(body.context or {}),
        )
        return result
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Evaluation failed: {exc}") from exc


@router.get("/{session_id}/inspection", summary="Inspection Result")
async def get_inspection_result(
    session_id: str,
    store: SessionStore = Depends(get_store),
) -> dict:
    """Get the InspectionSystem result for a completed session."""
    session = store.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return {
        "session_id": session_id,
        "performed": session.inspection_performed,
        "result": session.inspection_result,
        "timestamp": session.completed_at.isoformat() if session.completed_at else "",
    }


# ---------------------------------------------------------------------------
# ZKP endpoint (maps to /v1/verify/zkp)
# ---------------------------------------------------------------------------

zkp_router = APIRouter(prefix="/v1/verify/zkp", tags=["ZKP Verification"])


@zkp_router.post("", summary="Submit ZKP Proof")
async def submit_zkp(request: Request) -> dict:
    """
    Submit a Zero-Knowledge Proof for verification.
    Delegates to /v1/verify/evaluate internally.
    """
    body_data = await request.json()
    vp_token = body_data.get("vp_token") or body_data.get("proof")
    policy_id = body_data.get("presentation_policy_id") or body_data.get("policy_id", "")

    if not vp_token:
        raise HTTPException(status_code=400, detail="vp_token or proof is required")

    try:
        result = await _evaluate_via_grpc(
            policy_id=policy_id,
            vp_token=vp_token,
            nonce=body_data.get("nonce"),
        )
        return result
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"ZKP verification failed: {exc}") from exc


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

grpc_server = None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    global grpc_server

    logger.info(f"Starting {SERVICE_NAME} service on port {SERVICE_PORT}...")

    if GRPC_ENABLED:
        try:
            from common.grpc_factory import create_grpc_server, start_grpc_server_port
            from verification.infrastructure.adapters.grpc_adapter import VerificationServiceGrpc
            from marty_proto.v1.verification_service_pb2_grpc import (
                add_VerificationServiceServicer_to_server,
            )

            grpc_server, health_servicer = create_grpc_server("verification")
            servicer = VerificationServiceGrpc(get_store_fn=get_store)
            add_VerificationServiceServicer_to_server(servicer, grpc_server)
            start_grpc_server_port(
                grpc_server,
                GRPC_PORT,
                service_names=["marty.ui.verification.v1.VerificationService"],
                health_servicer=health_servicer,
            )
            await grpc_server.start()
            logger.info(f"Verification gRPC server listening on :{GRPC_PORT}")
        except Exception as exc:
            logger.warning("gRPC server startup failed (non-fatal): %s", exc)
            grpc_server = None

    from common.metrics import init_otel_tracing
    init_otel_tracing("verification")

    yield

    logger.info(f"Shutting down {SERVICE_NAME}...")
    if grpc_server:
        await grpc_server.stop(grace=5)


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

def create_app() -> FastAPI:
    app = FastAPI(
        title="Verification Service",
        description="Credential verification session management (OID4VP / SIOPv2)",
        version="1.0.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(router)
    app.include_router(zkp_router)

    @app.get("/health")
    async def health_check() -> dict:
        return {"status": "healthy", "service": SERVICE_NAME}

    from common.metrics import mount_metrics
    mount_metrics(app)

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=SERVICE_PORT)
