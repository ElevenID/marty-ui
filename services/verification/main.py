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
from typing import Annotated, Any, AsyncGenerator

import grpc
import grpc.aio as grpc_aio
from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from marty_common.service_setup import create_service_app

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
# Session store — Redis-backed with in-memory fallback for local dev
# ---------------------------------------------------------------------------

REDIS_URL = os.environ.get("REDIS_URL", "")
SESSION_PREFIX = "verification:session:"
SESSION_TTL_SECONDS = 60 * 60  # 1 hour (covers 15-min expiry + buffer)


def _session_to_redis_dict(session: VerificationSession) -> dict[str, Any]:
    """Serialize a VerificationSession to a JSON-safe dict for Redis storage."""
    return {
        "session_id": session.session_id,
        "flow_id": session.flow_id,
        "flow_instance_id": session.flow_instance_id,
        "organization_id": session.organization_id,
        "presentation_policy_id": session.presentation_policy_id,
        "response_type": session.response_type,
        "trust_profile_id": session.trust_profile_id,
        "deployment_profile_id": session.deployment_profile_id,
        "external_reference": session.external_reference,
        "callback_url": session.callback_url,
        "purpose": session.purpose,
        "nonce": session.nonce,
        "holder_id": session.holder_id,
        "status": session.status.value,
        "created_at": session.created_at.isoformat(),
        "updated_at": session.updated_at.isoformat(),
        "expires_at": session.expires_at.isoformat(),
        "result": session.result,
        "decision": session.decision,
        "decision_reason": session.decision_reason,
        "verified_claims": session.verified_claims,
        "credential_results": session.credential_results,
        "inspection_performed": session.inspection_performed,
        "inspection_result": session.inspection_result,
        "vp_token": session.vp_token,
        "completed_at": session.completed_at.isoformat() if session.completed_at else None,
        "error": session.error,
    }


def _session_from_dict(data: dict[str, Any]) -> VerificationSession:
    """Deserialize a dict back into a VerificationSession."""
    session = VerificationSession.__new__(VerificationSession)
    session.session_id = data["session_id"]
    session.flow_id = data["flow_id"]
    session.flow_instance_id = data["flow_instance_id"]
    session.organization_id = data["organization_id"]
    session.presentation_policy_id = data.get("presentation_policy_id")
    session.response_type = data.get("response_type", "vp_token")
    session.trust_profile_id = data.get("trust_profile_id")
    session.deployment_profile_id = data.get("deployment_profile_id")
    session.external_reference = data.get("external_reference")
    session.callback_url = data.get("callback_url")
    session.purpose = data.get("purpose", "")
    session.nonce = data["nonce"]
    session.holder_id = data.get("holder_id")
    session.status = SessionStatus(data["status"])
    session.created_at = datetime.fromisoformat(data["created_at"])
    session.updated_at = datetime.fromisoformat(data["updated_at"])
    session.expires_at = datetime.fromisoformat(data["expires_at"])
    session.result = data.get("result")
    session.decision = data.get("decision")
    session.decision_reason = data.get("decision_reason", "")
    session.verified_claims = data.get("verified_claims", {})
    session.credential_results = data.get("credential_results", [])
    session.inspection_performed = data.get("inspection_performed", False)
    session.inspection_result = data.get("inspection_result", "")
    session.vp_token = data.get("vp_token")
    session.completed_at = (
        datetime.fromisoformat(data["completed_at"]) if data.get("completed_at") else None
    )
    session.error = data.get("error")
    return session


class SessionStore:
    """Redis-backed session store. Falls back to in-memory if Redis unavailable."""

    def __init__(self, redis_client: Any | None = None) -> None:
        self._redis = redis_client
        self._fallback: dict[str, VerificationSession] = {}

    @property
    def _use_redis(self) -> bool:
        return self._redis is not None

    async def save(self, session: VerificationSession) -> None:
        session.updated_at = datetime.now(timezone.utc)
        if self._use_redis:
            key = f"{SESSION_PREFIX}{session.session_id}"
            await self._redis.set(key, json.dumps(_session_to_redis_dict(session)), ex=SESSION_TTL_SECONDS)
            # Index by org for list queries
            await self._redis.sadd(f"{SESSION_PREFIX}org:{session.organization_id}", session.session_id)
            await self._redis.expire(f"{SESSION_PREFIX}org:{session.organization_id}", SESSION_TTL_SECONDS)
        else:
            self._fallback[session.session_id] = session

    async def get(self, session_id: str) -> VerificationSession | None:
        if self._use_redis:
            raw = await self._redis.get(f"{SESSION_PREFIX}{session_id}")
            if raw is None:
                return None
            session = _session_from_dict(json.loads(raw))
        else:
            session = self._fallback.get(session_id)
        if session is None:
            return None
        if session.is_expired() and session.status == SessionStatus.PENDING:
            session.status = SessionStatus.EXPIRED
            session.error = "Session expired before presentation was submitted"
            session.updated_at = datetime.now(timezone.utc)
            await self.save(session) if self._use_redis else None
        return session

    async def list_by_org(self, org_id: str, status: str | None = None) -> list[VerificationSession]:
        if self._use_redis:
            session_ids = await self._redis.smembers(f"{SESSION_PREFIX}org:{org_id}")
            sessions = []
            for sid in session_ids:
                sid_str = sid.decode() if isinstance(sid, bytes) else sid
                session = await self.get(sid_str)
                if session:
                    sessions.append(session)
        else:
            sessions = [s for s in self._fallback.values() if s.organization_id == org_id]
        if status:
            sessions = [s for s in sessions if s.status.value == status]
        return sorted(sessions, key=lambda s: s.created_at, reverse=True)


_store: SessionStore | None = None


async def init_store() -> SessionStore:
    """Initialize the session store with Redis if configured, else in-memory."""
    global _store
    if REDIS_URL:
        try:
            import redis.asyncio as aioredis
            client = aioredis.from_url(REDIS_URL, decode_responses=False)
            await client.ping()
            _store = SessionStore(redis_client=client)
            logger.info("Verification session store: Redis (%s)", REDIS_URL)
        except Exception as exc:
            logger.warning("Redis unavailable (%s), falling back to in-memory sessions: %s", REDIS_URL, exc)
            _store = SessionStore()
    else:
        logger.warning("REDIS_URL not set — using in-memory session store (not suitable for production)")
        _store = SessionStore()
    return _store


def get_store() -> SessionStore:
    if _store is None:
        raise RuntimeError("SessionStore not initialized — call init_store() in lifespan")
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
    organization_id: str = Field(max_length=255)
    presentation_policy_id: str | None = Field(None, max_length=255)
    response_type: str = Field("vp_token", max_length=50)
    trust_profile_id: str | None = Field(None, max_length=255)
    deployment_profile_id: str | None = Field(None, max_length=255)
    external_reference: str | None = Field(None, max_length=500)
    callback_url: str | None = Field(None, max_length=2048)
    expiry_minutes: int = 15
    purpose: str = Field("", max_length=1000)


class SubmitVerificationRequest(BaseModel):
    vp_token: str = Field(max_length=1_000_000)
    presentation_submission: dict | None = None


class EvaluateRequest(BaseModel):
    vp_token: str = Field(max_length=1_000_000)
    presentation_policy_id: str = Field(max_length=255)
    nonce: str | None = Field(None, max_length=512)
    audience: str | None = Field(None, max_length=512)
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


def get_current_user_id(x_user_id: Annotated[str, Header()]) -> str:
    """Extract user ID from X-User-Id header (injected by gateway)."""
    return x_user_id


@router.post("", summary="Start Verification Session")
async def start_verification(
    body: StartVerificationRequest,
    store: SessionStore = Depends(get_store),
    user_id: str = Depends(get_current_user_id),
    x_organization_id: str = Header(alias="X-Organization-Id"),
) -> dict:
    """Create a verification session and return a request_uri for the wallet."""
    if body.organization_id and body.organization_id != x_organization_id:
        raise HTTPException(status_code=403, detail="Organization mismatch")
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
    await store.save(session)
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
    sessions = await store.list_by_org(organization_id, status)
    page = sessions[offset: offset + limit]
    return {"sessions": [_session_to_protocol_dict(s) for s in page], "total": len(sessions)}


@router.get("/{session_id}/request", summary="OID4VP Request Object")
async def get_request_object(
    session_id: str,
    store: SessionStore = Depends(get_store),
) -> dict:
    """Return the OID4VP request object for a pending session (fetched by wallet)."""
    session = await store.get(session_id)
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
    session = await store.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return _session_to_protocol_dict(session)


@router.post("/{session_id}/submit", summary="Submit VP Token")
async def submit_presentation(
    session_id: str,
    body: SubmitVerificationRequest,
    store: SessionStore = Depends(get_store),
    user_id: str = Depends(get_current_user_id),
) -> dict:
    """
    Receive a VP token from a wallet and evaluate it against the session policy.
    Optionally calls the Marty InspectionSystem for credential inspection.
    """
    session = await store.get(session_id)
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
    await store.save(session)

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
async def evaluate_presentation(
    body: EvaluateRequest,
    user_id: str = Depends(get_current_user_id),
) -> dict:
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
        logger.error("Evaluation via gRPC failed: %s", exc)
        raise HTTPException(status_code=502, detail="Evaluation failed") from exc


@router.get("/{session_id}/inspection", summary="Inspection Result")
async def get_inspection_result(
    session_id: str,
    store: SessionStore = Depends(get_store),
) -> dict:
    """Get the InspectionSystem result for a completed session."""
    session = await store.get(session_id)
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


class ZkpSubmitRequest(BaseModel):
    vp_token: str | None = Field(default=None, description="VP token for ZKP verification")
    proof: str | None = Field(default=None, description="ZKP proof (alias for vp_token)")
    presentation_policy_id: str | None = Field(default=None, description="Presentation policy ID")
    policy_id: str | None = Field(default=None, description="Policy ID (alias)")
    nonce: str | None = Field(default=None, description="Nonce for replay prevention")


@zkp_router.post("", summary="Submit ZKP Proof")
async def submit_zkp(body: ZkpSubmitRequest) -> dict:
    """
    Submit a Zero-Knowledge Proof for verification.
    Delegates to /v1/verify/evaluate internally.
    """
    vp_token = body.vp_token or body.proof
    policy_id = body.presentation_policy_id or body.policy_id or ""

    if not vp_token:
        raise HTTPException(status_code=400, detail="vp_token or proof is required")

    try:
        result = await _evaluate_via_grpc(
            policy_id=policy_id,
            vp_token=vp_token,
            nonce=body.nonce,
        )
        return result
    except Exception as exc:
        logger.error("ZKP verification failed: %s", exc)
        raise HTTPException(status_code=502, detail="ZKP verification failed") from exc


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

grpc_server = None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    global grpc_server

    logger.info(f"Starting {SERVICE_NAME} service on port {SERVICE_PORT}...")

    # Initialize session store (Redis or in-memory fallback)
    store = await init_store()

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
    app = create_service_app(
        title="Verification Service",
        description="Credential verification session management (OID4VP / SIOPv2)",
        service_name=SERVICE_NAME,
        lifespan=lifespan,
        routers=[router, zkp_router],
    )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        errors = exc.errors()
        missing = [e["loc"][-1] for e in errors if e.get("type") == "missing"]
        description = (
            f"Missing required parameter(s): {', '.join(str(m) for m in missing)}"
            if missing
            else "Request validation failed"
        )
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_request", "error_description": description},
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(
        request: Request, exc: Exception
    ) -> JSONResponse:
        logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
        return JSONResponse(
            status_code=500,
            content={"error": "server_error", "error_description": "Internal server error"},
        )

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=SERVICE_PORT)
