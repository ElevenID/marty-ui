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

Standalone sessions are polling-only. Authoritative callback delivery belongs
to the Flow service's transactional outbox. Redis is mandatory outside local
development and tests so submission leases and terminal results are shared.

Stateless shortcut:
  POST /v1/verify/evaluate — evaluate any VP token against a policy in one call

Port: 8012  |  gRPC: 9017
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import secrets
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Annotated, Any, AsyncGenerator, Awaitable

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from marty_common import ensure_membership_permission
from marty_common.org_authorization import get_organization_client
from marty_common.service_setup import create_service_app
from common.grpc_factory import create_grpc_channel
from common.native_backend import NativeOperationError
from common.oid4vp_native import (
    build_oid4vp_presentation_request,
    credential_requirement_input,
    initialize_native_oid4vp_backend,
    parse_policy_requirements,
    wallet_registry_format_names,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SERVICE_NAME = "verification"
SERVICE_PORT = int(os.environ.get("VERIFICATION_SERVICE_PORT", "8012"))
GRPC_ENABLED = os.environ.get("VERIF_GRPC_ENABLED", "false").lower() == "true"
GRPC_PORT = int(os.environ.get("VERIF_GRPC_PORT", "9017"))

# Downstream gRPC targets
PP_GRPC_TARGET = os.environ.get("PP_GRPC_TARGET", "presentation-policy:9009")
CT_GRPC_TARGET = os.environ.get("CT_GRPC_TARGET", "credential-template:9003")
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
        self.holder_binding_evidence: dict[str, Any] | None = None
        self.inspection_performed: bool = False
        self.inspection_result: str = ""
        self.inspection_result_sha256: str | None = None
        self.vp_token_sha256: str | None = None
        self.processing_token: str | None = None
        self.processing_expires_at: datetime | None = None
        self.total_requirements: int = 0
        self.satisfied_requirements: int = 0
        self.completed_at: datetime | None = None
        self.error: str | None = None

    def is_expired(self, now: datetime | None = None) -> bool:
        return (now or datetime.now(timezone.utc)) > self.expires_at

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
SUBMISSION_LEASE_SECONDS = 30
SUBMISSION_CAS_RETRIES = 8


class SubmissionOutcome(str, Enum):
    CLAIMED = "claimed"
    COMMITTED = "committed"
    DUPLICATE = "duplicate"
    BUSY = "busy"
    CONFLICT = "conflict"
    EXPIRED = "expired"
    MISSING = "missing"


def _datetime_from_redis_time(value: tuple[int, int] | list[int]) -> datetime:
    """Convert Redis TIME output to an aware UTC datetime."""
    seconds, microseconds = (int(part) for part in value)
    return datetime.fromtimestamp(seconds, tz=timezone.utc) + timedelta(
        microseconds=microseconds
    )


@dataclass(frozen=True)
class SubmissionTransition:
    outcome: SubmissionOutcome
    session: VerificationSession | None = None
    token: str | None = None


_SAFE_INSPECTION_RESULTS = {
    "error",
    "failed",
    "invalid",
    "ok",
    "passed",
    "recorded",
    "unavailable",
    "unsupported",
    "unverified",
    "valid",
    "verified",
}


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _minimize_verified_claims(claims: Any) -> dict[str, bool]:
    """Retain claim names and pass status, never disclosed values."""
    if not isinstance(claims, dict):
        return {}
    return {name: True for name in sorted(str(name) for name in claims) if name}


def _minimize_claim_result(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    result: dict[str, Any] = {}
    for key in ("claim_name", "satisfied"):
        item = value.get(key)
        if isinstance(item, (str, bool)) or item is None:
            if item is not None:
                result[key] = item
    constraint_results = value.get("constraint_results")
    if isinstance(constraint_results, list):
        minimized_constraints = []
        for constraint in constraint_results:
            if not isinstance(constraint, dict):
                continue
            minimized = {
                key: item
                for key in ("constraint_type", "passed", "satisfied")
                if isinstance((item := constraint.get(key)), (str, bool))
            }
            if minimized:
                minimized_constraints.append(minimized)
        if minimized_constraints:
            result["constraint_results"] = minimized_constraints
    return result or None


def _minimize_credential_results(results: Any) -> list[dict[str, Any]]:
    """Project credential evaluations to non-value decision evidence."""
    if not isinstance(results, list):
        return []
    minimized_results: list[dict[str, Any]] = []
    scalar_keys = (
        "credential_template_id",
        "credential_type",
        "credential_format",
        "satisfied",
        "issuer_did",
        "signature_valid",
        "trust_validated",
        "revocation_checked",
        "revocation_validated",
        "revocation_status_checked",
        "holder_binding_validated",
    )
    list_keys = ("claims_missing", "claims_satisfied")
    for result in results:
        if not isinstance(result, dict):
            continue
        minimized: dict[str, Any] = {
            key: item
            for key in scalar_keys
            if isinstance((item := result.get(key)), (str, bool, int, float))
        }
        for key in list_keys:
            values = result.get(key)
            if isinstance(values, list):
                minimized[key] = [str(item) for item in values if str(item)]
        claim_results = result.get("claim_results")
        if isinstance(claim_results, list):
            minimized_claims = [
                item
                for claim_result in claim_results
                if (item := _minimize_claim_result(claim_result)) is not None
            ]
            if minimized_claims:
                minimized["claim_results"] = minimized_claims
        minimized_results.append(minimized)
    return minimized_results


def _minimize_inspection_result(raw_result: str) -> tuple[str, str | None]:
    if not raw_result:
        return "", None
    digest = _sha256_text(raw_result)
    normalized = raw_result.strip().lower()
    try:
        parsed = json.loads(raw_result)
    except (TypeError, ValueError):
        parsed = None
    if isinstance(parsed, dict):
        for key in ("result", "status", "decision"):
            candidate = str(parsed.get(key, "")).strip().lower()
            if candidate in _SAFE_INSPECTION_RESULTS:
                normalized = candidate
                break
    safe_result = normalized if normalized in _SAFE_INSPECTION_RESULTS else "recorded"
    return safe_result, digest


def _minimize_terminal_session(session: VerificationSession) -> None:
    """Remove prohibited post-verification data before persistence."""
    if session.status == SessionStatus.PENDING:
        return
    session.callback_url = None
    session.processing_token = None
    session.processing_expires_at = None
    session.verified_claims = _minimize_verified_claims(session.verified_claims)
    session.credential_results = _minimize_credential_results(
        session.credential_results
    )
    if session.inspection_result and not (
        session.inspection_result_sha256
        and session.inspection_result in _SAFE_INSPECTION_RESULTS
    ):
        (
            session.inspection_result,
            session.inspection_result_sha256,
        ) = _minimize_inspection_result(session.inspection_result)


class _CompletedAwaitable:
    def __await__(self):
        if False:
            yield None
        return None


def _session_to_redis_dict(session: VerificationSession) -> dict[str, Any]:
    """Serialize a VerificationSession to a JSON-safe dict for Redis storage."""
    _minimize_terminal_session(session)
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
        "holder_binding_evidence": session.holder_binding_evidence,
        "inspection_performed": session.inspection_performed,
        "inspection_result": session.inspection_result,
        "inspection_result_sha256": session.inspection_result_sha256,
        "vp_token_sha256": session.vp_token_sha256,
        "processing_token": session.processing_token,
        "processing_expires_at": (
            session.processing_expires_at.isoformat()
            if session.processing_expires_at
            else None
        ),
        "total_requirements": session.total_requirements,
        "satisfied_requirements": session.satisfied_requirements,
        "completed_at": session.completed_at.isoformat()
        if session.completed_at
        else None,
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
    # Standalone callbacks were retired in favor of the Flow service's governed
    # transactional outbox. Ignore and scrub legacy destinations on rewrite.
    session.callback_url = None
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
    session.holder_binding_evidence = data.get("holder_binding_evidence")
    session.inspection_performed = data.get("inspection_performed", False)
    session.inspection_result = data.get("inspection_result", "")
    session.inspection_result_sha256 = data.get("inspection_result_sha256")
    legacy_vp_token = data.get("vp_token")
    session.vp_token_sha256 = data.get("vp_token_sha256") or (
        _sha256_text(legacy_vp_token) if isinstance(legacy_vp_token, str) else None
    )
    session.processing_token = data.get("processing_token")
    session.processing_expires_at = (
        datetime.fromisoformat(data["processing_expires_at"])
        if data.get("processing_expires_at")
        else None
    )
    session.total_requirements = int(data.get("total_requirements") or 0)
    session.satisfied_requirements = int(data.get("satisfied_requirements") or 0)
    session.completed_at = (
        datetime.fromisoformat(data["completed_at"])
        if data.get("completed_at")
        else None
    )
    session.error = data.get("error")
    _minimize_terminal_session(session)
    return session


def _clone_session(session: VerificationSession) -> VerificationSession:
    """Return a detached session so callers cannot mutate persisted state by alias."""
    return _session_from_dict(_session_to_redis_dict(session))


class SessionStore:
    """Session persistence with atomic submission ownership and finalization."""

    def __init__(self, redis_client: Any | None = None) -> None:
        self._redis = redis_client
        self._fallback: dict[str, VerificationSession] = {}
        self._lock = asyncio.Lock()

    @property
    def _use_redis(self) -> bool:
        return self._redis is not None

    async def close(self) -> None:
        if self._redis is not None:
            await self._redis.aclose()

    def save(
        self,
        session: VerificationSession,
        *,
        touch_updated_at: bool = True,
    ) -> Awaitable[None]:
        if touch_updated_at:
            session.updated_at = datetime.now(timezone.utc)
        _minimize_terminal_session(session)
        if self._use_redis:

            async def _save_to_redis() -> None:
                key = f"{SESSION_PREFIX}{session.session_id}"
                await self._redis.set(
                    key,
                    json.dumps(_session_to_redis_dict(session)),
                    ex=SESSION_TTL_SECONDS,
                )
                await self._redis.sadd(
                    f"{SESSION_PREFIX}org:{session.organization_id}", session.session_id
                )
                await self._redis.expire(
                    f"{SESSION_PREFIX}org:{session.organization_id}",
                    SESSION_TTL_SECONDS,
                )

            return _save_to_redis()

        self._fallback[session.session_id] = _clone_session(session)
        return _CompletedAwaitable()

    async def get(self, session_id: str) -> VerificationSession | None:
        if self._use_redis:
            raw = await self._redis.get(f"{SESSION_PREFIX}{session_id}")
            if raw is None:
                return None
            stored_data = json.loads(raw)
            session = _session_from_dict(stored_data)
            if (
                session.status != SessionStatus.PENDING
                and _session_to_redis_dict(session) != stored_data
            ):
                await self.save(session, touch_updated_at=False)
        else:
            session = self._fallback.get(session_id)
        if session is None:
            return None
        session = _clone_session(session)
        if session.status == SessionStatus.PENDING and session.vp_token_sha256 is None:
            now = (
                _datetime_from_redis_time(await self._redis.time())
                if self._use_redis
                else datetime.now(timezone.utc)
            )
        else:
            now = None
        if now is not None and session.is_expired(now):
            session.status = SessionStatus.EXPIRED
            session.error = "Session expired before presentation was submitted"
            session.updated_at = now
            session.processing_token = None
            session.processing_expires_at = None
        return session

    async def list_by_org(
        self, org_id: str, status: str | None = None
    ) -> list[VerificationSession]:
        if self._use_redis:
            session_ids = await self._redis.smembers(f"{SESSION_PREFIX}org:{org_id}")
            sessions = []
            for sid in session_ids:
                sid_str = sid.decode() if isinstance(sid, bytes) else sid
                session = await self.get(sid_str)
                if session:
                    sessions.append(session)
        else:
            sessions = [
                _clone_session(s)
                for s in self._fallback.values()
                if s.organization_id == org_id
            ]
        if status:
            sessions = [s for s in sessions if s.status.value == status]
        return sorted(sessions, key=lambda s: s.created_at, reverse=True)

    @staticmethod
    def _submission_state(
        session: VerificationSession,
        digest: str,
        now: datetime,
    ) -> SubmissionOutcome | None:
        if session.status == SessionStatus.EXPIRED:
            return SubmissionOutcome.EXPIRED
        if session.status != SessionStatus.PENDING:
            if session.vp_token_sha256 == digest:
                return SubmissionOutcome.DUPLICATE
            return SubmissionOutcome.CONFLICT
        if session.vp_token_sha256 and session.vp_token_sha256 != digest:
            return SubmissionOutcome.CONFLICT
        if (
            session.processing_token
            and session.processing_expires_at
            and session.processing_expires_at > now
        ):
            return SubmissionOutcome.BUSY
        # Once a presentation was accepted before session expiry, the digest
        # remains recoverable after a worker crash. No different presentation
        # can take over the session, and the lease token still fences workers.
        if session.vp_token_sha256 == digest:
            return None
        if session.is_expired(now):
            return SubmissionOutcome.EXPIRED
        return None

    @staticmethod
    def _expire_session(session: VerificationSession, now: datetime) -> None:
        session.status = SessionStatus.EXPIRED
        session.error = "Session expired before presentation was submitted"
        session.updated_at = now
        session.processing_token = None
        session.processing_expires_at = None

    async def claim_submission(
        self,
        session_id: str,
        digest: str,
    ) -> SubmissionTransition:
        """Atomically reserve one presentation digest for evaluation."""
        if self._use_redis:
            return await self._claim_submission_redis(session_id, digest)

        async with self._lock:
            stored = self._fallback.get(session_id)
            if stored is None:
                return SubmissionTransition(SubmissionOutcome.MISSING)
            session = _clone_session(stored)
            now = datetime.now(timezone.utc)
            outcome = self._submission_state(session, digest, now)
            if outcome == SubmissionOutcome.EXPIRED:
                self._expire_session(session, now)
                self._fallback[session_id] = _clone_session(session)
                return SubmissionTransition(outcome, _clone_session(session))
            if outcome is not None:
                return SubmissionTransition(outcome, _clone_session(session))

            token = secrets.token_urlsafe(32)
            session.vp_token_sha256 = digest
            session.processing_token = token
            session.processing_expires_at = now + timedelta(
                seconds=SUBMISSION_LEASE_SECONDS
            )
            session.updated_at = now
            self._fallback[session_id] = _clone_session(session)
            return SubmissionTransition(
                SubmissionOutcome.CLAIMED,
                _clone_session(session),
                token,
            )

    async def _claim_submission_redis(
        self,
        session_id: str,
        digest: str,
    ) -> SubmissionTransition:
        from redis.exceptions import WatchError

        key = f"{SESSION_PREFIX}{session_id}"
        for _attempt in range(SUBMISSION_CAS_RETRIES):
            async with self._redis.pipeline(transaction=True) as pipe:
                try:
                    await pipe.watch(key)
                    raw = await pipe.get(key)
                    if raw is None:
                        return SubmissionTransition(SubmissionOutcome.MISSING)
                    pending_ttl_ms = await pipe.pttl(key)
                    pending_ttl_options = (
                        {"keepttl": True}
                        if pending_ttl_ms >= 0
                        else {"ex": SESSION_TTL_SECONDS}
                    )
                    session = _session_from_dict(json.loads(raw))
                    # Redis time is shared by every application replica, so a
                    # skewed worker cannot expire a session or steal a lease
                    # early (or indefinitely delay recovery).
                    now = _datetime_from_redis_time(await pipe.time())
                    outcome = self._submission_state(session, digest, now)
                    if outcome == SubmissionOutcome.EXPIRED:
                        self._expire_session(session, now)
                        pipe.multi()
                        pipe.set(
                            key,
                            json.dumps(_session_to_redis_dict(session)),
                            # Expiry/claim transitions must not renew the
                            # unfinished transaction's absolute lifetime.
                            **pending_ttl_options,
                        )
                        await pipe.execute()
                        return SubmissionTransition(outcome, session)
                    if outcome is not None:
                        return SubmissionTransition(outcome, session)

                    token = secrets.token_urlsafe(32)
                    session.vp_token_sha256 = digest
                    session.processing_token = token
                    session.processing_expires_at = now + timedelta(
                        seconds=SUBMISSION_LEASE_SECONDS
                    )
                    session.updated_at = now
                    pipe.multi()
                    pipe.set(
                        key,
                        json.dumps(_session_to_redis_dict(session)),
                        # Same-digest crash recovery is bounded by the TTL set
                        # when the session was created; repeated claims cannot
                        # keep an expired transaction alive indefinitely.
                        **pending_ttl_options,
                    )
                    await pipe.execute()
                    return SubmissionTransition(
                        SubmissionOutcome.CLAIMED,
                        session,
                        token,
                    )
                except WatchError:
                    continue
        raise RuntimeError("Could not claim verification submission after retries")

    @staticmethod
    def _validate_terminal_candidate(
        current: VerificationSession,
        candidate: VerificationSession,
    ) -> None:
        immutable_fields = (
            "session_id",
            "flow_id",
            "flow_instance_id",
            "organization_id",
            "presentation_policy_id",
            "response_type",
            "nonce",
            "created_at",
            "expires_at",
        )
        if any(
            getattr(current, field) != getattr(candidate, field)
            for field in immutable_fields
        ):
            raise ValueError("Terminal session changed immutable verification state")
        if candidate.status == SessionStatus.PENDING or candidate.completed_at is None:
            raise ValueError("Terminal session must contain a completed outcome")

    async def finalize_submission(
        self,
        session_id: str,
        digest: str,
        token: str,
        candidate: VerificationSession,
    ) -> SubmissionTransition:
        """Commit a terminal result only for the current submission lease owner."""
        if self._use_redis:
            return await self._finalize_submission_redis(
                session_id,
                digest,
                token,
                candidate,
            )

        async with self._lock:
            stored = self._fallback.get(session_id)
            if stored is None:
                return SubmissionTransition(SubmissionOutcome.MISSING)
            current = _clone_session(stored)
            if current.status != SessionStatus.PENDING:
                outcome = (
                    SubmissionOutcome.DUPLICATE
                    if current.vp_token_sha256 == digest
                    else SubmissionOutcome.CONFLICT
                )
                return SubmissionTransition(outcome, current)
            if current.vp_token_sha256 != digest:
                return SubmissionTransition(SubmissionOutcome.CONFLICT, current)
            if current.processing_token != token:
                return SubmissionTransition(SubmissionOutcome.BUSY, current)
            self._validate_terminal_candidate(current, candidate)
            terminal = _clone_session(candidate)
            terminal.vp_token_sha256 = digest
            terminal.processing_token = None
            terminal.processing_expires_at = None
            _minimize_terminal_session(terminal)
            self._fallback[session_id] = _clone_session(terminal)
            return SubmissionTransition(SubmissionOutcome.COMMITTED, terminal)

    async def _finalize_submission_redis(
        self,
        session_id: str,
        digest: str,
        token: str,
        candidate: VerificationSession,
    ) -> SubmissionTransition:
        from redis.exceptions import WatchError

        key = f"{SESSION_PREFIX}{session_id}"
        for _attempt in range(SUBMISSION_CAS_RETRIES):
            async with self._redis.pipeline(transaction=True) as pipe:
                try:
                    await pipe.watch(key)
                    raw = await pipe.get(key)
                    if raw is None:
                        return SubmissionTransition(SubmissionOutcome.MISSING)
                    current = _session_from_dict(json.loads(raw))
                    if current.status != SessionStatus.PENDING:
                        outcome = (
                            SubmissionOutcome.DUPLICATE
                            if current.vp_token_sha256 == digest
                            else SubmissionOutcome.CONFLICT
                        )
                        return SubmissionTransition(outcome, current)
                    if current.vp_token_sha256 != digest:
                        return SubmissionTransition(
                            SubmissionOutcome.CONFLICT,
                            current,
                        )
                    if current.processing_token != token:
                        return SubmissionTransition(SubmissionOutcome.BUSY, current)

                    self._validate_terminal_candidate(current, candidate)
                    terminal = _clone_session(candidate)
                    terminal.vp_token_sha256 = digest
                    terminal.processing_token = None
                    terminal.processing_expires_at = None
                    _minimize_terminal_session(terminal)
                    pipe.multi()
                    pipe.set(
                        key,
                        json.dumps(_session_to_redis_dict(terminal)),
                        ex=SESSION_TTL_SECONDS,
                    )
                    await pipe.execute()
                    return SubmissionTransition(
                        SubmissionOutcome.COMMITTED,
                        terminal,
                    )
                except WatchError:
                    continue
        raise RuntimeError("Could not finalize verification submission after retries")


_store: SessionStore | None = None


async def init_store() -> SessionStore:
    """Initialize Redis persistence, failing closed outside local/test use."""
    global _store
    _store = None
    environment = os.environ.get("ENVIRONMENT", "development").strip().lower()
    allow_in_memory = environment in {"development", "dev", "local", "test"}
    if REDIS_URL:
        client = None
        try:
            import redis.asyncio as aioredis

            client = aioredis.from_url(REDIS_URL, decode_responses=False)
            await client.ping()
            _store = SessionStore(redis_client=client)
            logger.info("Verification session store: Redis")
        except Exception as exc:
            if client is not None:
                await client.aclose()
            if not allow_in_memory:
                raise RuntimeError(
                    "Redis is required for Verification session persistence in "
                    f"{environment or 'production'}"
                ) from exc
            logger.warning(
                "Redis unavailable; using development-only in-memory sessions: %s",
                exc,
            )
            _store = SessionStore()
    else:
        if not allow_in_memory:
            raise RuntimeError(
                "REDIS_URL is required for Verification session persistence in "
                f"{environment or 'production'}"
            )
        logger.warning("REDIS_URL not set; using development-only in-memory sessions")
        _store = SessionStore()
    return _store


def get_store() -> SessionStore:
    if _store is None:
        raise RuntimeError(
            "SessionStore not initialized — call init_store() in lifespan"
        )
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

        async with create_grpc_channel(
            PP_GRPC_TARGET,
            service_name="verification",
            require_workload_identity=True,
        ) as channel:
            stub = presentation_policy_service_pb2_grpc.PresentationPolicyServiceStub(
                channel
            )
            req = presentation_policy_service_pb2.EvaluatePresentationRequest(
                policy_id=policy_id,
                vp_token=vp_token,
                nonce=nonce or "",
                context_json=context_json,
            )
            resp = await stub.EvaluatePresentation(req)
        return {
            "result": resp.result,
            "decision": resp.decision,
            "decision_reason": resp.decision_reason,
            "verified_claims": json.loads(resp.verified_claims_json)
            if resp.verified_claims_json
            else {},
            "credential_results": json.loads(resp.credential_results_json)
            if resp.credential_results_json
            else [],
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

        async with create_grpc_channel(
            INSPECTION_SYSTEM_TARGET,
            service_name="verification",
        ) as channel:
            stub = inspection_system_pb2_grpc.InspectionSystemStub(channel)
            resp = await stub.Inspect(inspection_system_pb2.InspectRequest(item=item))
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


_API_KEY_VERIFICATION_SCOPES = frozenset(
    {"credentials:read", "flows:execute", "admin:full"}
)


def _management_authorization_enabled(request: Request) -> bool:
    """Return whether this app instance owns the production HTTP boundary.

    The repository's protocol-shape tests embed ``router`` in a small FastAPI
    harness. The production app factory explicitly enables authorization, so
    those handler-only tests remain independent from organization-service I/O
    without creating a deployment mode that silently disables the boundary.
    """

    return (
        getattr(
            request.app.state,
            "enforce_verification_management_authorization",
            False,
        )
        is True
    )


def _authorize_gateway_api_key_verification(
    request: Request,
    *,
    user_id: str,
    organization_id: str,
) -> bool:
    """Validate the complete gateway-owned API-key principal context."""

    api_key_id = request.headers.get("x-api-key-id", "").strip()
    forwarded_organization = request.headers.get("x-organization-id", "").strip()
    forwarded_permission = request.headers.get("x-required-permission", "").strip()
    forwarded_scopes = request.headers.get("x-api-key-scopes", "")
    scopes = {scope.strip() for scope in forwarded_scopes.split(",") if scope.strip()}
    api_key_principal = user_id.startswith("api_key:")
    has_api_key_context = bool(
        api_key_id
        or api_key_principal
        or forwarded_scopes.strip()
        or request.headers.get("x-api-key-id") is not None
        or request.headers.get("x-api-key-scopes") is not None
    )
    if not has_api_key_context:
        return False

    if (
        not api_key_id
        or user_id != f"api_key:{api_key_id}"
        or forwarded_organization != organization_id
        or forwarded_permission != "verification:execute"
        or not scopes.intersection(_API_KEY_VERIFICATION_SCOPES)
    ):
        raise HTTPException(
            status_code=403,
            detail="API key is not authorized to execute verification",
        )
    return True


async def _authorize_management_principal(
    request: Request,
    *,
    user_id: str,
    organization_id: str,
) -> None:
    """Bind a management operation to an API key or active tenant member."""

    if not _management_authorization_enabled(request):
        return
    if not user_id:
        raise HTTPException(status_code=401, detail="Authentication required")
    if _authorize_gateway_api_key_verification(
        request,
        user_id=user_id,
        organization_id=organization_id,
    ):
        return

    org_client = await get_organization_client(request)
    membership = await org_client.get_membership(user_id, organization_id)
    ensure_membership_permission(membership, "verification", "execute")


async def _get_presentation_policy_reference(policy_id: str) -> Any:
    """Resolve one saved policy over the workload-authenticated gRPC path."""

    import grpc

    from marty_proto.v1 import (
        presentation_policy_service_pb2,
        presentation_policy_service_pb2_grpc,
    )

    try:
        async with create_grpc_channel(
            PP_GRPC_TARGET,
            service_name="verification",
            require_workload_identity=True,
        ) as channel:
            stub = presentation_policy_service_pb2_grpc.PresentationPolicyServiceStub(
                channel
            )
            policy = await stub.GetPolicy(
                presentation_policy_service_pb2.GetPolicyRequest(policy_id=policy_id)
            )
    except grpc.aio.AioRpcError as exc:
        if exc.code() == grpc.StatusCode.NOT_FOUND:
            raise HTTPException(
                status_code=404,
                detail="Presentation policy not found",
            ) from exc
        logger.warning("Could not resolve presentation policy %s: %s", policy_id, exc)
        raise HTTPException(
            status_code=502,
            detail="Presentation policy service unavailable",
        ) from exc
    except Exception as exc:
        logger.warning("Could not resolve presentation policy %s: %s", policy_id, exc)
        raise HTTPException(
            status_code=502,
            detail="Presentation policy service unavailable",
        ) from exc
    if not getattr(policy, "id", ""):
        raise HTTPException(status_code=404, detail="Presentation policy not found")
    return policy


def _require_policy_organization(
    policy: Any,
    *,
    organization_id: str,
    require_active: bool = True,
) -> None:
    """Require a policy to belong to the session tenant and be executable."""

    if getattr(policy, "organization_id", "") != organization_id:
        raise HTTPException(status_code=404, detail="Presentation policy not found")
    if require_active and str(getattr(policy, "status", "")).lower() != "active":
        raise HTTPException(
            status_code=409,
            detail="Presentation policy is not active",
        )


def _require_policy_active(policy: Any) -> None:
    """Require an authoritative policy reference to remain executable."""

    if str(getattr(policy, "status", "")).lower() != "active":
        raise HTTPException(
            status_code=409,
            detail="Presentation policy is not active",
        )


async def _require_session_policy_reference(
    session: VerificationSession,
    *,
    require_active: bool = True,
) -> Any:
    policy_id = (session.presentation_policy_id or "").strip()
    if not policy_id or policy_id == "adhoc":
        raise HTTPException(
            status_code=409,
            detail="Verification session has no saved presentation policy",
        )
    policy = await _get_presentation_policy_reference(policy_id)
    _require_policy_organization(
        policy,
        organization_id=session.organization_id,
        require_active=require_active,
    )
    return policy


async def _resolve_policy_template_references(
    policy_id: str,
    policy: Any,
    *,
    organization_id: str,
) -> list[tuple[dict[str, Any], Any]]:
    """Resolve every policy requirement to an active template in the same tenant."""

    import grpc

    from marty_proto.v1 import (
        credential_template_service_pb2,
        credential_template_service_pb2_grpc,
    )

    requirements = parse_policy_requirements(
        policy_id,
        policy.credential_requirements_json,
    )
    resolved: list[tuple[dict[str, Any], Any]] = []
    async with create_grpc_channel(
        CT_GRPC_TARGET,
        service_name="verification",
        require_workload_identity=True,
    ) as channel:
        stub = credential_template_service_pb2_grpc.CredentialTemplateServiceStub(
            channel
        )
        for requirement in requirements:
            template_id = str(
                requirement.get("credential_template_id", "") or ""
            ).strip()
            if not template_id:
                raise HTTPException(
                    status_code=409,
                    detail="Presentation policy contains an invalid credential requirement",
                )
            try:
                template = await stub.GetTemplate(
                    credential_template_service_pb2.GetTemplateRequest(
                        template_id=template_id
                    )
                )
            except grpc.aio.AioRpcError as exc:
                if exc.code() == grpc.StatusCode.NOT_FOUND:
                    raise HTTPException(
                        status_code=404,
                        detail="Credential template not found",
                    ) from exc
                logger.warning(
                    "Could not resolve credential template %s: %s", template_id, exc
                )
                raise HTTPException(
                    status_code=502,
                    detail="Credential template service unavailable",
                ) from exc
            except Exception as exc:
                logger.warning(
                    "Could not resolve credential template %s: %s", template_id, exc
                )
                raise HTTPException(
                    status_code=502,
                    detail="Credential template service unavailable",
                ) from exc
            if not template.id or template.organization_id != organization_id:
                raise HTTPException(
                    status_code=404,
                    detail="Credential template not found",
                )
            if str(getattr(template, "status", "")).lower() != "active":
                raise HTTPException(
                    status_code=409,
                    detail="Credential template is not active",
                )
            resolved.append((requirement, template))
    return resolved


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


def _normalize_holder_binding_evidence(
    evaluation: dict[str, Any],
) -> dict[str, Any] | None:
    raw = evaluation.get("holder_binding_evidence")
    if not isinstance(raw, dict):
        if "holder_binding_validated" not in evaluation:
            return None
        raw = {
            "required": evaluation.get("holder_binding_required", True),
            "validated": evaluation["holder_binding_validated"],
        }

    evidence = {
        "required": bool(raw.get("required", False)),
        "validated": bool(raw.get("validated", False)),
    }
    for key in (
        "binding_method",
        "proof_profile",
        "challenge_validated",
        "audience_validated",
        "replay_checked",
        "proof_age_seconds",
        "failure_reason",
    ):
        if raw.get(key) is not None:
            evidence[key] = raw[key]
    return evidence


def _protocol_result_for_session(session: VerificationSession) -> dict[str, Any] | None:
    if not session.completed_at and not session.result:
        return None

    passed = session.result == "passed" and session.status != SessionStatus.FAILED
    result: dict[str, Any] = {"passed": passed}

    claims_satisfied = sorted(
        str(claim_name) for claim_name in session.verified_claims.keys()
    )
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

    if session.holder_binding_evidence is not None:
        result["holder_binding_evidence"] = session.holder_binding_evidence

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


# ---------------------------------------------------------------------------
# REST router
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/v1/verify", tags=["Verification"])


def get_current_user_id(
    x_user_id: Annotated[str | None, Header(alias="X-User-Id")] = None,
) -> str:
    """Extract user ID from X-User-Id header (injected by gateway)."""
    return (x_user_id or "").strip()


@router.post("", summary="Start Verification Session")
async def start_verification(
    body: StartVerificationRequest,
    http_request: Request,
    store: SessionStore = Depends(get_store),
    user_id: str = Depends(get_current_user_id),
    x_organization_id: str | None = Header(default=None, alias="X-Organization-Id"),
) -> dict:
    """Create a verification session and return a request_uri for the wallet."""
    if (
        x_organization_id
        and body.organization_id
        and body.organization_id != x_organization_id
    ):
        raise HTTPException(status_code=403, detail="Organization mismatch")
    if body.response_type == "vp_token" and not body.presentation_policy_id:
        raise HTTPException(
            status_code=400,
            detail="presentation_policy_id is required for vp_token response_type",
        )
    if body.callback_url:
        raise HTTPException(
            status_code=400,
            detail=(
                "Standalone Verification callbacks are not supported; use the "
                "Flow service transactional callback outbox"
            ),
        )

    if _management_authorization_enabled(http_request):
        if not body.organization_id.strip():
            raise HTTPException(status_code=400, detail="organization_id is required")
        if body.trust_profile_id or body.deployment_profile_id:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Standalone trust/deployment profile overrides are not supported; "
                    "use the Flow verification endpoint"
                ),
            )
        await _authorize_management_principal(
            http_request,
            user_id=user_id,
            organization_id=body.organization_id,
        )
        policy = await _get_presentation_policy_reference(
            body.presentation_policy_id or ""
        )
        _require_policy_organization(
            policy,
            organization_id=body.organization_id,
        )
        await _resolve_policy_template_references(
            body.presentation_policy_id or "",
            policy,
            organization_id=body.organization_id,
        )

    session = VerificationSession(
        organization_id=body.organization_id,
        presentation_policy_id=body.presentation_policy_id,
        response_type=body.response_type,
        trust_profile_id=body.trust_profile_id,
        deployment_profile_id=body.deployment_profile_id,
        external_reference=body.external_reference,
        callback_url=None,
        expiry_minutes=body.expiry_minutes,
        purpose=body.purpose,
    )
    await store.save(session, touch_updated_at=False)
    logger.info(
        "Created verification session %s (org=%s)",
        session.session_id,
        body.organization_id,
    )
    resp = _session_to_protocol_dict(session)
    # Include operational fields the wallet / UI needs to display QR and deep-link
    resp["request_uri"] = session.request_uri()
    resp["qr_code_data"] = session.qr_code_data()
    return resp


@router.get("/sessions", summary="List Verification Sessions")
async def list_sessions(
    http_request: Request,
    organization_id: str,
    status: str | None = None,
    limit: int = 50,
    offset: int = 0,
    store: SessionStore = Depends(get_store),
    user_id: str = Depends(get_current_user_id),
) -> dict:
    """List verification sessions for an organization."""
    await _authorize_management_principal(
        http_request,
        user_id=user_id,
        organization_id=organization_id,
    )
    sessions = await store.list_by_org(organization_id, status)
    page = sessions[offset : offset + limit]
    return {
        "sessions": [_session_to_protocol_dict(s) for s in page],
        "total": len(sessions),
    }


async def _build_presentation_request_artifacts(
    session: VerificationSession,
) -> dict[str, Any]:
    """Fetch application records and delegate all OID4VP construction to Rust."""
    policy_id = session.presentation_policy_id
    if not policy_id or policy_id == "adhoc":
        raise NativeOperationError("OID4VP requests require a presentation policy")

    policy = await _get_presentation_policy_reference(policy_id)
    _require_policy_organization(policy, organization_id=session.organization_id)

    native_requirements: list[dict[str, Any]] = []
    references = await _resolve_policy_template_references(
        policy_id,
        policy,
        organization_id=session.organization_id,
    )
    for requirement, template in references:
        native_requirements.append(credential_requirement_input(requirement, template))

    return build_oid4vp_presentation_request(
        {
            "id": str(uuid.uuid4()),
            "requirements": native_requirements,
            "wallet_formats": wallet_registry_format_names(),
        }
    )


async def _build_presentation_definition(
    session: VerificationSession,
) -> dict[str, Any]:
    """Compatibility adapter returning Rust's Presentation Exchange artifact."""
    artifacts = await _build_presentation_request_artifacts(session)
    return artifacts["presentation_definition"]


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

    artifacts = await _build_presentation_request_artifacts(session)

    return {
        "response_type": session.response_type,
        "client_id": PUBLIC_BASE_URL,
        "nonce": session.nonce,
        "response_uri": f"{PUBLIC_BASE_URL}/v1/verify/{session_id}/submit",
        "dcql_query": artifacts["dcql_query"],
    }


@router.get("/{session_id}", summary="Get Verification Session")
async def get_session(
    session_id: str,
    http_request: Request,
    store: SessionStore = Depends(get_store),
    user_id: str = Depends(get_current_user_id),
) -> dict:
    """Retrieve the current state of a verification session (poll)."""
    session = await store.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    await _authorize_management_principal(
        http_request,
        user_id=user_id,
        organization_id=session.organization_id,
    )
    return _session_to_protocol_dict(session)


def _submission_error(transition: SubmissionTransition) -> HTTPException:
    if transition.outcome == SubmissionOutcome.MISSING:
        return HTTPException(status_code=404, detail="Session not found")
    if transition.outcome == SubmissionOutcome.EXPIRED:
        return HTTPException(status_code=410, detail="Session expired")
    if transition.outcome == SubmissionOutcome.CONFLICT:
        return HTTPException(
            status_code=409,
            detail="Session is already bound to a different presentation",
        )
    if transition.outcome == SubmissionOutcome.BUSY:
        return HTTPException(
            status_code=409,
            detail="Presentation evaluation is already in progress",
        )
    return HTTPException(
        status_code=503,
        detail="Verification session coordination unavailable",
    )


async def process_session_submission(
    store: SessionStore,
    session_id: str,
    vp_token: str,
    *,
    validate_references: bool = False,
) -> VerificationSession:
    """Own, evaluate, and atomically finalize a standalone presentation."""
    if validate_references:
        session = await store.get(session_id)
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")
        policy = await _require_session_policy_reference(session)
        await _resolve_policy_template_references(
            session.presentation_policy_id or "",
            policy,
            organization_id=session.organization_id,
        )

    digest = _sha256_text(vp_token)
    try:
        transition = await store.claim_submission(session_id, digest)
    except Exception as exc:
        logger.error("Could not claim verification session %s: %s", session_id, exc)
        raise HTTPException(
            status_code=503,
            detail="Verification session coordination unavailable",
        ) from exc

    if transition.outcome == SubmissionOutcome.DUPLICATE and transition.session:
        return transition.session
    if (
        transition.outcome != SubmissionOutcome.CLAIMED
        or transition.session is None
        or transition.token is None
    ):
        raise _submission_error(transition)

    session = transition.session
    try:
        eval_result = await _evaluate_via_grpc(
            policy_id=session.presentation_policy_id or "",
            vp_token=vp_token,
            nonce=session.nonce,
            context_json=json.dumps({"session_id": session_id}),
        )
        session.result = eval_result.get("result", "failed")
        session.decision = eval_result.get("decision", "deny")
        session.decision_reason = eval_result.get("decision_reason", "")
        session.verified_claims = eval_result.get("verified_claims", {})
        session.credential_results = eval_result.get("credential_results", [])
        session.holder_binding_evidence = _normalize_holder_binding_evidence(
            eval_result
        )
        session.total_requirements = int(eval_result.get("total_requirements") or 0)
        session.satisfied_requirements = int(
            eval_result.get("satisfied_requirements") or 0
        )
        session.error = None
    except Exception as exc:
        logger.error("Evaluation failed for session %s: %s", session_id, exc)
        session.result = "failed"
        session.decision = "deny"
        session.decision_reason = "Credential evaluation failed"
        session.holder_binding_evidence = None
        session.total_requirements = 0
        session.satisfied_requirements = 0
        session.error = "Credential evaluation failed"

    if INSPECTION_SYSTEM_TARGET and session.result != "failed":
        inspection_result = await _inspect_via_grpc(vp_token)
        if inspection_result:
            session.inspection_performed = True
            session.inspection_result = inspection_result

    session.status = (
        SessionStatus.COMPLETED if session.result == "passed" else SessionStatus.FAILED
    )
    session.completed_at = datetime.now(timezone.utc)
    session.updated_at = session.completed_at

    try:
        finalized = await store.finalize_submission(
            session_id,
            digest,
            transition.token,
            session,
        )
    except Exception as exc:
        logger.error("Could not finalize verification session %s: %s", session_id, exc)
        raise HTTPException(
            status_code=503,
            detail="Verification session coordination unavailable",
        ) from exc

    if (
        finalized.outcome
        in {
            SubmissionOutcome.COMMITTED,
            SubmissionOutcome.DUPLICATE,
        }
        and finalized.session
    ):
        logger.info(
            "Verification session %s finalized: result=%s decision=%s",
            session_id,
            finalized.session.result,
            finalized.session.decision,
        )
        return finalized.session
    raise _submission_error(finalized)


@router.post("/{session_id}/submit", summary="Submit VP Token")
async def submit_presentation(
    session_id: str,
    body: SubmitVerificationRequest,
    http_request: Request,
    store: SessionStore = Depends(get_store),
) -> dict:
    """Evaluate one immutable submission and return its canonical outcome."""
    session = await process_session_submission(
        store,
        session_id,
        body.vp_token,
        validate_references=_management_authorization_enabled(http_request),
    )
    return _session_to_protocol_dict(session)


@router.post("/evaluate", summary="Stateless Evaluation")
async def evaluate_presentation(
    body: EvaluateRequest,
    http_request: Request,
    user_id: str = Depends(get_current_user_id),
) -> dict:
    """
    Evaluate a VP token against a presentation policy without creating a session.
    Useful for server-side verification where session state is not needed.
    """
    try:
        if _management_authorization_enabled(http_request):
            policy = await _get_presentation_policy_reference(
                body.presentation_policy_id
            )
            _require_policy_active(policy)
            await _authorize_management_principal(
                http_request,
                user_id=user_id,
                organization_id=policy.organization_id,
            )
            await _resolve_policy_template_references(
                body.presentation_policy_id,
                policy,
                organization_id=policy.organization_id,
            )
        result = await _evaluate_via_grpc(
            policy_id=body.presentation_policy_id,
            vp_token=body.vp_token,
            nonce=body.nonce,
            context_json=json.dumps(body.context or {}),
        )
        return result
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Evaluation via gRPC failed: %s", exc)
        raise HTTPException(status_code=502, detail="Evaluation failed") from exc


@router.get("/{session_id}/inspection", summary="Inspection Result")
async def get_inspection_result(
    session_id: str,
    http_request: Request,
    store: SessionStore = Depends(get_store),
    user_id: str = Depends(get_current_user_id),
) -> dict:
    """Get the InspectionSystem result for a completed session."""
    session = await store.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    await _authorize_management_principal(
        http_request,
        user_id=user_id,
        organization_id=session.organization_id,
    )
    return {
        "session_id": session_id,
        "performed": session.inspection_performed,
        "result": session.inspection_result,
        "result_sha256": session.inspection_result_sha256,
        "timestamp": session.completed_at.isoformat() if session.completed_at else "",
    }


# ---------------------------------------------------------------------------
# ZKP endpoint (maps to /v1/verify/zkp)
# ---------------------------------------------------------------------------

zkp_router = APIRouter(prefix="/v1/verify/zkp", tags=["ZKP Verification"])


class ZkpSubmitRequest(BaseModel):
    vp_token: str | None = Field(
        default=None, description="VP token for ZKP verification"
    )
    proof: str | None = Field(
        default=None, description="ZKP proof (alias for vp_token)"
    )
    presentation_policy_id: str | None = Field(
        default=None, description="Presentation policy ID"
    )
    policy_id: str | None = Field(default=None, description="Policy ID (alias)")
    nonce: str | None = Field(default=None, description="Nonce for replay prevention")


@zkp_router.post("", summary="Submit ZKP Proof")
async def submit_zkp(
    body: ZkpSubmitRequest,
    http_request: Request,
    user_id: str = Depends(get_current_user_id),
) -> dict:
    """
    Submit a Zero-Knowledge Proof for verification.
    Delegates to /v1/verify/evaluate internally.
    """
    vp_token = body.vp_token or body.proof
    policy_id = body.presentation_policy_id or body.policy_id or ""

    if not vp_token:
        raise HTTPException(status_code=400, detail="vp_token or proof is required")

    try:
        if _management_authorization_enabled(http_request):
            if not policy_id:
                raise HTTPException(
                    status_code=400,
                    detail="presentation_policy_id or policy_id is required",
                )
            policy = await _get_presentation_policy_reference(policy_id)
            _require_policy_active(policy)
            await _authorize_management_principal(
                http_request,
                user_id=user_id,
                organization_id=policy.organization_id,
            )
            await _resolve_policy_template_references(
                policy_id,
                policy,
                organization_id=policy.organization_id,
            )
        result = await _evaluate_via_grpc(
            policy_id=policy_id,
            vp_token=vp_token,
            nonce=body.nonce,
        )
        return result
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("ZKP verification failed: %s", exc)
        raise HTTPException(status_code=502, detail="ZKP verification failed") from exc


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

grpc_server = None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    global grpc_server, _store

    logger.info(f"Starting {SERVICE_NAME} service on port {SERVICE_PORT}...")

    native_diagnostics = initialize_native_oid4vp_backend()
    app.state.oid4vp_native_backend_diagnostics = native_diagnostics
    logger.info(
        "Native OID4VP builder ready: backend=%s version=%s capabilities=%s",
        native_diagnostics["backend"],
        native_diagnostics["version"],
        ",".join(native_diagnostics["capabilities"]),
    )

    # Production requires Redis; only local/test environments may use memory.
    await init_store()

    from common.di import setup_org_client, teardown_org_client

    await setup_org_client(app, "verification")

    if GRPC_ENABLED:
        try:
            from common.grpc_factory import create_grpc_server, start_grpc_server_port
            from verification.infrastructure.adapters.grpc_adapter import (
                VerificationServiceGrpc,
            )
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
    if _store is not None:
        await _store.close()
        _store = None
    await teardown_org_client(app)


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
    app.state.enforce_verification_management_authorization = True

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
        logger.exception(
            "Unhandled exception on %s %s", request.method, request.url.path
        )
        return JSONResponse(
            status_code=500,
            content={
                "error": "server_error",
                "error_description": "Internal server error",
            },
        )

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=SERVICE_PORT)
