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
from marty_common.service_setup import create_service_app
from common.grpc_factory import create_grpc_channel

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
        datetime.fromisoformat(data["completed_at"]) if data.get("completed_at") else None
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
                await self._redis.set(key, json.dumps(_session_to_redis_dict(session)), ex=SESSION_TTL_SECONDS)
                await self._redis.sadd(f"{SESSION_PREFIX}org:{session.organization_id}", session.session_id)
                await self._redis.expire(f"{SESSION_PREFIX}org:{session.organization_id}", SESSION_TTL_SECONDS)

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
        if (
            session.status == SessionStatus.PENDING
            and session.vp_token_sha256 is None
        ):
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


def get_current_user_id(x_user_id: Annotated[str | None, Header(alias="X-User-Id")] = None) -> str:
    """Extract user ID from X-User-Id header (injected by gateway)."""
    return x_user_id or "anonymous"


@router.post("", summary="Start Verification Session")
async def start_verification(
    body: StartVerificationRequest,
    store: SessionStore = Depends(get_store),
    user_id: str = Depends(get_current_user_id),
    x_organization_id: str | None = Header(default=None, alias="X-Organization-Id"),
) -> dict:
    """Create a verification session and return a request_uri for the wallet."""
    if x_organization_id and body.organization_id and body.organization_id != x_organization_id:
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


# SD-JWT presentation format algorithms (matches flow._SD_JWT_PRESENTATION_ALGS)
_SD_JWT_PRESENTATION_ALGS = {
    "sd-jwt_alg_values": ["ES256", "EdDSA"],
    "kb-jwt_alg_values": ["ES256", "EdDSA"],
}
CT_GRPC_TARGET = os.environ.get("CT_GRPC_TARGET", "credential-template:9003")

# ── OID4VP presentation formats: derived from wallet registry entries ─────
# Each wallet registry entry declares supported_formats that map directly to
# OID4VP presentation format identifiers.  A local fallback keeps presentation
# working when the credential_template module isn't importable at runtime.

_WALLET_FORMATS_FALLBACK: dict[str, dict[str, Any]] = {
    "vc+sd-jwt":        {"sd-jwt_alg_values": ["ES256", "EdDSA"], "kb-jwt_alg_values": ["ES256", "EdDSA"]},
    "dc+sd-jwt":        {"sd-jwt_alg_values": ["ES256", "EdDSA"], "kb-jwt_alg_values": ["ES256", "EdDSA"]},
    "mso_mdoc":         {"alg": ["ES256", "ES384"]},
    "jwt_vp":           {"alg": ["ES256", "EdDSA"]},
    "ldp_vp":           {"proof_type": ["Ed25519Signature2020"]},
}


def _oid4vp_wallet_registry_formats() -> dict[str, dict[str, Any]]:
    """Collect all unique OID4VP format identifiers from the wallet registry."""
    try:
        from credential_template.main import SYSTEM_WALLET_CATALOG  # type: ignore[import-untyped]
        result: dict[str, dict[str, Any]] = {}
        for entry in SYSTEM_WALLET_CATALOG:
            for fmt in entry.supported_formats:
                fmt_s = (fmt or "").strip()
                if fmt_s and fmt_s not in result:
                    result[fmt_s] = _oid4vp_format_alg(fmt_s)
        if result:
            return result
    except ImportError:
        pass
    return dict(_WALLET_FORMATS_FALLBACK)


def _oid4vp_format_alg(fmt: str) -> dict[str, Any]:
    """Return algorithm constraints for a given OID4VP format identifier."""
    fmt_n = (fmt or "").strip().lower()
    if fmt_n in {"vc+sd-jwt", "dc+sd-jwt", "sd_jwt_vc"}:
        return dict(_SD_JWT_PRESENTATION_ALGS)
    if fmt_n in {"mso_mdoc", "mdoc"}:
        return {"alg": ["ES256", "ES384"]}
    if fmt_n in {"jwt_vp", "jwt_vc", "jwt_vc_json"}:
        return {"alg": ["ES256", "EdDSA"]}
    if fmt_n == "ldp_vp":
        return {"proof_type": ["Ed25519Signature2020"]}
    return {"alg": ["ES256", "EdDSA"]}


def _oid4vp_presentation_formats(template_supported_formats: list[str]) -> dict[str, Any]:
    """Derive OID4VP format identifiers from template formats × wallet registry."""
    _SD_FAMILY = {"sd_jwt_vc", "vc+sd-jwt", "dc+sd-jwt"}
    _DOC_FAMILY = {"mso_mdoc", "mdoc"}
    _JWTVP_FAMILY = {"jwt_vc", "jwt_vc_json", "jwt_vp"}

    template_family: set[str] = set()
    for f in template_supported_formats:
        fn = (f or "").strip().lower()
        if fn in _SD_FAMILY:
            template_family.add("sd_jwt")
        elif fn in _DOC_FAMILY:
            template_family.add("mdoc")
        elif fn in _JWTVP_FAMILY:
            template_family.add("jwt_vp")
        else:
            template_family.add(fn)

    result: dict[str, Any] = {}
    registry_formats = _oid4vp_wallet_registry_formats()
    for fmt_key, fmt_alg in registry_formats.items():
        fn = (fmt_key or "").strip().lower()
        if ("sd_jwt" in template_family and fn in _SD_FAMILY) or \
           ("mdoc" in template_family and fn in _DOC_FAMILY) or \
           ("jwt_vp" in template_family and fn in _JWTVP_FAMILY) or \
           fn in template_family:
            result[fmt_key] = fmt_alg

    if not result:
        return {"jwt_vp": {"alg": ["ES256", "EdDSA"]}, "ldp_vp": {"proof_type": ["Ed25519Signature2020"]}}
    return result


def _is_sd_jwt_format(supported_formats: list[str]) -> bool:
    """Return True if any supported format is in the SD-JWT family."""
    _SD = {"sd_jwt_vc", "vc+sd-jwt", "dc+sd-jwt"}
    return any((f or "").strip().lower() in _SD for f in supported_formats)


def _is_mdoc_format(supported_formats: list[str]) -> bool:
    """Return True if any supported format is in the ISO mDoc family."""
    _DOC = {"mso_mdoc", "mdoc"}
    return any((f or "").strip().lower() in _DOC for f in supported_formats)


def _string_filter_for_values(values: list[str]) -> dict[str, Any]:
    """Build a JSON Schema string filter for one or more accepted values."""
    unique_values = [value for i, value in enumerate(values) if value and value not in values[:i]]
    if len(unique_values) == 1:
        return {"type": "string", "const": unique_values[0]}
    return {"type": "string", "enum": unique_values}


def _sd_jwt_vct_values(credential_vct: str | None, credential_type: str | None) -> list[str]:
    """Return accepted SD-JWT VC type values for the request object."""
    values = [credential_vct or credential_type] if (credential_vct or credential_type) else []
    if credential_type == "open_badge" or credential_vct == "https://beta.elevenidllc.com/credentials/marty-verified-member-badge":
        values.append("https://marty.example/credentials/open_badge")
    return [value for i, value in enumerate(values) if value and value not in values[:i]]


def _dcql_format_name(fmt: str) -> str:
    """Normalize OID4VP format identifiers to DCQL format names."""
    fmt_n = (fmt or "").strip().lower()
    if fmt_n in {"jwt_vp", "jwt_vc", "jwt_vc_json"}:
        return "jwt_vc_json"
    if fmt_n == "ldp_vp":
        return "ldp_vc"
    if fmt_n in {"vc+sd-jwt", "dc+sd-jwt", "sd_jwt_vc"}:
        return "dc+sd-jwt"
    if fmt_n in {"mso_mdoc", "mdoc"}:
        return "mso_mdoc"
    return fmt


def _json_schema_const_values(schema: dict[str, Any] | None) -> list[str]:
    """Extract string const/enum values from a JSON Schema fragment."""
    if not isinstance(schema, dict):
        return []

    values: list[str] = []

    def _append(value: Any) -> None:
        if isinstance(value, str) and value not in values:
            values.append(value)

    _append(schema.get("const"))
    enum_values = schema.get("enum")
    if isinstance(enum_values, list):
        for enum_value in enum_values:
            _append(enum_value)

    contains = schema.get("contains")
    if isinstance(contains, dict):
        for value in _json_schema_const_values(contains):
            _append(value)

    for keyword in ("anyOf", "oneOf", "allOf"):
        options = schema.get(keyword)
        if isinstance(options, list):
            for option in options:
                if isinstance(option, dict):
                    for value in _json_schema_const_values(option):
                        _append(value)

    return values


def _dcql_meta_for_descriptor(descriptor: dict[str, Any], fmt_name: str) -> dict[str, Any]:
    """Derive DCQL meta from Presentation Exchange type/vct filters."""
    sd_jwt_formats = {"dc+sd-jwt", "vc+sd-jwt", "sd_jwt_vc"}
    for field in descriptor.get("constraints", {}).get("fields", []):
        values = _json_schema_const_values(field.get("filter"))
        if not values:
            continue
        paths = field.get("path", [])
        if fmt_name in sd_jwt_formats or "$.vct" in paths:
            return {"vct_values": values}
        if any(path in {"$.vc.type", "$.type"} for path in paths):
            return {"type_values": [["VerifiableCredential", value] for value in values]}
    return {}


def _dcql_claims_for_descriptor(descriptor: dict[str, Any]) -> list[dict[str, Any]]:
    """Derive DCQL claim requests from Presentation Exchange fields."""
    fields = descriptor.get("constraints", {}).get("fields", [])
    required_fields = [field for field in fields if not field.get("optional")]
    candidate_fields = required_fields or fields

    claims: list[dict[str, Any]] = []
    seen: set[tuple[str, ...]] = set()
    for field in candidate_fields:
        if field.get("filter"):
            continue
        for path in reversed(field.get("path", [])):
            if not isinstance(path, str) or not path.startswith("$."):
                continue
            claim_path = path[2:].split(".")
            if not claim_path or claim_path[0] in {"vc", "credentialSubject", "type", "vct"}:
                continue
            key = tuple(claim_path)
            if key in seen:
                break
            seen.add(key)
            claims.append(
                {
                    "id": "claim_" + "_".join(part.replace("-", "_") for part in claim_path),
                    "path": claim_path,
                }
            )
            break
    return claims


async def _build_presentation_definition(session: VerificationSession) -> dict[str, Any]:
    """Build an OID4VP presentation_definition with proper input_descriptors.

    Fetches the presentation policy and each referenced credential template
    so that input_descriptors contain real credential-type filters that a
    wallet (including SpruceKit) can match against its stored credentials.
    Mirrors the canonical MIP implementation in the flow service.
    """
    policy_id = session.presentation_policy_id
    if not policy_id or policy_id == "adhoc":
        return {"id": "adhoc"}

    try:
        from marty_proto.v1 import (
            presentation_policy_service_pb2,
            presentation_policy_service_pb2_grpc,
            credential_template_service_pb2,
            credential_template_service_pb2_grpc,
        )

        async with create_grpc_channel(
            PP_GRPC_TARGET,
            service_name="verification",
            require_workload_identity=True,
        ) as pp_channel:
            pp_stub = presentation_policy_service_pb2_grpc.PresentationPolicyServiceStub(
                pp_channel
            )
            pp_resp = await pp_stub.GetPolicy(
                presentation_policy_service_pb2.GetPolicyRequest(policy_id=policy_id)
            )

        if not pp_resp.id:
            return {"id": policy_id}
        credential_requirements = json.loads(pp_resp.credential_requirements_json or "[]")
    except Exception as exc:
        logger.warning(
            "Could not fetch presentation policy %s for request object: %s",
            policy_id, exc,
        )
        return {"id": policy_id}

    if not credential_requirements:
        return {"id": policy_id}

    ct_channel = create_grpc_channel(CT_GRPC_TARGET, service_name="verification")
    ct_stub = credential_template_service_pb2_grpc.CredentialTemplateServiceStub(ct_channel)

    input_descriptors: list[dict[str, Any]] = []
    for i, req in enumerate(credential_requirements):
        template_id = req.get("credential_template_id", "")
        descriptor_id = req.get("id") or f"descriptor-{i}"
        display_name = req.get("display_name") or f"Credential {i + 1}"
        purpose = req.get("description") or f"Present {display_name}"

        # Fetch the credential template to get supported_formats and credential type
        credential_type: str | None = None
        credential_vct: str | None = None
        supported_formats: list[str] = []
        if template_id:
            try:
                tmpl_resp = await ct_stub.GetTemplate(
                    credential_template_service_pb2.GetTemplateRequest(template_id=template_id)
                )
                if tmpl_resp.id:
                    credential_type = tmpl_resp.credential_type or None
                    credential_vct = tmpl_resp.vct or None
                    supported_formats = list(tmpl_resp.supported_formats) or []
            except Exception as exc:
                logger.warning(
                    "_build_presentation_definition: could not fetch template %s: %s",
                    template_id, exc,
                )

        # Build type-filter constraint based on format. Presentation Exchange
        # fields are conjunctive, so only the SD-JWT vct selector is required
        # for SD-JWT credentials; W3C/Open Badge type hints stay optional.
        fields: list[dict[str, Any]] = []
        if credential_type:
            if _is_mdoc_format(supported_formats):
                fields.append({
                    "path": ["$.mdoc.docType", "$.docType"],
                    "filter": {"type": "string", "const": credential_type},
                })
            elif _is_sd_jwt_format(supported_formats):
                vct_values = _sd_jwt_vct_values(credential_vct, credential_type)
                fields.append({
                    "path": ["$.vct"],
                    "filter": _string_filter_for_values(vct_values),
                })
                fields.append({
                    "path": ["$.vc.type", "$.type"],
                    "filter": {
                        "anyOf": [
                            {"type": "array", "contains": {"const": credential_type}},
                            {"type": "string", "const": credential_type},
                        ],
                    },
                    "optional": True,
                })
            else:
                fields.append({
                    "path": ["$.vc.type", "$.type"],
                    "filter": {
                        "anyOf": [
                            {"type": "array", "contains": {"const": credential_type}},
                            {"type": "string", "const": credential_type},
                        ],
                    },
                })

        # Add path hints for requested claims (selective disclosure support)
        for claim in req.get("requested_claims", []) or []:
            claim_name = claim.get("claim_name") if isinstance(claim, dict) else getattr(claim, "claim_name", None)
            if claim_name:
                fields.append({
                    "path": [
                        f"$.vc.credentialSubject.{claim_name}",
                        f"$.credentialSubject.{claim_name}",
                        f"$.{claim_name}",
                    ],
                })

        # Build format object from template supported_formats (wallet-registry-driven)
        descriptor: dict[str, Any] = {"id": descriptor_id, "name": display_name, "purpose": purpose}
        descriptor["format"] = _oid4vp_presentation_formats(supported_formats)

        if fields:
            descriptor["constraints"] = {"fields": fields}
            if _is_sd_jwt_format(supported_formats):
                descriptor["constraints"]["limit_disclosure"] = "required"

        input_descriptors.append(descriptor)

    await ct_channel.close()

    # Collect unique formats for the top-level format block
    _top_formats: dict[str, Any] = {}
    for desc in input_descriptors:
        for fmt_key, fmt_val in desc.get("format", {}).items():
            if fmt_key not in _top_formats:
                _top_formats[fmt_key] = fmt_val
    if not _top_formats:
        _top_formats = {"jwt_vp": {"alg": ["ES256", "EdDSA"]}}

    # Fallback: no requirements
    if not input_descriptors:
        input_descriptors = [{
            "id": "default_requirement",
            "name": "Credential Presentation",
            "purpose": "Present credentials per policy requirements",
            "constraints": {"fields": []},
        }]

    return {
        "id": str(uuid.uuid4()),
        "format": _top_formats,
        "input_descriptors": input_descriptors,
    }


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

    presentation_definition = await _build_presentation_definition(session)
    dcql_entries: list[dict[str, Any]] = []
    for descriptor in presentation_definition.get("input_descriptors", []):
        fmt_map = descriptor.get("format", {})
        first_fmt = next(iter(fmt_map), "jwt_vc_json")
        fmt_name = _dcql_format_name(first_fmt)
        entry: dict[str, Any] = {"id": descriptor["id"], "format": fmt_name}
        dcql_meta = _dcql_meta_for_descriptor(descriptor, fmt_name)
        if dcql_meta:
            entry["meta"] = dcql_meta
        claims = _dcql_claims_for_descriptor(descriptor)
        if claims:
            entry["claims"] = claims
        dcql_entries.append(entry)
    if not dcql_entries:
        dcql_entries = [{"id": "default-credential", "format": "jwt_vc_json"}]

    return {
        "response_type": session.response_type,
        "client_id": PUBLIC_BASE_URL,
        "nonce": session.nonce,
        "response_uri": f"{PUBLIC_BASE_URL}/v1/verify/{session_id}/submit",
        "dcql_query": {"credentials": dcql_entries},
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
) -> VerificationSession:
    """Own, evaluate, and atomically finalize a standalone presentation."""
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
        SessionStatus.COMPLETED
        if session.result == "passed"
        else SessionStatus.FAILED
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

    if finalized.outcome in {
        SubmissionOutcome.COMMITTED,
        SubmissionOutcome.DUPLICATE,
    } and finalized.session:
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
    store: SessionStore = Depends(get_store),
    user_id: str = Depends(get_current_user_id),
) -> dict:
    """Evaluate one immutable submission and return its canonical outcome."""
    session = await process_session_submission(store, session_id, body.vp_token)
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
        "result_sha256": session.inspection_result_sha256,
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
    global grpc_server, _store

    logger.info(f"Starting {SERVICE_NAME} service on port {SERVICE_PORT}...")

    # Production requires Redis; only local/test environments may use memory.
    await init_store()

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
    if _store is not None:
        await _store.close()
        _store = None


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
