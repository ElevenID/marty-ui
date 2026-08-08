from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException

from services.verification import main as verification


def _terminal(
    session: verification.VerificationSession,
    *,
    result: str = "passed",
) -> verification.VerificationSession:
    session.status = (
        verification.SessionStatus.COMPLETED
        if result == "passed"
        else verification.SessionStatus.FAILED
    )
    session.result = result
    session.decision = "allow" if result == "passed" else "deny"
    session.verified_claims = {"email": "alice@example.com"}
    session.completed_at = datetime.now(timezone.utc)
    session.updated_at = session.completed_at
    return session


async def _real_redis_store():
    url = os.environ.get("VERIFICATION_ATOMIC_TEST_REDIS_URL")
    if not url:
        pytest.skip("VERIFICATION_ATOMIC_TEST_REDIS_URL is not configured")
    import redis.asyncio as aioredis

    client = aioredis.from_url(url, decode_responses=False)
    try:
        await client.ping()
    except Exception as exc:
        await client.aclose()
        pytest.skip(f"real Redis is unavailable: {exc}")
    return client, verification.SessionStore(redis_client=client)


@pytest.mark.asyncio
async def test_real_redis_claim_is_atomic_and_recoverable_after_lease_expiry():
    redis, store = await _real_redis_store()
    session = verification.VerificationSession("org-atomic", "policy-1")
    await store.save(session, touch_updated_at=False)
    key = f"{verification.SESSION_PREFIX}{session.session_id}"
    org_key = f"{verification.SESSION_PREFIX}org:{session.organization_id}"
    digest_a = verification._sha256_text("presentation-a")
    digest_b = verification._sha256_text("presentation-b")

    try:
        first, competing = await asyncio.gather(
            store.claim_submission(session.session_id, digest_a),
            store.claim_submission(session.session_id, digest_b),
        )
        outcomes = {first.outcome, competing.outcome}
        assert outcomes == {
            verification.SubmissionOutcome.CLAIMED,
            verification.SubmissionOutcome.CONFLICT,
        }
        claimed = first if first.outcome == verification.SubmissionOutcome.CLAIMED else competing
        claimed_digest = (
            digest_a if claimed is first else digest_b
        )
        assert claimed.session is not None
        assert claimed.token is not None

        busy = await store.claim_submission(session.session_id, claimed_digest)
        assert busy.outcome == verification.SubmissionOutcome.BUSY

        raw = await redis.get(key)
        persisted = json.loads(raw)
        persisted["processing_expires_at"] = (
            datetime.now(timezone.utc) - timedelta(seconds=1)
        ).isoformat()
        persisted["expires_at"] = (
            datetime.now(timezone.utc) - timedelta(seconds=1)
        ).isoformat()
        await redis.set(
            key,
            json.dumps(persisted),
            ex=verification.SESSION_TTL_SECONDS,
        )

        reclaimed = await store.claim_submission(session.session_id, claimed_digest)
        assert reclaimed.outcome == verification.SubmissionOutcome.CLAIMED
        assert reclaimed.token is not None
        assert reclaimed.token != claimed.token
        assert reclaimed.session is not None

        stale = await store.finalize_submission(
            session.session_id,
            claimed_digest,
            claimed.token,
            _terminal(claimed.session),
        )
        assert stale.outcome == verification.SubmissionOutcome.BUSY

        committed = await store.finalize_submission(
            session.session_id,
            claimed_digest,
            reclaimed.token,
            _terminal(reclaimed.session),
        )
        assert committed.outcome == verification.SubmissionOutcome.COMMITTED
        assert committed.session is not None
        assert committed.session.verified_claims == {"email": True}

        duplicate = await store.claim_submission(session.session_id, claimed_digest)
        assert duplicate.outcome == verification.SubmissionOutcome.DUPLICATE
        assert duplicate.session is not None
        assert duplicate.session.completed_at == committed.session.completed_at

        conflict = await store.claim_submission(
            session.session_id,
            verification._sha256_text("another-presentation"),
        )
        assert conflict.outcome == verification.SubmissionOutcome.CONFLICT
    finally:
        await redis.delete(key)
        await redis.srem(org_key, session.session_id)
        await redis.aclose()


@pytest.mark.asyncio
async def test_real_redis_allows_only_one_terminal_write():
    redis, store = await _real_redis_store()
    session = verification.VerificationSession("org-finalize", "policy-1")
    await store.save(session, touch_updated_at=False)
    key = f"{verification.SESSION_PREFIX}{session.session_id}"
    org_key = f"{verification.SESSION_PREFIX}org:{session.organization_id}"
    digest = verification._sha256_text("same-presentation")

    try:
        claimed = await store.claim_submission(session.session_id, digest)
        assert claimed.session is not None
        assert claimed.token is not None
        candidate_a = _terminal(claimed.session, result="passed")
        candidate_b = _terminal(
            verification._clone_session(claimed.session),
            result="failed",
        )

        first, second = await asyncio.gather(
            store.finalize_submission(
                session.session_id,
                digest,
                claimed.token,
                candidate_a,
            ),
            store.finalize_submission(
                session.session_id,
                digest,
                claimed.token,
                candidate_b,
            ),
        )

        assert sorted((first.outcome.value, second.outcome.value)) == [
            "committed",
            "duplicate",
        ]
        assert first.session is not None
        assert second.session is not None
        assert first.session.result == second.session.result
        stored = await store.get(session.session_id)
        assert stored is not None
        assert stored.result == first.session.result
    finally:
        await redis.delete(key)
        await redis.srem(org_key, session.session_id)
        await redis.aclose()


@pytest.mark.asyncio
async def test_duplicate_submission_reuses_canonical_result_without_reevaluation(
    monkeypatch: pytest.MonkeyPatch,
):
    store = verification.SessionStore()
    session = verification.VerificationSession("org-1", "policy-1")
    await store.save(session, touch_updated_at=False)
    evaluations = 0

    async def evaluate(**_kwargs):
        nonlocal evaluations
        evaluations += 1
        return {
            "result": "passed",
            "decision": "allow",
            "verified_claims": {"email": "alice@example.com"},
            "credential_results": [],
            "total_requirements": 1,
            "satisfied_requirements": 1,
        }

    monkeypatch.setattr(verification, "_evaluate_via_grpc", evaluate)
    first = await verification.process_session_submission(
        store,
        session.session_id,
        "presentation",
    )
    duplicate = await verification.process_session_submission(
        store,
        session.session_id,
        "presentation",
    )

    assert evaluations == 1
    assert duplicate.completed_at == first.completed_at
    assert duplicate.verified_claims == {"email": True}
    with pytest.raises(HTTPException) as conflict:
        await verification.process_session_submission(
            store,
            session.session_id,
            "different-presentation",
        )
    assert conflict.value.status_code == 409


@pytest.mark.asyncio
async def test_production_store_requires_redis(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setattr(verification, "REDIS_URL", "")

    with pytest.raises(RuntimeError, match="REDIS_URL is required"):
        await verification.init_store()
    assert verification._store is None


@pytest.mark.asyncio
async def test_production_store_does_not_fall_back_when_redis_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setattr(
        verification,
        "REDIS_URL",
        "redis://127.0.0.1:1/0?socket_connect_timeout=0.1",
    )

    with pytest.raises(RuntimeError, match="Redis is required"):
        await verification.init_store()
    assert verification._store is None
