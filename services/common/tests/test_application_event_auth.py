from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import pytest

from common.application_event_auth import (
    AUDIENCE,
    HEADER_AUDIENCE,
    HEADER_SIGNATURE,
    ApplicationEventAuthError,
    authenticate_application_event,
    sign_application_event,
    validate_application_event_configuration,
)


@dataclass
class _SharedRedisState:
    values: dict[str, str] = field(default_factory=dict)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


class _RedisClient:
    def __init__(self, state: _SharedRedisState | None = None) -> None:
        self.state = state or _SharedRedisState()
        self.calls = 0

    async def set(self, key, value, *, nx, ex):
        assert nx is True
        assert ex >= 60
        self.calls += 1
        async with self.state.lock:
            if key in self.state.values:
                return False
            self.state.values[key] = value
            return True


@pytest.fixture(autouse=True)
def _event_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "FLOW_APPLICATION_EVENT_HMAC_KEY",
        "test-application-event-key-that-is-distinct-and-long",
    )


@pytest.fixture
def event() -> dict:
    return {
        "event_type": "application.approved",
        "aggregate_id": "application-1",
        "aggregate_type": "application",
        "organization_id": "org-1",
        "data": {
            "applicant_id": "applicant-1",
            "claims": {"given_name": "Ada", "roles": ["member"]},
        },
        "timestamp": "2026-08-09T12:00:00+00:00",
    }


@pytest.mark.asyncio
async def test_exact_event_is_authenticated_and_minimized(event: dict) -> None:
    metadata = sign_application_event(
        event,
        event_id="f4593698-8155-4e83-ac82-fef05e2e5761",
        now=1_786_291_200,
    )

    evidence = await authenticate_application_event(
        event,
        metadata,
        replay_store=_RedisClient(),
        now=1_786_291_200,
    )

    assert evidence.producer == "marty-applicant-service"
    assert evidence.audience == AUDIENCE
    assert len(evidence.event_id_sha256) == 64
    assert len(evidence.payload_sha256) == 64
    assert "application-1" not in str(evidence.as_dict())


@pytest.mark.asyncio
async def test_tampered_payload_is_rejected_before_replay_consumption(event: dict) -> None:
    metadata = sign_application_event(event, now=1_786_291_200)
    event["organization_id"] = "org-attacker"
    redis = _RedisClient()

    with pytest.raises(ApplicationEventAuthError, match="signature is invalid"):
        await authenticate_application_event(
            event,
            metadata,
            replay_store=redis,
            now=1_786_291_200,
        )

    assert redis.calls == 0


@pytest.mark.asyncio
async def test_wrong_audience_and_stale_events_are_rejected(event: dict) -> None:
    metadata = sign_application_event(event, now=1_786_291_200)
    wrong_audience = dict(metadata)
    wrong_audience[HEADER_AUDIENCE] = "some-other-purpose"
    with pytest.raises(ApplicationEventAuthError) as wrong:
        await authenticate_application_event(
            event,
            wrong_audience,
            replay_store=_RedisClient(),
            now=1_786_291_200,
        )
    assert wrong.value.code == "wrong_purpose"

    with pytest.raises(ApplicationEventAuthError) as stale:
        await authenticate_application_event(
            event,
            metadata,
            replay_store=_RedisClient(),
            now=1_786_291_261,
        )
    assert stale.value.code == "stale_event"


@pytest.mark.asyncio
async def test_invalid_signature_is_constant_shape_failure(event: dict) -> None:
    metadata = sign_application_event(event, now=1_786_291_200)
    metadata[HEADER_SIGNATURE] = "0" * 64
    with pytest.raises(ApplicationEventAuthError) as failure:
        await authenticate_application_event(
            event,
            metadata,
            replay_store=_RedisClient(),
            now=1_786_291_200,
        )
    assert failure.value.code == "invalid_signature"


@pytest.mark.asyncio
async def test_replay_store_is_mandatory_and_replay_fails_closed(event: dict) -> None:
    metadata = sign_application_event(event, now=1_786_291_200)
    with pytest.raises(ApplicationEventAuthError) as unavailable:
        await authenticate_application_event(
            event,
            metadata,
            replay_store=None,
            now=1_786_291_200,
        )
    assert unavailable.value.code == "replay_store_unavailable"

    redis = _RedisClient()
    await authenticate_application_event(
        event, metadata, replay_store=redis, now=1_786_291_200
    )
    with pytest.raises(ApplicationEventAuthError) as replay:
        await authenticate_application_event(
            event,
            metadata,
            replay_store=redis,
            now=1_786_291_200,
        )
    assert replay.value.code == "replayed_event"


@pytest.mark.asyncio
async def test_two_flow_replicas_race_to_one_shared_winner(event: dict) -> None:
    metadata = sign_application_event(event, now=1_786_291_200)
    shared = _SharedRedisState()
    replicas = (_RedisClient(shared), _RedisClient(shared))

    results = await asyncio.gather(
        *(
            authenticate_application_event(
                event,
                metadata,
                replay_store=replica,
                now=1_786_291_200,
            )
            for replica in replicas
        ),
        return_exceptions=True,
    )

    assert sum(not isinstance(result, Exception) for result in results) == 1
    failures = [result for result in results if isinstance(result, ApplicationEventAuthError)]
    assert len(failures) == 1
    assert failures[0].code == "replayed_event"


def test_startup_configuration_rejects_short_keys_and_undersized_replay_ttl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FLOW_APPLICATION_EVENT_HMAC_KEY", "too-short")
    with pytest.raises(ApplicationEventAuthError) as short:
        validate_application_event_configuration()
    assert short.value.code == "configuration_error"

    monkeypatch.setenv(
        "FLOW_APPLICATION_EVENT_HMAC_KEY",
        "test-application-event-key-that-is-distinct-and-long",
    )
    monkeypatch.setenv("FLOW_APPLICATION_EVENT_MAX_AGE_SECONDS", "120")
    monkeypatch.setenv("FLOW_APPLICATION_EVENT_REPLAY_TTL_SECONDS", "60")
    with pytest.raises(ApplicationEventAuthError) as ttl:
        validate_application_event_configuration()
    assert ttl.value.code == "configuration_error"
