"""Marty-owned contracts for atomic, versioned device-key rotation."""

from __future__ import annotations

import asyncio
import base64
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from services.device_registration import main as device
from services.device_registration.challenges import (
    CHALLENGE_AUDIENCE,
    ChallengeRecord,
    ChallengeStore,
)
from services.device_registration.native import inspect_public_key

MIGRATIONS = Path(__file__).resolve().parents[1] / "infrastructure" / "migrations"


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _key_material():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.PKCS1,
    )
    encoded = _b64url(der)
    return private_key, encoded, inspect_public_key(encoded)["public_key_kid"]


def _sign(private_key, encoded_challenge: str) -> str:
    challenge = base64.urlsafe_b64decode(
        encoded_challenge + "=" * (-len(encoded_challenge) % 4)
    )
    return _b64url(
        private_key.sign(
            challenge,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=hashes.SHA256.digest_size,
            ),
            hashes.SHA256(),
        )
    )


def _client() -> tuple[TestClient, device.InMemoryDeviceRepository]:
    repository = device.InMemoryDeviceRepository()
    device._repo = repository
    device._challenge_store = ChallengeStore(None, 300)
    app = FastAPI()
    app.include_router(device.router)
    return TestClient(app), repository


def _register_keyed_device(client: TestClient):
    private_key, public_key_der, public_key_kid = _key_material()
    headers = {"X-User-Id": "user-1"}
    challenge = client.post(
        "/v1/devices/challenge",
        headers=headers,
        json={
            "device_id": "device-1",
            "public_key_der": public_key_der,
            "public_key_kid": public_key_kid,
        },
    ).json()
    response = client.post(
        "/v1/devices",
        headers={
            **headers,
            "X-Device-Challenge-Id": challenge["challenge_id"],
            "X-Device-Challenge-Signature": _sign(private_key, challenge["challenge"]),
        },
        json={
            "device_id": "device-1",
            "platform": "ios",
            "fcm_token": "push-token",
            "public_key_der": public_key_der,
            "public_key_kid": public_key_kid,
        },
    )
    assert response.status_code == 200
    assert response.json()["key_version"] == 1
    return response.json(), (private_key, public_key_der, public_key_kid)


def test_rotation_requires_exact_expected_version_and_projects_only_current_key() -> (
    None
):
    client, repository = _client()
    registration, old_material = _register_keyed_device(client)
    new_private_key, new_der, new_kid = _key_material()

    missing_version = client.post(
        "/v1/devices/challenge",
        headers={"X-User-Id": "user-1"},
        json={
            "registration_id": registration["id"],
            "device_id": "device-1",
            "public_key_der": new_der,
            "public_key_kid": new_kid,
        },
    )
    assert missing_version.status_code == 400

    challenge = client.post(
        "/v1/devices/challenge",
        headers={"X-User-Id": "user-1"},
        json={
            "registration_id": registration["id"],
            "device_id": "device-1",
            "public_key_der": new_der,
            "public_key_kid": new_kid,
            "expected_key_version": 1,
        },
    ).json()
    challenge_record = asyncio.run(
        device.get_challenge_store().get(challenge["challenge_id"])
    )
    assert challenge_record.registration_id == registration["id"]
    assert challenge_record.key_version == 1
    assert challenge_record.purpose == "device_key_rotation"

    rotated = client.patch(
        f"/v1/devices/{registration['id']}",
        headers={
            "X-User-Id": "user-1",
            "X-Device-Challenge-Id": challenge["challenge_id"],
            "X-Device-Challenge-Signature": _sign(
                new_private_key, challenge["challenge"]
            ),
        },
        json={
            "public_key_der": new_der,
            "public_key_kid": new_kid,
            "expected_key_version": 1,
        },
    )
    assert rotated.status_code == 200
    assert rotated.json()["key_version"] == 2
    assert rotated.json()["public_key_kid"] == new_kid
    assert old_material[2] not in rotated.text
    assert len(repository._keys[registration["id"]]) == 2


@pytest.mark.asyncio
async def test_concurrent_rotation_compare_and_swap_has_one_winner() -> None:
    repository = device.InMemoryDeviceRepository()
    old_private, old_der, old_kid = _key_material()
    del old_private
    registration = device.DeviceRegistration(
        user_id="user-1",
        device_id="device-1",
        fcm_token="push-token",
        public_key_der=old_der,
        public_key_kid=old_kid,
    )
    await repository.save(registration)
    _key_a, der_a, kid_a = _key_material()
    _key_b, der_b, kid_b = _key_material()

    results = await asyncio.gather(
        repository.rotate_key(
            registration.id,
            expected_version=1,
            public_key_der=der_a,
            public_key_kid=kid_a,
            grace_seconds=300,
        ),
        repository.rotate_key(
            registration.id,
            expected_version=1,
            public_key_der=der_b,
            public_key_kid=kid_b,
            grace_seconds=300,
        ),
        return_exceptions=True,
    )

    assert (
        sum(isinstance(result, device.DeviceKeyConflictError) for result in results)
        == 1
    )
    assert registration.key_version == 2
    assert sorted(repository._keys[registration.id]) == [1, 2]


@pytest.mark.asyncio
async def test_retiring_key_only_resolves_exact_pre_rotation_non_mutating_challenge() -> (
    None
):
    repository = device.InMemoryDeviceRepository()
    _old_private, old_der, old_kid = _key_material()
    registration = device.DeviceRegistration(
        user_id="user-1",
        device_id="device-1",
        fcm_token="push-token",
        public_key_der=old_der,
        public_key_kid=old_kid,
    )
    await repository.save(registration)
    issued_at = datetime.now(timezone.utc)
    pre_rotation = ChallengeRecord(
        challenge_id="challenge-before-rotation",
        user_id="user-1",
        device_id="device-1",
        public_key_kid=old_kid,
        public_key_sha256=inspect_public_key(old_der)["public_key_sha256"],
        nonce="nonce",
        created_at=issued_at.isoformat(),
        expires_at=(issued_at + timedelta(minutes=5)).isoformat(),
        registration_id=registration.id,
        key_version=1,
        purpose="device_authentication",
    )
    _new_private, new_der, new_kid = _key_material()
    await repository.rotate_key(
        registration.id,
        expected_version=1,
        public_key_der=new_der,
        public_key_kid=new_kid,
        grace_seconds=300,
    )
    retiring = repository._keys[registration.id][1]
    within_grace = retiring.rotated_at + timedelta(seconds=1)

    resolved = await repository.resolve_challenge_key(
        pre_rotation,
        purpose="device_authentication",
        audience=CHALLENGE_AUDIENCE,
        now=within_grace,
    )
    assert resolved == retiring

    after_rotation = ChallengeRecord(
        **{
            **pre_rotation.__dict__,
            "challenge_id": "challenge-after-rotation",
            "created_at": retiring.rotated_at.isoformat(),
        }
    )
    assert (
        await repository.resolve_challenge_key(
            after_rotation,
            purpose="device_authentication",
            audience=CHALLENGE_AUDIENCE,
            now=within_grace,
        )
        is None
    )
    assert (
        await repository.resolve_challenge_key(
            ChallengeRecord(
                **{**pre_rotation.__dict__, "purpose": "device_key_rotation"}
            ),
            purpose="device_key_rotation",
            audience=CHALLENGE_AUDIENCE,
            now=within_grace,
        )
        is None
    )
    assert (
        await repository.resolve_challenge_key(
            pre_rotation,
            purpose="device_authentication",
            audience=CHALLENGE_AUDIENCE,
            now=retiring.retire_at,
        )
        is None
    )

    await repository.deactivate(registration.id)
    assert (
        await repository.resolve_challenge_key(
            pre_rotation,
            purpose="device_authentication",
            audience=CHALLENGE_AUDIENCE,
            now=within_grace,
        )
        is None
    )


def test_callers_cannot_select_key_lifetime_or_rotation_grace() -> None:
    client, _repository = _client()
    _private_key, public_key_der, public_key_kid = _key_material()
    response = client.post(
        "/v1/devices",
        headers={"X-User-Id": "user-1"},
        json={
            "device_id": "device-1",
            "platform": "ios",
            "fcm_token": "push-token",
            "public_key_der": public_key_der,
            "public_key_kid": public_key_kid,
            "key_valid_until": "2099-01-01T00:00:00Z",
        },
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "key validity timestamps are server-assigned"


@pytest.mark.parametrize("value", ["-1", "901", "not-an-integer"])
def test_server_rotation_grace_is_bounded(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setenv("DEVICE_KEY_ROTATION_GRACE_SECONDS", value)

    with pytest.raises(RuntimeError, match="DEVICE_KEY_ROTATION_GRACE_SECONDS"):
        device._rotation_grace_seconds()


def test_reregistration_after_deactivation_gets_new_identity_and_key_history() -> None:
    client, repository = _client()
    original, _old_material = _register_keyed_device(client)
    deleted = client.delete(
        f"/v1/devices/{original['id']}", headers={"X-User-Id": "user-1"}
    )
    assert deleted.status_code == 200

    new_private, new_der, new_kid = _key_material()
    challenge = client.post(
        "/v1/devices/challenge",
        headers={"X-User-Id": "user-1"},
        json={
            "device_id": "device-1",
            "public_key_der": new_der,
            "public_key_kid": new_kid,
        },
    ).json()
    replacement = client.post(
        "/v1/devices",
        headers={
            "X-User-Id": "user-1",
            "X-Device-Challenge-Id": challenge["challenge_id"],
            "X-Device-Challenge-Signature": _sign(new_private, challenge["challenge"]),
        },
        json={
            "device_id": "device-1",
            "platform": "ios",
            "fcm_token": "new-push-token",
            "public_key_der": new_der,
            "public_key_kid": new_kid,
        },
    )

    assert replacement.status_code == 200
    assert replacement.json()["id"] != original["id"]
    assert replacement.json()["key_version"] == 1
    assert repository._keys[original["id"]][1].state is device.DeviceKeyState.REVOKED


@pytest.mark.asyncio
async def test_real_postgres_concurrent_rotation_has_one_transactional_winner() -> None:
    """Exercise the row lock and partial unique index against a dedicated database."""
    database_url = os.environ.get("DEVICE_KEY_TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("DEVICE_KEY_TEST_DATABASE_URL is not configured")

    from alembic import command
    from alembic.config import Config
    from device_registration.infrastructure.models import (
        device_key_transitions,
        device_registration_keys,
        device_registrations,
        mapper_registry,
    )

    sync_url = database_url.replace("postgresql+asyncpg://", "postgresql+psycopg2://")
    config = Config(str(MIGRATIONS / "alembic.ini"))
    config.set_main_option("script_location", str(MIGRATIONS))
    config.set_main_option("sqlalchemy.url", sync_url)
    config.attributes["target_metadata"] = mapper_registry.metadata
    command.upgrade(config, "head")

    async_url = database_url
    if async_url.startswith("postgresql://"):
        async_url = async_url.replace("postgresql://", "postgresql+asyncpg://", 1)
    elif async_url.startswith("postgresql+psycopg2://"):
        async_url = async_url.replace(
            "postgresql+psycopg2://", "postgresql+asyncpg://", 1
        )
    engine = create_async_engine(async_url)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    repository = device.PostgresDeviceRegistrationRepository(sessions)
    initial_private, initial_der, initial_kid = _key_material()
    del initial_private
    registration = device.DeviceRegistration(
        user_id=f"race-user-{uuid.uuid4()}",
        device_id=f"race-device-{uuid.uuid4()}",
        fcm_token="race-test-token",
        public_key_der=initial_der,
        public_key_kid=initial_kid,
    )
    await repository.save(registration)
    _key_a, der_a, kid_a = _key_material()
    _key_b, der_b, kid_b = _key_material()

    try:
        results = await asyncio.gather(
            repository.rotate_key(
                registration.id,
                expected_version=1,
                public_key_der=der_a,
                public_key_kid=kid_a,
                grace_seconds=300,
            ),
            repository.rotate_key(
                registration.id,
                expected_version=1,
                public_key_der=der_b,
                public_key_kid=kid_b,
                grace_seconds=300,
            ),
            return_exceptions=True,
        )
        assert (
            sum(isinstance(result, device.DeviceKeyConflictError) for result in results)
            == 1
        )
        async with sessions() as session:
            current_versions = (
                (
                    await session.execute(
                        select(device_registration_keys.c.key_version).where(
                            device_registration_keys.c.registration_id
                            == registration.id,
                            device_registration_keys.c.state == "CURRENT",
                        )
                    )
                )
                .scalars()
                .all()
            )
            projection = (
                await session.execute(
                    select(device_registrations.c.key_version).where(
                        device_registrations.c.id == registration.id
                    )
                )
            ).scalar_one()
        assert current_versions == [2]
        assert projection == 2
    finally:
        async with sessions.begin() as session:
            await session.execute(
                delete(device_key_transitions).where(
                    device_key_transitions.c.registration_id == registration.id
                )
            )
            await session.execute(
                delete(device_registration_keys).where(
                    device_registration_keys.c.registration_id == registration.id
                )
            )
            await session.execute(
                delete(device_registrations).where(
                    device_registrations.c.id == registration.id
                )
            )
        await engine.dispose()
