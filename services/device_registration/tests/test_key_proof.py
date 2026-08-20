from __future__ import annotations

import asyncio
import base64
import hashlib
import os

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import FastAPI
from fastapi.testclient import TestClient

from services.device_registration import main as device
from services.device_registration.challenges import ChallengeStore
from services.device_registration.native import inspect_public_key


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _key_material(key_size: int = 2048):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.PKCS1,
    )
    encoded = _b64url(der)
    kid = (
        inspect_public_key(encoded)["public_key_kid"]
        if key_size >= 2048
        else "w" * 43
    )
    return private_key, encoded, kid


def _sign(private_key, encoded_challenge: str) -> str:
    challenge = base64.urlsafe_b64decode(
        encoded_challenge + "=" * (-len(encoded_challenge) % 4)
    )
    signature = private_key.sign(
        challenge,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=hashes.SHA256.digest_size,
        ),
        hashes.SHA256(),
    )
    return _b64url(signature)


def _client() -> TestClient:
    device._repo = device.InMemoryDeviceRepository()
    device._challenge_store = ChallengeStore(None, 300)
    app = FastAPI()
    app.include_router(device.router)
    return TestClient(app)


def _registration(public_key_der: str, public_key_kid: str) -> dict:
    return {
        "device_id": "device-1",
        "platform": "ios",
        "fcm_token": "sensitive-push-token",
        "public_key_der": public_key_der,
        "public_key_kid": public_key_kid,
    }


def test_registration_requires_and_consumes_key_proof_once() -> None:
    private_key, public_key_der, public_key_kid = _key_material()
    client = _client()
    headers = {"X-User-Id": "user-1"}
    challenge = client.post(
        "/v1/devices/challenge",
        headers=headers,
        json={
            "device_id": "device-1",
            "public_key_der": public_key_der,
            "public_key_kid": public_key_kid,
        },
    )
    assert challenge.status_code == 200
    challenge_body = challenge.json()
    assert challenge_body["algorithm"] == "PS256"
    assert challenge_body["audience"] == "marty-device-registration"

    proof_headers = {
        **headers,
        "X-Device-Challenge-Id": challenge_body["challenge_id"],
        "X-Device-Challenge-Signature": _sign(
            private_key,
            challenge_body["challenge"],
        ),
    }
    registered = client.post(
        "/v1/devices",
        headers=proof_headers,
        json=_registration(public_key_der, public_key_kid),
    )
    assert registered.status_code == 200
    assert registered.json()["user_id"] == "user-1"
    assert registered.json()["public_key_kid"] == public_key_kid

    replay = client.post(
        "/v1/devices",
        headers=proof_headers,
        json=_registration(public_key_der, public_key_kid),
    )
    assert replay.status_code == 400
    assert "invalid or expired" in replay.json()["detail"]


def test_invalid_signature_does_not_burn_challenge() -> None:
    private_key, public_key_der, public_key_kid = _key_material()
    wrong_key, _wrong_der, _wrong_kid = _key_material()
    client = _client()
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
    base_headers = {
        **headers,
        "X-Device-Challenge-Id": challenge["challenge_id"],
    }

    invalid = client.post(
        "/v1/devices",
        headers={
            **base_headers,
            "X-Device-Challenge-Signature": _sign(
                wrong_key,
                challenge["challenge"],
            ),
        },
        json=_registration(public_key_der, public_key_kid),
    )
    assert invalid.status_code == 400
    assert "signature is invalid" in invalid.json()["detail"]

    valid = client.post(
        "/v1/devices",
        headers={
            **base_headers,
            "X-Device-Challenge-Signature": _sign(
                private_key,
                challenge["challenge"],
            ),
        },
        json=_registration(public_key_der, public_key_kid),
    )
    assert valid.status_code == 200


def test_challenge_is_bound_to_authenticated_user_device_and_key() -> None:
    private_key, public_key_der, public_key_kid = _key_material()
    client = _client()
    challenge = client.post(
        "/v1/devices/challenge",
        headers={"X-User-Id": "user-1"},
        json={
            "device_id": "device-1",
            "public_key_der": public_key_der,
            "public_key_kid": public_key_kid,
        },
    ).json()
    signature = _sign(private_key, challenge["challenge"])

    wrong_user = client.post(
        "/v1/devices",
        headers={
            "X-User-Id": "user-2",
            "X-Device-Challenge-Id": challenge["challenge_id"],
            "X-Device-Challenge-Signature": signature,
        },
        json=_registration(public_key_der, public_key_kid),
    )
    assert wrong_user.status_code == 400
    assert "binding mismatch" in wrong_user.json()["detail"]

    wrong_device = client.post(
        "/v1/devices",
        headers={
            "X-User-Id": "user-1",
            "X-Device-Challenge-Id": challenge["challenge_id"],
            "X-Device-Challenge-Signature": signature,
        },
        json={
            **_registration(public_key_der, public_key_kid),
            "device_id": "device-2",
        },
    )
    assert wrong_device.status_code == 400
    assert "binding mismatch" in wrong_device.json()["detail"]

    valid = client.post(
        "/v1/devices",
        headers={
            "X-User-Id": "user-1",
            "X-Device-Challenge-Id": challenge["challenge_id"],
            "X-Device-Challenge-Signature": signature,
        },
        json=_registration(public_key_der, public_key_kid),
    )
    assert valid.status_code == 200


def test_key_rotation_requires_fresh_proof() -> None:
    client = _client()
    created = client.post(
        "/v1/devices",
        headers={"X-User-Id": "user-1"},
        json={
            "device_id": "device-1",
            "platform": "ios",
            "fcm_token": "push-token",
        },
    )
    assert created.status_code == 200
    registration_id = created.json()["id"]
    private_key, public_key_der, public_key_kid = _key_material()

    unproved = client.patch(
        f"/v1/devices/{registration_id}",
        headers={"X-User-Id": "user-1"},
        json={
            "public_key_der": public_key_der,
            "public_key_kid": public_key_kid,
            "fcm_token": "must-not-commit",
        },
    )
    assert unproved.status_code == 400
    unchanged = client.get(
        f"/v1/devices/{registration_id}",
        headers={"X-User-Id": "user-1"},
    )
    assert unchanged.json()["fcm_token"] == "push-token"

    challenge = client.post(
        "/v1/devices/challenge",
        headers={"X-User-Id": "user-1"},
        json={
            "device_id": "device-1",
            "public_key_der": public_key_der,
            "public_key_kid": public_key_kid,
        },
    ).json()
    rotated = client.patch(
        f"/v1/devices/{registration_id}",
        headers={
            "X-User-Id": "user-1",
            "X-Device-Challenge-Id": challenge["challenge_id"],
            "X-Device-Challenge-Signature": _sign(
                private_key,
                challenge["challenge"],
            ),
        },
        json={
            "public_key_der": public_key_der,
            "public_key_kid": public_key_kid,
        },
    )
    assert rotated.status_code == 200
    assert rotated.json()["public_key_kid"] == public_key_kid


def test_authenticated_user_cannot_register_for_another_user() -> None:
    client = _client()
    response = client.post(
        "/v1/devices",
        headers={"X-User-Id": "user-1"},
        json={
            "user_id": "victim-user",
            "device_id": "device-1",
            "platform": "web",
            "fcm_token": "attacker-token",
        },
    )
    assert response.status_code == 403


@pytest.mark.parametrize("key_size", [1024])
def test_challenge_rejects_weak_rsa_key(key_size: int) -> None:
    _private_key, public_key_der, public_key_kid = _key_material(key_size)
    client = _client()
    response = client.post(
        "/v1/devices/challenge",
        headers={"X-User-Id": "user-1"},
        json={
            "device_id": "device-1",
            "public_key_der": public_key_der,
            "public_key_kid": public_key_kid,
        },
    )
    assert response.status_code == 400
    assert "at least 2048 bits" in response.json()["detail"]


def test_rfc7638_kid_is_not_a_raw_der_digest_and_spki_is_rejected() -> None:
    private_key, public_key_der, public_key_kid = _key_material()
    raw_der = base64.urlsafe_b64decode(
        public_key_der + "=" * (-len(public_key_der) % 4)
    )
    old_der_digest = _b64url(hashlib.sha256(raw_der).digest())
    assert public_key_kid != old_der_digest

    spki = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    client = _client()
    response = client.post(
        "/v1/devices/challenge",
        headers={"X-User-Id": "user-1"},
        json={
            "device_id": "device-1",
            "public_key_der": _b64url(spki),
            "public_key_kid": public_key_kid,
        },
    )
    assert response.status_code == 400
    assert "canonical PKCS#1 DER" in response.json()["detail"]


@pytest.mark.asyncio
async def test_real_redis_consumes_challenge_once_across_replicas() -> None:
    url = os.environ.get("DEVICE_CHALLENGE_TEST_REDIS_URL")
    if not url:
        pytest.skip("DEVICE_CHALLENGE_TEST_REDIS_URL is not configured")
    import redis.asyncio as aioredis

    client_a = aioredis.from_url(url, decode_responses=False)
    client_b = aioredis.from_url(url, decode_responses=False)
    try:
        await client_a.ping()
    except Exception as exc:
        await client_a.aclose()
        await client_b.aclose()
        pytest.skip(f"real Redis is unavailable: {exc}")
    store_a = ChallengeStore(client_a, 300)
    store_b = ChallengeStore(client_b, 300)
    record = await store_a.issue("user-1", "device-1", "kid-1", "digest-1")
    try:
        same_record = await store_b.get(record.challenge_id)
        assert same_record == record
        consumed = await asyncio.gather(
            store_a.consume(record),
            store_b.consume(record),
        )
        assert sorted(consumed) == [False, True]
    finally:
        await client_a.delete(f"device-registration:challenge:{record.challenge_id}")
        await store_a.close()
        await store_b.close()


@pytest.mark.asyncio
async def test_production_requires_shared_challenge_store(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setattr(device, "REDIS_URL", "")
    with pytest.raises(RuntimeError, match="REDIS_URL is required"):
        await device.init_challenge_store()
    assert device._challenge_store is None
