"""
Device Registration Service

Manages user device registrations for push notifications and key-based
challenge/response authentication.

Port: 8014
"""

from __future__ import annotations

import asyncio
import logging
import os
import uuid
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Annotated

from device_registration.challenges import ChallengeStore
from device_registration.infrastructure.adapters import (
    PostgresDeviceRegistrationRepository,
)
from device_registration.infrastructure.models import mapper_registry
from device_registration.keys import (
    MAX_KEY_VERSION,
    MAX_ROTATION_GRACE_SECONDS,
    DeviceKey,
    DeviceKeyConflictError,
    DeviceKeyState,
    InactiveDeviceRegistrationError,
)
from device_registration.native import (
    challenge_binding_matches,
    challenge_key_is_eligible,
    initialize_device_auth_backend,
    validate_public_key,
    verify_challenge_signature,
)
from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Query, Request
from marty_common.org_authorization import get_organization_client
from marty_common.service_setup import create_service_app
from pydantic import BaseModel, Field
from sqlalchemy import inspect

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SERVICE_NAME = "device-registration-service"
SERVICE_PORT = int(os.environ.get("DEVICE_REGISTRATION_SERVICE_PORT", "8014"))

# MIP §20.3 — Challenge nonce TTL (seconds)
_CHALLENGE_TTL_SECONDS = int(os.environ.get("DEVICE_CHALLENGE_TTL", "300"))
REDIS_URL = os.environ.get("REDIS_URL", "")


def get_config() -> dict[str, str]:
    return {
        "database_url": os.environ.get(
            "DATABASE_URL",
        ),
    }


def _rotation_grace_seconds() -> int:
    raw = os.environ.get("DEVICE_KEY_ROTATION_GRACE_SECONDS", "300")
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError("DEVICE_KEY_ROTATION_GRACE_SECONDS must be an integer") from exc
    if not 0 <= value <= MAX_ROTATION_GRACE_SECONDS:
        raise RuntimeError(
            "DEVICE_KEY_ROTATION_GRACE_SECONDS must be between 0 and "
            f"{MAX_ROTATION_GRACE_SECONDS}"
        )
    return value


class Platform(str, Enum):
    IOS = "ios"
    ANDROID = "android"
    WEB = "web"


@dataclass
class DevicePreferences:
    credential_notifications: bool = True
    verification_notifications: bool = True
    system_notifications: bool = True
    quiet_hours_start: str | None = None
    quiet_hours_end: str | None = None


@dataclass
class DeviceRegistration:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str = ""
    organization_id: str | None = None
    device_id: str = ""
    platform: Platform = Platform.WEB
    fcm_token: str = ""
    app_version: str | None = None
    os_version: str | None = None
    device_model: str | None = None
    preferences: DevicePreferences = field(default_factory=DevicePreferences)
    public_key_der: str | None = None
    public_key_kid: str | None = None
    key_valid_from: datetime | None = None
    key_valid_until: datetime | None = None
    key_version: int | None = None
    is_active: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen_at: datetime | None = None


class InMemoryDeviceRepository:
    def __init__(self):
        self._registrations: dict[str, DeviceRegistration] = {}
        self._keys: dict[str, dict[int, DeviceKey]] = {}
        self._lock = asyncio.Lock()

    async def save(self, registration: DeviceRegistration) -> DeviceRegistration:
        async with self._lock:
            existing = next(
                (
                    record for record in self._registrations.values()
                    if record.is_active
                    and record.user_id == registration.user_id
                    and record.device_id == registration.device_id
                    and record.organization_id == registration.organization_id
                ),
                None,
            )
            if existing:
                registration.id = existing.id
                registration.created_at = existing.created_at
                if existing.key_version is not None and (
                    registration.public_key_der != existing.public_key_der
                    or registration.public_key_kid != existing.public_key_kid
                ):
                    raise DeviceKeyConflictError(
                        "existing device keys must use the rotation transition"
                    )
            if registration.public_key_der and registration.key_version is None:
                now = datetime.now(timezone.utc)
                registration.key_version = 1
                registration.key_valid_from = now
                registration.key_valid_until = None
                self._keys.setdefault(registration.id, {})[1] = DeviceKey(
                    id=str(uuid.uuid4()),
                    registration_id=registration.id,
                    key_version=1,
                    public_key_der=registration.public_key_der,
                    public_key_kid=registration.public_key_kid or "",
                    state=DeviceKeyState.CURRENT,
                    valid_from=now,
                    created_at=now,
                )
            self._registrations[registration.id] = registration
            return registration

    async def get(self, registration_id: str) -> DeviceRegistration | None:
        return self._registrations.get(registration_id)

    async def list_for_user(self, user_id: str, organization_id: str | None = None) -> list[DeviceRegistration]:
        return [
            record for record in self._registrations.values()
            if record.user_id == user_id and (organization_id is None or record.organization_id == organization_id)
        ]

    async def rotate_key(
        self,
        registration_id: str,
        *,
        expected_version: int,
        public_key_der: str,
        public_key_kid: str,
        grace_seconds: int,
    ) -> DeviceRegistration:
        async with self._lock:
            if not 0 <= grace_seconds <= MAX_ROTATION_GRACE_SECONDS:
                raise ValueError("device key rotation grace is outside server bounds")
            record = self._registrations.get(registration_id)
            if record is None or record.key_version != expected_version:
                raise DeviceKeyConflictError("current device key version changed")
            if not record.is_active:
                raise InactiveDeviceRegistrationError(
                    "inactive device registrations cannot rotate keys"
                )
            if expected_version >= MAX_KEY_VERSION:
                raise DeviceKeyConflictError("device key version limit reached")
            old = self._keys.get(registration_id, {}).get(expected_version)
            if old is None or old.state is not DeviceKeyState.CURRENT:
                raise DeviceKeyConflictError("current device key version changed")
            now = datetime.now(timezone.utc)
            self._keys[registration_id][expected_version] = DeviceKey(
                **{
                    **old.__dict__,
                    "state": DeviceKeyState.RETIRING,
                    "rotated_at": now,
                    "retire_at": now + timedelta(seconds=grace_seconds),
                }
            )
            new_version = expected_version + 1
            self._keys[registration_id][new_version] = DeviceKey(
                id=str(uuid.uuid4()),
                registration_id=registration_id,
                key_version=new_version,
                public_key_der=public_key_der,
                public_key_kid=public_key_kid,
                state=DeviceKeyState.CURRENT,
                valid_from=now,
                created_at=now,
            )
            record.public_key_der = public_key_der
            record.public_key_kid = public_key_kid
            record.key_valid_from = now
            record.key_valid_until = None
            record.key_version = new_version
            record.updated_at = now
            record.last_seen_at = now
            return record

    async def deactivate(self, registration_id: str) -> DeviceRegistration | None:
        async with self._lock:
            record = self._registrations.get(registration_id)
            if record is None:
                return None
            now = datetime.now(timezone.utc)
            record.is_active = False
            record.updated_at = now
            for version, key in self._keys.get(registration_id, {}).items():
                if key.state in {DeviceKeyState.CURRENT, DeviceKeyState.RETIRING}:
                    self._keys[registration_id][version] = DeviceKey(
                        **{
                            **key.__dict__,
                            "state": DeviceKeyState.REVOKED,
                            "revoked_at": now,
                        }
                    )
            record.public_key_der = None
            record.public_key_kid = None
            record.key_valid_from = None
            record.key_valid_until = None
            record.key_version = None
            return record

    async def resolve_challenge_key(
        self,
        challenge,
        *,
        purpose: str,
        audience: str,
        now: datetime | None = None,
    ) -> DeviceKey | None:
        if challenge.registration_id is None or challenge.key_version is None:
            return None
        record = self._registrations.get(challenge.registration_id)
        key = self._keys.get(challenge.registration_id, {}).get(
            challenge.key_version
        )
        if record is None or key is None:
            return None
        return key if challenge_key_is_eligible(
            key,
            registration_active=record.is_active,
            challenge=challenge,
            purpose=purpose,
            audience=audience,
            now=now,
        ) else None

class DevicePreferencesModel(BaseModel):
    credential_notifications: bool = True
    verification_notifications: bool = True
    system_notifications: bool = True
    quiet_hours_start: str | None = None
    quiet_hours_end: str | None = None


class CreateDeviceRegistrationRequest(BaseModel):
    user_id: str | None = Field(None, max_length=255)
    organization_id: str | None = Field(None, max_length=255)
    device_id: str = Field(min_length=1, max_length=255)
    platform: str = Field(min_length=1, max_length=50)
    fcm_token: str = Field(min_length=1, max_length=4096)
    app_version: str | None = None
    os_version: str | None = None
    device_model: str | None = None
    preferences: DevicePreferencesModel = Field(default_factory=DevicePreferencesModel)
    public_key_der: str | None = Field(None, max_length=8192)
    public_key_kid: str | None = Field(None, min_length=43, max_length=43)
    key_valid_from: str | None = None
    key_valid_until: str | None = None
    is_active: bool = True


class UpdateDeviceRegistrationRequest(BaseModel):
    fcm_token: str | None = None
    app_version: str | None = None
    os_version: str | None = None
    device_model: str | None = None
    preferences: DevicePreferencesModel | None = None
    public_key_der: str | None = Field(None, max_length=8192)
    public_key_kid: str | None = Field(None, min_length=43, max_length=43)
    key_valid_from: str | None = None
    key_valid_until: str | None = None
    expected_key_version: int | None = Field(
        None, ge=1, le=MAX_KEY_VERSION
    )
    is_active: bool | None = None
    last_seen_at: str | None = None


class DeviceRegistrationResponse(BaseModel):
    id: str
    user_id: str
    organization_id: str | None = None
    device_id: str
    platform: str
    fcm_token: str
    app_version: str | None = None
    os_version: str | None = None
    device_model: str | None = None
    preferences: dict = Field(default_factory=dict)
    public_key_der: str | None = None
    public_key_kid: str | None = None
    key_valid_from: str | None = None
    key_valid_until: str | None = None
    key_version: int | None = Field(None, ge=1, le=MAX_KEY_VERSION)
    is_active: bool
    created_at: str
    updated_at: str
    last_seen_at: str | None = None


class ChallengeRequest(BaseModel):
    device_id: str = Field(min_length=1, max_length=255)
    public_key_der: str = Field(min_length=1, max_length=8192)
    public_key_kid: str = Field(min_length=43, max_length=43)
    registration_id: str | None = Field(None, max_length=36)
    expected_key_version: int | None = Field(
        None, ge=1, le=MAX_KEY_VERSION
    )


class ChallengeResponseModel(BaseModel):
    challenge_id: str
    challenge: str
    algorithm: str = "PS256"
    audience: str = "marty-device-registration"
    expires_in: int = _CHALLENGE_TTL_SECONDS


_challenge_store: ChallengeStore | None = None


router = APIRouter(prefix="/v1/devices", tags=["devices"])

_repo: InMemoryDeviceRepository | PostgresDeviceRegistrationRepository | None = None


def get_repo() -> InMemoryDeviceRepository | PostgresDeviceRegistrationRepository:
    if _repo is None:
        raise RuntimeError("Service not configured")
    return _repo


def get_challenge_store() -> ChallengeStore:
    if _challenge_store is None:
        raise RuntimeError("Challenge store is not configured")
    return _challenge_store


async def init_challenge_store() -> ChallengeStore:
    global _challenge_store
    _challenge_store = None
    environment = os.environ.get("ENVIRONMENT", "development").strip().lower()
    allow_in_memory = environment in {"development", "dev", "local", "test"}
    if REDIS_URL:
        client = None
        try:
            import redis.asyncio as aioredis

            client = aioredis.from_url(REDIS_URL, decode_responses=False)
            await client.ping()
            _challenge_store = ChallengeStore(client, _CHALLENGE_TTL_SECONDS)
            return _challenge_store
        except Exception as exc:
            if client is not None:
                await client.aclose()
            if not allow_in_memory:
                raise RuntimeError(
                    "Redis is required for atomic device challenges in production"
                ) from exc
            logger.warning(
                "Redis unavailable; using development-only device challenges: %s",
                exc,
            )
    elif not allow_in_memory:
        raise RuntimeError(
            "REDIS_URL is required for atomic device challenges in production"
        )
    _challenge_store = ChallengeStore(None, _CHALLENGE_TTL_SECONDS)
    return _challenge_store


def get_current_user_id(x_user_id: Annotated[str, Header()]) -> str:
    return x_user_id


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid key timestamp") from exc
    if parsed.tzinfo is None:
        raise HTTPException(status_code=400, detail="Key timestamps require a timezone")
    return parsed


def _validate_public_key(public_key_der: str, public_key_kid: str | None):
    if not public_key_kid:
        raise HTTPException(
            status_code=400,
            detail="public_key_kid is required when public_key_der is present",
        )
    try:
        return validate_public_key(public_key_der, public_key_kid)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


async def _consume_key_proof(
    *,
    store: ChallengeStore,
    user_id: str,
    device_id: str,
    public_key_der: str,
    public_key_kid: str | None,
    challenge_id: str | None,
    signature: str | None,
    registration_id: str | None,
    expected_key_version: int | None,
    purpose: str,
) -> str:
    inspection = _validate_public_key(public_key_der, public_key_kid)
    if not challenge_id or not signature:
        raise HTTPException(
            status_code=400,
            detail="device challenge id and signature are required for public key changes",
        )
    record = await store.get(challenge_id)
    if record is None:
        raise HTTPException(status_code=400, detail="Device challenge is invalid or expired")
    bindings = challenge_binding_matches(
        record,
        user_id=user_id,
        device_id=device_id,
        public_key_kid=public_key_kid or "",
        public_key_sha256=inspection["public_key_sha256"],
        registration_id=registration_id,
        key_version=expected_key_version,
        purpose=purpose,
        audience="marty-device-registration",
    )
    if not bindings:
        raise HTTPException(status_code=400, detail="Device challenge binding mismatch")
    try:
        verify_challenge_signature(public_key_der, record, signature)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not await store.consume(record):
        raise HTTPException(status_code=409, detail="Device challenge was already consumed")
    return public_key_kid or ""


def _to_response(record: DeviceRegistration) -> DeviceRegistrationResponse:
    return DeviceRegistrationResponse(
        id=record.id,
        user_id=record.user_id,
        organization_id=record.organization_id,
        device_id=record.device_id,
        platform=record.platform.value,
        fcm_token=record.fcm_token,
        app_version=record.app_version,
        os_version=record.os_version,
        device_model=record.device_model,
        preferences={
            "credential_notifications": record.preferences.credential_notifications,
            "verification_notifications": record.preferences.verification_notifications,
            "system_notifications": record.preferences.system_notifications,
            "quiet_hours_start": record.preferences.quiet_hours_start,
            "quiet_hours_end": record.preferences.quiet_hours_end,
        },
        public_key_der=record.public_key_der,
        public_key_kid=record.public_key_kid,
        key_valid_from=record.key_valid_from.isoformat() if record.key_valid_from else None,
        key_valid_until=record.key_valid_until.isoformat() if record.key_valid_until else None,
        key_version=record.key_version,
        is_active=record.is_active,
        created_at=record.created_at.isoformat(),
        updated_at=record.updated_at.isoformat(),
        last_seen_at=record.last_seen_at.isoformat() if record.last_seen_at else None,
    )


async def _verify_org_membership(request: Request, user_id: str, organization_id: str | None) -> None:
    if organization_id is None:
        return
    org_client = await get_organization_client(request)
    membership = await org_client.get_membership(user_id, organization_id)
    if not membership or not membership.is_active():
        raise HTTPException(status_code=403, detail="Not a member of this organization")


# MIP §20.3 — Challenge endpoint for proof-of-possession
@router.post("/challenge", response_model=ChallengeResponseModel)
async def request_challenge(
    body: ChallengeRequest,
    user_id: str = Depends(get_current_user_id),
    store: ChallengeStore = Depends(get_challenge_store),
    repo: InMemoryDeviceRepository | PostgresDeviceRegistrationRepository = Depends(get_repo),
) -> ChallengeResponseModel:
    """Issue a challenge nonce that the device must sign to prove key possession."""
    inspection = _validate_public_key(
        body.public_key_der,
        body.public_key_kid,
    )
    registration: DeviceRegistration | None = None
    if body.registration_id is not None:
        registration = await repo.get(body.registration_id)
        if (
            registration is None
            or registration.user_id != user_id
            or registration.device_id != body.device_id
        ):
            raise HTTPException(status_code=404, detail="Device registration not found")
    else:
        matches = [
            candidate
            for candidate in await repo.list_for_user(user_id)
            if candidate.device_id == body.device_id and candidate.is_active
        ]
        if len(matches) > 1:
            raise HTTPException(
                status_code=400,
                detail="registration_id is required for an ambiguous device_id",
            )
        if matches:
            registration = matches[0]
    if registration is not None and not registration.is_active:
        raise HTTPException(status_code=409, detail="Device registration is inactive")

    expected_version = registration.key_version if registration else None
    if expected_version is not None:
        if body.expected_key_version is None:
            raise HTTPException(
                status_code=400,
                detail="expected_key_version is required for key rotation",
            )
        if body.expected_key_version != expected_version:
            raise HTTPException(status_code=409, detail="Current device key version changed")
        purpose = "device_key_rotation"
    else:
        if body.expected_key_version is not None:
            raise HTTPException(
                status_code=400,
                detail="expected_key_version requires an existing current key",
            )
        purpose = "device_registration"

    record = await store.issue(
        user_id,
        body.device_id,
        body.public_key_kid,
        inspection["public_key_sha256"],
        registration_id=registration.id if registration else None,
        key_version=expected_version,
        purpose=purpose,
    )
    return ChallengeResponseModel(
        challenge_id=record.challenge_id,
        challenge=record.encoded_message(),
    )


@router.post("", response_model=DeviceRegistrationResponse, response_model_exclude_none=True)
async def register_device(
    body: CreateDeviceRegistrationRequest,
    request: Request,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryDeviceRepository | PostgresDeviceRegistrationRepository = Depends(get_repo),
    challenge_store: ChallengeStore = Depends(get_challenge_store),
    challenge_id: Annotated[
        str | None,
        Header(alias="X-Device-Challenge-Id"),
    ] = None,
    challenge_signature: Annotated[
        str | None,
        Header(alias="X-Device-Challenge-Signature"),
    ] = None,
) -> DeviceRegistrationResponse:
    if body.user_id and body.user_id != user_id:
        raise HTTPException(status_code=403, detail="user_id must match authenticated user")
    effective_user_id = user_id
    await _verify_org_membership(request, user_id, body.organization_id)

    if body.public_key_der is not None and not body.is_active:
        raise HTTPException(
            status_code=400,
            detail="an initial device key requires an active registration",
        )

    now = datetime.now(timezone.utc)
    if body.key_valid_from is not None or body.key_valid_until is not None:
        raise HTTPException(
            status_code=400,
            detail="key validity timestamps are server-assigned",
        )
    public_key_kid = body.public_key_kid
    if body.public_key_der:
        public_key_kid = await _consume_key_proof(
            store=challenge_store,
            user_id=user_id,
            device_id=body.device_id,
            public_key_der=body.public_key_der,
            public_key_kid=body.public_key_kid,
            challenge_id=challenge_id,
            signature=challenge_signature,
            registration_id=None,
            expected_key_version=None,
            purpose="device_registration",
        )
    elif public_key_kid:
        raise HTTPException(
            status_code=400,
            detail="public_key_kid requires public_key_der",
        )

    registration = DeviceRegistration(
        user_id=effective_user_id,
        organization_id=body.organization_id,
        device_id=body.device_id,
        platform=Platform(body.platform),
        fcm_token=body.fcm_token,
        app_version=body.app_version,
        os_version=body.os_version,
        device_model=body.device_model,
        preferences=DevicePreferences(**body.preferences.model_dump()),
        public_key_der=body.public_key_der,
        public_key_kid=public_key_kid,
        key_valid_from=now if body.public_key_der else None,
        key_valid_until=None,
        is_active=body.is_active,
        updated_at=now,
        last_seen_at=now,
    )
    try:
        saved = await repo.save(registration)
    except DeviceKeyConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    logger.info("Registered device %s for user %s", saved.device_id, saved.user_id)
    return _to_response(saved)


@router.get("", response_model=list[DeviceRegistrationResponse], response_model_exclude_none=True)
async def list_devices(
    request: Request,
    organization_id: str | None = Query(None),
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryDeviceRepository | PostgresDeviceRegistrationRepository = Depends(get_repo),
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[DeviceRegistrationResponse]:
    await _verify_org_membership(request, user_id, organization_id)
    records = await repo.list_for_user(user_id, organization_id)
    return [_to_response(record) for record in records[offset:offset + limit]]


@router.get("/{registration_id}", response_model=DeviceRegistrationResponse, response_model_exclude_none=True)
async def get_device(
    registration_id: str,
    request: Request,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryDeviceRepository | PostgresDeviceRegistrationRepository = Depends(get_repo),
) -> DeviceRegistrationResponse:
    record = await repo.get(registration_id)
    if not record or record.user_id != user_id:
        raise HTTPException(status_code=404, detail="Device registration not found")
    await _verify_org_membership(request, user_id, record.organization_id)
    return _to_response(record)


@router.patch("/{registration_id}", response_model=DeviceRegistrationResponse, response_model_exclude_none=True)
async def update_device(
    registration_id: str,
    body: UpdateDeviceRegistrationRequest,
    request: Request,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryDeviceRepository | PostgresDeviceRegistrationRepository = Depends(get_repo),
    challenge_store: ChallengeStore = Depends(get_challenge_store),
    challenge_id: Annotated[
        str | None,
        Header(alias="X-Device-Challenge-Id"),
    ] = None,
    challenge_signature: Annotated[
        str | None,
        Header(alias="X-Device-Challenge-Signature"),
    ] = None,
) -> DeviceRegistrationResponse:
    record = await repo.get(registration_id)
    if not record or record.user_id != user_id:
        raise HTTPException(status_code=404, detail="Device registration not found")
    await _verify_org_membership(request, user_id, record.organization_id)

    if body.key_valid_from is not None or body.key_valid_until is not None:
        raise HTTPException(
            status_code=400,
            detail="key validity timestamps are server-assigned",
        )
    if body.public_key_der is not None:
        combined_fields = body.model_fields_set - {
            "public_key_der",
            "public_key_kid",
            "expected_key_version",
        }
        if combined_fields:
            raise HTTPException(
                status_code=400,
                detail="key rotation cannot be combined with registration metadata changes",
            )
        expected_version = record.key_version
        if expected_version is not None and body.expected_key_version is None:
            raise HTTPException(
                status_code=400,
                detail="expected_key_version is required for key rotation",
            )
        if body.expected_key_version != expected_version:
            raise HTTPException(status_code=409, detail="Current device key version changed")
        purpose = (
            "device_key_rotation"
            if expected_version is not None
            else "device_registration"
        )
        key_id = await _consume_key_proof(
            store=challenge_store,
            user_id=user_id,
            device_id=record.device_id,
            public_key_der=body.public_key_der,
            public_key_kid=body.public_key_kid,
            challenge_id=challenge_id,
            signature=challenge_signature,
            registration_id=registration_id,
            expected_key_version=expected_version,
            purpose=purpose,
        )
        try:
            if expected_version is None:
                record.public_key_der = body.public_key_der
                record.public_key_kid = key_id
                record.key_valid_from = datetime.now(timezone.utc)
                record.key_valid_until = None
                saved = await repo.save(record)
            else:
                saved = await repo.rotate_key(
                    registration_id,
                    expected_version=expected_version,
                    public_key_der=body.public_key_der,
                    public_key_kid=key_id,
                    grace_seconds=_rotation_grace_seconds(),
                )
        except DeviceKeyConflictError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except InactiveDeviceRegistrationError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return _to_response(saved)
    elif body.public_key_kid is not None:
        raise HTTPException(
            status_code=400,
            detail="public_key_kid cannot change without public_key_der and proof",
        )
    elif body.expected_key_version is not None:
        raise HTTPException(
            status_code=400,
            detail="expected_key_version requires a public key rotation",
        )

    if body.is_active is True and not record.is_active:
        raise HTTPException(
            status_code=409,
            detail="a deactivated device must be registered with a new key",
        )
    if body.is_active is False:
        deactivated = await repo.deactivate(registration_id)
        if deactivated is None:
            raise HTTPException(status_code=404, detail="Device registration not found")
        return _to_response(deactivated)

    parsed_last_seen_at = (
        _parse_dt(body.last_seen_at) if body.last_seen_at is not None else None
    )

    if body.fcm_token is not None:
        record.fcm_token = body.fcm_token
    if body.app_version is not None:
        record.app_version = body.app_version
    if body.os_version is not None:
        record.os_version = body.os_version
    if body.device_model is not None:
        record.device_model = body.device_model
    if body.preferences is not None:
        record.preferences = DevicePreferences(**body.preferences.model_dump())
    if body.last_seen_at is not None:
        record.last_seen_at = parsed_last_seen_at
    else:
        record.last_seen_at = datetime.now(timezone.utc)
    record.updated_at = datetime.now(timezone.utc)
    await repo.save(record)
    return _to_response(record)


@router.delete("/{registration_id}")
async def delete_device(
    registration_id: str,
    request: Request,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryDeviceRepository | PostgresDeviceRegistrationRepository = Depends(get_repo),
) -> dict[str, bool]:
    record = await repo.get(registration_id)
    if not record or record.user_id != user_id:
        raise HTTPException(status_code=404, detail="Device registration not found")
    await _verify_org_membership(request, user_id, record.organization_id)
    # Device registrations are audit records. MIP §14 requires DELETE to
    # deactivate the registration instead of physically removing it.
    await repo.deactivate(registration_id)
    return {"success": True}


def _require_migrated_device_schema(connection) -> None:
    """Fail closed when the owned Device Registration migration was not run."""
    inspector = inspect(connection)
    expected = {
        table.name
        for table in mapper_registry.metadata.tables.values()
        if table.schema == "device_registration_service"
    }
    actual = set(
        inspector.get_table_names(schema="device_registration_service")
    )
    missing = expected - actual
    if missing:
        raise RuntimeError(
            "Device Registration migrations are required; missing tables: "
            + ", ".join(sorted(missing))
        )
    if "alembic_version" not in actual:
        raise RuntimeError("Device Registration migration version table is missing")
    registration_columns = {
        column["name"]
        for column in inspector.get_columns(
            "device_registrations", schema="device_registration_service"
        )
    }
    if "key_version" not in registration_columns:
        raise RuntimeError("versioned Device Registration key projection is missing")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    global _repo, _challenge_store
    logger.info("Starting %s...", SERVICE_NAME)
    _rotation_grace_seconds()
    native_diagnostics = initialize_device_auth_backend()
    app.state.native_backend_diagnostics = native_diagnostics
    logger.info(
        "Native device-auth backend ready: backend=%s version=%s revision=%s",
        native_diagnostics["backend"],
        native_diagnostics["version"],
        native_diagnostics.get("build_revision", "unknown"),
    )
    from marty_common.database import DatabaseConfig, DatabaseManager
    db = DatabaseManager(DatabaseConfig.from_env("device-registration"))
    async with db.engine.connect() as conn:
        await conn.run_sync(_require_migrated_device_schema)
    session_factory = db.session_factory
    _repo = PostgresDeviceRegistrationRepository(session_factory)
    await init_challenge_store()

    from common.di import setup_org_client, teardown_org_client
    await setup_org_client(app, "device-registration")
    app.state.db_engine = db.engine

    yield
    logger.info("Shutting down %s...", SERVICE_NAME)
    await teardown_org_client(app)
    if _challenge_store is not None:
        await _challenge_store.close()
        _challenge_store = None
    await db.close()


def create_app() -> FastAPI:
    created = create_service_app(
        title="Device Registration Service",
        description="Manages user device registrations for push and challenge-response authentication",
        service_name=SERVICE_NAME,
        lifespan=lifespan,
        routers=[router],
    )

    @created.get("/health/native-backend")
    async def native_backend_health() -> dict:
        diagnostics = getattr(created.state, "native_backend_diagnostics", None)
        if not isinstance(diagnostics, dict) or diagnostics.get("available") is not True:
            raise HTTPException(status_code=503, detail="Native backend is unavailable")
        return {"status": "ready", **diagnostics}

    return created


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=SERVICE_PORT, reload=False)
