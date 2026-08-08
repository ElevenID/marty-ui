"""
Device Registration Service

Manages user device registrations for push notifications and key-based
challenge/response authentication.

Port: 8014
"""

from __future__ import annotations

import hmac
import logging
import os
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, AsyncGenerator

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import text

from marty_common.org_authorization import get_organization_client
from marty_common.service_setup import create_service_app
from device_registration.infrastructure.adapters import PostgresDeviceRegistrationRepository
from device_registration.infrastructure.models import mapper_registry
from device_registration.challenges import ChallengeStore
from device_registration.proof import (
    parse_device_public_key,
    public_key_digest,
    public_key_thumbprint,
    verify_challenge_signature,
)

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
    is_active: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen_at: datetime | None = None


class InMemoryDeviceRepository:
    def __init__(self):
        self._registrations: dict[str, DeviceRegistration] = {}

    async def save(self, registration: DeviceRegistration) -> DeviceRegistration:
        existing = next(
            (
                record for record in self._registrations.values()
                if record.user_id == registration.user_id
                and record.device_id == registration.device_id
                and record.organization_id == registration.organization_id
            ),
            None,
        )
        if existing:
            registration.id = existing.id
            registration.created_at = existing.created_at
        self._registrations[registration.id] = registration
        return registration

    async def get(self, registration_id: str) -> DeviceRegistration | None:
        return self._registrations.get(registration_id)

    async def list_for_user(self, user_id: str, organization_id: str | None = None) -> list[DeviceRegistration]:
        return [
            record for record in self._registrations.values()
            if record.user_id == user_id and (organization_id is None or record.organization_id == organization_id)
        ]

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
    public_key_der: str | None = None
    public_key_kid: str | None = None
    key_valid_from: str | None = None
    key_valid_until: str | None = None
    is_active: bool = True


class UpdateDeviceRegistrationRequest(BaseModel):
    fcm_token: str | None = None
    app_version: str | None = None
    os_version: str | None = None
    device_model: str | None = None
    preferences: DevicePreferencesModel | None = None
    public_key_der: str | None = None
    public_key_kid: str | None = None
    key_valid_from: str | None = None
    key_valid_until: str | None = None
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
    is_active: bool
    created_at: str
    updated_at: str
    last_seen_at: str | None = None


class ChallengeRequest(BaseModel):
    device_id: str = Field(min_length=1, max_length=255)
    public_key_der: str = Field(min_length=1, max_length=8192)
    public_key_kid: str = Field(min_length=1, max_length=255)


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
        key, raw_der = parse_device_public_key(public_key_der)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    expected_kid = public_key_thumbprint(key)
    if not hmac.compare_digest(public_key_kid, expected_kid):
        raise HTTPException(
            status_code=400,
            detail="public_key_kid must be the RFC 7638 thumbprint of public_key_der",
        )
    return key, raw_der


async def _consume_key_proof(
    *,
    store: ChallengeStore,
    user_id: str,
    device_id: str,
    public_key_der: str,
    public_key_kid: str | None,
    challenge_id: str | None,
    signature: str | None,
) -> str:
    key, raw_der = _validate_public_key(public_key_der, public_key_kid)
    if not challenge_id or not signature:
        raise HTTPException(
            status_code=400,
            detail="device challenge id and signature are required for public key changes",
        )
    record = await store.get(challenge_id)
    if record is None:
        raise HTTPException(status_code=400, detail="Device challenge is invalid or expired")
    bindings = (
        record.user_id == user_id
        and record.device_id == device_id
        and hmac.compare_digest(record.public_key_kid, public_key_kid or "")
        and hmac.compare_digest(record.public_key_sha256, public_key_digest(raw_der))
    )
    if not bindings:
        raise HTTPException(status_code=400, detail="Device challenge binding mismatch")
    try:
        verify_challenge_signature(key, record.message(), signature)
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
) -> ChallengeResponseModel:
    """Issue a challenge nonce that the device must sign to prove key possession."""
    _key, raw_der = _validate_public_key(
        body.public_key_der,
        body.public_key_kid,
    )
    record = await store.issue(
        user_id,
        body.device_id,
        body.public_key_kid,
        public_key_digest(raw_der),
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

    now = datetime.now(timezone.utc)
    key_valid_until = _parse_dt(body.key_valid_until)
    if key_valid_until is not None and key_valid_until <= now:
        raise HTTPException(
            status_code=400,
            detail="key_valid_until must be after key_valid_from",
        )
    public_key_kid = body.public_key_kid
    if body.public_key_der:
        if body.key_valid_from is not None:
            raise HTTPException(
                status_code=400,
                detail="key_valid_from is server-assigned after proof of possession",
            )
        public_key_kid = await _consume_key_proof(
            store=challenge_store,
            user_id=user_id,
            device_id=body.device_id,
            public_key_der=body.public_key_der,
            public_key_kid=body.public_key_kid,
            challenge_id=challenge_id,
            signature=challenge_signature,
        )
    elif public_key_kid:
        raise HTTPException(
            status_code=400,
            detail="public_key_kid requires public_key_der",
        )
    elif body.key_valid_from is not None or body.key_valid_until is not None:
        raise HTTPException(
            status_code=400,
            detail="key validity requires a proved public_key_der",
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
        key_valid_from=now if body.public_key_der else _parse_dt(body.key_valid_from),
        key_valid_until=key_valid_until,
        is_active=body.is_active,
        updated_at=now,
        last_seen_at=now,
    )
    saved = await repo.save(registration)
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

    key_id: str | None = None
    key_valid_from: datetime | None = None
    key_valid_until: datetime | None = None
    parsed_last_seen_at = (
        _parse_dt(body.last_seen_at) if body.last_seen_at is not None else None
    )
    if body.public_key_der is not None:
        if body.key_valid_from is not None:
            raise HTTPException(
                status_code=400,
                detail="key_valid_from is server-assigned after proof of possession",
            )
        key_valid_from = datetime.now(timezone.utc)
        key_valid_until = _parse_dt(body.key_valid_until)
        if key_valid_until is not None and key_valid_until <= key_valid_from:
            raise HTTPException(
                status_code=400,
                detail="key_valid_until must be after key_valid_from",
            )
        key_id = await _consume_key_proof(
            store=challenge_store,
            user_id=user_id,
            device_id=record.device_id,
            public_key_der=body.public_key_der,
            public_key_kid=body.public_key_kid,
            challenge_id=challenge_id,
            signature=challenge_signature,
        )
    elif body.public_key_kid is not None:
        raise HTTPException(
            status_code=400,
            detail="public_key_kid cannot change without public_key_der and proof",
        )
    elif body.key_valid_from is not None or body.key_valid_until is not None:
        raise HTTPException(
            status_code=400,
            detail="key validity cannot change without public key proof",
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
    if body.public_key_der is not None and key_id and key_valid_from:
        record.public_key_der = body.public_key_der
        record.public_key_kid = key_id
        record.key_valid_from = key_valid_from
        record.key_valid_until = key_valid_until
    if body.is_active is not None:
        record.is_active = body.is_active
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
    record.is_active = False
    record.updated_at = datetime.now(timezone.utc)
    await repo.save(record)
    return {"success": True}


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    global _repo, _challenge_store
    logger.info("Starting %s...", SERVICE_NAME)
    from marty_common.database import DatabaseManager, DatabaseConfig
    db = DatabaseManager(DatabaseConfig.from_env("device-registration"))
    async with db.engine.begin() as conn:
        await conn.execute(text("CREATE SCHEMA IF NOT EXISTS device_registration_service"))
        await conn.run_sync(mapper_registry.metadata.create_all)
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
    return create_service_app(
        title="Device Registration Service",
        description="Manages user device registrations for push and challenge-response authentication",
        service_name=SERVICE_NAME,
        lifespan=lifespan,
        routers=[router],
    )


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=SERVICE_PORT, reload=False)
