"""
Device Registration Service

Manages user device registrations for push notifications and key-based
challenge/response authentication.

Port: 8014
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import secrets
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Annotated, AsyncGenerator

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from marty_common.org_authorization import get_organization_client
from marty_common.middleware import RequestIdMiddleware, RequestLoggingMiddleware
from marty_common.service_setup import create_service_app
from device_registration.infrastructure.adapters import PostgresDeviceRegistrationRepository
from device_registration.infrastructure.models import mapper_registry

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SERVICE_NAME = "device-registration-service"
SERVICE_PORT = int(os.environ.get("DEVICE_REGISTRATION_SERVICE_PORT", "8014"))

# MIP §20.3 — Challenge nonce TTL (seconds)
_CHALLENGE_TTL_SECONDS = int(os.environ.get("DEVICE_CHALLENGE_TTL", "300"))


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

    async def delete(self, registration_id: str) -> None:
        self._registrations.pop(registration_id, None)


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
    challenge_nonce: str | None = None


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


# ── MIP §20.3 — Challenge nonce store for proof-of-possession ──────────────
@dataclass
class _ChallengeEntry:
    nonce: str
    device_id: str
    created_at: datetime


class ChallengeNonceStore:
    """In-memory nonce store for device key proof-of-possession challenges."""

    def __init__(self, ttl_seconds: int = _CHALLENGE_TTL_SECONDS):
        self._entries: dict[str, _ChallengeEntry] = {}
        self._ttl = timedelta(seconds=ttl_seconds)

    def create(self, device_id: str) -> str:
        self._purge_expired()
        nonce = secrets.token_urlsafe(32)
        self._entries[nonce] = _ChallengeEntry(
            nonce=nonce, device_id=device_id, created_at=datetime.now(timezone.utc)
        )
        return nonce

    def consume(self, nonce: str, device_id: str) -> bool:
        self._purge_expired()
        entry = self._entries.pop(nonce, None)
        if entry is None:
            return False
        return entry.device_id == device_id

    def _purge_expired(self) -> None:
        now = datetime.now(timezone.utc)
        expired = [k for k, v in self._entries.items() if now - v.created_at > self._ttl]
        for k in expired:
            del self._entries[k]


class ChallengeRequest(BaseModel):
    device_id: str


class ChallengeResponseModel(BaseModel):
    nonce: str
    expires_in: int = _CHALLENGE_TTL_SECONDS


_challenge_store = ChallengeNonceStore()


router = APIRouter(prefix="/v1/devices", tags=["devices"])

_repo: InMemoryDeviceRepository | PostgresDeviceRegistrationRepository | None = None


def get_repo() -> InMemoryDeviceRepository | PostgresDeviceRegistrationRepository:
    if _repo is None:
        raise RuntimeError("Service not configured")
    return _repo


def get_current_user_id(x_user_id: Annotated[str, Header()]) -> str:
    return x_user_id


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _compute_public_key_kid(public_key_der: str) -> str:
    padding = "=" * (-len(public_key_der) % 4)
    raw = base64.urlsafe_b64decode(public_key_der + padding)
    digest = hashlib.sha256(raw).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


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
) -> ChallengeResponseModel:
    """Issue a challenge nonce that the device must sign to prove key possession."""
    nonce = _challenge_store.create(body.device_id)
    return ChallengeResponseModel(nonce=nonce, expires_in=_CHALLENGE_TTL_SECONDS)


@router.post("", response_model=DeviceRegistrationResponse, response_model_exclude_none=True)
async def register_device(
    body: CreateDeviceRegistrationRequest,
    request: Request,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryDeviceRepository | PostgresDeviceRegistrationRepository = Depends(get_repo),
) -> DeviceRegistrationResponse:
    effective_user_id = body.user_id or user_id
    await _verify_org_membership(request, user_id, body.organization_id)

    public_key_kid = body.public_key_kid
    if body.public_key_der:
        # MIP §20.3 — Require challenge nonce for proof-of-possession
        if not body.challenge_nonce:
            raise HTTPException(
                status_code=400,
                detail="challenge_nonce is required when registering a public key",
            )
        if not _challenge_store.consume(body.challenge_nonce, body.device_id):
            raise HTTPException(
                status_code=400,
                detail="Invalid or expired challenge nonce",
            )
        computed_kid = _compute_public_key_kid(body.public_key_der)
        if public_key_kid and public_key_kid != computed_kid:
            raise HTTPException(status_code=400, detail="public_key_kid does not match public_key_der")
        public_key_kid = computed_kid

    now = datetime.now(timezone.utc)
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
        key_valid_until=_parse_dt(body.key_valid_until),
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
) -> DeviceRegistrationResponse:
    record = await repo.get(registration_id)
    if not record or record.user_id != user_id:
        raise HTTPException(status_code=404, detail="Device registration not found")
    await _verify_org_membership(request, user_id, record.organization_id)

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
    if body.public_key_der is not None:
        record.public_key_der = body.public_key_der
        computed_kid = _compute_public_key_kid(body.public_key_der)
        if body.public_key_kid and body.public_key_kid != computed_kid:
            raise HTTPException(status_code=400, detail="public_key_kid does not match public_key_der")
        record.public_key_kid = computed_kid
    elif body.public_key_kid is not None:
        record.public_key_kid = body.public_key_kid
    if body.key_valid_from is not None:
        record.key_valid_from = _parse_dt(body.key_valid_from)
    if body.key_valid_until is not None:
        record.key_valid_until = _parse_dt(body.key_valid_until)
    if body.is_active is not None:
        record.is_active = body.is_active
    if body.last_seen_at is not None:
        record.last_seen_at = _parse_dt(body.last_seen_at)
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
    await repo.delete(registration_id)
    return {"success": True}


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    global _repo
    logger.info("Starting %s...", SERVICE_NAME)
    config = get_config()
    from marty_common.database import DatabaseManager, DatabaseConfig
    db = DatabaseManager(DatabaseConfig.from_env("device-registration"))
    async with db.engine.begin() as conn:
        await conn.execute(text("CREATE SCHEMA IF NOT EXISTS device_registration_service"))
        await conn.run_sync(mapper_registry.metadata.create_all)
    session_factory = db.session_factory
    _repo = PostgresDeviceRegistrationRepository(session_factory)

    from common.di import setup_org_client, teardown_org_client
    await setup_org_client(app, "device-registration")
    app.state.db_engine = db.engine

    yield
    logger.info("Shutting down %s...", SERVICE_NAME)
    await teardown_org_client(app)
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
    uvicorn.run("device_registration.main:app", host="0.0.0.0", port=SERVICE_PORT, reload=True)
