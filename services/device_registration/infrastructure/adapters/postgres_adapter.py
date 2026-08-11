"""PostgreSQL adapter for atomic, versioned device-key persistence."""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import TYPE_CHECKING, Any

from device_registration.infrastructure.models import (
    device_key_transitions,
    device_registration_keys,
    device_registrations,
)
from device_registration.keys import (
    MAX_KEY_VERSION,
    MAX_ROTATION_GRACE_SECONDS,
    DeviceKey,
    DeviceKeyConflictError,
    DeviceKeyState,
    InactiveDeviceRegistrationError,
)
from device_registration.native import challenge_key_is_eligible
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

if TYPE_CHECKING:
    from datetime import datetime

    from device_registration.challenges import ChallengeRecord
    from device_registration.main import DeviceRegistration


class PostgresDeviceRegistrationRepository:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]):
        self._session_factory = session_factory

    @staticmethod
    def _to_registration(row: dict[str, Any]) -> DeviceRegistration:
        from device_registration.main import (
            DevicePreferences,
            DeviceRegistration,
            Platform,
        )

        return DeviceRegistration(
            id=row["id"],
            user_id=row["user_id"],
            organization_id=row["organization_id"],
            device_id=row["device_id"],
            platform=Platform(row["platform"]),
            fcm_token=row["fcm_token"],
            app_version=row["app_version"],
            os_version=row["os_version"],
            device_model=row["device_model"],
            preferences=DevicePreferences(**(row["preferences"] or {})),
            public_key_der=row["public_key_der"],
            public_key_kid=row["public_key_kid"],
            key_valid_from=row["key_valid_from"],
            key_valid_until=row["key_valid_until"],
            key_version=row["key_version"],
            is_active=row["is_active"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            last_seen_at=row["last_seen_at"],
        )

    @staticmethod
    def _to_key(row: dict[str, Any]) -> DeviceKey:
        return DeviceKey(
            id=row["id"],
            registration_id=row["registration_id"],
            key_version=row["key_version"],
            public_key_der=row["public_key_der"],
            public_key_kid=row["public_key_kid"],
            state=DeviceKeyState(row["state"]),
            valid_from=row["valid_from"],
            valid_until=row["valid_until"],
            rotated_at=row["rotated_at"],
            retire_at=row["retire_at"],
            revoked_at=row["revoked_at"],
            created_at=row["created_at"],
        )

    @staticmethod
    def _registration_payload(registration: DeviceRegistration) -> dict[str, Any]:
        return {
            "id": registration.id,
            "user_id": registration.user_id,
            "organization_id": registration.organization_id,
            "device_id": registration.device_id,
            "platform": registration.platform.value,
            "fcm_token": registration.fcm_token,
            "app_version": registration.app_version,
            "os_version": registration.os_version,
            "device_model": registration.device_model,
            "preferences": {
                "credential_notifications": registration.preferences.credential_notifications,
                "verification_notifications": registration.preferences.verification_notifications,
                "system_notifications": registration.preferences.system_notifications,
                "quiet_hours_start": registration.preferences.quiet_hours_start,
                "quiet_hours_end": registration.preferences.quiet_hours_end,
            },
            "public_key_der": registration.public_key_der,
            "public_key_kid": registration.public_key_kid,
            "key_valid_from": registration.key_valid_from,
            "key_valid_until": registration.key_valid_until,
            "key_version": registration.key_version,
            "is_active": registration.is_active,
            "updated_at": registration.updated_at,
            "last_seen_at": registration.last_seen_at,
        }

    async def save(self, registration: DeviceRegistration) -> DeviceRegistration:
        """Create/update registration metadata and atomically persist an initial key."""
        async with self._session_factory() as session:
            async with session.begin():
                stmt = (
                    select(device_registrations)
                    .where(
                        device_registrations.c.user_id == registration.user_id,
                        device_registrations.c.device_id == registration.device_id,
                        device_registrations.c.is_active.is_(True),
                        device_registrations.c.organization_id.is_(None)
                        if registration.organization_id is None
                        else device_registrations.c.organization_id
                        == registration.organization_id,
                    )
                    .with_for_update()
                )
                existing = (await session.execute(stmt)).mappings().first()
                create_initial_key = bool(registration.public_key_der)

                if existing:
                    registration.id = existing["id"]
                    registration.created_at = existing["created_at"]
                    if existing["is_active"] and not registration.is_active:
                        raise DeviceKeyConflictError(
                            "device deactivation must use the revocation transition"
                        )
                    if existing["key_version"] is not None:
                        if (
                            registration.public_key_der != existing["public_key_der"]
                            or registration.public_key_kid != existing["public_key_kid"]
                        ):
                            raise DeviceKeyConflictError(
                                "existing device keys must use the rotation transition"
                            )
                        create_initial_key = False

                committed_at = None
                if create_initial_key:
                    committed_at = (
                        await session.execute(select(func.now()))
                    ).scalar_one()
                    registration.key_version = 1
                    registration.key_valid_from = committed_at
                    registration.key_valid_until = None

                payload = self._registration_payload(registration)
                if existing and existing["key_version"] is not None:
                    registration.key_version = existing["key_version"]
                    registration.key_valid_from = existing["key_valid_from"]
                    registration.key_valid_until = existing["key_valid_until"]
                    payload.update(
                        public_key_der=existing["public_key_der"],
                        public_key_kid=existing["public_key_kid"],
                        key_valid_from=existing["key_valid_from"],
                        key_valid_until=existing["key_valid_until"],
                        key_version=existing["key_version"],
                    )

                if existing:
                    await session.execute(
                        device_registrations.update()
                        .where(device_registrations.c.id == registration.id)
                        .values(**payload)
                    )
                else:
                    payload["created_at"] = registration.created_at
                    await session.execute(
                        device_registrations.insert().values(**payload)
                    )

                if create_initial_key:
                    assert committed_at is not None
                    await session.execute(
                        device_registration_keys.insert().values(
                            id=str(uuid.uuid4()),
                            registration_id=registration.id,
                            key_version=1,
                            public_key_der=registration.public_key_der,
                            public_key_kid=registration.public_key_kid,
                            state=DeviceKeyState.CURRENT.value,
                            valid_from=committed_at,
                            valid_until=None,
                            created_at=committed_at,
                        )
                    )
                    await session.execute(
                        device_key_transitions.insert().values(
                            id=str(uuid.uuid4()),
                            registration_id=registration.id,
                            event="KEY_REGISTERED",
                            from_version=None,
                            to_version=1,
                            committed_at=committed_at,
                        )
                    )
            return registration

    async def get(self, registration_id: str) -> DeviceRegistration | None:
        async with self._session_factory() as session:
            row = (
                (
                    await session.execute(
                        select(device_registrations).where(
                            device_registrations.c.id == registration_id
                        )
                    )
                )
                .mappings()
                .first()
            )
            return self._to_registration(row) if row else None

    async def list_for_user(
        self, user_id: str, organization_id: str | None = None
    ) -> list[DeviceRegistration]:
        async with self._session_factory() as session:
            stmt = select(device_registrations).where(
                device_registrations.c.user_id == user_id
            )
            if organization_id is not None:
                stmt = stmt.where(
                    device_registrations.c.organization_id == organization_id
                )
            rows = (
                (
                    await session.execute(
                        stmt.order_by(device_registrations.c.updated_at.desc())
                    )
                )
                .mappings()
                .all()
            )
            return [self._to_registration(row) for row in rows]

    async def rotate_key(
        self,
        registration_id: str,
        *,
        expected_version: int,
        public_key_der: str,
        public_key_kid: str,
        grace_seconds: int,
    ) -> DeviceRegistration:
        if not 0 <= grace_seconds <= MAX_ROTATION_GRACE_SECONDS:
            raise ValueError("device key rotation grace is outside server bounds")
        async with self._session_factory() as session, session.begin():
            row = (
                (
                    await session.execute(
                        select(device_registrations)
                        .where(device_registrations.c.id == registration_id)
                        .with_for_update()
                    )
                )
                .mappings()
                .first()
            )
            if row is None:
                raise DeviceKeyConflictError("device registration no longer exists")
            if not row["is_active"]:
                raise InactiveDeviceRegistrationError(
                    "inactive device registrations cannot rotate keys"
                )
            if row["key_version"] != expected_version:
                raise DeviceKeyConflictError("current device key version changed")
            if expected_version >= MAX_KEY_VERSION:
                raise DeviceKeyConflictError("device key version limit reached")

            committed_at = (await session.execute(select(func.now()))).scalar_one()
            retire_at = committed_at + timedelta(seconds=grace_seconds)
            retired = await session.execute(
                update(device_registration_keys)
                .where(
                    device_registration_keys.c.registration_id == registration_id,
                    device_registration_keys.c.key_version == expected_version,
                    device_registration_keys.c.state == DeviceKeyState.CURRENT.value,
                )
                .values(
                    state=DeviceKeyState.RETIRING.value,
                    rotated_at=committed_at,
                    retire_at=retire_at,
                )
            )
            if retired.rowcount != 1:
                raise DeviceKeyConflictError("current device key version changed")

            new_version = expected_version + 1
            await session.execute(
                device_registration_keys.insert().values(
                    id=str(uuid.uuid4()),
                    registration_id=registration_id,
                    key_version=new_version,
                    public_key_der=public_key_der,
                    public_key_kid=public_key_kid,
                    state=DeviceKeyState.CURRENT.value,
                    valid_from=committed_at,
                    valid_until=None,
                    created_at=committed_at,
                )
            )
            projected = await session.execute(
                device_registrations.update()
                .where(
                    device_registrations.c.id == registration_id,
                    device_registrations.c.key_version == expected_version,
                )
                .values(
                    public_key_der=public_key_der,
                    public_key_kid=public_key_kid,
                    key_valid_from=committed_at,
                    key_valid_until=None,
                    key_version=new_version,
                    updated_at=committed_at,
                    last_seen_at=committed_at,
                )
            )
            if projected.rowcount != 1:
                raise DeviceKeyConflictError("current device key version changed")
            await session.execute(
                device_key_transitions.insert().values(
                    id=str(uuid.uuid4()),
                    registration_id=registration_id,
                    event="KEY_ROTATED",
                    from_version=expected_version,
                    to_version=new_version,
                    committed_at=committed_at,
                )
            )
            current = (
                (
                    await session.execute(
                        select(device_registrations).where(
                            device_registrations.c.id == registration_id
                        )
                    )
                )
                .mappings()
                .one()
            )
            return self._to_registration(current)

    async def deactivate(self, registration_id: str) -> DeviceRegistration | None:
        async with self._session_factory() as session, session.begin():
            row = (
                (
                    await session.execute(
                        select(device_registrations)
                        .where(device_registrations.c.id == registration_id)
                        .with_for_update()
                    )
                )
                .mappings()
                .first()
            )
            if row is None:
                return None
            if not row["is_active"]:
                return self._to_registration(row)
            committed_at = (await session.execute(select(func.now()))).scalar_one()
            await session.execute(
                update(device_registration_keys)
                .where(
                    device_registration_keys.c.registration_id == registration_id,
                    device_registration_keys.c.state.in_(
                        [
                            DeviceKeyState.CURRENT.value,
                            DeviceKeyState.RETIRING.value,
                        ]
                    ),
                )
                .values(
                    state=DeviceKeyState.REVOKED.value,
                    revoked_at=committed_at,
                )
            )
            await session.execute(
                device_registrations.update()
                .where(device_registrations.c.id == registration_id)
                .values(
                    is_active=False,
                    public_key_der=None,
                    public_key_kid=None,
                    key_valid_from=None,
                    key_valid_until=None,
                    key_version=None,
                    updated_at=committed_at,
                )
            )
            await session.execute(
                device_key_transitions.insert().values(
                    id=str(uuid.uuid4()),
                    registration_id=registration_id,
                    event="KEYS_REVOKED",
                    from_version=row["key_version"],
                    to_version=None,
                    committed_at=committed_at,
                )
            )
            updated = dict(row)
            updated["is_active"] = False
            updated["public_key_der"] = None
            updated["public_key_kid"] = None
            updated["key_valid_from"] = None
            updated["key_valid_until"] = None
            updated["key_version"] = None
            updated["updated_at"] = committed_at
            return self._to_registration(updated)

    async def resolve_challenge_key(
        self,
        challenge: ChallengeRecord,
        *,
        purpose: str,
        audience: str,
        now: datetime | None = None,
    ) -> DeviceKey | None:
        if challenge.registration_id is None or challenge.key_version is None:
            return None
        async with self._session_factory() as session:
            result = await session.execute(
                select(device_registration_keys, device_registrations.c.is_active)
                .join(
                    device_registrations,
                    device_registrations.c.id
                    == device_registration_keys.c.registration_id,
                )
                .where(
                    device_registration_keys.c.registration_id
                    == challenge.registration_id,
                    device_registration_keys.c.key_version == challenge.key_version,
                    device_registration_keys.c.public_key_kid
                    == challenge.public_key_kid,
                )
            )
            row = result.mappings().first()
            if row is None:
                return None
            key = self._to_key(row)
            return (
                key
                if challenge_key_is_eligible(
                    key,
                    registration_active=row["is_active"],
                    challenge=challenge,
                    purpose=purpose,
                    audience=audience,
                    now=now,
                )
                else None
            )
