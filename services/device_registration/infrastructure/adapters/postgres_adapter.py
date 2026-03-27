"""PostgreSQL adapter for device registration service."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from device_registration.infrastructure.models import device_registrations

if TYPE_CHECKING:
    from device_registration.main import DeviceRegistration


class PostgresDeviceRegistrationRepository:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]):
        self._session_factory = session_factory

    @staticmethod
    def _to_registration(row: dict[str, Any]) -> "DeviceRegistration":
        from device_registration.main import DevicePreferences, DeviceRegistration, Platform

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
            is_active=row["is_active"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            last_seen_at=row["last_seen_at"],
        )

    async def save(self, registration: "DeviceRegistration") -> "DeviceRegistration":
        async with self._session_factory() as session:
            stmt = select(device_registrations).where(
                device_registrations.c.user_id == registration.user_id,
                device_registrations.c.device_id == registration.device_id,
                device_registrations.c.organization_id.is_(None)
                if registration.organization_id is None
                else device_registrations.c.organization_id == registration.organization_id,
            )
            result = await session.execute(stmt)
            existing = result.mappings().first()

            payload = {
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
                "is_active": registration.is_active,
                "updated_at": registration.updated_at,
                "last_seen_at": registration.last_seen_at,
            }

            if existing:
                registration.id = existing["id"]
                registration.created_at = existing["created_at"]
                payload["id"] = registration.id
                stmt = (
                    device_registrations.update()
                    .where(device_registrations.c.id == registration.id)
                    .values(**payload)
                )
            else:
                payload["created_at"] = registration.created_at
                stmt = device_registrations.insert().values(**payload)
            await session.execute(stmt)
            await session.commit()
            return registration

    async def get(self, registration_id: str) -> "DeviceRegistration | None":
        async with self._session_factory() as session:
            result = await session.execute(
                select(device_registrations).where(device_registrations.c.id == registration_id)
            )
            row = result.mappings().first()
            if not row:
                return None
            return self._to_registration(row)

    async def list_for_user(self, user_id: str, organization_id: str | None = None) -> list["DeviceRegistration"]:
        async with self._session_factory() as session:
            stmt = select(device_registrations).where(device_registrations.c.user_id == user_id)
            if organization_id is not None:
                stmt = stmt.where(device_registrations.c.organization_id == organization_id)
            stmt = stmt.order_by(device_registrations.c.updated_at.desc())
            result = await session.execute(stmt)
            rows = result.mappings().all()
            return [self._to_registration(row) for row in rows]

    async def delete(self, registration_id: str) -> None:
        async with self._session_factory() as session:
            await session.execute(delete(device_registrations).where(device_registrations.c.id == registration_id))
            await session.commit()
