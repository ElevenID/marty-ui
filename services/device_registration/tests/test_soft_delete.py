"""Marty-owned device-registration lifecycle tests.

The imported protocol conformance corpus is intentionally not modified here.
"""

from __future__ import annotations

from datetime import datetime, timezone

from services.device_registration import main as device


async def test_delete_deactivates_registration_without_removing_audit_record(
    monkeypatch,
) -> None:
    repository = device.InMemoryDeviceRepository()
    original_updated_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
    registration = device.DeviceRegistration(
        user_id="user-123",
        organization_id="org-123",
        device_id="device-123",
        platform=device.Platform.ANDROID,
        fcm_token="registration-token",
        public_key_der="stored-public-key",
        public_key_kid="stored-key-id",
        updated_at=original_updated_at,
    )
    await repository.save(registration)

    async def allow_membership(*_args, **_kwargs) -> None:
        return None

    monkeypatch.setattr(device, "_verify_org_membership", allow_membership)

    response = await device.delete_device(
        registration.id,
        object(),
        user_id="user-123",
        repo=repository,
    )

    stored = await repository.get(registration.id)
    assert response == {"success": True}
    assert stored is registration
    assert stored.is_active is False
    assert stored.updated_at > original_updated_at
    assert stored.fcm_token == "registration-token"
    assert stored.public_key_der == "stored-public-key"
    assert stored.public_key_kid == "stored-key-id"


async def test_delete_remains_idempotent_for_inactive_registration(monkeypatch) -> None:
    repository = device.InMemoryDeviceRepository()
    registration = device.DeviceRegistration(
        user_id="user-123",
        device_id="device-123",
        fcm_token="registration-token",
        is_active=False,
    )
    await repository.save(registration)

    async def allow_membership(*_args, **_kwargs) -> None:
        return None

    monkeypatch.setattr(device, "_verify_org_membership", allow_membership)

    response = await device.delete_device(
        registration.id,
        object(),
        user_id="user-123",
        repo=repository,
    )

    assert response == {"success": True}
    assert await repository.get(registration.id) is registration
    assert registration.is_active is False
