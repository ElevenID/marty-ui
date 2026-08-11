"""Domain rules for immutable, versioned Device Registration keys."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum


MAX_KEY_VERSION = 9_007_199_254_740_991
MAX_ROTATION_GRACE_SECONDS = 900
class DeviceKeyState(str, Enum):
    CURRENT = "CURRENT"
    RETIRING = "RETIRING"
    RETIRED = "RETIRED"
    REVOKED = "REVOKED"


@dataclass(frozen=True)
class DeviceKey:
    id: str
    registration_id: str
    key_version: int
    public_key_der: str
    public_key_kid: str
    state: DeviceKeyState
    valid_from: datetime
    valid_until: datetime | None = None
    rotated_at: datetime | None = None
    retire_at: datetime | None = None
    revoked_at: datetime | None = None
    created_at: datetime | None = None


class DeviceKeyConflictError(Exception):
    """A stale or concurrent key transition lost its compare-and-swap."""


class InactiveDeviceRegistrationError(Exception):
    """A key transition was attempted for an inactive registration."""
