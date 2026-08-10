"""Domain rules for immutable, versioned Device Registration keys."""

from __future__ import annotations

import base64
import hashlib
import hmac
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from device_registration.challenges import ChallengeRecord


MAX_KEY_VERSION = 9_007_199_254_740_991
MAX_ROTATION_GRACE_SECONDS = 900
NON_GRACE_PURPOSES = {
    "device_registration",
    "device_key_rotation",
    "device_registration_update",
}


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


def challenge_key_is_eligible(
    key: DeviceKey,
    *,
    registration_active: bool,
    challenge: ChallengeRecord,
    purpose: str,
    audience: str,
    now: datetime | None = None,
) -> bool:
    """Return whether an exact challenge may resolve to this stored key."""
    checked_at = now or datetime.now(timezone.utc)
    try:
        raw_key = base64.b64decode(
            key.public_key_der + "=" * (-len(key.public_key_der) % 4),
            altchars=b"-_",
            validate=True,
        )
    except ValueError:
        return False
    stored_digest = hashlib.sha256(raw_key).hexdigest()
    if not registration_active or key.state in {
        DeviceKeyState.RETIRED,
        DeviceKeyState.REVOKED,
    }:
        return False
    if (
        challenge.registration_id != key.registration_id
        or challenge.key_version != key.key_version
        or not hmac.compare_digest(challenge.public_key_kid, key.public_key_kid)
        or not hmac.compare_digest(challenge.public_key_sha256, stored_digest)
        or challenge.purpose != purpose
        or challenge.audience != audience
        or challenge.is_expired(checked_at)
        or checked_at < key.valid_from
        or (key.valid_until is not None and checked_at >= key.valid_until)
    ):
        return False
    if key.state is DeviceKeyState.CURRENT:
        return True
    if purpose in NON_GRACE_PURPOSES or key.state is not DeviceKeyState.RETIRING:
        return False
    if key.rotated_at is None or key.retire_at is None:
        return False
    issued_at = datetime.fromisoformat(challenge.created_at)
    return issued_at < key.rotated_at and checked_at < key.retire_at
