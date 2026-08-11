"""Thin, fail-closed adapters to the canonical Rust device-auth kernel."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from types import ModuleType
from typing import Any

from common.native_backend import (
    NativeBackendUnavailable,
    NativeOperationError,
    get_marty_rs_diagnostics,
    load_marty_rs,
)

_backend: ModuleType | None = None
_diagnostics: dict[str, Any] | None = None


def initialize_device_auth_backend() -> dict[str, Any]:
    """Load the required native capability and retain its health snapshot."""

    global _backend, _diagnostics
    backend = load_marty_rs(required_capability="device_authentication")
    diagnostics = get_marty_rs_diagnostics(
        backend,
        required_capability="device_authentication",
    )
    _backend = backend
    _diagnostics = diagnostics
    return diagnostics


def device_auth_diagnostics() -> dict[str, Any]:
    if _diagnostics is None:
        return initialize_device_auth_backend()
    return dict(_diagnostics)


def _get_backend() -> ModuleType:
    if _backend is None:
        initialize_device_auth_backend()
    if _backend is None:  # pragma: no cover - defensive invariant
        raise NativeBackendUnavailable("The device-auth Rust backend is unavailable")
    return _backend


def _call(name: str, *args: Any) -> Any:
    backend = _get_backend()
    function = getattr(backend, name, None)
    if not callable(function):
        raise NativeBackendUnavailable(
            f"The Marty Rust backend lacks required operation: {name}"
        )
    try:
        return function(*args)
    except Exception as error:
        native_error = getattr(backend, "DeviceAuthError", ())
        if isinstance(native_error, type) and isinstance(error, native_error):
            raise ValueError(str(error)) from error
        raise NativeOperationError(
            f"The Marty Rust device-auth operation {name} failed"
        ) from error


def _call_json(name: str, payload: dict[str, Any]) -> dict[str, Any]:
    raw = _call(name, json.dumps(payload, sort_keys=True, separators=(",", ":")))
    try:
        result = json.loads(raw)
    except (TypeError, ValueError) as error:
        raise NativeOperationError(
            f"The Marty Rust device-auth operation {name} returned invalid JSON"
        ) from error
    if not isinstance(result, dict):
        raise NativeOperationError(
            f"The Marty Rust device-auth operation {name} returned an invalid result"
        )
    return result


def _timestamp(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _decision(result: dict[str, Any], *, allowed_codes: set[str]) -> tuple[bool, str]:
    if set(result) != {"eligible", "code"}:
        raise NativeOperationError("Rust device-auth decision fields are malformed")
    eligible = result.get("eligible")
    code = result.get("code")
    if not isinstance(eligible, bool) or not isinstance(code, str) or code not in allowed_codes:
        raise NativeOperationError("Rust device-auth decision is malformed")
    return eligible, code


def challenge_payload(record: Any) -> dict[str, Any]:
    return {
        "challenge_id": record.challenge_id,
        "user_id": record.user_id,
        "device_id": record.device_id,
        "public_key_kid": record.public_key_kid,
        "public_key_sha256": record.public_key_sha256,
        "nonce": record.nonce,
        "created_at": record.created_at,
        "expires_at": record.expires_at,
        "registration_id": record.registration_id,
        "key_version": record.key_version,
        "purpose": record.purpose,
        "audience": record.audience,
        "message_version": record.message_version,
    }


def _parse_key_facts(raw: Any, *, expected_kid: str | None = None) -> dict[str, Any]:
    try:
        result = json.loads(raw)
    except (TypeError, ValueError) as error:
        raise NativeOperationError("Rust public-key validation returned invalid JSON") from error
    if (
        not isinstance(result, dict)
        or (expected_kid is not None and result.get("public_key_kid") != expected_kid)
        or not isinstance(result.get("public_key_kid"), str)
        or not isinstance(result.get("public_key_sha256"), str)
        or not isinstance(result.get("key_bits"), int)
    ):
        raise NativeOperationError("Rust public-key validation returned invalid facts")
    return result


def inspect_public_key(public_key_der: str) -> dict[str, Any]:
    return _parse_key_facts(_call("device_public_key_inspect", public_key_der))


def validate_public_key(public_key_der: str, public_key_kid: str) -> dict[str, Any]:
    return _parse_key_facts(
        _call("device_public_key_validate", public_key_der, public_key_kid),
        expected_kid=public_key_kid,
    )


def encoded_challenge_message(record: Any) -> str:
    return _call(
        "device_build_challenge_message",
        json.dumps(challenge_payload(record), sort_keys=True, separators=(",", ":")),
    )


def challenge_message(record: Any) -> bytes:
    encoded = encoded_challenge_message(record)
    try:
        return base64.b64decode(
            encoded + "=" * (-len(encoded) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (TypeError, ValueError) as error:
        raise NativeOperationError("Rust challenge message is not base64url") from error


def challenge_is_expired(record: Any, now: datetime | None = None) -> bool:
    result = _call(
        "device_challenge_is_expired",
        json.dumps(challenge_payload(record), sort_keys=True, separators=(",", ":")),
        (now or datetime.now(timezone.utc)).isoformat(),
    )
    if not isinstance(result, bool):
        raise NativeOperationError("Rust challenge expiry returned an invalid result")
    return result


def verify_challenge_signature(
    public_key_der: str,
    record: Any,
    signature_b64url: str,
) -> None:
    _call(
        "device_verify_challenge_signature",
        public_key_der,
        json.dumps(challenge_payload(record), sort_keys=True, separators=(",", ":")),
        signature_b64url,
    )


def challenge_binding_matches(
    record: Any,
    *,
    user_id: str,
    device_id: str,
    public_key_kid: str,
    public_key_sha256: str,
    registration_id: str | None,
    key_version: int | None,
    purpose: str,
    audience: str,
    now: datetime | None = None,
) -> bool:
    result = _call_json(
        "device_challenge_binding",
        {
            "challenge": challenge_payload(record),
            "user_id": user_id,
            "device_id": device_id,
            "public_key_kid": public_key_kid,
            "public_key_sha256": public_key_sha256,
            "registration_id": registration_id,
            "key_version": key_version,
            "purpose": purpose,
            "audience": audience,
            "now": (now or datetime.now(timezone.utc)).isoformat(),
        },
    )
    eligible, code = _decision(
        result,
        allowed_codes={
            "CHALLENGE_BINDING_MATCH",
            "CHALLENGE_BINDING_MISMATCH",
            "CHALLENGE_EXPIRED",
        },
    )
    return eligible and code == "CHALLENGE_BINDING_MATCH"


def challenge_key_is_eligible(
    key: Any,
    *,
    registration_active: bool,
    challenge: Any,
    purpose: str,
    audience: str,
    now: datetime | None = None,
) -> bool:
    result = _call_json(
        "device_key_eligibility",
        {
            "key": {
                "id": key.id,
                "registration_id": key.registration_id,
                "key_version": key.key_version,
                "public_key_der": key.public_key_der,
                "public_key_kid": key.public_key_kid,
                "state": key.state.value,
                "valid_from": _timestamp(key.valid_from),
                "valid_until": _timestamp(key.valid_until),
                "rotated_at": _timestamp(key.rotated_at),
                "retire_at": _timestamp(key.retire_at),
                "revoked_at": _timestamp(key.revoked_at),
                "created_at": _timestamp(key.created_at),
            },
            "registration_active": registration_active,
            "challenge": challenge_payload(challenge),
            "purpose": purpose,
            "audience": audience,
            "now": (now or datetime.now(timezone.utc)).isoformat(),
        },
    )
    eligible, code = _decision(
        result,
        allowed_codes={
            "ELIGIBLE_CURRENT",
            "ELIGIBLE_ROTATION_GRACE",
            "REGISTRATION_INACTIVE",
            "KEY_STATE_INELIGIBLE",
            "KEY_VERSION_INVALID",
            "KEY_MATERIAL_INVALID",
            "KEY_MATERIAL_MISMATCH",
            "CHALLENGE_BINDING_MISMATCH",
            "CHALLENGE_EXPIRED",
            "KEY_NOT_YET_VALID",
            "KEY_EXPIRED",
            "ROTATION_GRACE_DISALLOWED",
            "ROTATION_WINDOW_INVALID",
            "CHALLENGE_NOT_PRE_ROTATION",
            "ROTATION_GRACE_EXPIRED",
        },
    )
    return eligible and code in {"ELIGIBLE_CURRENT", "ELIGIBLE_ROTATION_GRACE"}
