"""Privacy and size boundaries for outbound notification payload data."""

from __future__ import annotations

import json
import re
from typing import Any

MAX_NOTIFICATION_DATA_BYTES = 4096
MAX_NOTIFICATION_DATA_DEPTH = 5
MAX_NOTIFICATION_COLLECTION_ITEMS = 64
MAX_NOTIFICATION_KEY_LENGTH = 128

_COMPACT_TOKEN_PATTERN = re.compile(
    r"(?:^|[^A-Za-z0-9_-])"
    r"[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
    r"(?:$|[^A-Za-z0-9_-])"
)
_RAW_CREDENTIAL_TEXT_MARKERS = (
    '"credentialSubject"',
    '"presentation_submission"',
    '"privateKey"',
    '"proof"',
    '"vp_token"',
)
_FORBIDDEN_KEYS = {
    "accesstoken",
    "claims",
    "clientsecret",
    "credential",
    "credentialjwt",
    "credentialpayload",
    "idtoken",
    "mdoc",
    "msomdoc",
    "payload",
    "presentation",
    "presentationsubmission",
    "privatekey",
    "proof",
    "rawcredential",
    "refreshtoken",
    "sdjwt",
    "sdjwtvc",
    "signedcredential",
    "subjectclaims",
    "token",
    "verifiablecredential",
    "verifiablepresentation",
    "vptoken",
}
_INTERNAL_EVENT_FIELDS: dict[str, frozenset[str]] = {
    "credential.offered": frozenset(
        {
            "application_id",
            "credential_template_id",
            "credential_type",
            "offer_uri",
        }
    ),
    "credential.issued": frozenset(
        {
            "application_id",
            "credential_id",
            "credential_template_id",
            "credential_type",
            "status",
        }
    ),
    "credential.revoked": frozenset(
        {
            "application_id",
            "credential_id",
            "credential_template_id",
            "credential_type",
            "reason_code",
            "status",
        }
    ),
    "verification.requested": frozenset(
        {"expires_at", "policy_id", "request_uri", "verification_id"}
    ),
    "application.received": frozenset(
        {"applicant_id", "application_id", "credential_template_id", "status"}
    ),
    "application.approved": frozenset(
        {"applicant_id", "application_id", "credential_template_id", "status"}
    ),
    "application.rejected": frozenset(
        {"applicant_id", "application_id", "credential_template_id", "status"}
    ),
    "applicant.submitted": frozenset(
        {"applicant_id", "application_id", "credential_template_id", "status"}
    ),
    "applicant.approved": frozenset(
        {"applicant_id", "application_id", "credential_template_id", "status"}
    ),
    "applicant.rejected": frozenset(
        {"applicant_id", "application_id", "credential_template_id", "status"}
    ),
    "applicant.status_changed": frozenset(
        {"applicant_id", "application_id", "credential_template_id", "status"}
    ),
    "device.key_expiring": frozenset({"device_id", "expires_at", "key_id"}),
}


class NotificationPayloadSecurityError(ValueError):
    """Outbound notification data violates the protocol privacy boundary."""


def _normalized_key(key: str) -> str:
    return "".join(character for character in key.lower() if character.isalnum())


def _validate_value(value: Any, *, depth: int) -> None:
    if depth > MAX_NOTIFICATION_DATA_DEPTH:
        raise NotificationPayloadSecurityError("notification data is too deeply nested")
    if isinstance(value, dict):
        if len(value) > MAX_NOTIFICATION_COLLECTION_ITEMS:
            raise NotificationPayloadSecurityError(
                "notification data contains too many object fields"
            )
        for key, child in value.items():
            if not isinstance(key, str) or len(key) > MAX_NOTIFICATION_KEY_LENGTH:
                raise NotificationPayloadSecurityError(
                    "notification data contains an invalid field name"
                )
            normalized = _normalized_key(key)
            if (
                normalized in _FORBIDDEN_KEYS
                or normalized.endswith("privatekey")
                or normalized.endswith("secret")
            ):
                raise NotificationPayloadSecurityError(
                    "notification data contains protected credential material"
                )
            _validate_value(child, depth=depth + 1)
        return
    if isinstance(value, list):
        if len(value) > MAX_NOTIFICATION_COLLECTION_ITEMS:
            raise NotificationPayloadSecurityError(
                "notification data contains too many list items"
            )
        for child in value:
            _validate_value(child, depth=depth + 1)
        return
    if isinstance(value, str) and _COMPACT_TOKEN_PATTERN.search(value):
        raise NotificationPayloadSecurityError(
            "notification data contains protected credential material"
        )
    if value is not None and not isinstance(value, (str, int, float, bool)):
        raise NotificationPayloadSecurityError(
            "notification data contains a non-JSON value"
        )


def validate_notification_data(data: dict[str, Any]) -> dict[str, Any]:
    """Enforce the protocol's 4 KB and no-raw-credential requirements."""
    _validate_value(data, depth=1)
    try:
        encoded = json.dumps(
            data,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise NotificationPayloadSecurityError(
            "notification data is not valid JSON"
        ) from exc
    if len(encoded) > MAX_NOTIFICATION_DATA_BYTES:
        raise NotificationPayloadSecurityError(
            "notification data exceeds the 4 KB protocol limit"
        )
    return data


def validate_notification_text(title: str, body: str) -> None:
    """Bound user-visible content and reject embedded serialized credentials."""
    if len(title) > 256:
        raise NotificationPayloadSecurityError(
            "notification title exceeds the 256 character protocol limit"
        )
    if len(body) > 2048:
        raise NotificationPayloadSecurityError(
            "notification body exceeds the 2048 character protocol limit"
        )
    for value in (title, body):
        if _COMPACT_TOKEN_PATTERN.search(value) or any(
            marker in value for marker in _RAW_CREDENTIAL_TEXT_MARKERS
        ):
            raise NotificationPayloadSecurityError(
                "notification content contains protected credential material"
            )


def validate_internal_event_data(
    event_type: str, data: dict[str, Any]
) -> dict[str, Any]:
    """Require a minimized, event-specific projection for webhook fan-out."""
    allowed_fields = _INTERNAL_EVENT_FIELDS.get(event_type)
    if allowed_fields is None:
        raise NotificationPayloadSecurityError(
            "event_type is not supported for notification fan-out"
        )
    if not set(data).issubset(allowed_fields):
        raise NotificationPayloadSecurityError(
            "event data contains fields outside the minimized event contract"
        )
    validate_notification_data(data)
    for field_name, value in data.items():
        if isinstance(value, (dict, list)):
            raise NotificationPayloadSecurityError(
                "internal event data must contain scalar projection values"
            )
        if value is not None and not isinstance(value, str):
            raise NotificationPayloadSecurityError(
                "internal event projection values must be strings"
            )
        if isinstance(value, str):
            max_length = 2048 if field_name.endswith("_uri") else 256
            if len(value) > max_length:
                raise NotificationPayloadSecurityError(
                    "internal event projection value exceeds its size limit"
                )
    return data
