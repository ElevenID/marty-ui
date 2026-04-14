"""Shared license parsing and runtime validation for Marty services."""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


DEFAULT_LICENSE_ISSUER = "marty-license-issuer"
DISABLED_ENFORCEMENT_VALUES = {"", "0", "false", "off", "disabled", "none"}
KNOWN_PLAN_TIERS = {"sandbox", "program", "institution", "system"}
PLACEHOLDER_PREFIXES = (
    "change-me",
    "change_me",
    "changeme",
    "replace-me",
    "replace_me",
)
VERIFIER_PRODUCT = "verifier"


class LicenseValidationError(RuntimeError):
    """Raised when license material is missing or invalid."""


def _b64url_decode(value: str) -> bytes:
    padding = (-len(value)) % 4
    return base64.urlsafe_b64decode(value + ("=" * padding))


def _string_value(payload: Mapping[str, Any], key: str, *, required: bool) -> str | None:
    value = payload.get(key)
    if value is None:
        if required:
            raise LicenseValidationError(f"License claim {key} is required.")
        return None

    if not isinstance(value, str):
        raise LicenseValidationError(f"License claim {key} must be a string.")

    normalized = value.strip()
    if required and not normalized:
        raise LicenseValidationError(f"License claim {key} cannot be blank.")

    return normalized or None


def _int_value(payload: Mapping[str, Any], key: str, *, required: bool, default: int = 0) -> int | None:
    value = payload.get(key)
    if value is None:
        if required:
            raise LicenseValidationError(f"License claim {key} is required.")
        return default

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise LicenseValidationError(f"License claim {key} must be an integer.")

    return int(value)


def _string_list_value(payload: Mapping[str, Any], key: str) -> list[str]:
    value = payload.get(key, [])
    if value is None:
        return []

    if not isinstance(value, list):
        raise LicenseValidationError(f"License claim {key} must be a list of strings.")

    normalized: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise LicenseValidationError(f"License claim {key} must contain only strings.")
        item_value = item.strip()
        if item_value:
            normalized.append(item_value)
    return normalized


def _int_mapping_value(payload: Mapping[str, Any], key: str) -> dict[str, int]:
    value = payload.get(key, {})
    if value is None:
        return {}

    if not isinstance(value, dict):
        raise LicenseValidationError(f"License claim {key} must be an object.")

    normalized: dict[str, int] = {}
    for item_key, item_value in value.items():
        if not isinstance(item_key, str) or not item_key.strip():
            raise LicenseValidationError(f"License claim {key} must use string keys.")
        if isinstance(item_value, bool) or not isinstance(item_value, (int, float)):
            raise LicenseValidationError(
                f"License claim {key} must use integer values for {item_key!r}."
            )
        numeric_value = int(item_value)
        if numeric_value < 0:
            raise LicenseValidationError(
                f"License claim {key} must use non-negative values for {item_key!r}."
            )
        normalized[item_key.strip()] = numeric_value
    return normalized


def is_placeholder_value(value: str) -> bool:
    normalized = value.strip().lower()
    return any(normalized.startswith(prefix) for prefix in PLACEHOLDER_PREFIXES)


def _coerce_timestamp(now: datetime | int | float | None) -> int:
    if now is None:
        return int(datetime.now(timezone.utc).timestamp())
    if isinstance(now, datetime):
        reference = now if now.tzinfo is not None else now.replace(tzinfo=timezone.utc)
        return int(reference.timestamp())
    if isinstance(now, bool) or not isinstance(now, (int, float)):
        raise LicenseValidationError("Current time must be provided as a datetime or unix timestamp.")
    return int(now)


def _read_text_file(path_value: str, source_name: str) -> str:
    path = Path(path_value)
    try:
        raw_value = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise LicenseValidationError(
            f"{source_name} points to an unreadable file: {path}"
        ) from exc

    resolved_value = raw_value.strip()
    if not resolved_value:
        raise LicenseValidationError(f"{source_name} points to an empty file: {path}")
    return resolved_value


def _resolve_env_file_value(
    env: Mapping[str, str],
    *,
    direct_key: str,
    file_key: str | None = None,
    path_keys: tuple[str, ...] = (),
    label: str,
) -> str:
    sources: list[tuple[str, str, str]] = []

    direct_value = str(env.get(direct_key, "")).strip()
    if direct_value:
        sources.append((direct_key, direct_value, "value"))

    if file_key:
        file_value = str(env.get(file_key, "")).strip()
        if file_value:
            sources.append((file_key, file_value, "file"))

    for path_key in path_keys:
        path_value = str(env.get(path_key, "")).strip()
        if path_value:
            sources.append((path_key, path_value, "file"))

    if not sources:
        available_sources = [direct_key]
        if file_key:
            available_sources.append(file_key)
        available_sources.extend(path_keys)
        joined_sources = ", ".join(available_sources)
        raise LicenseValidationError(
            f"{label} is required but was not provided via {joined_sources}."
        )

    if len(sources) > 1:
        joined_sources = ", ".join(source[0] for source in sources)
        raise LicenseValidationError(
            f"{label} was provided multiple times ({joined_sources}); choose exactly one source."
        )

    source_name, source_value, source_kind = sources[0]
    resolved_value = source_value if source_kind == "value" else _read_text_file(source_value, source_name)
    if is_placeholder_value(resolved_value):
        raise LicenseValidationError(
            f"{label} still uses a shipped placeholder value; replace it before startup."
        )
    return resolved_value


def resolve_license_token(env: Mapping[str, str] | None = None) -> str:
    runtime_env = os.environ if env is None else env
    return _resolve_env_file_value(
        runtime_env,
        direct_key="LICENSE_KEY",
        file_key="LICENSE_KEY_FILE",
        path_keys=("LICENSE_PATH",),
        label="License key",
    )


def resolve_license_public_key(env: Mapping[str, str] | None = None) -> str:
    runtime_env = os.environ if env is None else env
    return _resolve_env_file_value(
        runtime_env,
        direct_key="LICENSE_PUBLIC_KEY",
        file_key="LICENSE_PUBLIC_KEY_FILE",
        label="License public key",
    )


def _normalize_required_plan_tier(value: str | None) -> str | None:
    if value is None:
        return None

    normalized = value.strip().lower()
    if not normalized:
        return None
    if normalized not in KNOWN_PLAN_TIERS:
        raise LicenseValidationError(
            f"Unsupported required plan tier {value!r}; expected one of {sorted(KNOWN_PLAN_TIERS)}."
        )
    return normalized


def _csv_values(value: str | None) -> list[str]:
    if value is None:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


@dataclass(frozen=True)
class LicenseClaims:
    """Canonical Marty license claims mirrored into the Python runtime."""

    iss: str
    sub: str
    iat: int
    exp: int
    nbf: int | None = None
    jti: str | None = None
    features: list[str] = field(default_factory=list)
    deployment_mode: str | None = None
    max_verifications_total: int = 0
    hardware_binding: str | None = None
    hardware_tier: str | None = None
    org_name: str | None = None
    update_channels: list[str] = field(default_factory=list)
    grace_period_days: int = 30
    plan_tier: str | None = None
    entitled_products: list[str] = field(default_factory=list)
    max_instances: dict[str, int] = field(default_factory=dict)
    registry_access: bool = False
    api_calls_limit: int = 0

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "LicenseClaims":
        issuer = _string_value(payload, "iss", required=True)
        subject = _string_value(payload, "sub", required=True)
        issued_at = _int_value(payload, "iat", required=True)
        expires_at = _int_value(payload, "exp", required=True)
        not_before = _int_value(payload, "nbf", required=False, default=None)
        jwt_id = _string_value(payload, "jti", required=False)
        deployment_mode = _string_value(payload, "deployment_mode", required=False)
        hardware_binding = _string_value(payload, "hardware_binding", required=False)
        hardware_tier = _string_value(payload, "hardware_tier", required=False)
        org_name = _string_value(payload, "org_name", required=False)
        plan_tier = _normalize_required_plan_tier(_string_value(payload, "plan_tier", required=False))

        max_verifications_total = _int_value(
            payload,
            "max_verifications_total",
            required=False,
            default=0,
        )
        if max_verifications_total is None or max_verifications_total < 0:
            raise LicenseValidationError(
                "License claim max_verifications_total must be a non-negative integer."
            )

        grace_period_days = _int_value(
            payload,
            "grace_period_days",
            required=False,
            default=30,
        )
        if grace_period_days is None or grace_period_days < 0:
            raise LicenseValidationError(
                "License claim grace_period_days must be a non-negative integer."
            )

        api_calls_limit = _int_value(payload, "api_calls_limit", required=False, default=0)
        if api_calls_limit is None or api_calls_limit < 0:
            raise LicenseValidationError(
                "License claim api_calls_limit must be a non-negative integer."
            )

        registry_access = payload.get("registry_access", False)
        if not isinstance(registry_access, bool):
            raise LicenseValidationError("License claim registry_access must be a boolean.")

        return cls(
            iss=issuer,
            sub=subject,
            iat=issued_at,
            exp=expires_at,
            nbf=not_before,
            jti=jwt_id,
            features=_string_list_value(payload, "features"),
            deployment_mode=deployment_mode,
            max_verifications_total=max_verifications_total,
            hardware_binding=hardware_binding,
            hardware_tier=hardware_tier,
            org_name=org_name,
            update_channels=_string_list_value(payload, "update_channels"),
            grace_period_days=grace_period_days,
            plan_tier=plan_tier,
            entitled_products=_string_list_value(payload, "entitled_products"),
            max_instances=_int_mapping_value(payload, "max_instances"),
            registry_access=registry_access,
            api_calls_limit=api_calls_limit,
        )

    @property
    def expires_at(self) -> datetime:
        return datetime.fromtimestamp(self.exp, tz=timezone.utc)

    def days_until_expiry(self, now: datetime | int | float | None = None) -> int:
        current_time = _coerce_timestamp(now)
        return (self.exp - current_time) // 86400

    def has_feature(self, feature: str) -> bool:
        if "*" in self.features:
            return True
        return feature in self.features or any(feature.startswith(value) for value in self.features)

    def has_product(self, product: str) -> bool:
        if not self.entitled_products:
            return product == VERIFIER_PRODUCT
        if "*" in self.entitled_products:
            return True
        return product in self.entitled_products

    def is_self_hosted(self) -> bool:
        return self.plan_tier == "system"


def validate_license_claims(claims: LicenseClaims) -> None:
    if not claims.sub:
        raise LicenseValidationError("License claim sub cannot be blank.")
    if not claims.features and not claims.entitled_products and claims.plan_tier is None:
        raise LicenseValidationError(
            "License must include features, entitled products, or a plan tier."
        )


def _decode_token_parts(token: str) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise LicenseValidationError("License token must be a JWT with three segments.")

    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        signature = _b64url_decode(parts[2])
    except (ValueError, json.JSONDecodeError) as exc:
        raise LicenseValidationError("License token is not valid base64url JSON.") from exc

    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise LicenseValidationError("License token header and payload must be JSON objects.")

    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    return header, payload, signing_input, signature


def _load_public_key(public_key_pem: str) -> Ed25519PublicKey:
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    except ValueError as exc:
        raise LicenseValidationError("License public key is not a valid PEM-encoded public key.") from exc

    if not isinstance(public_key, Ed25519PublicKey):
        raise LicenseValidationError("License public key must be an Ed25519 public key.")

    return public_key


def validate_license_token(
    token: str,
    public_key_pem: str,
    *,
    issuer: str = DEFAULT_LICENSE_ISSUER,
    now: datetime | int | float | None = None,
) -> LicenseClaims:
    header, payload, signing_input, signature = _decode_token_parts(token)

    algorithm = header.get("alg")
    if algorithm != "EdDSA":
        raise LicenseValidationError(
            f"License token must use EdDSA; received {algorithm!r}."
        )

    public_key = _load_public_key(public_key_pem)
    try:
        public_key.verify(signature, signing_input)
    except InvalidSignature as exc:
        raise LicenseValidationError("License signature is invalid.") from exc

    claims = LicenseClaims.from_payload(payload)
    validate_license_claims(claims)

    if claims.iss != issuer:
        raise LicenseValidationError(
            f"License issuer {claims.iss!r} does not match required issuer {issuer!r}."
        )

    current_time = _coerce_timestamp(now)
    if claims.nbf is not None and current_time < claims.nbf:
        raise LicenseValidationError("License is not active yet.")
    if current_time >= claims.exp:
        raise LicenseValidationError(
            f"License expired at {claims.expires_at.isoformat().replace('+00:00', 'Z')}."
        )

    return claims


def license_enforcement_enabled(env: Mapping[str, str] | None = None) -> bool:
    runtime_env = os.environ if env is None else env
    value = str(runtime_env.get("MARTY_LICENSE_ENFORCEMENT", "")).strip().lower()
    return value not in DISABLED_ENFORCEMENT_VALUES


def validate_runtime_license_from_env(
    env: Mapping[str, str] | None = None,
    *,
    now: datetime | int | float | None = None,
) -> LicenseClaims | None:
    runtime_env = os.environ if env is None else env
    if not license_enforcement_enabled(runtime_env):
        return None

    token = resolve_license_token(runtime_env)
    public_key_pem = resolve_license_public_key(runtime_env)
    required_issuer = str(
        runtime_env.get("MARTY_LICENSE_REQUIRED_ISSUER", DEFAULT_LICENSE_ISSUER)
    ).strip() or DEFAULT_LICENSE_ISSUER
    required_plan_tier = _normalize_required_plan_tier(
        str(runtime_env.get("MARTY_LICENSE_REQUIRED_PLAN_TIER", "")).strip() or None
    )
    required_products = _csv_values(
        str(runtime_env.get("MARTY_LICENSE_REQUIRED_PRODUCTS", "")).strip() or None
    )

    claims = validate_license_token(token, public_key_pem, issuer=required_issuer, now=now)

    if required_plan_tier and claims.plan_tier != required_plan_tier:
        raise LicenseValidationError(
            f"License plan tier {claims.plan_tier or 'none'!r} does not satisfy required tier {required_plan_tier!r}."
        )

    missing_products = [product for product in required_products if not claims.has_product(product)]
    if missing_products:
        raise LicenseValidationError(
            "License is missing required entitled products: "
            + ", ".join(sorted(missing_products))
        )

    return claims