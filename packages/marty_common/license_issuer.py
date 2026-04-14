"""Internal tooling to issue signed self-host licenses outside the runtime product boundary."""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .licensing import DEFAULT_LICENSE_ISSUER, KNOWN_PLAN_TIERS, LicenseClaims, LicenseValidationError, validate_license_claims


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unique_nonempty(values: list[str] | tuple[str, ...]) -> list[str]:
    unique: list[str] = []
    seen: set[str] = set()
    for item in values:
        normalized = item.strip()
        if not normalized or normalized in seen:
            continue
        unique.append(normalized)
        seen.add(normalized)
    return unique


def _write_text_file(path: Path, value: str, *, mode: int, overwrite: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        raise FileExistsError(f"Refusing to overwrite existing file: {path}")
    path.write_text(value, encoding="utf-8")
    try:
        os.chmod(path, mode)
    except OSError:
        pass


@dataclass(frozen=True)
class SelfHostLicenseRequest:
    """Claims used for an issuer-signed self-host license."""

    subject: str
    org_name: str | None = None
    issuer: str = DEFAULT_LICENSE_ISSUER
    plan_tier: str = "system"
    entitled_products: tuple[str, ...] = ("ui-app",)
    features: tuple[str, ...] = ()
    deployment_mode: str = "production"
    days_valid: int = 365
    grace_period_days: int = 30
    jwt_id: str | None = None
    max_verifications_total: int = 0
    registry_access: bool = False
    api_calls_limit: int = 0
    update_channels: tuple[str, ...] = ()
    max_instances: dict[str, int] = field(default_factory=dict)

    def to_payload(self, *, now: datetime | None = None) -> dict[str, object]:
        current_time = now if now is not None else datetime.now(timezone.utc)
        if current_time.tzinfo is None:
            current_time = current_time.replace(tzinfo=timezone.utc)

        subject = self.subject.strip()
        if not subject:
            raise LicenseValidationError("License subject cannot be blank.")

        issuer = self.issuer.strip()
        if not issuer:
            raise LicenseValidationError("License issuer cannot be blank.")

        plan_tier = self.plan_tier.strip().lower()
        if plan_tier not in KNOWN_PLAN_TIERS:
            raise LicenseValidationError(
                f"Unsupported license plan tier {self.plan_tier!r}; expected one of {sorted(KNOWN_PLAN_TIERS)}."
            )

        if self.days_valid <= 0:
            raise LicenseValidationError("License days_valid must be greater than zero.")
        if self.grace_period_days < 0:
            raise LicenseValidationError("License grace_period_days must be non-negative.")
        if self.max_verifications_total < 0:
            raise LicenseValidationError("License max_verifications_total must be non-negative.")
        if self.api_calls_limit < 0:
            raise LicenseValidationError("License api_calls_limit must be non-negative.")
        if any(value < 0 for value in self.max_instances.values()):
            raise LicenseValidationError("License max_instances values must be non-negative.")

        issued_at = int(current_time.timestamp())
        expires_at = issued_at + (self.days_valid * 86400)
        jwt_id = self.jwt_id.strip() if self.jwt_id else f"lic-selfhost-{issued_at}-{uuid4().hex[:12]}"

        payload: dict[str, object] = {
            "iss": issuer,
            "sub": subject,
            "iat": issued_at,
            "exp": expires_at,
            "jti": jwt_id,
            "plan_tier": plan_tier,
            "entitled_products": _unique_nonempty(self.entitled_products),
            "grace_period_days": self.grace_period_days,
            "deployment_mode": self.deployment_mode.strip() or "production",
        }

        if self.org_name and self.org_name.strip():
            payload["org_name"] = self.org_name.strip()

        features = _unique_nonempty(self.features)
        if features:
            payload["features"] = features

        update_channels = _unique_nonempty(self.update_channels)
        if update_channels:
            payload["update_channels"] = update_channels

        if self.max_verifications_total:
            payload["max_verifications_total"] = self.max_verifications_total
        if self.registry_access:
            payload["registry_access"] = True
        if self.api_calls_limit:
            payload["api_calls_limit"] = self.api_calls_limit
        if self.max_instances:
            payload["max_instances"] = dict(self.max_instances)

        claims = LicenseClaims.from_payload(payload)
        validate_license_claims(claims)
        return payload


def generate_license_signing_keypair() -> tuple[str, str]:
    """Generate a new Ed25519 signing keypair and return PEM strings."""

    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_pem, public_pem


def write_license_signing_keypair(
    private_key_path: Path,
    public_key_path: Path,
    *,
    overwrite: bool = False,
) -> tuple[Path, Path]:
    """Generate and persist an Ed25519 signing keypair."""

    private_pem, public_pem = generate_license_signing_keypair()
    _write_text_file(private_key_path, private_pem, mode=0o600, overwrite=overwrite)
    _write_text_file(public_key_path, public_pem, mode=0o644, overwrite=overwrite)
    return private_key_path, public_key_path


def public_key_pem_from_private_key(private_key_pem: str) -> str:
    """Derive the PEM-encoded public key from an Ed25519 private key."""

    try:
        private_key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    except ValueError as exc:
        raise LicenseValidationError("License private key is not a valid PEM-encoded private key.") from exc

    if not isinstance(private_key, Ed25519PrivateKey):
        raise LicenseValidationError("License private key must be an Ed25519 private key.")

    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def issue_selfhost_license(
    private_key_pem: str,
    request: SelfHostLicenseRequest,
    *,
    now: datetime | None = None,
) -> tuple[str, str, dict[str, object]]:
    """Issue a signed self-host JWT and return the token, public key, and payload."""

    try:
        private_key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    except ValueError as exc:
        raise LicenseValidationError("License private key is not a valid PEM-encoded private key.") from exc

    if not isinstance(private_key, Ed25519PrivateKey):
        raise LicenseValidationError("License private key must be an Ed25519 private key.")

    payload = request.to_payload(now=now)
    header = {"alg": "EdDSA", "typ": "JWT"}
    header_part = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_part = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_part}.{payload_part}".encode("ascii")
    signature = private_key.sign(signing_input)
    token = f"{header_part}.{payload_part}.{_b64url_encode(signature)}"

    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return token, public_key_pem, payload
