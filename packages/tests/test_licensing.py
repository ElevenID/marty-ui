"""Unit tests for runtime license validation."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from marty_common.licensing import (
    LicenseClaims,
    LicenseValidationError,
    resolve_license_public_key,
    validate_license_claims,
    validate_runtime_license_from_env,
)
from marty_common import licensing


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _signed_license_token(private_key: Ed25519PrivateKey, claims: dict) -> str:
    header = {"alg": "EdDSA", "typ": "JWT"}
    header_part = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_part = _b64url_encode(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_part}.{payload_part}".encode("ascii")
    signature = private_key.sign(signing_input)
    return f"{header_part}.{payload_part}.{_b64url_encode(signature)}"


def _runtime_claims(**overrides: object) -> dict[str, object]:
    now = datetime.now(timezone.utc)
    payload: dict[str, object] = {
        "iss": "marty-license-issuer",
        "sub": "org-selfhost",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(days=30)).timestamp()),
        "plan_tier": "system",
        "entitled_products": ["ui-app"],
        "grace_period_days": 30,
        "features": [],
    }
    payload.update(overrides)
    return payload


def test_validate_license_claims_accepts_product_only_entitlement() -> None:
    claims = LicenseClaims.from_payload(_runtime_claims())

    validate_license_claims(claims)

    assert claims.is_self_hosted()
    assert claims.has_product("ui-app")


def test_validate_runtime_license_from_env_accepts_signed_system_tier_license_from_files(
    tmp_path,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    token = _signed_license_token(private_key, _runtime_claims(entitled_products=["ui-app", "oid4vc-api"]))

    license_key_path = tmp_path / "license.key"
    public_key_path = tmp_path / "license_public_key.pem"
    license_key_path.write_text(token, encoding="utf-8")
    public_key_path.write_text(public_key_pem, encoding="utf-8")

    claims = validate_runtime_license_from_env(
        {
            "MARTY_LICENSE_ENFORCEMENT": "required",
            "MARTY_LICENSE_ALLOW_RUNTIME_PUBLIC_KEY": "true",
            "MARTY_LICENSE_REQUIRED_PLAN_TIER": "system",
            "MARTY_LICENSE_REQUIRED_PRODUCTS": "ui-app, oid4vc-api",
            "LICENSE_KEY_FILE": str(license_key_path),
            "LICENSE_PUBLIC_KEY_FILE": str(public_key_path),
        }
    )

    assert claims is not None
    assert claims.plan_tier == "system"
    assert claims.has_product("oid4vc-api")


def test_resolve_license_public_key_loads_embedded_trust_anchor() -> None:
    public_key_pem = resolve_license_public_key({})

    assert "BEGIN PUBLIC KEY" in public_key_pem
    assert "change-me" not in public_key_pem.lower()


def test_validate_runtime_license_from_env_accepts_embedded_public_key(monkeypatch, tmp_path) -> None:
    private_key = Ed25519PrivateKey.generate()
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    public_key_path = tmp_path / "embedded-public.pem"
    public_key_path.write_text(public_key_pem, encoding="utf-8")
    token = _signed_license_token(private_key, _runtime_claims())

    class FakeResourceRoot:
        def joinpath(self, _name: str) -> object:
            return public_key_path

    monkeypatch.setattr(licensing.resources, "files", lambda _package: FakeResourceRoot())

    claims = validate_runtime_license_from_env(
        {
            "MARTY_LICENSE_ENFORCEMENT": "required",
            "MARTY_LICENSE_REQUIRED_PLAN_TIER": "system",
            "MARTY_LICENSE_REQUIRED_PRODUCTS": "ui-app",
            "LICENSE_KEY": token,
        }
    )

    assert claims is not None
    assert claims.has_product("ui-app")


def test_validate_runtime_license_from_env_rejects_runtime_public_key_by_default() -> None:
    private_key = Ed25519PrivateKey.generate()
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    token = _signed_license_token(private_key, _runtime_claims())

    with pytest.raises(LicenseValidationError, match="public-key overrides are disabled"):
        validate_runtime_license_from_env(
            {
                "MARTY_LICENSE_ENFORCEMENT": "required",
                "LICENSE_KEY": token,
                "LICENSE_PUBLIC_KEY": public_key_pem,
            }
        )


def test_validate_runtime_license_from_env_rejects_multiple_license_sources(tmp_path) -> None:
    license_path = tmp_path / "license.jwt"
    license_path.write_text("placeholder.jwt.value", encoding="utf-8")

    with pytest.raises(LicenseValidationError, match="multiple times"):
        validate_runtime_license_from_env(
            {
                "MARTY_LICENSE_ENFORCEMENT": "required",
                "MARTY_LICENSE_ALLOW_RUNTIME_PUBLIC_KEY": "true",
                "LICENSE_KEY": "header.payload.signature",
                "LICENSE_PATH": str(license_path),
                "LICENSE_PUBLIC_KEY": "-----BEGIN PUBLIC KEY-----\nchange-me-public-key\n-----END PUBLIC KEY-----",
            }
        )


def test_validate_runtime_license_from_env_rejects_plan_tier_mismatch(tmp_path) -> None:
    private_key = Ed25519PrivateKey.generate()
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    token = _signed_license_token(
        private_key,
        _runtime_claims(plan_tier="institution", entitled_products=["ui-app"]),
    )

    with pytest.raises(LicenseValidationError, match="required tier 'system'"):
        validate_runtime_license_from_env(
            {
                "MARTY_LICENSE_ENFORCEMENT": "required",
                "MARTY_LICENSE_ALLOW_RUNTIME_PUBLIC_KEY": "true",
                "MARTY_LICENSE_REQUIRED_PLAN_TIER": "system",
                "LICENSE_KEY": token,
                "LICENSE_PUBLIC_KEY": public_key_pem,
            }
        )