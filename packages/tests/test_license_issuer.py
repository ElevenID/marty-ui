"""Unit tests for the internal self-host license issuer tooling."""

from __future__ import annotations

from marty_common.license_issuer import SelfHostLicenseRequest, generate_license_signing_keypair, issue_selfhost_license
from marty_common.licensing import validate_runtime_license_from_env


def test_issue_selfhost_license_validates_against_runtime_policy() -> None:
    private_key_pem, public_key_pem = generate_license_signing_keypair()
    token, _, payload = issue_selfhost_license(
        private_key_pem,
        SelfHostLicenseRequest(
            subject="00000000-0000-0000-0000-000000000001",
            org_name="Marty Self-Host Local",
            entitled_products=("ui-app", "oid4vc-api"),
        ),
    )

    claims = validate_runtime_license_from_env(
        {
            "MARTY_LICENSE_ENFORCEMENT": "required",
            "MARTY_LICENSE_ALLOW_RUNTIME_PUBLIC_KEY": "true",
            "MARTY_LICENSE_REQUIRED_ISSUER": "marty-license-issuer",
            "MARTY_LICENSE_REQUIRED_PLAN_TIER": "system",
            "MARTY_LICENSE_REQUIRED_PRODUCTS": "ui-app,oid4vc-api",
            "LICENSE_KEY": token,
            "LICENSE_PUBLIC_KEY": public_key_pem,
        }
    )

    assert claims is not None
    assert claims.sub == payload["sub"]
    assert claims.plan_tier == "system"
    assert claims.has_product("ui-app")
