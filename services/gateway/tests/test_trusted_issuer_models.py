"""Regression coverage for public trusted-issuer provisioning."""

from gateway.models import TrustedIssuerCreate


def test_trusted_issuer_create_preserves_pinned_public_jwks() -> None:
    key = {
        "kty": "EC",
        "crv": "P-256",
        "kid": "oidf-final-fixture",
        "x": "fixture-x",
        "y": "fixture-y",
    }

    model = TrustedIssuerCreate.model_validate(
        {
            "name": "OIDF Final fixture issuer",
            "issuer_did": "https://localhost.emobix.co.uk:8443",
            "issuer_url": "https://localhost.emobix.co.uk:8443",
            "verification_keys": [key],
        }
    )

    assert model.verification_keys == [key]
