"""Regression coverage for protocol-defined issuer relationships."""

import pytest
from pydantic import ValidationError

from gateway.models import IssuerEntityCreate, TrustProfileIssuerCreate


ENTITY_ID = "10000000-0000-4000-8000-000000000001"


def test_public_jwk_material_belongs_to_issuer_entity() -> None:
    key = {
        "kty": "EC",
        "crv": "P-256",
        "kid": "oidf-final-fixture",
        "x": "fixture-x",
        "y": "fixture-y",
    }

    entity = IssuerEntityCreate.model_validate(
        {
            "organization_id": "20000000-0000-4000-8000-000000000001",
            "issuer_id": "https://localhost.emobix.co.uk:8443",
            "display_name": "OIDF Final fixture issuer",
            "metadata": {"verification_keys": [key]},
        }
    )
    relationship = TrustProfileIssuerCreate.model_validate({"issuer_id": ENTITY_ID})

    assert entity.metadata["verification_keys"] == [key]
    assert relationship.issuer_id == ENTITY_ID


def test_private_jwk_material_is_rejected_from_public_issuer_metadata() -> None:
    with pytest.raises(ValidationError, match="private JWK parameter"):
        IssuerEntityCreate.model_validate(
            {
                "organization_id": "20000000-0000-4000-8000-000000000001",
                "issuer_id": "did:web:issuer.example",
                "display_name": "Example Issuer",
                "metadata": {
                    "verification_keys": [
                        {
                            "kty": "EC",
                            "crv": "P-256",
                            "x": "public-x",
                            "y": "public-y",
                            "d": "must-remain-in-managed-custody",
                        }
                    ]
                },
            }
        )


def test_obsolete_combined_trusted_issuer_shape_is_rejected() -> None:
    with pytest.raises(ValidationError):
        TrustProfileIssuerCreate.model_validate(
            {
                "issuer_id": ENTITY_ID,
                "name": "Legacy combined resource",
                "issuer_did": "did:example:legacy",
            }
        )
