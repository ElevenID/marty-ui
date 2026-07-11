"""Tests for OID4VCI issuer metadata compatibility normalization."""

from __future__ import annotations

import json

from gateway.main import _normalize_oid4vci_issuer_metadata_content


def test_oid4vci_metadata_normalizer_strips_legacy_claim_descriptors() -> None:
    legacy_metadata = {
        "credential_issuer": "https://issuer.example/org/org-1",
        "credential_configurations_supported": {
            "MemberCredential": {
                "format": "jwt_vc_json",
                "credential_definition": {
                    "type": ["VerifiableCredential", "MemberCredential"],
                    "credentialSubject": {
                        "email": {
                            "display": [{"name": "Email Address", "locale": "en-US"}],
                            "description": "Holder email address",
                        },
                        "given_name": {
                            "display": [{"name": "Given Name", "locale": "en-US"}],
                            "required": True,
                        },
                    },
                },
                "display": [{"name": "Member Login Credential", "locale": "en-US"}],
            }
        },
    }

    content = json.dumps(legacy_metadata).encode("utf-8")
    normalized = json.loads(
        _normalize_oid4vci_issuer_metadata_content(content, "application/json").decode("utf-8")
    )

    config = normalized["credential_configurations_supported"]["MemberCredential"]
    assert config["credential_definition"] == {
        "type": ["VerifiableCredential", "MemberCredential"]
    }
    assert config["credential_metadata"]["display"] == [
        {"name": "Member Login Credential", "locale": "en-US"}
    ]
    assert "claims" not in config["credential_metadata"]


def test_oid4vci_metadata_normalizer_serves_waltid_legacy_metadata_shape() -> None:
    metadata = {
        "credential_issuer": "https://issuer.example/org/org-1",
        "credential_endpoint": "https://issuer.example/v1/credential",
        "credential_configurations_supported": {
            "MemberCredential": {
                "format": "jwt_vc_json",
                "credential_definition": {
                    "type": ["VerifiableCredential", "MemberCredential"],
                    "credentialSubject": {
                        "email": {"display": [{"name": "Email Address"}]},
                    },
                },
                "display": [{"name": "Member Login Credential", "locale": "en-US"}],
                "cryptographic_binding_methods_supported": ["did:key", "jwk"],
                "credential_signing_alg_values_supported": ["ES256"],
            },
            "com.icao.dtc.1#vds-nc": {
                "format": "vds_nc",
                "display": [{"name": "Unsupported legacy VDS credential"}],
            }
        },
    }

    content = json.dumps(metadata).encode("utf-8")
    normalized = json.loads(
        _normalize_oid4vci_issuer_metadata_content(
            content,
            "application/json",
            wallet_variant="waltid",
        ).decode("utf-8")
    )

    assert normalized["credential_issuer"] == "https://issuer.example/org/org-1/waltid"
    supported = normalized["credentials_supported"]
    assert [credential["id"] for credential in supported] == [
        "MemberCredential",
        "MemberCredential#sd-jwt",
    ]
    assert list(normalized["credential_configurations_supported"].keys()) == [
        "MemberCredential",
        "MemberCredential#sd-jwt",
    ]
    assert normalized["credential_configurations_supported"]["MemberCredential#sd-jwt"] == supported[1]
    assert supported[1]["format"] == "jwt_vc_json"
    assert supported[1]["types"] == ["VerifiableCredential", "MemberCredential"]
    assert supported[1]["display"] == [
        {"name": "Member Login Credential", "locale": "en-US"}
    ]
    assert supported[1]["cryptographic_binding_methods_supported"] == ["did:key", "jwk"]
    assert supported[1]["cryptographic_suites_supported"] == ["ES256"]
    assert "credentialSubject" not in supported[1]


def test_oid4vci_metadata_normalizer_leaves_non_json_content_untouched() -> None:
    content = b"not-json"

    assert _normalize_oid4vci_issuer_metadata_content(content, "text/plain") is content
