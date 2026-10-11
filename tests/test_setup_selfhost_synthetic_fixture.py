"""Synthetic fixture refuses unrelated identities and unbound transit keys."""

import base64
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from setup_selfhost_synthetic_fixture import (  # noqa: E402
    managed_reference,
    profile_proof,
    required_environment,
    validate_audit_token,
    validate_installed_model,
    validate_profile_projection,
    validate_transit_binding,
)


def fixture_env() -> dict[str, str]:
    names = (
        "SELFHOST_GATEWAY_URL", "SELFHOST_KEYCLOAK_URL", "SELFHOST_PUBLIC_DOMAIN",
        "SELFHOST_TEST_USERNAME", "SELFHOST_TEST_PASSWORD", "SELFHOST_ORG_ID",
        "SELFHOST_ISSUER_DID", "SELFHOST_VERIFIER_DID",
        "SELFHOST_SECRET_ROOT", "SELFHOST_COMPOSE_MODEL_PATH",
        "SELFHOST_BAO_AUDIT_URL", "SELFHOST_BAO_AUDIT_TOKEN_FILE",
        "SELFHOST_CUSTODY_SIGNING_KEY_FILE", "SELFHOST_SOURCE_SHA",
        "SELFHOST_ARCHIVE_SHA256", "SELFHOST_IMAGE_LOCK_SHA256",
        "SELFHOST_KMS_CUSTODY_EVIDENCE_PATH", "SELFHOST_KMS_CUSTODY_SIGNATURE_PATH",
    )
    values = {name: "fixture" for name in names}
    values.update(SELFHOST_PUBLIC_DOMAIN="selfhost.marty.test",
                  SELFHOST_TEST_USERNAME="operator@selfhost.marty.invalid",
                  SELFHOST_ORG_ID="00000000-0000-0000-0000-000000000001",
                  SELFHOST_GATEWAY_URL="http://127.0.0.1:19080",
                  SELFHOST_KEYCLOAK_URL="http://127.0.0.1:18180",
                  SELFHOST_BAO_AUDIT_URL="http://127.0.0.1:18200")
    did = "did:web:selfhost.marty.test:orgs:" + values["SELFHOST_ORG_ID"]
    values.update(SELFHOST_ISSUER_DID=did, SELFHOST_VERIFIER_DID=did)
    return values


def test_synthetic_identity_is_bound_to_public_domain_and_seeded_org() -> None:
    values = fixture_env()
    assert required_environment(values)["SELFHOST_ISSUER_DID"] == values["SELFHOST_VERIFIER_DID"]
    values["SELFHOST_VERIFIER_DID"] = "did:web:elsewhere"
    with pytest.raises(ValueError, match="share the local organization DID"):
        required_environment(values)
    values = fixture_env()
    values["SELFHOST_TEST_USERNAME"] = "real@company.example"
    with pytest.raises(ValueError, match="reserved test domain"):
        required_environment(values)


def test_migration_admin_must_match_synthetic_public_operator() -> None:
    values = fixture_env()
    model = {"services": {
        "db-migrate": {"environment": {"MARTY_ORG_ID": values["SELFHOST_ORG_ID"],
                                       "MARTY_ORG_ADMIN_EMAIL": values["SELFHOST_TEST_USERNAME"],
                                       "PUBLIC_DOMAIN": values["SELFHOST_PUBLIC_DOMAIN"]}},
        "keycloak-configurator": {"environment": {
            "MARTY_ORG_ADMIN_EMAIL": values["SELFHOST_TEST_USERNAME"],
            "KEYCLOAK_REALM": "11id", "PUBLIC_DOMAIN": values["SELFHOST_PUBLIC_DOMAIN"]}},
        "signing-keys": {"environment": {"BAO_ADDR": "http://host.docker.internal:18200"}},
        "edge": {"ports": [{"host_ip": "127.0.0.1", "published": "19080",
                            "target": 80, "protocol": "tcp"}]},
        "keycloak": {"ports": [{"host_ip": "127.0.0.1", "published": "18180",
                                "target": 8080, "protocol": "tcp"}]},
    }}
    validate_installed_model(model, values)
    model["services"]["db-migrate"]["environment"]["MARTY_ORG_ADMIN_EMAIL"] = "other@example.test"
    with pytest.raises(ValueError, match="migration-seeded organization"):
        validate_installed_model(model, values)


@pytest.mark.parametrize("service,url_name,other_port", [
    ("edge", "SELFHOST_GATEWAY_URL", 19081),
    ("keycloak", "SELFHOST_KEYCLOAK_URL", 18181),
])
def test_journey_urls_must_use_installed_published_ports(
        service: str, url_name: str, other_port: int) -> None:
    values = fixture_env()
    model = {"services": {
        "db-migrate": {"environment": {"MARTY_ORG_ID": values["SELFHOST_ORG_ID"],
                                       "MARTY_ORG_ADMIN_EMAIL": values["SELFHOST_TEST_USERNAME"],
                                       "PUBLIC_DOMAIN": values["SELFHOST_PUBLIC_DOMAIN"]}},
        "keycloak-configurator": {"environment": {
            "MARTY_ORG_ADMIN_EMAIL": values["SELFHOST_TEST_USERNAME"],
            "KEYCLOAK_REALM": "11id", "PUBLIC_DOMAIN": values["SELFHOST_PUBLIC_DOMAIN"]}},
        "signing-keys": {"environment": {"BAO_ADDR": "http://host.docker.internal:18200"}},
        "edge": {"ports": [{"host_ip": "127.0.0.1", "published": "19080", "target": 80}]},
        "keycloak": {"ports": [{"host_ip": "127.0.0.1", "published": "18180", "target": 8080}]},
    }}
    validate_installed_model(model, values)
    values[url_name] = f"http://127.0.0.1:{other_port}"
    with pytest.raises(ValueError, match="differs from installed"):
        validate_installed_model(model, values)
    values = fixture_env()
    model["services"][service]["ports"].append(
        {"host_ip": "127.0.0.1", "published": str(other_port), "target": 80})
    with pytest.raises(ValueError, match="differs from installed"):
        validate_installed_model(model, values)


def test_signed_profile_selector_has_no_null_private_id() -> None:
    values = fixture_env()
    selector = validate_profile_projection({
        "issuer_did": values["SELFHOST_ISSUER_DID"],
        "key_purpose": "vc_jwt_issuer", "credential_format": "SD_JWT_VC",
        "algorithm": "ES256", "status": "active",
    }, did=values["SELFHOST_ISSUER_DID"], purpose="vc_jwt_issuer")
    assert selector == {"issuer_did": values["SELFHOST_ISSUER_DID"],
                        "key_purpose": "vc_jwt_issuer", "credential_format": "SD_JWT_VC",
                        "algorithm": "ES256"}
    assert "profile_id" not in selector
    assert profile_proof(selector, "cred-issuer-test-es256", 1) == {
        "profile_selector": selector,
        "key_reference": "cred-issuer-test-es256", "key_version": 1}
    with pytest.raises(ValueError, match="incomplete"):
        profile_proof(selector, "cred-issuer-test-es256", 0)
    with pytest.raises(ValueError, match="differs from expected selector"):
        validate_profile_projection({**selector, "status": "active",
                                     "key_purpose": "oid4vp_request_signing"},
                                    did=values["SELFHOST_ISSUER_DID"], purpose="vc_jwt_issuer")


def test_purpose_specific_managed_key_references_are_distinct() -> None:
    values = fixture_env()
    org, did = values["SELFHOST_ORG_ID"], values["SELFHOST_ISSUER_DID"]
    issuer = managed_reference(org, did, "vc_jwt_issuer")
    verifier = managed_reference(org, did, "oid4vp_request_signing")
    assert issuer.startswith("cred-issuer-")
    assert verifier.startswith("oid4vp-verifier-")
    assert issuer != verifier
    with pytest.raises(ValueError, match="unsupported"):
        managed_reference(org, did, "mdoc_dsc")


def test_public_profile_key_must_equal_nonexportable_transit_key() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    public = key.public_key()
    numbers = public.public_numbers()
    def encode(value: int) -> str:
        return base64.urlsafe_b64encode(value.to_bytes(32, "big")).decode().rstrip("=")
    jwk = {"kty": "EC", "crv": "P-256", "x": encode(numbers.x), "y": encode(numbers.y)}
    pem = public.public_bytes(serialization.Encoding.PEM,
                              serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    metadata = {"type": "ecdsa-p256", "exportable": False, "latest_version": 2,
                "keys": {"2": {"public_key": pem}}}
    assert validate_transit_binding(metadata, jwk) == 2
    with pytest.raises(ValueError, match="public DID key differs"):
        validate_transit_binding(metadata, {**jwk, "x": "wrong"})
    with pytest.raises(ValueError, match="non-exportable"):
        validate_transit_binding({**metadata, "exportable": True}, jwk)


def test_openbao_audit_token_rejects_root_or_long_lived_authority() -> None:
    scoped = {"policies": ["default", "selfhost-qualification-audit"], "ttl": 900}
    validate_audit_token(scoped)
    for candidate in ({**scoped, "policies": ["root"]},
                      {**scoped, "ttl": 7200},
                      {**scoped, "policies": ["selfhost-qualification-audit", "admin"]}):
        with pytest.raises(ValueError, match="expected policy name or short TTL"):
            validate_audit_token(candidate)
