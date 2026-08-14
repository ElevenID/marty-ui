import json
import sys
import types

if "marty_common.migration" not in sys.modules:
    migration_stub = types.ModuleType("marty_common.migration")
    migration_stub.AlembicMigrationAdapter = object
    migration_stub.MigrationError = RuntimeError
    sys.modules["marty_common.migration"] = migration_stub

import run_all_migrations as migrations


class FakeRedis:
    def __init__(self):
        self.store = {}

    def get(self, key):
        return self.store.get(key)

    def set(self, key, value):
        self.store[key] = value
        return True


def test_revocation_schema_is_removed_from_the_python_migration_graph() -> None:
    order = [service["name"] for service in migrations.SERVICES]

    assert "revocation_profile" not in order
    assert order.index("credential_template") < order.index("trust_profile")


def test_notification_schema_is_removed_from_the_python_migration_graph() -> None:
    services = {service["name"]: service["module"] for service in migrations.SERVICES}

    assert "notification" not in services


def test_notification_webhook_envelope_key_is_prepared_before_migration(
    monkeypatch,
) -> None:
    calls = []
    monkeypatch.setenv("BAO_ADDR", "https://bao.example")
    monkeypatch.setenv("OPENBAO_SERVICE_TOKEN", "scoped-token")
    monkeypatch.delenv("BAO_TOKEN", raising=False)
    monkeypatch.setattr(
        migrations,
        "_ensure_transit_mount",
        lambda address, token: calls.append(("mount", address, token)),
    )
    monkeypatch.setattr(
        migrations,
        "_ensure_openbao_symmetric_key",
        lambda address, token, key_id, description: calls.append(
            ("key", address, token, key_id, description)
        ),
    )

    assert migrations.prepare_notification_webhook_envelope_key() is True
    assert calls == [
        ("mount", "https://bao.example", "scoped-token"),
        (
            "key",
            "https://bao.example",
            "scoped-token",
            migrations.MARTY_NOTIFICATION_WEBHOOK_ENVELOPE_KEY_ID,
            "notification webhook envelope",
        ),
    ]


def test_notification_webhook_envelope_preparation_fails_without_kms(
    monkeypatch,
) -> None:
    for name in (
        "BAO_ADDR",
        "BAO_TOKEN",
        "BAO_TOKEN_FILE",
        "OPENBAO_SERVICE_TOKEN",
        "OPENBAO_SERVICE_TOKEN_FILE",
    ):
        monkeypatch.delenv(name, raising=False)

    assert migrations.prepare_notification_webhook_envelope_key() is False


def test_device_registration_schema_is_owned_by_the_deployment_migration_runner() -> None:
    services = {service["name"]: service["module"] for service in migrations.SERVICES}

    assert services["device_registration"] == "device_registration.infrastructure.models"


def test_seed_signing_registry_binds_lti_key_inside_multi_key_service() -> None:
    redis = FakeRedis()
    organization_id = "00000000-0000-0000-0000-000000000001"

    migrations._seed_signing_registry(
        redis,
        organization_id,
        migrations.MARTY_KMS_KEY_SPECS,
    )

    payload = json.loads(redis.store[migrations._storage_key(organization_id)])
    managed = next(
        service
        for service in payload["services"]
        if service["id"] == migrations.MANAGED_OPENBAO_SERVICE_ID
    )
    bindings = payload["key_reference_purposes"][migrations.MANAGED_OPENBAO_SERVICE_ID]

    assert "lti_tool_signing" in managed["key_purposes"]
    assert "oid4vp_request_signing" in managed["key_purposes"]
    assert "vc_jwt_issuer" in managed["key_purposes"]
    assert "ldp_vc" in managed["credential_formats"]
    assert payload["format_defaults"]["ldp_vc"] == migrations.MANAGED_OPENBAO_SERVICE_ID
    ldp_keys = [
        key
        for key in migrations.MARTY_KMS_KEY_SPECS
        if "ldp_vc" in key.get("credential_formats", [])
    ]
    assert [key["id"] for key in ldp_keys] == ["cred-issuer-marty-eddsa"]
    assert ldp_keys[0]["algorithm"] == "EdDSA"
    assert bindings["lti-tool-marty-rs256"] == ["lti_tool_signing"]
    assert bindings["oid4vp-verifier-marty-es256"] == ["oid4vp_request_signing"]
    assert bindings["cred-issuer-marty-rs256"] == ["vc_jwt_issuer"]
    assert bindings["lti-tool-marty-rs256"] != bindings["cred-issuer-marty-rs256"]


def test_seed_signing_registry_preserves_custom_managed_key_bindings() -> None:
    redis = FakeRedis()
    organization_id = "00000000-0000-0000-0000-000000000001"
    redis.store[migrations._storage_key(organization_id)] = json.dumps(
        {
            "key_reference_purposes": {
                migrations.MANAGED_OPENBAO_SERVICE_ID: {
                    "cred-issuer-customer-es256": ["vc_jwt_issuer"],
                }
            }
        }
    )

    migrations._seed_signing_registry(
        redis,
        organization_id,
        migrations.MARTY_KMS_KEY_SPECS,
    )

    payload = json.loads(redis.store[migrations._storage_key(organization_id)])
    bindings = payload["key_reference_purposes"][migrations.MANAGED_OPENBAO_SERVICE_ID]
    assert bindings["cred-issuer-customer-es256"] == ["vc_jwt_issuer"]
    assert bindings["lti-tool-marty-rs256"] == ["lti_tool_signing"]


def test_seed_issuer_did_publishes_lti_assertion_but_credential_jwks_excludes_it() -> None:
    redis = FakeRedis()
    organization_id = "00000000-0000-0000-0000-000000000001"
    issuer_did = "did:web:issuer.example"
    credential_key = {
        "id": "cred-issuer-marty-rs256",
        "key_purposes": ["vc_jwt_issuer"],
        "public_jwk": {
            "kty": "RSA",
            "alg": "RS256",
            "n": "credential-modulus",
            "e": "AQAB",
        },
    }
    lti_key = {
        "id": "lti-tool-marty-rs256",
        "key_purposes": ["lti_tool_signing"],
        "public_jwk": {
            "kty": "RSA",
            "alg": "RS256",
            "n": "lti-modulus",
            "e": "AQAB",
        },
    }

    migrations._seed_did_and_jwks(
        redis,
        organization_id,
        issuer_did,
        [credential_key, lti_key],
    )

    did_document = json.loads(
        redis.store[migrations._did_doc_storage_key(organization_id)]
    )
    scoped_did_document = json.loads(
        redis.store[migrations._did_doc_storage_key(organization_id, issuer_did)]
    )
    issuer_jwks = json.loads(redis.store[migrations._jwks_storage_key(organization_id)])
    assert scoped_did_document == did_document
    serialized_did = json.dumps(did_document)
    assert "cred-issuer-marty-rs256" in serialized_did
    assert "lti-tool-marty-rs256" in serialized_did
    assert any(
        "lti-tool-marty-rs256" in method
        for method in did_document["assertionMethod"]
    )
    assert [key["kid"] for key in issuer_jwks["keys"]] == ["cred-issuer-marty-rs256"]


def test_seed_issuer_did_backfills_legacy_mixed_documents_by_controller() -> None:
    redis = FakeRedis()
    organization_id = "00000000-0000-0000-0000-000000000001"
    seeded_did = "did:web:beta.elevenidllc.com:orgs:marty"
    suite_did = "did:web:beta.elevenidllc.com:orgs:official-suite"
    seeded_method = f"{seeded_did}#seeded-key"
    suite_method = f"{suite_did}#suite-key"
    redis.store[migrations._did_doc_storage_key(organization_id)] = json.dumps(
        {
            "id": suite_did,
            "controller": suite_did,
            "verificationMethod": [
                {
                    "id": seeded_method,
                    "controller": seeded_did,
                    "publicKeyJwk": {"kty": "EC", "crv": "P-256"},
                },
                {
                    "id": suite_method,
                    "controller": suite_did,
                    "publicKeyJwk": {"kty": "EC", "crv": "P-256"},
                },
            ],
            "assertionMethod": [seeded_method, suite_method],
        }
    )

    migrations._seed_did_and_jwks(redis, organization_id, seeded_did, [])

    seeded_document = json.loads(
        redis.store[migrations._did_doc_storage_key(organization_id, seeded_did)]
    )
    suite_document = json.loads(
        redis.store[migrations._did_doc_storage_key(organization_id, suite_did)]
    )
    assert [
        method["id"] for method in seeded_document["verificationMethod"]
    ] == [seeded_method]
    assert seeded_document["assertionMethod"] == [seeded_method]
    assert [method["id"] for method in suite_document["verificationMethod"]] == [
        suite_method
    ]
    assert suite_document["assertionMethod"] == [suite_method]


def test_seed_issuer_profiles_creates_active_marty_kms_profiles():
    redis = FakeRedis()
    organization_id = "00000000-0000-0000-0000-000000000001"
    issuer_did = "did:web:beta.elevenidllc.com:orgs:marty"

    migrations._seed_issuer_profiles(
        redis,
        organization_id,
        issuer_did,
        "https://beta.elevenidllc.com",
    )

    payload = json.loads(
        redis.store[migrations._issuer_profiles_storage_key(organization_id)]
    )
    profiles = {profile["id"]: profile for profile in payload["profiles"]}

    assert set(profiles) == {
        "ip-marty-vc-jwt-issuer",
        "ip-marty-sd-jwt-issuer",
        "ip-marty-oid4vp-verifier",
        "ip-marty-canvas-lti-tool",
        "ip-marty-mdoc-dsc",
        "ip-marty-vdsnc-issuer",
    }
    assert (
        profiles["ip-marty-vc-jwt-issuer"]["signing_service_id"]
        == migrations.MANAGED_OPENBAO_SERVICE_ID
    )
    assert (
        profiles["ip-marty-vc-jwt-issuer"]["signing_key_reference"]
        == "cred-issuer-marty-es256"
    )
    assert profiles["ip-marty-vc-jwt-issuer"]["key_purpose"] == "vc_jwt_issuer"
    assert profiles["ip-marty-vc-jwt-issuer"]["credential_format"] == "VC_JWT"
    assert profiles["ip-marty-vc-jwt-issuer"]["algorithm"] == "ES256"
    assert (
        profiles["ip-marty-sd-jwt-issuer"]["signing_key_reference"]
        == "cred-issuer-marty-es256"
    )
    assert profiles["ip-marty-sd-jwt-issuer"]["key_purpose"] == "vc_jwt_issuer"
    assert profiles["ip-marty-sd-jwt-issuer"]["credential_format"] == "SD_JWT_VC"
    assert profiles["ip-marty-sd-jwt-issuer"]["algorithm"] == "ES256"
    assert (
        profiles["ip-marty-oid4vp-verifier"]["signing_key_reference"]
        == "oid4vp-verifier-marty-es256"
    )
    assert (
        profiles["ip-marty-oid4vp-verifier"]["key_purpose"] == "oid4vp_request_signing"
    )
    assert (
        profiles["ip-marty-oid4vp-verifier"]["credential_format"] == "SD_JWT_VC"
    )
    assert profiles["ip-marty-oid4vp-verifier"]["algorithm"] == "ES256"
    assert (
        profiles["ip-marty-canvas-lti-tool"]["signing_key_reference"]
        == "lti-tool-marty-rs256"
    )
    assert profiles["ip-marty-canvas-lti-tool"]["key_purpose"] == "lti_tool_signing"
    assert profiles["ip-marty-canvas-lti-tool"]["credential_format"] == "VC_JWT"
    assert profiles["ip-marty-canvas-lti-tool"]["algorithm"] == "RS256"
    assert (
        profiles["ip-marty-mdoc-dsc"]["signing_key_reference"]
        == "cred-dsc-marty-primary"
    )
    assert profiles["ip-marty-mdoc-dsc"]["key_purpose"] == "mdoc_dsc"
    assert profiles["ip-marty-mdoc-dsc"]["credential_format"] == "MDOC"
    assert profiles["ip-marty-mdoc-dsc"]["algorithm"] == "ES256"
    assert (
        profiles["ip-marty-vdsnc-issuer"]["signing_key_reference"]
        == "cred-dsc-marty-primary"
    )
    assert profiles["ip-marty-vdsnc-issuer"]["credential_format"] == "MDOC"
    assert profiles["ip-marty-vdsnc-issuer"]["key_purpose"] == "vdsnc_signing"
    assert profiles["ip-marty-vdsnc-issuer"]["algorithm"] == "ES256"

    for profile in profiles.values():
        assert profile["organization_id"] == organization_id
        assert profile["issuer_did"] == issuer_did
        assert profile["status"] == "active"
        assert profile["verification_method_id"].startswith(f"{issuer_did}#")


def test_seed_issuer_profiles_repairs_and_deduplicates_legacy_oid4vp_binding():
    redis = FakeRedis()
    organization_id = "00000000-0000-0000-0000-000000000001"
    issuer_did = "did:web:beta.elevenidllc.com:orgs:marty"
    storage_key = migrations._issuer_profiles_storage_key(organization_id)
    common = {
        "organization_id": organization_id,
        "issuer_did": issuer_did,
        "signing_service_id": migrations.MANAGED_OPENBAO_SERVICE_ID,
        "signing_key_reference": "oid4vp-verifier-marty-es256",
        "key_purpose": "oid4vp_request_signing",
        "algorithm": "ES256",
        "status": "active",
    }
    redis.store[storage_key] = json.dumps(
        {
            "profiles": [
                {"id": "ip-marty-oid4vp-verifier", **common},
                {
                    "id": "generated-duplicate",
                    **common,
                    "credential_format": "SD_JWT_VC",
                },
            ]
        }
    )

    migrations._seed_issuer_profiles(
        redis,
        organization_id,
        issuer_did,
        "https://beta.elevenidllc.com",
    )

    profiles = json.loads(redis.store[storage_key])["profiles"]
    matching = [
        profile
        for profile in profiles
        if profile.get("key_purpose") == "oid4vp_request_signing"
        and profile.get("issuer_did") == issuer_did
    ]
    assert [profile["id"] for profile in matching] == [
        "ip-marty-oid4vp-verifier"
    ]
    assert matching[0]["credential_format"] == "SD_JWT_VC"
