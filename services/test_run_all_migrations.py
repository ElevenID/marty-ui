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


def test_revocation_schema_precedes_dependent_migrations() -> None:
    order = [service["name"] for service in migrations.SERVICES]

    assert order.index("revocation_profile") < order.index("credential_template")
    assert order.index("revocation_profile") < order.index("trust_profile")


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
    assert "vc_jwt_issuer" in managed["key_purposes"]
    assert bindings["lti-tool-marty-rs256"] == ["lti_tool_signing"]
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


def test_seed_issuer_did_and_jwks_excludes_lti_protocol_key() -> None:
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

    did_document = json.loads(redis.store[migrations._did_doc_storage_key(organization_id)])
    issuer_jwks = json.loads(redis.store[migrations._jwks_storage_key(organization_id)])
    serialized_did = json.dumps(did_document)
    assert "cred-issuer-marty-rs256" in serialized_did
    assert "lti-tool-marty-rs256" not in serialized_did
    assert [key["kid"] for key in issuer_jwks["keys"]] == [
        "cred-issuer-marty-rs256"
    ]


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

    payload = json.loads(redis.store[migrations._issuer_profiles_storage_key(organization_id)])
    profiles = {profile["id"]: profile for profile in payload["profiles"]}

    assert set(profiles) == {
        "ip-marty-vc-jwt-issuer",
        "ip-marty-mdoc-dsc",
        "ip-marty-vdsnc-issuer",
    }
    assert profiles["ip-marty-vc-jwt-issuer"]["signing_service_id"] == migrations.MANAGED_OPENBAO_SERVICE_ID
    assert profiles["ip-marty-vc-jwt-issuer"]["signing_key_reference"] == "cred-issuer-marty-es256"
    assert profiles["ip-marty-vc-jwt-issuer"]["key_purpose"] == "vc_jwt_issuer"
    assert profiles["ip-marty-mdoc-dsc"]["signing_key_reference"] == "cred-dsc-marty-primary"
    assert profiles["ip-marty-mdoc-dsc"]["key_purpose"] == "mdoc_dsc"
    assert profiles["ip-marty-vdsnc-issuer"]["signing_key_reference"] == "cred-dsc-marty-primary"
    assert profiles["ip-marty-vdsnc-issuer"]["key_purpose"] == "vdsnc_signing"

    for profile in profiles.values():
        assert profile["organization_id"] == organization_id
        assert profile["issuer_did"] == issuer_did
        assert profile["status"] == "active"
        assert profile["verification_method_id"].startswith(f"{issuer_did}#")
