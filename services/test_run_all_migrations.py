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
