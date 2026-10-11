"""Behavior freeze for the last shared Python deployment bootstrap."""

from __future__ import annotations

import json
from types import SimpleNamespace

from scripts.capture_migration_bootstrap_reference import OUTPUT, capture
from scripts import check_migration_bootstrap_reference as comparison


def _cases():
    reference = capture()
    assert reference == json.loads(OUTPUT.read_text(encoding="utf-8"))
    return {case["name"]: case for case in reference["cases"]}


def test_apply_order_and_repeat_are_idempotent():
    cases = _cases()
    clean = cases["clean_apply"]
    repeat = cases["repeat_apply"]
    effects = clean["effects"]
    assert clean["exit_codes"] == [0]
    assert effects.index("postgres.commit") < effects.index(
        "openbao.post:sys/mounts/transit")
    assert effects.index("openbao.post:transit/keys/notification-webhook-envelope-marty-aes256") < effects.index(
        "openbao.post:transit/keys/flow-response-envelope-marty-aes256")
    assert effects.index("redis.set:org:00000000-0000-0000-0000-000000000001:signing-key-services") < effects.index(
        "redis.set:org:00000000-0000-0000-0000-000000000001:issuer-profiles")
    assert repeat["exit_codes"] == [0, 0]
    assert repeat["state"] == clean["state"]
    assert sum(effect.startswith("openbao.post:transit/keys/")
               for effect in repeat["effects"]) == 9
    jwks = clean["state"]["redis"][
        "org:00000000-0000-0000-0000-000000000001:signing-key-jwks"]["keys"]
    by_kid = {jwk["kid"]: jwk for jwk in jwks}
    assert by_kid["cred-issuer-marty-rs256"]["kty"] == "RSA"
    assert by_kid["cred-issuer-marty-eddsa"]["crv"] == "Ed25519"
    assert by_kid["cred-issuer-marty-es384"]["crv"] == "P-384"


def test_existing_profiles_and_did_controllers_survive():
    cases = _cases()
    org = "00000000-0000-0000-0000-000000000001"
    preserved = cases["preserve_customer_profile"]["state"]["redis"]
    profiles = preserved[f"org:{org}:issuer-profiles"]["profiles"]
    assert any(profile["id"] == "customer-profile" for profile in profiles)
    services = preserved[f"org:{org}:signing-key-services"]
    assert any(service["id"] == "customer-hsm" for service in services["services"])
    assert services["key_reference_purposes"]["managed-openbao-transit"][
        "customer-key"] == ["vc_jwt_issuer"]
    backfilled = cases["backfill_mixed_did"]["state"]["redis"]
    assert any(key.endswith(":did:" + __import__("hashlib").sha256(
        b"did:web:other.example").hexdigest()) for key in backfilled)


def test_failure_and_verify_only_boundaries():
    cases = _cases()
    for name in ("disposable_bad_tuple", "unsafe_notification_kek",
                 "missing_notification_kek_create_denied",
                 "redis_ping_final_failure", "missing_database_url",
                 "missing_bao_token", "schema_failure"):
        assert cases[name]["exit_codes"] == [1], name
    assert cases["conflicting_managed_purpose"]["exit_codes"] == [1]
    assert cases["disposable_precreated_keys"]["exit_codes"] == [0]
    assert cases["token_precedence"]["state"]["openbao_token_roles_used"] == [
        "service", "bao"]
    for name in ("bootstrap_disabled", "redis_absent"):
        assert cases[name]["exit_codes"] == [0]
        assert cases[name]["state"]["redis"] == {}
    assert cases["partial_redis_write_then_retry"]["exit_codes"] == [1, 0]
    assert cases["partial_redis_write_then_retry"]["state"] == cases["clean_apply"]["state"]
    assert cases["redis_ping_final_failure"]["effects"].count("redis.ping") == 5
    assert cases["schema_failure"]["state"]["postgres_schemas"] == []
    assert cases["verify_only"]["exit_codes"] == [0]
    assert cases["verify_only"]["effects"] == ["run:1"]
    assert cases["verify_only"]["state"]["openbao_keys"] == {}


def test_shell_runs_rust_notification_only_after_python_success():
    reference = capture()
    assert reference["shell_guard_markers"][:3] == [
        "set -e", ". /app/load-secrets-env.sh",
        "require_secret_var MARTY_DB_PASSWORD",
    ]
    assert reference["shell_commands_after_secret_and_admin_guards"] == [
        "python /app/services/run_all_migrations.py",
        "exec /usr/local/bin/marty-notification --migrate",
    ]


def test_candidate_receives_only_explicit_simulated_inputs(monkeypatch):
    reference = capture()
    expected = {case["name"]: case for case in reference["cases"]}
    for name in ("DATABASE_URL", "REDIS_URL", "BAO_TOKEN",
                 "OPENBAO_SERVICE_TOKEN"):
        monkeypatch.setenv(name, "live-value-that-must-not-pass")

    def fake_run(_command, *, input, env, **_kwargs):
        assert not {"DATABASE_URL", "REDIS_URL", "BAO_TOKEN",
                    "OPENBAO_SERVICE_TOKEN"} & set(env)
        invocation = json.loads(input)
        assert invocation["input"]["environment"]["BAO_ADDR"] == (
            "http://openbao.test:8200")
        case = expected[invocation["name"]]
        return SimpleNamespace(returncode=0, stdout=json.dumps({
            key: case[key] for key in
            ("exit_codes", "effects", "state", "error_tags")}), stderr="")

    monkeypatch.setattr(comparison.subprocess, "run", fake_run)
    monkeypatch.setattr(comparison, "capture", lambda: reference)
    assert comparison.check(["fixture-candidate"]) == []
