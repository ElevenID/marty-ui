"""Committed language-neutral bootstrap corpus and active Rust launch contract."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from scripts import check_migration_bootstrap_reference as comparison

ROOT = Path(__file__).resolve().parents[1]


def _cases():
    reference = json.loads(comparison.OUTPUT.read_text(encoding="utf-8"))
    assert len(reference["cases"]) == 18
    return {case["name"]: case for case in reference["cases"]}


def test_frozen_apply_order_and_retry_boundaries():
    cases = _cases()
    clean = cases["clean_apply"]
    effects = clean["effects"]
    assert effects.index("postgres.commit") < effects.index("openbao.post:sys/mounts/transit")
    assert effects.index("openbao.post:transit/keys/notification-webhook-envelope-marty-aes256") < effects.index("openbao.post:transit/keys/flow-response-envelope-marty-aes256")
    assert effects.index("redis.set:org:00000000-0000-0000-0000-000000000001:signing-key-services") < effects.index("redis.set:org:00000000-0000-0000-0000-000000000001:issuer-profiles")
    assert cases["repeat_apply"]["state"] == clean["state"]
    assert cases["partial_redis_write_then_retry"]["exit_codes"] == [1, 0]
    assert cases["partial_redis_write_then_retry"]["state"] == clean["state"]
    assert cases["redis_ping_final_failure"]["effects"].count("redis.ping") == 5


def test_frozen_profile_preservation_disposable_and_verify_only():
    cases = _cases()
    org = "00000000-0000-0000-0000-000000000001"
    preserved = cases["preserve_customer_profile"]["state"]["redis"]
    assert any(profile["id"] == "customer-profile" for profile in preserved[f"org:{org}:issuer-profiles"]["profiles"])
    assert cases["disposable_precreated_keys"]["exit_codes"] == [0]
    for name in ("disposable_bad_tuple", "unsafe_notification_kek", "missing_notification_kek_create_denied", "missing_database_url", "missing_bao_token", "schema_failure"):
        assert cases[name]["exit_codes"] == [1], name
    assert cases["verify_only"]["effects"] == ["run:1"]
    assert cases["verify_only"]["state"]["openbao_keys"] == {}


def test_guarded_shell_runs_notification_after_successful_rust_bootstrap():
    shell = (ROOT / "scripts/run-migrations-with-secrets.sh").read_text(encoding="utf-8")
    ordered = ["set -e", ". /app/load-secrets-env.sh", "require_secret_var MARTY_DB_PASSWORD", "admin_email=", "case \"${admin_email}\" in", "/usr/local/bin/marty-migration-bootstrap", "exec /usr/local/bin/marty-notification --migrate"]
    assert [shell.index(marker) for marker in ordered] == sorted(shell.index(marker) for marker in ordered)
    assert "admin@example.com|user@example.com|example@example.com|change-me*" in shell
    assert "python " not in shell


def test_candidate_receives_only_explicit_simulated_inputs(monkeypatch):
    cases = _cases()
    for name in ("DATABASE_URL", "REDIS_URL", "BAO_TOKEN", "OPENBAO_SERVICE_TOKEN"):
        monkeypatch.setenv(name, "live-value-that-must-not-pass")

    def fake_run(_command, *, input, env, **_kwargs):
        assert not {"DATABASE_URL", "REDIS_URL", "BAO_TOKEN", "OPENBAO_SERVICE_TOKEN"} & set(env)
        invocation = json.loads(input)
        assert invocation["input"]["environment"]["BAO_ADDR"] == "http://openbao.test:8200"
        case = cases[invocation["name"]]
        return SimpleNamespace(returncode=0, stdout=json.dumps({key: case[key] for key in ("exit_codes", "effects", "state", "error_tags")}), stderr="")

    monkeypatch.setattr(comparison.subprocess, "run", fake_run)
    assert comparison.check(["fixture-candidate"]) == []
