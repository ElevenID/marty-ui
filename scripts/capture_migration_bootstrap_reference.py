#!/usr/bin/env python3
"""Freeze the shared Python bootstrap's externally visible decisions.

The adapters below are in-memory PostgreSQL, OpenBao, and Redis boundaries.
They run the published Python orchestration without network or secrets. Rust
consumers can replay the resulting language-neutral JSON cases.
"""

from __future__ import annotations

import argparse
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import types
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "contracts/migration-bootstrap-python-reference.json"
ORG = "00000000-0000-0000-0000-000000000001"
DID = "did:web:issuer.example:orgs:marty"


def _tracked_blob(relative: str) -> str:
    path = ROOT / relative
    actual = subprocess.check_output(
        ["git", "-C", str(ROOT), "hash-object", str(path)], text=True).strip()
    committed = subprocess.check_output(
        ["git", "-C", str(ROOT), "rev-parse", f"HEAD:{relative}"],
        text=True,
    ).strip()
    if actual != committed:
        raise ValueError(f"Executed source differs from committed {relative}")
    return actual


def _load_owner():
    # Only the profile and system-id imports are needed by this producer. The
    # released wheel is intentionally not a requirement for reference capture.
    common = types.ModuleType("marty_common")
    common.__path__ = []
    migration = types.ModuleType("marty_common.migration")
    migration.AlembicMigrationAdapter = object
    migration.MigrationError = RuntimeError
    profile = types.ModuleType("marty_common.migration_profile")
    profile.migration_profile = lambda: os.environ.get("MARTY_MIGRATION_PROFILE", "dev")
    profile.migration_profile_settings = lambda: types.SimpleNamespace(
        include_demo_seed_data=True, include_beta_seed_data=True,
        include_experimental_seed_data=False, include_test_seed_data=False,
        allow_experimental_data_fixes=True, persistent=False,
    )
    ids = types.ModuleType("marty_common.system_ids")
    ids.MARTY_DEFAULT_ORG_ID = ORG
    ids.MARTY_DEFAULT_ORG_SLUG = "marty"
    with patch.dict(sys.modules, {
        "marty_common": common, "marty_common.migration": migration,
        "marty_common.migration_profile": profile,
        "marty_common.system_ids": ids,
    }):
        original_path = list(sys.path)
        sys.path.insert(0, str(ROOT / "services"))
        try:
            spec = importlib.util.spec_from_file_location(
                "_captured_migration_bootstrap_owner",
                ROOT / "services/run_all_migrations.py",
            )
            assert spec is not None and spec.loader is not None
            run_all_migrations = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(run_all_migrations)
        finally:
            sys.path[:] = original_path
    return run_all_migrations


class FakeDatabase:
    def __init__(self, effects: list[str], fail: bool = False):
        self.effects = effects
        self.schemas: list[str] = []
        self.pending: list[str] = []
        self.fail = fail

    def connect(self):
        return self

    def __enter__(self):
        self.effects.append("postgres.connect")
        return self

    def __exit__(self, *_args):
        self.pending.clear()
        self.effects.append("postgres.close")

    def execute(self, sql):
        statement = str(sql)
        name = statement.removeprefix("CREATE SCHEMA IF NOT EXISTS ")
        if self.fail and name == "notification_service":
            self.effects.append("postgres.create_schema_failed:notification_service")
            raise RuntimeError("injected schema failure")
        self.effects.append(f"postgres.create_schema:{name}")
        if name not in self.schemas and name not in self.pending:
            self.pending.append(name)

    def commit(self):
        self.effects.append("postgres.commit")
        self.schemas.extend(self.pending)
        self.pending.clear()

    def dispose(self):
        self.effects.append("postgres.dispose")


class FakeRedis:
    def __init__(self, effects: list[str], initial: dict | None = None,
                 ping_failures: int = 0, fail_set: str | None = None):
        self.effects = effects
        self.store = {key: json.dumps(value) if isinstance(value, dict) else value
                      for key, value in (initial or {}).items()}
        self.ping_failures = ping_failures
        self.fail_set = fail_set

    def ping(self):
        self.effects.append("redis.ping")
        if self.ping_failures:
            self.ping_failures -= 1
            raise RuntimeError("injected Redis ping failure")
        return True

    def get(self, key):
        self.effects.append(f"redis.get:{key}")
        return self.store.get(key)

    def set(self, key, value):
        if key == self.fail_set:
            self.effects.append(f"redis.set_failed:{key}")
            self.fail_set = None
            raise RuntimeError("injected Redis write failure")
        self.effects.append(f"redis.set:{key}")
        self.store[key] = value
        return True


class FakeBao:
    def __init__(self, effects: list[str], *, unsafe_notification: bool = False,
                 deny_notification_create: bool = False,
                 precreated_disposable: list[str] | None = None):
        self.effects = effects
        self.mounted = False
        self.keys: dict[str, dict] = {}
        self.token_ids: list[str] = []
        self.deny_notification_create = deny_notification_create
        if unsafe_notification:
            self.keys["notification-webhook-envelope-marty-aes256"] = {
                "type": "aes256-gcm96", "exportable": True,
            }
        for key in precreated_disposable or []:
            self.keys[key] = {
                "type": "ecdsa-p256", "exportable": False,
                "latest_version": 1,
                "keys": {"1": {"public_key": self.public_pem("ecdsa-p256")}},
            }

    @staticmethod
    def public_pem(key_type: str) -> str:
        public_key = {
            "ecdsa-p256": lambda: ec.derive_private_key(1, ec.SECP256R1()).public_key(),
            "ecdsa-p384": lambda: ec.derive_private_key(1, ec.SECP384R1()).public_key(),
            "rsa-2048": lambda: rsa.RSAPublicNumbers(
                65537, (1 << 2048) - 159).public_key(),
            "ed25519": lambda: ed25519.Ed25519PublicKey.from_public_bytes(
                bytes(range(32))),
        }.get(key_type)
        return (public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode("ascii")
            if public_key else "")

    def record_token(self, token: str):
        label = {"fixture-token": "service", "fixture-bao-token": "bao"}.get(
            token, "other")
        if label not in self.token_ids:
            self.token_ids.append(label)

    def read(self, key: str, token: str):
        self.record_token(token)
        self.effects.append(f"openbao.read_key:{key}")
        return deepcopy(self.keys.get(key))

    def request(self, method, path, **_kwargs):
        self.record_token(_kwargs["bao_token"])
        self.effects.append(f"openbao.{method.lower()}:{path}")
        if path == "sys/mounts":
            return {"data": {"transit/": {}} if self.mounted else {}}
        if path == "sys/mounts/transit":
            self.mounted = True
            return {}
        if method == "POST" and path.startswith("transit/keys/"):
            key = path.removeprefix("transit/keys/")
            if self.deny_notification_create and key.startswith("notification-webhook-"):
                raise RuntimeError("injected OpenBao create failure")
            spec = _kwargs["json_body"]
            key_type = spec["type"]
            self.keys[key] = {
                "type": key_type, "exportable": spec.get("exportable", False),
                "latest_version": 1,
                "keys": {"1": {"public_key": self.public_pem(key_type)}},
            }
            return {}
        raise AssertionError((method, path))


def _state(database: FakeDatabase, bao: FakeBao, redis: FakeRedis) -> dict:
    docs = {}
    for key, value in sorted(redis.store.items()):
        try:
            parsed = json.loads(value)
        except (ValueError, TypeError):
            parsed = value
        # Capture stable substantive fields; timestamps are nondeterministic.
        def normalize(item):
            if isinstance(item, dict):
                return {k: normalize(v) for k, v in item.items()
                        if k not in {"created_at", "updated_at"}}
            if isinstance(item, list):
                return [normalize(v) for v in item]
            return item
        docs[key] = normalize(parsed)
    return {
        "postgres_schemas": sorted(database.schemas),
        "openbao_mounted": bao.mounted,
        "openbao_token_roles_used": bao.token_ids,
        "openbao_keys": {key: {"type": value["type"],
                                "exportable": value.get("exportable", False)}
                         for key, value in sorted(bao.keys.items())},
        "redis": docs,
    }


def _base_environment() -> dict[str, str]:
    return {
        "DATABASE_URL": "postgresql://fixture@db/marty",
        "MARTY_MIGRATION_PROFILE": "beta",
        "MARTY_ORG_ID": ORG,
        "MARTY_ORG_SLUG": "marty",
        "MARTY_ISSUER_DID": DID,
        "MARTY_ISSUER_BASE_URL": "https://issuer.example",
        "PUBLIC_DOMAIN": "issuer.example",
        "BAO_ADDR": "http://openbao.test:8200",
        "OPENBAO_SERVICE_TOKEN": "fixture-token",
        "REDIS_URL": "redis://redis.test:6379",
        "REDIS_DB_GATEWAY": "2",
        "MARTY_KMS_BOOTSTRAP_ENABLED": "true",
    }


def _run_case(owner, case: dict) -> dict:
    effects: list[str] = []
    database = FakeDatabase(effects, fail=case.get("schema_failure", False))
    disposable_keys = ([owner.managed_key_reference(29876, purpose)
                        for purpose in ("csca", "x509_doc_signer")]
                       if case.get("precreated_disposable") else [])
    bao = FakeBao(effects, unsafe_notification=case.get("unsafe_notification", False),
                  deny_notification_create=case.get("deny_notification_create", False),
                  precreated_disposable=disposable_keys)
    redis = FakeRedis(effects, initial=case.get("initial_redis"),
                      ping_failures=case.get("ping_failures", 0),
                      fail_set=case.get("fail_set"))
    env = _base_environment()
    env.update(case.get("env", {}))
    for name in case.get("unset", []):
        env.pop(name, None)
    system_env = {key: os.environ[key] for key in
                  ("SystemRoot", "WINDIR", "PATH") if key in os.environ}
    output = io.StringIO()
    error = io.StringIO()
    exits = []
    patches = [
        patch.dict(os.environ, {**system_env, **env}, clear=True),
        patch.object(sys, "argv", ["run_all_migrations.py"] +
                     (["--verify-only"] if case.get("verify_only") else [])),
        patch.object(owner, "create_engine", lambda _url: database),
        patch.object(owner, "_bao_request", bao.request),
        patch.object(owner, "_read_openbao_transit_key",
                     lambda _addr, token, key: bao.read(key, token)),
        patch.object(owner.time, "sleep", lambda seconds:
                     effects.append(f"sleep:{seconds}")),
    ]
    import redis as redis_module  # pylint: disable=import-outside-toplevel
    patches.append(patch.object(redis_module.Redis, "from_url",
                                lambda _url, **_kwargs: redis))
    from contextlib import ExitStack
    with ExitStack() as stack:
        for item in patches:
            stack.enter_context(item)
        stack.enter_context(redirect_stdout(output))
        stack.enter_context(redirect_stderr(error))
        for attempt in range(case.get("runs", 1)):
            effects.append(f"run:{attempt + 1}")
            try:
                owner.main()
            except SystemExit as exc:
                exits.append(int(exc.code or 0))
            else:
                exits.append(0)
    # Freeze observable writes and retry/failure boundaries, not incidental
    # lookup implementation order. Rust may batch reads without feature loss.
    semantic_effects = [effect for effect in effects if effect.startswith((
        "run:", "postgres.create_schema:", "postgres.create_schema_failed:",
        "postgres.commit", "openbao.post:", "redis.ping", "redis.set:",
        "redis.set_failed:", "sleep:",
    ))]
    return {
        "name": case["name"],
        "input": {
            "environment": env,
            "public_pem_by_type": {key_type: FakeBao.public_pem(key_type)
                                   for key_type in ("ecdsa-p256", "ecdsa-p384",
                                                    "rsa-2048", "ed25519")},
            **{key: value for key, value in case.items()
               if key not in {"name", "env", "unset"}},
        },
        "exit_codes": exits,
        "effects": semantic_effects,
        "state": _state(database, bao, redis),
        "error_tags": sorted(set(re.findall(
            r"Failed Marty KMS/DID bootstrap|Notification webhook KMS preparation failed|"
            r"OpenBao address/token are required|Error creating schemas|DATABASE_URL environment variable not set",
            error.getvalue(),
        ))),
    }


def capture() -> dict:
    owner_blob = _tracked_blob("services/run_all_migrations.py")
    shell_blob = _tracked_blob("scripts/run-migrations-with-secrets.sh")
    owner = _load_owner()
    assert owner.SERVICES == [], "The frozen source expects Rust-owned Alembic migrations"
    issuer_key = f"org:{ORG}:issuer-profiles"
    legacy_did = f"org:{ORG}:signing-key-did-document"
    registry = f"org:{ORG}:signing-key-services"
    cases = [
        {"name": "clean_apply"},
        {"name": "repeat_apply", "runs": 2},
        {"name": "preserve_customer_profile", "initial_redis": {
            issuer_key: {"profiles": [{"id": "customer-profile", "status": "active",
                                      "issuer_did": "did:web:customer.example"}]},
            registry: {"services": [{"id": "customer-hsm"}],
                       "key_reference_purposes": {"managed-openbao-transit": {
                           "customer-key": ["vc_jwt_issuer"]}}},
        }},
        {"name": "backfill_mixed_did", "initial_redis": {
            legacy_did: {"id": "did:web:other.example", "controller": "did:web:other.example",
                         "verificationMethod": [
                             {"id": DID + "#marty", "controller": DID},
                             {"id": "did:web:other.example#other",
                              "controller": "did:web:other.example"}],
                         "assertionMethod": [DID + "#marty",
                                             "did:web:other.example#other"]},
        }},
        {"name": "disposable_bad_tuple", "env": {
            "PASSPORT_DISPOSABLE_ICAO_BOOTSTRAP": "true",
            "PASSPORT_ACCEPTANCE_PROJECT": "marty-passport-acceptance-base-abcdef",
            "PASSPORT_ACCEPTANCE_GATEWAY_PORT": "29876",
        }},
        {"name": "disposable_precreated_keys", "precreated_disposable": True,
         "env": {
             "PASSPORT_DISPOSABLE_ICAO_BOOTSTRAP": "true",
             "PASSPORT_ACCEPTANCE_PROJECT": "marty-passport-acceptance-base-abcdef",
             "PASSPORT_ACCEPTANCE_GATEWAY_PORT": "29876",
             "PUBLIC_DOMAIN": "localhost:29876",
             "MARTY_ISSUER_DID": "did:web:localhost%3A29876:orgs:marty",
             "MARTY_ISSUER_BASE_URL": "https://localhost:29876",
         }},
        {"name": "token_precedence", "env": {"BAO_TOKEN": "fixture-bao-token"}},
        {"name": "bootstrap_disabled", "env": {
            "MARTY_KMS_BOOTSTRAP_ENABLED": "false"}},
        {"name": "redis_absent", "unset": ["REDIS_URL"]},
        {"name": "conflicting_managed_purpose", "initial_redis": {
            registry: {"key_reference_purposes": {"managed-openbao-transit": {
                "cred-issuer-marty-es256": ["x509_doc_signer"]}}},
        }},
        {"name": "unsafe_notification_kek", "unsafe_notification": True},
        {"name": "missing_notification_kek_create_denied",
         "deny_notification_create": True},
        {"name": "redis_ping_final_failure", "ping_failures": 5},
        {"name": "partial_redis_write_then_retry", "runs": 2,
         "fail_set": f"org:{ORG}:signing-key-jwks"},
        {"name": "verify_only", "verify_only": True},
        {"name": "missing_database_url", "unset": ["DATABASE_URL"]},
        {"name": "missing_bao_token", "unset": ["OPENBAO_SERVICE_TOKEN"]},
        {"name": "schema_failure", "schema_failure": True},
    ]
    captured = [_run_case(owner, case) for case in cases]
    shell = (ROOT / "scripts/run-migrations-with-secrets.sh").read_text(
        encoding="utf-8")
    guards = [
        "set -e",
        ". /app/load-secrets-env.sh",
        "require_secret_var MARTY_DB_PASSWORD",
        "admin_email=",
        'case "${admin_email}" in',
        '""|admin@example.com|user@example.com|example@example.com|change-me*)',
        "MARTY_ORG_ADMIN_EMAIL must be set",
        "exit 1",
    ]
    assert re.search(r"(?m)^set -e$", shell)
    assert all(marker in shell for marker in guards)
    assert [shell.index(marker) for marker in guards] == sorted(
        shell.index(marker) for marker in guards)
    assert shell.index("exit 1") < shell.index(
        "python /app/services/run_all_migrations.py")
    commands = [line.strip() for line in shell.splitlines()
                if line.strip().startswith(("python /app/services/", "exec /usr/local/bin/"))]
    assert commands == ["python /app/services/run_all_migrations.py",
                        "exec /usr/local/bin/marty-notification --migrate"]
    return {
        "schema": "marty.migration-bootstrap-python-reference/v1",
        "owner_git_blob": owner_blob,
        "shell_git_blob": shell_blob,
        "scope": "Python shared bootstrap after Rust service migration ownership",
        "shell_guard_markers": guards,
        "shell_commands_after_secret_and_admin_guards": commands,
        "cases": captured,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.write == args.check:
        parser.error("choose exactly one of --write or --check")
    reference = capture()
    encoded = json.dumps(reference, sort_keys=True, indent=2) + "\n"
    if args.write:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(encoded, encoding="utf-8")
        print(f"wrote {len(reference['cases'])} reference cases")
        return 0
    if OUTPUT.read_text(encoding="utf-8") != encoded:
        print("Migration bootstrap Python reference changed", file=sys.stderr)
        return 1
    print(f"verified {len(reference['cases'])} reference cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
