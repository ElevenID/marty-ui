"""Pre-effect controls for the closed D12 executor; no Docker or database."""
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from scoped_d12_native_execution import D12CurrentExecution, exact_exported_sql
from scoped_native_profiles import D12_PASSPORT_CURRENT
from scoped_native_runtime import MIGRATIONS, ref
import scoped_d12_native_execution as execution
import json
import subprocess


def inputs():
    return {"runId": "00000000-0000-4000-8000-000000000001",
            "rolloutProfile": "d12-passport-current-functional", "buildProfile": None,
            "uiRevision": D12_PASSPORT_CURRENT.ui_revision,
            "coreRevision": D12_PASSPORT_CURRENT.core_revision,
            "roleBinaries": dict(D12_PASSPORT_CURRENT.roles), "scope": "FUNCTIONAL_ONLY",
            "releaseQualified": False, "recordingQualified": False}


def test_no_lock_or_dispatch_refuses_before_any_command():
    commands = []
    context = {"dispatch_enabled": False, "operation_lock_held": lambda: False,
               "command": lambda argv: commands.append(argv)}
    executor = D12CurrentExecution(context, inputs(), object())
    with pytest.raises(ValueError, match="D12_EXCLUSIVE_AUTHORITY_REQUIRED"):
        executor.run()
    assert not commands


@pytest.mark.parametrize("edit", [
    {"uiRevision": "d2debf0fde2a0c826f8925aca648c9d3dabfbc9f"},
    {"coreRevision": "4320b5fa1c6f41231ee0aa2bc57d8008549f67ac"},
    {"roleBinaries": {"flow": "marty-flow", "gateway": "marty-gateway"}},
    {"releaseQualified": True},
    {"quiescence": {"sha256": "a" * 64}},
])
def test_stale_or_partial_selection_refuses_before_build_or_mutation(edit):
    commands = []
    context = {"dispatch_enabled": True, "operation_lock_held": lambda: True,
               "recording_lock_held": lambda: True,
               "command": lambda argv: commands.append(argv)}
    executor = D12CurrentExecution(context, dict(inputs(), **edit), object())
    with pytest.raises(ValueError):
        executor.run()
    assert not commands


def test_unsynced_one_shot_intent_refuses_before_first_stop():
    commands = []
    class Journal:
        def exclusive(self, name, row):
            assert name == "build-apply-intent.json" and row["automaticRetry"] is False
            return {"fileFsync": True, "parentDirectory": {"supported": False, "synced": False}}
    value = inputs()
    value.update({"selection": {"sha256": "a" * 64}, "executorSource": {},
                  "runtimeBefore": {}, "databaseBefore": {}, "d12Authority": {}})
    executor = D12CurrentExecution({"command": lambda argv: commands.append(argv)}, value, Journal())
    executor.preflight = lambda: (object(), {}, {"stopSteps": [{"role": "gateway", "argv": ["docker", "stop"]}]}, {})
    with pytest.raises(ValueError, match="D12_DURABLE_ONE_SHOT_INTENT_REQUIRED"):
        executor.run()
    assert not commands


def test_actual_quiescence_is_bound_after_stop_without_mutating_frozen_input(tmp_path, monkeypatch):
    barrier = {"fileFsync": True, "parentDirectory": {"supported": True, "synced": True}}
    phases = []
    class Journal:
        def exclusive(self, name, row):
            phases.append(name)
            return barrier
        def state(self, row):
            phases.append(row["phase"])
            return barrier
    class StopAtDatabase:
        def __init__(self):
            self.i = None
        def command(self, args):
            phases.append("STOP_DISPATCHED")
            return b""
        def run(self):
            assert self.i["quiescence"]["sha256"] == ref(tmp_path / "d12-all22-quiescent.private.json")["sha256"]
            phases.append("DATABASE_DISPATCHED")
            raise RuntimeError("bounded test stop after phase binding")
    database = StopAtDatabase()
    frozen = inputs()
    frozen.update({"selection": {"sha256": "a" * 64}, "executorSource": {},
                   "runtimeBefore": {}, "databaseBefore": {}, "d12Authority": {}})
    def save(name, value):
        path = tmp_path / name
        path.write_text(json.dumps(value))
        return ref(path)
    context = {"save": save, "inspect_role": lambda role: None}
    executor = D12CurrentExecution(context, frozen, Journal())
    executor.preflight = lambda: (database, {"roles": []},
        {"stopSteps": [{"role": "gateway", "containerId": "a" * 64,
                        "argv": ["docker", "--context", "desktop-linux", "stop", "a" * 64]}]}, {})
    executor.inspect_all22 = lambda: {"roles": []}
    context["inspect_role"] = lambda role: {"containerId": "a" * 64, "state": "exited",
                                              "hostPid": 0, "containerExitCode": 0, "oomKilled": False}
    monkeypatch.setattr(execution.maintenance, "validate_quiescent", lambda *args: None)
    with pytest.raises(RuntimeError, match="bounded test stop"):
        executor.run()
    assert "quiescence" not in frozen
    assert phases.index("STOP_DISPATCHED") < phases.index("ALL22_QUIESCENT") < phases.index("DATABASE_DISPATCHED")


def test_unknown_stop_retains_pending_effect_and_never_binds_database(tmp_path):
    barrier = {"fileFsync": True, "parentDirectory": {"supported": True, "synced": True}}
    phases = []
    class Journal:
        def exclusive(self, *args):
            return barrier
        def state(self, row):
            phases.append(row["phase"])
            return barrier
    class UnknownStop:
        def command(self, args):
            raise TimeoutError("unknown stop outcome")
        def run(self):
            assert False, "database must not start"
    frozen = inputs()
    frozen.update({"selection": {"sha256": "a" * 64}, "executorSource": {},
                   "runtimeBefore": {}, "databaseBefore": {}, "d12Authority": {}})
    executor = D12CurrentExecution({}, frozen, Journal())
    executor.preflight = lambda: (UnknownStop(), {},
        {"stopSteps": [{"role": "gateway", "argv": ["docker", "stop"]}]}, {})
    with pytest.raises(TimeoutError, match="unknown stop outcome"):
        executor.run()
    assert phases[-1] == "PENDING_EFFECT" and "ALL22_QUIESCENT" not in phases


def test_exact_git_exported_sql_bytes_pass_and_crlf_checkout_bytes_refuse(tmp_path):
    from scoped_native_maintenance import operational_sql_sources, migration_requirements
    revision = D12_PASSPORT_CURRENT.ui_revision
    root = tmp_path / "source"
    def exported(name):
        destination = root / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(subprocess.check_output(["git", "show", revision + ":" + name]))
        return ref(destination)
    sql = {name: exported("scripts/sql/" + name) for name in operational_sql_sources()}
    catalog = exported("scripts/sql/passport-beta-maintenance-catalog.sql")
    migration_paths = {"rust/services/" + item.replace("/", "/migrations/", 1) + ".sql"
                       for item in MIGRATIONS}
    migrations = {name: exported(name) for name in migration_paths}
    plan = {"sources": {"ui": {"revision": revision, "directory": str(root)}}}
    inputs = {"sqlSources": sql, "catalogSql": catalog, "migrationSources": migrations}
    assert catalog["sha256"] == migration_requirements()["catalogSqlSha256"]
    exact_exported_sql(plan, inputs)
    changed = root / "scripts/sql/passport-beta-native-attestation.sql"
    changed.write_bytes(changed.read_bytes().replace(b"\n", b"\r\n"))
    inputs["sqlSources"][changed.name] = ref(changed)
    with pytest.raises(ValueError, match="D12_EXACT_GIT_EXPORTED_SQL_REQUIRED"):
        exact_exported_sql(plan, inputs)
