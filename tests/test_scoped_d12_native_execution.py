"""Pre-effect controls for the closed D12 executor; no Docker or database."""
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from scoped_d12_native_execution import D12CurrentExecution, exact_exported_sql
from scoped_native_profiles import D12_PASSPORT_CURRENT
from scoped_native_runtime import MIGRATIONS, ref
from scoped_native_runtime import D12_CURRENT_RUNTIME_ROLES
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


def test_current_inspect_batch_reads_once_and_legacy_fallback_still_reads_each_role():
    snapshot = {"roles": [{"role": role, "containerId": f"{index+1:064x}"}
                          for index, role in enumerate(sorted(D12_CURRENT_RUNTIME_ROLES))]}
    calls = []
    context = {"inspect_all22": lambda: calls.append("batch") or snapshot,
               "inspect_role": lambda role: (_ for _ in ()).throw(AssertionError("unexpected role read"))}
    executor = D12CurrentExecution(context, inputs(), object())
    assert executor.inspect_all22() is snapshot
    assert calls == ["batch"]
    roles = []
    context = {"inspect_role": lambda role: roles.append(role) or
               next(row for row in snapshot["roles"] if row["role"] == role)}
    assert D12CurrentExecution(context, inputs(), object()).inspect_all22()["roles"] == snapshot["roles"]
    assert roles == sorted(D12_CURRENT_RUNTIME_ROLES)


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
        # CI may have a shallow checkout; the production guard below pins every exported byte.
        destination.write_bytes(subprocess.check_output(["git", "show", "HEAD:" + name]))
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


def test_recovery_entry_uses_recovery_preflight_and_shared_finish_without_stopping_again(tmp_path):
    from scoped_native_runtime import ref
    source = tmp_path / "recovery.json"
    source.write_text(json.dumps({"quiescence": {"sha256": "actual-stopped-ref"}}))
    value = execution.D12CurrentExecution.__new__(execution.D12CurrentExecution)
    value.read_only_preflight = False
    value.i = {"runId": "SYNTHETIC"}; value.state = {}
    calls = []
    class Database:
        def resume_after_fence_install(self, recovery_ref):
            calls.append(("resume", recovery_ref)); return "proof"
    database = Database()
    def preflight(recovery_ref):
        calls.append(("recovery-preflight", recovery_ref))
        return database, "before", "preview", "overlay"
    value.recovery_preflight = preflight
    value.preflight = lambda: (_ for _ in ()).throw(AssertionError("normal stop preflight must not replay"))
    value._finish_after_database = lambda *args: calls.append(("shared-finish", args)) or "result"
    recovery_ref = ref(source)
    assert value.resume_after_fence_install(recovery_ref) == "result"
    assert database.i == {"runId": "SYNTHETIC", "quiescence": {"sha256": "actual-stopped-ref"}}
    assert value.i == {"runId": "SYNTHETIC"} and value.state["recoveryAuthority"] == recovery_ref
    assert calls == [("recovery-preflight", recovery_ref), ("resume", recovery_ref),
                     ("shared-finish", (database, "before", "preview", "overlay", "proof"))]


@pytest.mark.parametrize("change", [None, "unselected", "quiescence-changed"])
def test_shared_finish_binds_actual_quiescence_before_unselected_create_comparison(tmp_path, monkeypatch, change):
    from copy import deepcopy
    from types import SimpleNamespace
    import hashlib
    value = D12CurrentExecution.__new__(D12CurrentExecution)
    value.profile = execution.CURRENT_PROFILE
    value.read_only_preflight = False
    value.roles = {"flow": "fixture-bin"}
    value.native_preimage = None
    value.state = {"steps": []}
    value.build_profile = SimpleNamespace(ui_revision="synthetic-source", core_revision="synthetic-core")
    value.i = {"runId": "SYNTHETIC", "selection": {"sha256": "selected"},
        "executorSource": {}, "databaseBefore": {"sha256": "database"}, "composeArguments": ["docker", "compose"]}
    before = {"roles": [{"role": role, "containerId": hashlib.sha256(role.encode()).hexdigest(),
        "imageId": "sha256:"+"a"*64, "state": "running", "running": True, "hostPid": 100,
        "containerExitCode": 0, "oomKilled": False, "binaryMounts": []} for role in sorted(D12_CURRENT_RUNTIME_ROLES)]}
    old_binary = str(tmp_path / "old-elf"); new_binary = str(tmp_path / "new-elf")
    target = "/usr/local/bin/fixture-bin"
    flow = next(row for row in before["roles"] if row["role"] == "flow")
    flow["binaryMounts"] = [{"destination": target, "type": "bind", "writable": False, "source": old_binary}]
    stopped = deepcopy(before)
    for row in stopped["roles"]:
        row.update(state="exited", running=False, hostPid=0)
    q = tmp_path / "quiescence.json"; q.write_text(json.dumps(stopped)); qref = ref(q)
    created = deepcopy(stopped)
    selected = next(row for row in created["roles"] if row["role"] == "flow")
    selected.update(containerId="f"*64, state="created")
    selected["binaryMounts"][0]["source"] = new_binary
    if change == "unselected":
        next(row for row in created["roles"] if row["role"] == "gateway")["imageId"] = "sha256:"+"b"*64
    if change == "quiescence-changed":
        q.write_text("{}")
    nodes = []
    identity = {"containerId": "SYNTHETIC_DATABASE"}
    database = SimpleNamespace(i={"quiescence": qref}, commands=[], baseline_refs={}, engine_id="engine", identity=identity,
        selection={"binaries": {"flow": {"path": new_binary}}},
        node=lambda *args, **kwargs: nodes.append(args) or {"sourceCommit": "synthetic-source", "databaseIdentity": identity})
    saved = []
    value.g = {"save": lambda name, data: saved.append((name, deepcopy(data))) or {"path": name, "sha256": "saved"}}
    value.store = SimpleNamespace(state=lambda row: {"fileFsync": True, "parentDirectory": {"supported": True, "synced": True}})
    value.inspect_all22 = lambda: deepcopy(created)
    monkeypatch.setattr(execution.overlay, "compose_recreate_arguments", lambda *args, **kwargs: ["docker", "compose", "create"])
    commands = []
    class ReachedFirstStart(Exception): pass
    def command(_database, step, args):
        commands.append(step)
        if step.startswith("START_"):
            raise ReachedFirstStart
    value.command = command
    if change is None:
        with pytest.raises(ReachedFirstStart):
            value._finish_after_database(database, before, {"restoreOrder": ["flow"]}, {"path": "overlay"}, {})
        assert commands == ["CREATE_SELECTED", "START_flow"]
    else:
        code = "D12_UNSELECTED_CREATE_CHANGED:gateway" if change == "unselected" else "BOUND_FILE_CHANGED"
        with pytest.raises(ValueError, match=code):
            value._finish_after_database(database, before, {"restoreOrder": ["flow"]}, {"path": "overlay"}, {})
        assert commands == (["CREATE_SELECTED"] if change == "unselected" else [])
        if change == "quiescence-changed":
            assert nodes == []  # fail before DB metadata verification or recreate
