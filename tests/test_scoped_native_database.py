"""Mock transport controls only; no SQL, Docker, schema or runtime qualification."""
from copy import deepcopy
import json
from pathlib import Path
import sys
from urllib.parse import parse_qs, urlsplit
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import scoped_native_database as database

POSITIVE = {"fileFsync": True, "parentDirectory": {"supported": True, "synced": True}}


@pytest.mark.parametrize("command,role", [("migrate", "postgres"), ("verify-owned-schema", "marty")])
def test_schema_url_uses_sqlx_url_role_options(command, role):
    value = urlsplit(database.schema_url("postgres://postgres:SYNTHETIC_PASSWORD@postgres:5432/marty", command))
    assert value.username == "postgres" and value.hostname == "postgres"
    assert parse_qs(value.query) == {"options[role]": [role]}


@pytest.mark.parametrize("url", ["postgres://marty:fixture@postgres/marty", "postgres://postgres:fixture@foreign/marty",
    "postgres://postgres:fixture@postgres/foreign", "postgres://postgres:fixture@postgres/marty?options[role]=other",
    "postgres://postgres:fixture@postgres/marty#fragment"])
def test_schema_url_refuses_target_or_existing_options_drift(url):
    with pytest.raises(ValueError, match="EXACT_PRIVATE_SCHEMA_DATABASE_URL_REQUIRED"):
        database.schema_url(url, "verify-owned-schema")


def operator(barrier=POSITIVE):
    value = database.NativeDatabasePhase.__new__(database.NativeDatabasePhase)
    value.state = {"phase": "NOT_STARTED", "operations": []}
    value.guard = lambda: None
    saved = []
    value.i = {"quiescence": {}}
    value.g = {"save": lambda name, row: {"path": name, "sha256": "a" * 64}, "verify_all22_quiescent": lambda ref: None}
    class Journal:
        def state(self, row):
            saved.append(deepcopy(row))
            return deepcopy(barrier)
    value.store = Journal()
    return value, saved


def test_unsynced_pre_effect_state_never_invokes_operation():
    value, saved = operator({"fileFsync": True, "parentDirectory": {"supported": False, "synced": False}})
    calls = []
    with pytest.raises(ValueError, match="DURABLE_DATABASE_STATE_REQUIRED"):
        value.step("FENCE_INSTALL", lambda: calls.append("SQL"))
    assert not calls and len(saved) == 1 and not value.state["operations"]


def test_unknown_operation_retains_pending_state_without_retry():
    value, saved = operator()
    calls = []
    def unknown():
        calls.append("one command")
        raise TimeoutError("synthetic unknown outcome")
    with pytest.raises(TimeoutError):
        value.step("FENCE_INSTALL", unknown)
    assert len(calls) == len(saved) == 1
    assert value.state["phase"] == "DATABASE_OPERATION_PENDING"
    assert value.state["pendingStep"] == "FENCE_INSTALL" and not value.state["operations"]


def test_rust_helper_retirement_follows_durable_terminal_state():
    value, saved = operator()
    observed = []
    value.retire_schema_helper = lambda cid: observed.append((cid, deepcopy(saved[-1])))
    value.step("FLOW_MIGRATE", lambda: {"role": "flow", "containerId": "b" * 64})
    assert [x["phase"] for x in saved] == ["DATABASE_OPERATION_PENDING", "DATABASE_OPERATION_TERMINAL"]
    assert observed[0][0] == "b" * 64 and observed[0][1]["phase"] == "DATABASE_OPERATION_TERMINAL"
    row = value.state["operations"][0]
    assert row["intentDurability"] == row["terminalDurability"] == POSITIVE
    assert row["intentSequence"] == 1 and row["terminalSequence"] == 2


def test_run_refuses_before_any_operation_when_host_not_armed():
    value = database.NativeDatabasePhase.__new__(database.NativeDatabasePhase)
    value.g = {"dispatch_enabled": False}
    with pytest.raises(ValueError, match="DATABASE_DISPATCH_DISABLED"):
        value.run()


def test_runner_order_matches_shared_source_contract(tmp_path, monkeypatch):
    value, _ = operator()
    value.i = {"runId": "fixture", "selection": {"sha256": "a" * 64}, "executorSource": {"sha256": "b" * 64},
        "migrationSources": {}, "migrationSetSha256": "c" * 64, "databaseBefore": {}, "sqlSources": {}}
    admin = tmp_path / "admin.url"
    admin.write_text("postgres://postgres:SYNTHETIC@postgres/marty")
    value.selection = {"preparedSource": {}, "canonicalBuildReceipt": {}}
    monkeypatch.setattr(database, "select_canonical_binaries", lambda *a: value.selection)
    monkeypatch.setattr(database, "validate_compatibility", lambda *a: None)
    monkeypatch.setattr(database, "read_ref", lambda *a: admin)
    value.i.update(compatibility={"plan": {}, "result": {}}, databaseAdminUrl={})
    value.g.update(dispatch_enabled=True, verify_all22_quiescent=lambda ref: None, build_journal=None)
    value.i["quiescence"] = {"sha256": "q" * 64}
    value.store.read = lambda name: {"phase": "ALL22_QUIESCENT", "quiescenceSha256": "q" * 64, "runId": "fixture"} if name == "build-state.json" else {"runId": "fixture", "selectionSha256": "a" * 64, "executorSource": {"sha256": "b" * 64}}
    value.sql_receipts, value.commands, value.projections, seen = {}, [], {}, []
    value.node = lambda mode, **payload: "c" * 64 if mode == "digest" else {"epoch": 1, "transition_txid": 2}
    value.sql = lambda name, **kw: {"stdout": {}, "script": name}
    value.schema = lambda role, command: {"role": role, "command": command}
    value.catalog = lambda: {"projection": {}}
    value.backup = lambda: {"backupFile": {}}
    def step(step_id, operation):
        seen.append(step_id)
        return {"path": step_id, "sha256": "d" * 64}, operation()
    value.step = step
    value.run()
    import subprocess
    module = Path(__file__).resolve().parents[1] / "tests/scripts/native-maintenance-metadata.js"
    expected = json.loads(subprocess.check_output(["node", "-e", "process.stdout.write(JSON.stringify(require(process.argv[1]).DATABASE_ORDER.map(x=>x[0])))", str(module)]))
    assert seen == expected
    assert seen.index("ACL_FINALIZE") < seen.index("FLOW_VERIFY") < seen.index("ISSUER_VERIFY")


@pytest.mark.parametrize("step_id", ["ENABLE_APP_LOGIN", "ISSUER_MIGRATE", "ACL_FINALIZE", "DATABASE_BACKUP"])
def test_late_phase_rechecks_quiescence_before_effect(step_id):
    value, saved = operator()
    def restarted(_ref):
        raise ValueError("KNOWN_OLD_SERVICE_RESTARTED")
    value.g["verify_all22_quiescent"] = restarted
    called = []
    with pytest.raises(ValueError, match="KNOWN_OLD_SERVICE_RESTARTED"):
        value.step(step_id, lambda: called.append("SQL"))
    assert not called and not saved


def test_sql_request_is_saved_and_durable_before_unknown_exec():
    import base64
    value, saved = operator()
    value.i["sqlSources"] = {"fixture.sql": {"path": "fixture.sql", "sha256": "a" * 64}}
    value.identity = {"containerId": "b" * 64}
    value.target_settings = lambda: {}
    value.node = lambda *a, **kw: {"stdin": base64.b64encode(b"FIXED_SYNTHETIC_SQL").decode(), "pgOptions": "fixed", "argv": ["psql"]}
    value.g["save_bytes"] = lambda name, raw: {"path": name, "sha256": "c" * 64}
    def unknown(*a, **kw):
        assert saved[-1]["pendingRequest"]["stdin"]["path"] == "fixture.sql.stdin"
        assert saved[-1]["pendingRequest"]["transportArgv"][7] == "b" * 64
        raise TimeoutError("synthetic exec outcome unknown")
    value.result = unknown
    with pytest.raises(TimeoutError):
        value.sql("fixture.sql")
    assert len(saved) == 1 and saved[-1]["pendingRequest"]["source"]["sha256"] == "a" * 64


def test_nonzero_node_reader_preserves_private_stdout(tmp_path, monkeypatch):
    import hashlib
    import subprocess
    value, _ = operator()
    source = tmp_path / "module.js"
    source.write_bytes(b"SYNTHETIC_NOT_EXECUTED")
    value.i.update(metadataModule={"path": str(source), "sha256": hashlib.sha256(source.read_bytes()).hexdigest()}, executables={"docker": {"path": "unused"}})
    value.g.update(assert_inputs=lambda **kw: None, nodeExecutable="unused", env={})
    outputs = {}
    value.g["save_bytes"] = lambda name, data: outputs.update({name: data})
    value.g["save"] = lambda name, data: {"path": str(tmp_path / name)}
    result = subprocess.CompletedProcess([], 1, b"SYNTHETIC_DIAGNOSTIC", b"SYNTHETIC_ERROR")
    result.observation = {"timedOut": False, "failures": []}
    monkeypatch.setattr(database, "bounded_run", lambda *a, **kw: result)
    with pytest.raises(ValueError, match="SOURCE_BOUND_METADATA_READER_FAILED"):
        value.node("render")
    assert b"SYNTHETIC_DIAGNOSTIC" in outputs.values()
    assert b"SYNTHETIC_ERROR" in outputs.values()


def test_owned_child_output_is_capped_during_read():
    import os
    result = database.bounded_run([sys.executable, "-c", "import sys;sys.stdout.buffer.write(b'x'*4096)"],
        env=dict(os.environ), stdout_limit=128, timeout=3)
    assert result.stdout == b"x" * 128
    assert "stdout_limit" in result.observation["failures"]
    assert result.returncode is not None


def test_backup_style_stdout_stream_never_accumulates_dump_in_memory(tmp_path):
    import os
    path = tmp_path / "partial.dump"
    with path.open("xb") as target:
        result = database.bounded_run([sys.executable, "-c", "import sys;sys.stdout.buffer.write(b'x'*4096)"],
            env=dict(os.environ), stdout_limit=128, stdout_file=target, timeout=3)
    assert result.stdout == b"" and path.read_bytes() == b"x" * 128
    assert "stdout_limit" in result.observation["failures"]


def test_owned_child_timeout_is_unknown_and_has_no_implicit_retry():
    import os
    result = database.bounded_run([sys.executable, "-c", "import time;time.sleep(3)"], env=dict(os.environ), timeout=0.05)
    assert result.observation["timedOut"] is True
    assert result.returncode is not None


def test_executable_ref_has_distinct_bound_and_generic_refs_stay_small(tmp_path):
    from scoped_native_runtime import read_executable_ref, read_ref, ref, EXECUTABLE_REF_MAXIMUM
    large = tmp_path / "synthetic-executable"
    with large.open("wb") as stream:
        stream.truncate(17 * 1024 * 1024)
    bound = ref(large)
    assert read_executable_ref(bound) == large
    with pytest.raises(ValueError, match="BOUNDED_EXACT_REF_REQUIRED"):
        read_ref(bound)
    with large.open("wb") as stream:
        stream.truncate(EXECUTABLE_REF_MAXIMUM + 1)
    with pytest.raises(ValueError, match="BOUNDED_EXACT_REF_REQUIRED"):
        read_executable_ref(bound)
