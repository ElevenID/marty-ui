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


def test_current_database_target_settings_are_explicit_and_historical_default_stays_pinned():
    phase = database.NativeDatabasePhase.__new__(database.NativeDatabasePhase)
    phase.epoch = None
    old = phase.target_settings()
    assert old["marty.passport_beta_expected_system_identifier"] == "7698090346923700258"
    assert old["marty.passport_beta_expected_database_oid"] == "16387"
    phase.current_database_target = {"systemIdentifier": "7702258360779493410", "databaseOid": "16387"}
    current = phase.target_settings()
    assert current["marty.passport_beta_expected_system_identifier"] == "7702258360779493410"
    assert current["marty.passport_beta_expected_database_oid"] == "16387"


def test_current_baseline_requires_reviewed_refs_and_typed_shared_target():
    refs = {name: {"path": name, "sha256": name[0] * 64}
            for name in ("catalog", "proof", "job")}
    inputs = {"databaseBaseline": refs}
    authority = {"approvedBaselineCatalogSha256": refs["catalog"]["sha256"],
                 "approvedBaselineProofSha256": refs["proof"]["sha256"],
                 "approvedBaselineJobSha256": refs["job"]["sha256"]}
    assert database.reviewed_database_baseline_refs(inputs, authority) == refs
    with pytest.raises(ValueError, match="D12_REVIEWED_DATABASE_BASELINE_REQUIRED"):
        database.reviewed_database_baseline_refs(inputs,
            {**authority, "approvedBaselineJobSha256": "0" * 64})
    with pytest.raises(ValueError, match="D12_CURRENT_DATABASE_BASELINE_REFS_REQUIRED"):
        database.reviewed_database_baseline_refs({"databaseBaseline": {"proof": refs["proof"]}}, authority)
    target = {"database": "marty", "systemIdentifier": "7702258360779493410", "databaseOid": "16387"}
    assert database.consume_current_database_target(target) == {"systemIdentifier": target["systemIdentifier"],
                                                             "databaseOid": target["databaseOid"]}
    with pytest.raises(ValueError, match="D12_BASELINE_DATABASE_TARGET_INVALID"):
        database.consume_current_database_target({**target, "systemIdentifier": 7702258360779493410})


def test_current_d12_authority_rejects_old_build_before_database_phase(tmp_path, monkeypatch):
    from scoped_native_profiles import D12_PASSPORT_CURRENT
    authority = tmp_path / "authority.json"
    authority.write_text(json.dumps({"schema": "marty.d12-current-native-authority/v1",
        "sourceRevision": D12_PASSPORT_CURRENT.ui_revision,
        "coreRevision": D12_PASSPORT_CURRENT.core_revision,
        "scope": "FUNCTIONAL_ONLY", "releaseQualified": False,
        "recordingQualified": False, "runId": "owned",
        "approvedDatabaseBeforeSha256": "a" * 64,
        "approvedSelectionSha256": "b" * 64,
        "approvedRuntimeBeforeSha256": "c" * 64,
        "dispatchAuthorized": True}))
    monkeypatch.setattr(database, "read_ref", lambda *args: authority)
    inputs = {"runId": "owned", "d12Authority": {"path": str(authority)},
        "databaseBefore": {"sha256": "a" * 64}, "selection": {"sha256": "b" * 64},
        "executorSource": {"sha256": "d" * 64}, "metadataModule": {"sha256": "e" * 64},
        "runtimeBefore": {"sha256": "c" * 64}}
    context = {"operation_lock_held": lambda: True, "recording_lock_held": lambda: True,
               "authorization_verified": lambda ref: True}
    with pytest.raises(ValueError, match="EXACT_D12_CURRENT_AUTHORITY_REQUIRED"):
        database.D12CurrentDatabasePhase(context, inputs, object())
    authority_row = json.loads(authority.read_text())
    authority_row["sourceRevision"] = "d2debf0fde2a0c826f8925aca648c9d3dabfbc9f"
    authority.write_text(json.dumps(authority_row))
    with pytest.raises(ValueError, match="EXACT_D12_CURRENT_AUTHORITY_REQUIRED"):
        database.D12CurrentDatabasePhase(context, inputs, object())
    authority_row["sourceRevision"] = D12_PASSPORT_CURRENT.ui_revision
    authority_row.update(approvedDatabaseExecutorSha256="d" * 64,
                         approvedBuildReceiptSha256="e" * 64,
                         schemaHelperImageId="sha256:" + "f" * 64,
                         engineId="11111111-1111-4111-8111-111111111111")
    authority.write_text(json.dumps(authority_row))
    with pytest.raises(ValueError, match="EXACT_D12_CURRENT_AUTHORITY_REQUIRED"):
        database.D12CurrentDatabasePhase({**context, "recording_lock_held": lambda: False},
                                         inputs, object())
    with pytest.raises(ValueError, match="EXACT_D12_CURRENT_AUTHORITY_REQUIRED"):
        database.D12CurrentDatabasePhase(context, inputs, object())


@pytest.mark.parametrize("current_ten", [False, True])
def test_runner_order_matches_shared_source_contract(tmp_path, monkeypatch, current_ten):
    value, _ = operator()
    value.i = {"runId": "fixture", "selection": {"sha256": "a" * 64}, "executorSource": {"sha256": "b" * 64},
        "migrationSources": {}, "migrationSetSha256": "c" * 64, "databaseBefore": {}, "sqlSources": {}}
    admin = tmp_path / "admin.url"
    admin.write_text("postgres://postgres:SYNTHETIC@postgres/marty")
    value.selection = {"preparedSource": {}, "canonicalBuildReceipt": {}}
    value.select_binaries = lambda *a: value.selection
    value.check_compatibility = lambda *a: None
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
    if current_ten:
        value.tenant_id = "11111111-1111-4111-8111-111111111111"
    value.run()
    import subprocess
    module = Path(__file__).resolve().parents[1] / "tests/scripts/native-maintenance-metadata.js"
    expected = json.loads(subprocess.check_output(["node", "-e", "process.stdout.write(JSON.stringify(require(process.argv[1]).currentDatabaseOrder({profile:process.argv[2]}).map(x=>x[0])))", str(module), "d05-membership-current-functional" if current_ten else "historical"]))
    assert seen == expected
    assert seen.index("ACL_FINALIZE") < seen.index("FLOW_VERIFY") < seen.index("ISSUER_VERIFY")
    if current_ten:
        assert seen.index("CREDENTIAL_TEMPLATE_MIGRATE") < seen.index("ISSUER_MIGRATE") < seen.index("ACL_FINALIZE")
        assert seen.index("ACL_FINALIZE") < seen.index("CREDENTIAL_TEMPLATE_VERIFY") < seen.index("ISSUER_VERIFY")


@pytest.mark.parametrize("step_id", ["ENABLE_APP_LOGIN", "ISSUER_MIGRATE", "CREDENTIAL_TEMPLATE_MIGRATE", "CREDENTIAL_TEMPLATE_VERIFY", "ACL_FINALIZE", "DATABASE_BACKUP"])
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


def recovery_fixture(tmp_path):
    from scoped_native_runtime import ref
    def saved(name, value):
        p = tmp_path / name; p.write_text(json.dumps(value)); return ref(p)
    db = {"containerId": "SYNTHETIC_DATABASE"}
    before = saved("db.json", {"databaseIdentity": db})
    sql = saved("source.json", {"synthetic": True})
    original = {"runId": "SYNTHETIC_RUN", "uiRevision": "source", "coreRevision": "core",
        "selection": {"sha256": "selection"}, "runtimeBefore": {"sha256": "runtime"}, "databaseBefore": before,
        "sqlSources": {"passport-beta-fence-install.sql": sql}, "d12Authority": {"sha256": "old-authority"}}
    for key in database.RECOVERY_SOURCE_FIELDS: original[key] = {"sha256": "old-"+key}
    for key in database.RECOVERY_TRUST_FIELDS: original[key] = {"sha256": "old-"+key}
    url = tmp_path / "synthetic-url"
    url.write_text("postgres://postgres:synthetic@postgres:5432/marty")
    original.update(databaseAdminUrl=ref(url), compatibility={"plan": {}, "result": {}},
                    migrationSources={}, migrationSetSha256="digest")
    generation = tmp_path / "synthetic-generation"
    beta = {"secrets": {"trust_profile_workload_server_cert": {"file": str(generation / "trust_profile_workload_server_cert")},
                        "trust_profile_tls_kms_token": {"file": str(generation / "trust_profile_workload_server_kms_token")}},
            "services": {"trust-profile": {"environment": {"MANAGED_AUTHORITY_TLS_KMS_KEY_NAME": "retained-key"}}}}
    original["plannedModels"] = {"elevenid-beta": saved("beta.json", beta), "elevenid-beta-ui": saved("ui.json", {"services": {}})}
    original["runScopedTrustLeaseProof"] = saved("lease.json", {"generationDirectory": str(generation)})
    inputs = deepcopy(original)
    for key in database.RECOVERY_SOURCE_FIELDS: inputs[key] = {"sha256": "new-"+key}
    inputs["d12Authority"] = {"sha256": "new-authority"}
    quiescence = saved("stopped.json", {"roles": []}); inputs["quiescence"] = quiescence
    intent = {"schema": "marty.d12-current-apply-intent/v1", "runId": original["runId"],
        "selectionSha256": "selection", "executorSource": original["executorSource"],
        "runtimeBefore": original["runtimeBefore"], "databaseBefore": before, "authority": original["d12Authority"]}
    request = {"kind": "PSQL", "source": sql, "stdin": {}, "transportArgv": ["synthetic"], "pgOptions": "synthetic"}
    receipt = saved("fence-install.json", {"runId": inputs["runId"], "state": "exited", "exitCode": 0,
        "oomKilled": False, "databaseIdentity": db, "source": sql, "stdin": {}, "transportArgv": ["synthetic"], "pgOptions": "synthetic"})
    state = {"schema": "marty.native-d12-current-operation-state/v1", "phase": "DATABASE_OPERATION_TERMINAL",
        "runId": inputs["runId"], "sourceRevision": "source", "coreRevision": "core", "selectionSha256": "selection",
        "executorSource": original["executorSource"], "databaseIdentity": db, "pendingStep": None, "pendingRequest": None,
        "operations": [{"stepId": "FENCE_INSTALL", "state": "SUCCEEDED", "unknownOutcome": False,
            "exitCode": 0, "sequence": 1, "intentSequence": 1, "terminalSequence": 2,
            "intentDurability": POSITIVE, "receipt": receipt, "request": request}]}
    backend = saved("backend.json", {"rootProof": {"synthetic": True}})
    journal = [{"state": "EXACT_ROOT_DURABLE_METADATA_READ_COMPLETE", "mountReadOnly": True,
        "files": {"build-state.json": {"present": True, "sha256": "original-state-digest", "document": state},
            "build-apply-intent.json": {"present": True, "document": intent},
            "build-receipt.json": {"present": False}, "configuration-receipt.json": {"present": False}}}]
    resource = saved("resource.json", {"runId": inputs["runId"], "runtimeBefore": original["runtimeBefore"],
        "operationJournal": backend, "journalRead": saved("journal.json", journal)})
    response = {"ok": True, "name": "build-state.json", "sha256": "original-state-digest", "value": state,
        "rootProof": {"synthetic": True}, "barrier": POSITIVE}
    terminal = saved("terminal.json", {"containerId": "SYNTHETIC_RETIRED_HELPER", "exitCode": 0,
        "oomKilled": False, "logsCommandExitCode": 0, "stderr": "", "stdout": json.dumps(response)})
    retired = saved("retired.json", {"containerId": "SYNTHETIC_RETIRED_HELPER", "removed": True, "consumersAfter": []})
    recovery = {"schema": "marty.d12-fence-install-recovery/v1", "operation": "RESUME_AFTER_TERMINAL_FENCE_INSTALL",
        "draftOnly": False, "dispatchAuthorized": True, "runId": inputs["runId"],
        "originalInputs": saved("original-inputs.json", original), "originalDatabaseState": saved("state.json", state),
        "originalApplyIntent": saved("intent.json", intent), "maintenanceResourceRecovery": resource,
        "fenceInstallReceipt": receipt, "quiescence": quiescence, "originalTerminalWrite": terminal,
        "originalTerminalRetirement": retired,
        "sourceMap": {key: {"original": original[key], "recovery": inputs[key]} for key in database.RECOVERY_SOURCE_FIELDS},
        "trustDataMap": {key: {"original": original[key], "recovery": inputs[key]} for key in database.RECOVERY_TRUST_FIELDS}}
    return inputs, state, intent, recovery, saved


def test_exact_terminal_fence_install_recovery_keeps_original_receipt_and_barrier(tmp_path):
    inputs, state, intent, recovery, _saved = recovery_fixture(tmp_path)
    before = deepcopy(state)
    step, barrier = database.fence_install_recovery_checkpoint(inputs, state, intent, recovery)
    assert step == state["operations"][0] and barrier == POSITIVE
    assert "terminalDurability" not in step  # real serializer returns it after the first state write
    assert state == before


@pytest.mark.parametrize("change", ["pending", "extra", "unknown", "receipt", "source-map", "database", "intent", "missing-barrier"])
def test_fence_install_recovery_refuses_pending_extra_or_changed_checkpoint(tmp_path, change):
    inputs, state, intent, recovery, saved = recovery_fixture(tmp_path)
    if change == "pending": state.update(phase="DATABASE_OPERATION_PENDING", pendingStep="FENCE_VERIFY")
    elif change == "extra": state["operations"].append(deepcopy(state["operations"][0]))
    elif change == "unknown": state["operations"][0]["unknownOutcome"] = True
    elif change == "receipt": recovery["fenceInstallReceipt"] = {}
    elif change == "source-map": recovery["sourceMap"]["executorSource"]["original"] = {}
    elif change == "database": inputs["databaseBefore"] = saved("wrong-db.json", {"databaseIdentity": {}})
    elif change == "intent": intent["executorSource"] = {}
    else:
        terminal = json.loads(Path(recovery["originalTerminalWrite"]["path"]).read_bytes())
        response = json.loads(terminal["stdout"]); response["barrier"] = None; terminal["stdout"] = json.dumps(response)
        recovery["originalTerminalWrite"] = saved("missing-barrier.json", terminal)
    if change in ("pending", "extra", "unknown"):
        # Consistent synthetic observations isolate the checkpoint policy,
        # rather than merely fail snapshot equality after a one-sided edit.
        recovery["originalDatabaseState"] = saved("changed-state.json", state)
        resource = json.loads(Path(recovery["maintenanceResourceRecovery"]["path"]).read_bytes())
        journal = json.loads(Path(resource["journalRead"]["path"]).read_bytes())
        journal[0]["files"]["build-state.json"]["document"] = state
        resource["journalRead"] = saved("changed-journal.json", journal)
        recovery["maintenanceResourceRecovery"] = saved("changed-resource.json", resource)
    with pytest.raises(ValueError):
        database.fence_install_recovery_checkpoint(inputs, state, intent, recovery)


def test_resume_enters_shared_sequence_at_fence_verify_without_rewriting_originals(tmp_path):
    from scoped_native_runtime import ref
    inputs, state, intent, recovery, saved = recovery_fixture(tmp_path)
    recovery_ref = saved("recovery.json", recovery)
    original_state = deepcopy(state); original_intent = deepcopy(intent)
    value = database.D12CurrentDatabasePhase.__new__(database.D12CurrentDatabasePhase)
    value.i = inputs; value.authority = inputs["d12Authority"]
    value.selection = {"preparedSource": {}, "canonicalBuildReceipt": {}}
    value.select_binaries = lambda *_: value.selection
    value.check_compatibility = lambda *_: None
    value.node = lambda *_args, **_kwargs: "digest"
    value.sql_receipts = {}
    writes = []; guards = []
    class Store:
        def read(self, name):
            return deepcopy(intent if name == "build-apply-intent.json" else state)
        def state(self, row):
            writes.append(deepcopy(row)); return deepcopy(POSITIVE)
        def exclusive(self, *_):
            raise AssertionError("original one-shot intent must not be recreated")
    value.store = Store()
    value.g = {"dispatch_enabled": True, "build_journal": object(),
        "recovery_authorization_verified": lambda *_: guards.append("authority") or True,
        "verify_recovery_quiescent": lambda *_: guards.append("fresh22") or True}
    reached = []
    class FirstRemainingStep(Exception): pass
    def step(step_id, operation):
        reached.append(step_id)
        raise FirstRemainingStep
    value.step = step
    with pytest.raises(FirstRemainingStep):
        value.resume_after_fence_install(recovery_ref)
    assert guards == ["authority", "fresh22"] and reached == ["FENCE_VERIFY"]
    assert len(writes) == 1 and writes[0]["recoveryAuthority"] == recovery_ref
    assert writes[0]["operations"][0]["receipt"] == state["operations"][0]["receipt"]
    assert writes[0]["operations"][0]["terminalDurability"] == POSITIVE
    assert state == original_state and intent == original_intent
    assert value.sql_receipts["passport-beta-fence-install.sql"] == recovery["fenceInstallReceipt"]


def test_recovery_trust_rebinding_refuses_any_other_target_model_change(tmp_path):
    inputs, state, intent, recovery, saved = recovery_fixture(tmp_path)
    model = json.loads(Path(inputs["plannedModels"]["elevenid-beta"]["path"]).read_bytes())
    model["services"]["trust-profile"]["environment"]["MANAGED_AUTHORITY_TLS_KMS_KEY_NAME"] = "foreign-key"
    inputs["plannedModels"] = {**inputs["plannedModels"], "elevenid-beta": saved("changed-model.json", model)}
    recovery["trustDataMap"]["plannedModels"]["recovery"] = inputs["plannedModels"]
    with pytest.raises(ValueError, match="D12_RECOVERY_TARGET_MODEL_DRIFT"):
        database.fence_install_recovery_checkpoint(inputs, state, intent, recovery)


def test_recovery_trust_rebinding_accepts_only_honest_new_credential_paths(tmp_path):
    inputs, state, intent, recovery, saved = recovery_fixture(tmp_path)
    generation = tmp_path / "new-synthetic-generation"
    model = json.loads(Path(inputs["plannedModels"]["elevenid-beta"]["path"]).read_bytes())
    model["secrets"]["trust_profile_workload_server_cert"]["file"] = str(generation / "trust_profile_workload_server_cert")
    model["secrets"]["trust_profile_tls_kms_token"]["file"] = str(generation / "trust_profile_workload_server_kms_token")
    inputs["plannedModels"] = {**inputs["plannedModels"], "elevenid-beta": saved("new-credentials-model.json", model)}
    inputs["runScopedTrustLeaseProof"] = saved("new-lease.json", {"generationDirectory": str(generation)})
    for key in ("plannedModels", "runScopedTrustLeaseProof"):
        recovery["trustDataMap"][key]["recovery"] = inputs[key]
    step, _ = database.fence_install_recovery_checkpoint(inputs, state, intent, recovery)
    assert step["stepId"] == "FENCE_INSTALL"
