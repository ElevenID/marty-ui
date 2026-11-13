"""Pure local D12 host context controls; no Docker, SQL, or runtime effect."""
import hashlib
import json
import sys
from pathlib import Path

import pytest
from copy import deepcopy

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from scoped_d12_native_effect_host import D12CurrentEffectObserver, D12CurrentHostBindings, D12HeldCanonicalLock
import scoped_d12_native_effect_host as effect
from scoped_d12_native_host import D12ReadOnlyHost
from scoped_linux_journal import LinuxBuildJournal
from scoped_native_runtime import D12_CURRENT_RUNTIME_ROLES, ref


@pytest.mark.parametrize("change", [None, "cid", "image", "started", "pid", "project",
                                    "service", "paused", "oom", "health", "stopped", "engine"])
def test_database_identity_reader_refuses_replaced_or_unhealthy_generation(tmp_path, change):
    identity = {"containerId": "a" * 64, "imageId": "sha256:" + "b" * 64,
                "startedAt": "2026-11-08T05:43:47.282755687Z", "hostPid": 2820,
                "project": "elevenid-beta", "service": "postgres"}
    file = tmp_path / "database.json"
    file.write_text(json.dumps({"databaseIdentity": identity}))
    row = {"Id": identity["containerId"], "Image": identity["imageId"],
           "Config": {"Labels": {"com.docker.compose.project": identity["project"],
                                  "com.docker.compose.service": "postgres"}},
           "State": {"StartedAt": identity["startedAt"], "Pid": 2820, "Running": True,
                     "Status": "running", "Paused": False, "OOMKilled": False,
                     "Health": {"Status": "healthy"}}}
    if change == "cid":
        row["Id"] = "c" * 64
    if change == "image":
        row["Image"] = "sha256:" + "d" * 64
    if change == "started":
        row["State"]["StartedAt"] = "2026-11-08T06:00:00Z"
    if change == "pid":
        row["State"]["Pid"] = 2821
    if change == "project":
        row["Config"]["Labels"]["com.docker.compose.project"] = "marty-production"
    if change == "service":
        row["Config"]["Labels"]["com.docker.compose.service"] = "foreign"
    if change == "paused":
        row["State"]["Paused"] = True
    if change == "oom":
        row["State"]["OOMKilled"] = True
    if change == "health":
        row["State"]["Health"]["Status"] = "unhealthy"
    if change == "stopped":
        row["State"].update(Running=False, Status="exited")
    host = D12ReadOnlyHost.__new__(D12ReadOnlyHost)
    host.before = {}
    host.engine_id = "3dbbbe66-1c98-4e0c-b0a6-f927c05e7341"
    host._recheck_source = lambda: None
    calls = []
    def docker(argv):
        calls.append(deepcopy(argv))
        if argv == ["info", "--format", "{{.ID}}"]:
            return "foreign-engine" if change == "engine" else host.engine_id
        assert argv == ["inspect", identity["containerId"]]
        return json.dumps([row])
    host._docker = docker
    journal = LinuxBuildJournal.__new__(LinuxBuildJournal)
    observer = D12CurrentEffectObserver(host, {}, journal, None)
    if change is None:
        assert observer.database_snapshot(ref(file)) == {"databaseIdentity": identity}
        assert calls == [["info", "--format", "{{.ID}}"], ["inspect", identity["containerId"]],
                         ["info", "--format", "{{.ID}}"]]
    else:
        with pytest.raises(ValueError, match="D12_ENGINE_CHANGED|D12_DATABASE_GENERATION_OR_HEALTH_CHANGED"):
            observer.database_snapshot(ref(file))


def setup_context(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda _cls: tmp_path))
    private = tmp_path / ".codex" / "private"
    run = private / "run"
    run.mkdir(parents=True)
    config = tmp_path / "docker-config"
    config.mkdir()
    meta = config / "contexts" / "meta" / ("a" * 64) / "meta.json"
    meta.parent.mkdir(parents=True)
    meta.write_text("{}")
    inp = tmp_path / "inputs.json"
    selected = tmp_path / "selection.json"
    selected.write_text("{}")
    inp.write_text(json.dumps({"runId": "00000000-0000-4000-8000-000000000001",
                               "selection": ref(selected)}))
    node = tmp_path / "node.exe"
    docker = tmp_path / "docker.exe"
    node.write_bytes(b"node")
    docker.write_bytes(b"docker")
    host = D12ReadOnlyHost.__new__(D12ReadOnlyHost)
    host.before = {role: {"health": "healthy"} for role in D12_CURRENT_RUNTIME_ROLES}
    host._root = Path(effect.__file__).resolve().parents[1]
    host._source_files = {"scripts/scoped_d12_native_effect_host.py":
                          {"sha256": ref(effect.__file__)["sha256"]}}
    rows = {"roles": [{"role": role, "containerId": f"{index+1:064x}", "state": "running",
                       "running": True, "paused": False, "oomKilled": False,
                       "hostPid": 100, "health": "healthy"}
                      for index, role in enumerate(sorted(D12_CURRENT_RUNTIME_ROLES))]}
    calls = []
    host._recheck_source = lambda: calls.append("source")
    host.observe22 = lambda: calls.append("actual22") or rows
    host.inspect_role = lambda role: next(row for row in rows["roles"] if row["role"] == role)
    host.compose_model = lambda args, overlay_ref=None: {}
    operation = LinuxBuildJournal.__new__(LinuxBuildJournal)
    build = LinuxBuildJournal.__new__(LinuxBuildJournal)
    operation.private = private / "operation-journal"
    build.private = private / "build-journal"
    operation.read = lambda name: {"phase": "ALL22_QUIESCENT", "quiescenceSha256": ref(inp)["sha256"]}
    binding = D12CurrentHostBindings(host, inputs_ref=ref(inp), private_root=run,
        operation_journal=operation, build_journal=build, node_executable=ref(node),
        docker_executable=ref(docker), docker_config=config, docker_config_refs={str(meta): ref(meta)})
    binding.observer.inspect_all22 = host.observe22
    return binding, rows, calls, inp, meta


def test_real_private_saves_and_fresh_health_without_dispatch(tmp_path, monkeypatch):
    binding, rows, calls, inp, meta = setup_context(tmp_path, monkeypatch)
    context = binding.context()
    assert context["dispatch_enabled"] is False
    assert context["authorization_verified"]({}) is False
    assert context["operation_lock_held"]() is False
    assert context["recording_lock_held"]() is False
    assert context["wait_all22_healthy"](1) is True
    assert calls.count("actual22") == 1
    output = context["save"]("receipt.json", {"scope": "FUNCTIONAL_ONLY"})
    assert json.loads(Path(output["path"]).read_bytes()) == {"scope": "FUNCTIONAL_ONLY"}
    with pytest.raises(FileExistsError):
        context["save"]("receipt.json", {})
    meta.write_text("changed")
    with pytest.raises(ValueError, match="BOUND_FILE_CHANGED"):
        context["assert_inputs"]()


def test_quiescence_rechecks_fresh_all22_and_durable_journal(tmp_path, monkeypatch):
    binding, rows, calls, inp, meta = setup_context(tmp_path, monkeypatch)
    for row in rows["roles"]:
        row.update(state="exited", running=False, hostPid=0, containerExitCode=0)
    frozen = binding.save("quiescence.json", rows)
    binding.store.read = lambda name: {"phase": "ALL22_QUIESCENT", "runId": binding.inputs["runId"], "quiescenceSha256": frozen["sha256"]}
    assert binding.verify_all22_quiescent(frozen) is True
    assert calls.count("actual22") == 1
    rows["roles"][0]["hostPid"] = 1
    with pytest.raises(ValueError, match="D12_QUIESCENCE_CHANGED_BEFORE_DATABASE"):
        binding.verify_all22_quiescent(frozen)


def test_existing_exclusive_lock_owner_is_live_and_never_inferred_from_boolean(tmp_path, monkeypatch):
    owner = tmp_path / "beta_operation_lock.py"
    owner.write_text("""import os,json\nfrom pathlib import Path\nfrom contextlib import contextmanager\n@contextmanager\ndef operation_lock(path,action):\n fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)\n try:\n  os.write(fd,(json.dumps({'pid':os.getpid(),'action':action})+'\\n').encode());os.fsync(fd);yield\n finally:\n  os.close(fd);Path(path).unlink()\n""")
    monkeypatch.setattr(effect, "LOCK_OWNER_SHA", hashlib.sha256(owner.read_bytes()).hexdigest())
    artifacts = tmp_path / "marty-demo-recorder" / "artifacts"
    artifacts.mkdir(parents=True)
    path = artifacts / ".recording.lock"
    lease = D12HeldCanonicalLock(ref(owner), path, "00000000-0000-4000-8000-000000000001")
    assert lease.held() is False
    with lease:
        assert lease.held() is True
        with pytest.raises(FileExistsError):
            with D12HeldCanonicalLock(ref(owner), path, "00000000-0000-4000-8000-000000000002"):
                pass
    assert lease.held() is False and not path.exists()


def test_owned_create_ack_rebinds_only_exact_three_cids_and_refuses_foreign_same_image(tmp_path):
    from scoped_native_profiles import D12_PASSPORT_CURRENT
    from scoped_native_runtime import daemon_source
    roles = dict(D12_PASSPORT_CURRENT.roles)
    ids = {role: f"{index+1:064x}" for index, role in enumerate(sorted(D12_CURRENT_RUNTIME_ROLES))}
    new_ids = {role: f"{index+100:064x}" for index, role in enumerate(sorted(roles))}
    image = "sha256:" + "a" * 64
    before = {}
    binaries = {}
    for role in sorted(D12_CURRENT_RUNTIME_ROLES):
        mounts = []
        if role in roles:
            target = "/usr/local/bin/" + roles[role]
            mounts = [{"type": "bind", "destination": target, "source": "/run/desktop/mnt/host/c/old/" + roles[role],
                       "writable": False}]
            file = tmp_path / roles[role]
            file.write_bytes(role.encode())
            binaries[role] = ref(file)
        before[role] = {"role": role, "containerId": ids[role], "imageId": image,
                        "project": "elevenid-beta-ui" if role == "ui-prod" else "elevenid-beta",
                        "binaryMounts": mounts}
    selection = tmp_path / "selection.json"
    selection.write_text(json.dumps({"sourceRevision": D12_PASSPORT_CURRENT.ui_revision,
        "coreRevision": D12_PASSPORT_CURRENT.core_revision, "binaries": binaries}))
    state = {"phase": "EFFECT_ACKNOWLEDGED", "acknowledgedStep": "CREATE_SELECTED",
             "runId": "00000000-0000-4000-8000-000000000001"}
    journal = LinuxBuildJournal.__new__(LinuxBuildJournal)
    journal.read = lambda name: state
    host = D12ReadOnlyHost.__new__(D12ReadOnlyHost)
    host.before = before
    host.engine_id = "3dbbbe66-1c98-4e0c-b0a6-f927c05e7341"
    host._recheck_source = lambda: None
    foreign = {"id": None}

    def docker(argv):
        if argv[0] == "info":
            return host.engine_id
        if argv[0] == "ps":
            role = argv[-1].rsplit("=", 1)[1]
            return new_ids[role]
        assert argv[0] == "inspect"
        rows = []
        for cid in argv[1:]:
            role = next(role for role in ids if cid in (ids[role], new_ids.get(role)))
            created = role in roles and cid == new_ids[role]
            selected_mounts = before[role]["binaryMounts"]
            source = daemon_source(binaries[role]["path"]) if created else None
            mounts = [{"Type": item["type"], "Destination": item["destination"],
                       "Source": source if created else item["source"], "RW": item["writable"]}
                      for item in selected_mounts]
            rows.append({"Id": foreign["id"] if foreign["id"] and role == "flow" else cid,
                         "Image": image, "Mounts": mounts,
                         "Config": {"Labels": {"com.docker.compose.project": before[role]["project"],
                                               "com.docker.compose.service": role}},
                         "State": {"StartedAt": "2026-11-08T00:00:00Z", "Running": False,
                                   "Paused": False, "Pid": 0, "Status": "created" if created else "exited",
                                   "ExitCode": 0, "OOMKilled": False}})
        return json.dumps(rows)

    host._docker = docker
    def save(name, value):
        path = tmp_path / name
        path.write_text(json.dumps(value))
        return ref(path)
    observer = D12CurrentEffectObserver(host, ref(selection), journal, save)
    proof = observer.bind_created_after_ack("CREATE_SELECTED", state)
    assert proof["sha256"] == ref(tmp_path / "d12-created-cids-after-ack.private.json")["sha256"]
    assert {role: observer.current[role]["containerId"] for role in roles} == new_ids
    assert observer.inspect_all22()["roles"]
    foreign["id"] = "f" * 64
    with pytest.raises(ValueError, match="D12_EXACT_OWNED_INSPECTION_REQUIRED"):
        observer.inspect_role("flow")


@pytest.mark.parametrize("change", [None, "cid", "image", "generation", "failed", "bool_exit", "lock", "lock_lost", "compose_fail", "recovery"])
def test_root_intent_requires_held_lock_and_actual_full_resource_binding(tmp_path, monkeypatch, change):
    binding, rows, _, inp, _ = setup_context(tmp_path, monkeypatch)
    for row in rows["roles"]:
        row.update(imageId="sha256:" + "a" * 64,
                   project="elevenid-beta-ui" if row["role"] == "ui-prod" else "elevenid-beta",
                   startedAt="2026-11-08T00:00:00Z")
    private = tmp_path / ".codex" / "private"
    runtime = tmp_path / "runtime-before.json"
    runtime.write_text(json.dumps(rows))
    authority = tmp_path / "authority.json"
    authority.write_text("{}")
    recovery_ref = None
    stopped = None
    if change == "recovery":
        stopped = deepcopy(rows)
        for row in stopped["roles"]:
            row.update(state="exited", running=False, hostPid=0, containerExitCode=0)
        quiescence = private / "stopped.json"
        quiescence.write_text(json.dumps(stopped))
        resource_recovery = private / "maintenance-resource.json"
        resource_recovery.write_text("{}")
        recovery = private / "recovery.json"
        recovery.write_text(json.dumps({"schema": "marty.d12-fence-install-recovery/v1",
            "operation": "RESUME_AFTER_TERMINAL_FENCE_INSTALL", "dispatchAuthorized": True, "draftOnly": False,
            "runId": binding.inputs["runId"], "quiescence": ref(quiescence),
            "maintenanceResourceRecovery": ref(resource_recovery)}))
        recovery_ref = ref(recovery)
        authority.write_text(json.dumps({"approvedRecoveryAuthoritySha256": recovery_ref["sha256"]}))
    profile = private / "resource-profile.json"
    profile.write_text(json.dumps({"schema": "marty.functional-mixed-runtime/v2",
        "scope": "FUNCTIONAL_ONLY", "releaseQualified": False,
        "recordingQualified": False, "resourceRestart": {}}))
    module = Path(effect.__file__).resolve().parents[1] / "tests/scripts/functional-debug-runtime.js"
    binding.host._source_files["tests/scripts/functional-debug-runtime.js"] = {
        "sha256": ref(module)["sha256"]}
    value = json.loads(inp.read_text())
    value.update(d12Authority=ref(authority), runtimeBefore=ref(runtime),
                 resourceProfile=ref(profile), functionalRuntimeModule=ref(module))
    inp.write_text(json.dumps(value))
    permit_path = private / "dispatch-permit.json"
    permit = {"schema": "marty.d12-current-dispatch-intent/v1",
              "dispatchAuthorized": True, "runId": value["runId"], "scope": "FUNCTIONAL_ONLY",
              "releaseQualified": False, "recordingQualified": False,
              "inputs": ref(inp), "authority": ref(authority), "resourceProfile": ref(profile)}
    permit_path.write_text(json.dumps(permit))
    lease = D12HeldCanonicalLock.__new__(D12HeldCanonicalLock)
    live = {"held": change != "lock", "lockChecks": 0, "sourceChecks": 0}
    def held():
        live["lockChecks"] += 1
        return live["held"]
    lease.held = held
    original_recheck = binding.host._recheck_source
    def recheck():
        live["sourceChecks"] += 1
        return original_recheck()
    binding.host._recheck_source = recheck
    config = tmp_path / "docker-config"
    meta = config / "contexts" / "meta" / ("a" * 64) / "meta.json"
    plugin = tmp_path / "cli-plugins" / "docker-compose.exe"
    plugin.parent.mkdir()
    plugin.write_bytes(b"reviewed compose plugin fixture")
    monkeypatch.setattr(effect, "COMPOSE_PLUGIN_SHA", ref(plugin)["sha256"])
    compose_config = config / "config.json"
    compose_config.write_text(json.dumps({"currentContext": "desktop-linux",
        "cliPluginsExtraDirs": [str(plugin.parent)]}))
    owner = D12CurrentHostBindings(binding.host, inputs_ref=ref(inp),
        private_root=private / "run", operation_journal=binding.store,
        build_journal=binding.build_journal, node_executable=ref(tmp_path / "node.exe"),
        docker_executable=ref(tmp_path / "docker.exe"), docker_config=config,
        docker_config_refs={str(meta): ref(meta), str(compose_config): ref(compose_config)},
        lock_lease=lease, dispatch_permit_ref=ref(permit_path),
        compose_plugin_ref=ref(plugin))
    assert owner.context()["dispatch_enabled"] is True
    actual = deepcopy(stopped if change == "recovery" else rows)
    if change == "cid":
        actual["roles"][0]["containerId"] = "f" * 64
    if change == "image":
        actual["roles"][0]["imageId"] = "sha256:" + "f" * 64
    if change == "generation":
        actual["roles"][0]["startedAt"] = "2026-11-08T01:00:00Z"
    class Result:
        returncode = False if change == "bool_exit" else 1 if change == "failed" else 0
        stdout = json.dumps({**actual, "scope": "MAINTENANCE_RECOVERY_ONLY" if change == "recovery" else "FUNCTIONAL_ONLY",
            "releaseQualified": False, "recordingQualified": False}).encode()
        stderr = b""
        observation = {"timedOut": False, "failures": []}
    class ComposeResult:
        returncode = 1 if change == "compose_fail" else 0
        stdout = b"v2.39.4\n"
        stderr = b""
        observation = {"timedOut": False, "failures": []}
    calls = []
    def run(*args, **kwargs):
        calls.append(args)
        if args[0][3:6] == ["compose", "version", "--short"]:
            return ComposeResult()
        if change == "lock_lost":
            live["held"] = False
        return Result()
    monkeypatch.setattr(effect, "bounded_run", run)
    if change == "recovery":
        assert owner.context()["recovery_authorization_verified"](ref(authority), recovery_ref) is True
        assert len(calls) == 2 and "verifyMaintenanceRuntime" in calls[1][0][2]
        receipt = json.loads((private / "run" / "d12-authorization-0001-d12-resource28-bound.private.json").read_bytes())
        assert receipt["scope"] == "MAINTENANCE_RECOVERY_ONLY" and receipt["functionalQualification"] is False
        assert receipt["recoveryAuthority"] == recovery_ref
        request = json.loads((private / "run" / "d12-authorization-0001-d12-resource28-request.private.json").read_bytes())
        assert request["scope"] == "MAINTENANCE_RECOVERY_ONLY"
        with pytest.raises(ValueError, match="D12_ACTUAL_RESOURCE_RESULT_REQUIRED"):
            owner.authorization_verified(ref(authority))
    elif change is None:
        assert owner.context()["authorization_verified"](ref(authority)) is True
        assert len(calls) == 2
        assert calls[0][0][3:6] == ["compose", "version", "--short"]
        assert (private / "run" / "d12-authorization-0001-d12-compose-version-terminal.private.json").is_file()
        assert (private / "run" / "d12-authorization-0001-d12-resource28-bound.private.json").is_file()
        first_files = {p.name: p.read_bytes() for p in (private / "run").glob("d12-authorization-0001-*")}
        checks = (live["lockChecks"], live["sourceChecks"])
        assert owner.authorization_verified(ref(authority)) is True
        assert len(calls) == 4
        assert [args[0][3:6] for args in calls[::2]] == [["compose", "version", "--short"]] * 2
        assert live["lockChecks"] > checks[0] and live["sourceChecks"] > checks[1]
        assert first_files == {p.name: p.read_bytes() for p in (private / "run").glob("d12-authorization-0001-*")}
        for number in (1, 2):
            receipt = json.loads((private / "run" / f"d12-authorization-{number:04d}-d12-resource28-bound.private.json").read_bytes())
            assert receipt["authorizationAttempt"] == number
            request = json.loads((private / "run" / f"d12-authorization-{number:04d}-d12-resource28-request.private.json").read_bytes())
            assert request["scope"] == "FUNCTIONAL_ONLY"
            assert len(receipt["observations"]) == 7
            for bound in receipt["observations"].values():
                assert ref(Path(bound["path"])) == bound
        live["held"] = False
        with pytest.raises(ValueError, match="D12_ROOT_INTENT_AND_HELD_LOCK_REQUIRED"):
            owner.authorization_verified(ref(authority))
        assert len(calls) == 4
    elif change == "lock":
        with pytest.raises(ValueError, match="D12_ROOT_INTENT_AND_HELD_LOCK_REQUIRED"):
            owner.context()["authorization_verified"](ref(authority))
        assert calls == []
    elif change == "lock_lost":
        with pytest.raises(ValueError, match="D12_CANONICAL_LOCK_LOST_DURING_RESOURCE_READ"):
            owner.context()["authorization_verified"](ref(authority))
        assert not (private / "run" / "d12-authorization-0001-d12-resource28-bound.private.json").exists()
    elif change == "compose_fail":
        with pytest.raises(ValueError, match="D12_PINNED_COMPOSE_DISCOVERY_FAILED"):
            owner.context()["authorization_verified"](ref(authority))
        assert len(calls) == 1
        assert not (private / "run" / "d12-authorization-0001-d12-resource28-request.private.json").exists()
    else:
        with pytest.raises(ValueError, match="D12_ACTUAL_RESOURCE28_VERIFIER_FAILED|D12_RESOURCE28_AND_NATIVE22_DIVERGED"):
            owner.context()["authorization_verified"](ref(authority))
        assert not (private / "run" / "d12-authorization-0001-d12-resource28-bound.private.json").exists()

@pytest.mark.parametrize("shape", ["historical", "current", "extra", "wrong-engine", "writes-true", "writes-zero", "missing-engine", "missing-writes"])
def test_database_preimage_closed_metadata_shape_preserves_observed_proof(tmp_path, shape):
    from types import SimpleNamespace
    engine = "3dbbbe66-1c98-4e0c-b0a6-f927c05e7341"
    identity = {"containerId": "a" * 64, "imageId": "sha256:" + "b" * 64,
                "startedAt": "2026-11-11T14:54:24Z", "hostPid": 5202,
                "project": "elevenid-beta", "service": "postgres"}
    frozen = {"databaseIdentity": identity}
    if shape != "historical":
        frozen.update(engineId=engine, runtimeWrites=False)
    if shape == "extra": frozen["unbound"] = True
    if shape == "wrong-engine": frozen["engineId"] = "foreign"
    if shape == "writes-true": frozen["runtimeWrites"] = True
    if shape == "writes-zero": frozen["runtimeWrites"] = 0
    if shape == "missing-engine": frozen.pop("engineId")
    if shape == "missing-writes": frozen.pop("runtimeWrites")
    path = tmp_path / "database.json"
    path.write_text(json.dumps(frozen))
    calls = []
    def read(args):
        calls.append(args)
        if args == ["info", "--format", "{{.ID}}"]:
            return engine.encode()
        assert args == ["inspect", identity["containerId"]]
        return json.dumps([{"Id": identity["containerId"], "Image": identity["imageId"],
            "Config": {"Labels": {"com.docker.compose.project": "elevenid-beta",
                                  "com.docker.compose.service": "postgres"}},
            "State": {"StartedAt": identity["startedAt"], "Pid": identity["hostPid"],
                      "Running": True, "Status": "running", "Paused": False,
                      "OOMKilled": False, "Health": {"Status": "healthy"}}}]).encode()
    observer = D12CurrentEffectObserver.__new__(D12CurrentEffectObserver)
    observer.host = SimpleNamespace(engine_id=engine, _recheck_source=lambda: None, _docker=read)
    if shape in ("historical", "current"):
        assert observer.database_snapshot(ref(path)) == frozen
        assert calls == [["info", "--format", "{{.ID}}"], ["inspect", identity["containerId"]],
                         ["info", "--format", "{{.ID}}"]]
    else:
        with pytest.raises(ValueError, match="D12_DATABASE_PREIMAGE"):
            observer.database_snapshot(ref(path))
        assert not calls


def test_two_real_database_steps_keep_the_durable_quiescence_binding(tmp_path, monkeypatch):
    import scoped_native_database as database
    binding, rows, calls, inp, _meta = setup_context(tmp_path, monkeypatch)
    for row in rows["roles"]:
        row.update(state="exited", running=False, hostPid=0, containerExitCode=0)
    quiescence = binding.save("quiescence.json", rows)
    before = binding.save("db-before.json", {"databaseIdentity": {"containerId": "a" * 64}})
    binding.inputs.update(uiRevision="source", coreRevision="core", executorSource={"path": "executor", "sha256": "b" * 64}, databaseBefore=before)
    inp.write_text(json.dumps(binding.inputs))
    binding.inputs_ref = ref(inp)
    inputs = {**binding.inputs, "quiescence": quiescence, "compatibility": {"plan": {}, "result": {}},
              "databaseAdminUrl": binding.save_bytes("synthetic-url", b"postgres://postgres:synthetic@postgres:5432/marty"),
              "migrationSources": {}, "migrationSetSha256": "digest"}
    value = database.D12CurrentDatabasePhase.__new__(database.D12CurrentDatabasePhase)
    value.i = inputs
    value.selection = {"preparedSource": {}, "canonicalBuildReceipt": {}}
    value.select_binaries = lambda *_: value.selection
    value.check_compatibility = lambda *_: None
    value.guard = lambda: None
    value.state = {"schema": value.operation_schema, "phase": "NOT_STARTED", "runId": inputs["runId"],
        "sourceRevision": "source", "coreRevision": "core", "selectionSha256": inputs["selection"]["sha256"],
        "executorSource": inputs["executorSource"], "databaseIdentity": {"containerId": "a" * 64}, "operations": []}
    value.SCHEMA_BINARIES = {}
    durable = {"phase": "ALL22_QUIESCENT", "runId": inputs["runId"], "quiescenceSha256": quiescence["sha256"]}
    history = []
    intent = {"runId": inputs["runId"], "selectionSha256": inputs["selection"]["sha256"], "executorSource": inputs["executorSource"]}
    class Journal:
        def read(self, name):
            return deepcopy(intent if name == "build-apply-intent.json" else durable)
        def state(self, row):
            durable.clear(); durable.update(deepcopy(row)); history.append(deepcopy(row))
            return {"fileFsync": True, "parentDirectory": {"supported": True, "synced": True}}
    value.store = binding.store = Journal()
    value.g = {"dispatch_enabled": True, "build_journal": object(), "verify_all22_quiescent": binding.verify_all22_quiescent, "save": binding.save}
    value.node = lambda mode, **_: "digest" if mode == "digest" else {"epoch": 1}
    effects = []
    value.sql = lambda name: effects.append(name) or {"stdout": {}, "state": "exited", "exitCode": 0}
    value.sql_receipts = {}
    class SelectedTwoStepsComplete(Exception):
        pass
    def selected_step(step_id, operation):
        if step_id == "MAINTENANCE_START":
            raise SelectedTwoStepsComplete
        return database.NativeDatabasePhase.step(value, step_id, operation)
    value.step = selected_step
    with pytest.raises(SelectedTwoStepsComplete):
        database.NativeDatabasePhase.run(value)
    assert effects == ["passport-beta-fence-install.sql", "passport-beta-fence-verify.sql"]
    assert [row["stepId"] for row in durable["operations"]] == ["FENCE_INSTALL", "FENCE_VERIFY"]
    assert all(row["quiescenceSha256"] == quiescence["sha256"] for row in history)
    assert durable["phase"] == "DATABASE_OPERATION_TERMINAL"
    assert calls.count("actual22") == 3  # run entry and independently before both effects


@pytest.mark.parametrize("change", ["missing-hash", "run", "selection", "executor", "database", "pending", "unknown-outcome"])
def test_terminal_database_quiescence_refuses_unbound_or_unknown_checkpoint(tmp_path, change):
    from scoped_native_database import require_bound_quiescence
    p = tmp_path / "db.json"
    p.write_text(json.dumps({"databaseIdentity": {"containerId": "a" * 64}}))
    inputs = {"runId": "run", "uiRevision": "source", "coreRevision": "core", "selection": {"sha256": "b" * 64},
              "executorSource": {"path": "executor", "sha256": "c" * 64}, "databaseBefore": ref(p)}
    bound = {"sha256": "d" * 64}
    state = {"schema": "marty.native-d12-current-operation-state/v1", "phase": "DATABASE_OPERATION_TERMINAL", "runId": "run",
             "quiescenceSha256": bound["sha256"], "sourceRevision": "source", "coreRevision": "core",
             "selectionSha256": inputs["selection"]["sha256"], "executorSource": inputs["executorSource"],
             "databaseIdentity": {"containerId": "a" * 64}, "pendingStep": None, "pendingRequest": None,
             "operations": [{"state": "SUCCEEDED", "exitCode": 0, "unknownOutcome": False}]}
    if change == "missing-hash": state.pop("quiescenceSha256")
    elif change == "run": state["runId"] = "foreign"
    elif change == "selection": state["selectionSha256"] = "foreign"
    elif change == "executor": state["executorSource"] = {}
    elif change == "database": state["databaseIdentity"] = {}
    elif change == "pending": state.update(phase="DATABASE_OPERATION_PENDING", pendingStep="FENCE_VERIFY")
    else: state["operations"][0]["unknownOutcome"] = True
    with pytest.raises(ValueError, match="D12_DURABLE_QUIESCENCE_NOT_BOUND"):
        require_bound_quiescence(state, inputs, bound)
