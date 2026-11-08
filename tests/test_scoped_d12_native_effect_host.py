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
    meta = config / "meta.json"
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
    binding.store.read = lambda name: {"phase": "ALL22_QUIESCENT", "quiescenceSha256": frozen["sha256"]}
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
