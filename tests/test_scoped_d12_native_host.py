"""Read-only current D12 host bindings; all transport calls are local stubs."""
import copy
import hashlib
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from scoped_native_runtime import D12_CURRENT_RUNTIME_ROLES, ref
from scoped_d12_native_host import D12ReadOnlyHost, ORIGIN

ENGINE = "3dbbbe66-1c98-4e0c-b0a6-f927c05e7341"

def fixture(tmp_path):
    source_root = Path(__file__).resolve().parents[1]
    roles = sorted(D12_CURRENT_RUNTIME_ROLES)
    binding = {"roles": [{"role": role, "project": "elevenid-beta-ui" if role == "ui-prod" else "elevenid-beta",
                           "containerId": f"{index+1:064x}", "imageId": "sha256:" + "a" * 64,
                           "source": "1" * 40, "sha256": "b" * 64, "binaryMounts": []}
                          for index, role in enumerate(roles)]}
    before = tmp_path / "before.json"
    before.write_text(json.dumps(binding))
    models = {project: {"name": project, "services": {role: {} for role in roles
                      if (role == "ui-prod") == (project == "elevenid-beta-ui")}}
              for project in ("elevenid-beta", "elevenid-beta-ui")}
    args, sources, planned = {}, {}, {}
    for project, model in models.items():
        compose = tmp_path / (project + ".yml")
        compose.write_text("services: {}\n")
        frozen = tmp_path / (project + ".json")
        frozen.write_text(json.dumps(model))
        args[project] = ["docker", "compose", "-p", project, "--project-directory", str(tmp_path), "-f", str(compose)]
        sources[project], planned[project] = {str(compose): ref(compose)}, ref(frozen)
    revision, tree = "1" * 40, "2" * 40
    files = {}
    for file in (source_root / "scripts").glob("*.py"):
        raw = file.read_bytes()
        name = "scripts/" + file.name
        files[name] = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
                       "gitBlob": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()}
    closure = tmp_path / "closure.json"
    closure.write_text(json.dumps({"schema": "marty.d12-db-preview-source-closure/v2",
        "operatorRevision": revision, "operatorTree": tree, "files": files,
        "applyAuthorized": False, "runtimeDeployed": False}))
    repository = tmp_path / "repo"
    repository.mkdir()
    def git(_repo, *argv):
        assert _repo == repository.resolve()
        if argv == ("remote", "get-url", "origin"):
            return (ORIGIN + "\n").encode()
        if argv == ("cat-file", "-t", revision):
            return b"commit\n"
        if argv == ("rev-parse", revision + "^{tree}"):
            return (tree + "\n").encode()
        if len(argv) == 2 and argv[0] in ("show", "rev-parse"):
            name = argv[1].removeprefix(revision + ":")
            if argv[0] == "show":
                return (source_root / name).read_bytes()
            return (files[name]["gitBlob"] + "\n").encode()
        raise AssertionError("unreviewed Git read")
    inputs = {"schema": "marty.d12-readonly-host-input/v1", "dispatchEnabled": False,
              "sourceRoot": str(source_root), "sourceClosure": ref(closure),
              "sourceRepository": str(repository),
              "hostSource": ref(source_root / "scripts" / "scoped_d12_native_host.py"),
              "runtimeBefore": ref(before), "engineId": ENGINE,
              "composeArguments": args, "composeSources": sources, "plannedModels": planned}
    inspections = [{"Id": row["containerId"], "Image": row["imageId"], "Mounts": [],
        "Config": {"Labels": {"com.docker.compose.project": row["project"],
                              "com.docker.compose.service": row["role"]}},
        "State": {"StartedAt": "2026-11-08T00:00:00Z", "Running": True, "Paused": False,
                  "Pid": 100, "Status": "running", "ExitCode": 0, "OOMKilled": False}}
                   for row in binding["roles"]]
    calls = []
    def docker(argv):
        calls.append(("docker", argv))
        return ENGINE if argv[0] == "info" else json.dumps(inspections)
    def compose(argv):
        calls.append(("compose", argv))
        return json.dumps(models[argv[3]])
    return inputs, binding, inspections, models, calls, docker, compose, git

def test_exact_current_roles_inspection_and_planned_two_project_render(tmp_path):
    inputs, binding, inspections, models, calls, docker, compose, git = fixture(tmp_path)
    host = D12ReadOnlyHost(inputs, docker_read=docker, compose_read=compose, git_read=git)
    observed = host.observe22()
    assert {row["role"] for row in observed["roles"]} == D12_CURRENT_RUNTIME_ROLES
    assert host.inspect_role("event-stream")["role"] == "event-stream"
    assert host.render_two_project_baseline() == models
    assert host.read_only_context()["dispatch_enabled"] is False
    assert all(call[1][0] in ("info", "inspect", "docker") for call in calls)
    assert all(call[1][-3:] == ["config", "--format", "json"] for call in calls if call[0] == "compose")

def test_wrong_role_cid_and_foreign_label_refuse(tmp_path):
    inputs, binding, inspections, models, calls, docker, compose, git = fixture(tmp_path)
    host = D12ReadOnlyHost(inputs, docker_read=docker, compose_read=compose, git_read=git)
    inspections[0]["Id"] = "f" * 64
    with pytest.raises(ValueError, match="D12_ROLE_CID_SET_CHANGED"):
        host.observe22()
    inspections[0]["Id"] = binding["roles"][0]["containerId"]
    inspections[0]["Config"]["Labels"]["com.docker.compose.service"] = "foreign"
    with pytest.raises(ValueError, match="D12_ROLE_IDENTITY_CHANGED"):
        host.observe22()

def test_stopped_and_created_projected_state_does_not_claim_new_elf_probe(tmp_path):
    inputs, binding, inspections, models, calls, docker, compose, git = fixture(tmp_path)
    host = D12ReadOnlyHost(inputs, docker_read=docker, compose_read=compose, git_read=git)
    stopped = copy.deepcopy(inspections)
    for row in stopped:
        row["State"].update(Running=False, Pid=0, Status="exited", ExitCode=0)
    projected = host.project_inspections(binding, stopped)
    assert all(not row["running"] and row["hostPid"] == 0 for row in projected["roles"])
    assert projected["sourceFactsBoundToPriorReceiptNotNewElfProbe"] is True
    created_binding = copy.deepcopy(binding)
    created = copy.deepcopy(stopped)
    created_binding["roles"][0]["containerId"] = "e" * 64
    created[0]["Id"] = "e" * 64
    created[0]["State"]["Status"] = "created"
    projected = host.project_inspections(created_binding, created)
    assert projected["roles"][0]["state"] == "created"
    assert projected["roles"][0]["source"] == binding["roles"][0]["source"]
    assert projected["sourceFactsBoundToPriorReceiptNotNewElfProbe"] is True

def test_compose_drift_and_effect_verbs_refuse(tmp_path):
    inputs, binding, inspections, models, calls, docker, compose, git = fixture(tmp_path)
    host = D12ReadOnlyHost(inputs, docker_read=docker, compose_read=compose, git_read=git)
    with pytest.raises(ValueError, match="D12_READONLY_DOCKER_COMMAND_REQUIRED"):
        host.docker_read(["stop", binding["roles"][0]["containerId"]])
    with pytest.raises(ValueError, match="D12_FROZEN_COMPOSE_ARGUMENTS_REQUIRED"):
        host.compose_model([*inputs["composeArguments"]["elevenid-beta"], "up"])
    models["elevenid-beta"]["services"]["foreign"] = {}
    with pytest.raises(ValueError, match="D12_PLANNED_MODEL_DRIFT"):
        host.compose_model(inputs["composeArguments"]["elevenid-beta"])


def test_source_closure_and_runtime_binding_refuse_unreviewed_bytes(tmp_path):
    inputs, binding, inspections, models, calls, docker, compose, git = fixture(tmp_path)
    wrong = copy.deepcopy(inputs)
    wrong["sourceClosure"]["sha256"] = "f" * 64
    with pytest.raises(ValueError, match="BOUND_FILE_CHANGED"):
        D12ReadOnlyHost(wrong, docker_read=docker, compose_read=compose, git_read=git)
    wrong = copy.deepcopy(inputs)
    wrong["runtimeBefore"]["sha256"] = "f" * 64
    with pytest.raises(ValueError, match="BOUND_FILE_CHANGED"):
        D12ReadOnlyHost(wrong, docker_read=docker, compose_read=compose, git_read=git)


def test_reviewed_successor_revision_can_bind_same_exported_modules(tmp_path):
    inputs, binding, inspections, models, calls, docker, compose, git = fixture(tmp_path)
    old = json.loads(Path(inputs["sourceClosure"]["path"]).read_text())
    old_revision = old["operatorRevision"]
    new_revision, new_tree = "3" * 40, "4" * 40
    old.update(operatorRevision=new_revision, operatorTree=new_tree)
    newer = tmp_path / "closure-successor.json"
    newer.write_text(json.dumps(old))
    inputs["sourceClosure"] = ref(newer)
    def successor_git(repo, *args):
        if args == ("cat-file", "-t", new_revision):
            return b"commit\n"
        if args == ("rev-parse", new_revision + "^{tree}"):
            return (new_tree + "\n").encode()
        if len(args) == 2 and args[1].startswith(new_revision + ":"):
            return git(repo, args[0], old_revision + args[1][len(new_revision):])
        return git(repo, *args)
    assert D12ReadOnlyHost(inputs, docker_read=docker, compose_read=compose,
                           git_read=successor_git).read_only_context()["dispatch_enabled"] is False

def test_git_object_content_mismatch_refuses_even_when_receipt_hash_matches(tmp_path):
    inputs, binding, inspections, models, calls, docker, compose, git = fixture(tmp_path)
    def changed_git(repo, *args):
        if len(args) == 2 and args[0] == "show" and args[1].endswith("scoped_passport_maintenance.py"):
            return b"foreign source\n"
        return git(repo, *args)
    with pytest.raises(ValueError, match="D12_GIT_EXPORTED_SOURCE_CHANGED"):
        D12ReadOnlyHost(inputs, docker_read=docker, compose_read=compose, git_read=changed_git)


def test_mutated_caller_arguments_and_source_bytes_refuse_before_compose_callback(tmp_path):
    inputs, binding, inspections, models, calls, docker, compose, git = fixture(tmp_path)
    host = D12ReadOnlyHost(inputs, docker_read=docker, compose_read=compose, git_read=git)
    original = list(inputs["composeArguments"]["elevenid-beta"])
    inputs["composeArguments"]["elevenid-beta"].append("up")
    with pytest.raises(ValueError, match="D12_FROZEN_COMPOSE_ARGUMENTS_REQUIRED"):
        host.compose_model(inputs["composeArguments"]["elevenid-beta"])
    assert not [row for row in calls if row[0] == "compose"]
    source = next(iter(inputs["composeSources"]["elevenid-beta"]))
    Path(source).write_text("services: {changed: {}}\n")
    with pytest.raises(ValueError, match="BOUND_FILE_CHANGED"):
        host.compose_model(original)
    assert not [row for row in calls if row[0] == "compose"]

def test_mutated_planned_model_refuses_before_compose_callback(tmp_path):
    inputs, binding, inspections, models, calls, docker, compose, git = fixture(tmp_path)
    host = D12ReadOnlyHost(inputs, docker_read=docker, compose_read=compose, git_read=git)
    ref_path = Path(inputs["plannedModels"]["elevenid-beta"]["path"])
    ref_path.write_text(json.dumps({"name": "elevenid-beta", "services": {"foreign": {}}}))
    with pytest.raises(ValueError, match="BOUND_FILE_CHANGED"):
        host.compose_model(inputs["composeArguments"]["elevenid-beta"])
    assert not [row for row in calls if row[0] == "compose"]


@pytest.mark.parametrize("field", ["operatorRevision", "operatorTree", "gitBlob"])
def test_source_identity_requires_immutable_hex_ids_before_transport(tmp_path, field):
    inputs, _, _, _, calls, docker, compose, git = fixture(tmp_path)
    closure = Path(inputs["sourceClosure"]["path"])
    value = json.loads(closure.read_text())
    if field == "gitBlob":
        value["files"][next(iter(value["files"]))][field] = "z" * 40
    else:
        value[field] = "z" * 40
    closure.write_text(json.dumps(value))
    inputs["sourceClosure"] = ref(closure)
    with pytest.raises(ValueError, match="D12_REVIEWED_SOURCE_RECEIPT_REQUIRED|D12_SOURCE_FILE_SCOPE_CHANGED"):
        D12ReadOnlyHost(inputs, docker_read=docker, compose_read=compose, git_read=git)
    assert calls == []
