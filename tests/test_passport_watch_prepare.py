"""Cold watcher preparation must fail before application or credential exposure."""

from datetime import datetime, timedelta, timezone
import copy
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
from types import SimpleNamespace

import pytest
import yaml

from scripts import passport_watch_prepare as preparation


ROOT = Path(__file__).resolve().parents[1]
IMAGE_ID = "sha256:" + "e" * 64
BUILDER = "Name: default\nDriver: docker\n\nNodes:\nName: default\nEndpoint: default\nStatus: running\n"
INFO = {"OSType": "linux", "CgroupDriver": "systemd", "CgroupVersion": "2",
        "MemoryLimit": True, "SwapLimit": True, "CpuCfsPeriod": True, "CpuCfsQuota": True,
        "PidsLimit": True}
pytestmark = pytest.mark.usefixtures("rootful_docker_environment")


@pytest.fixture
def source(tmp_path):
    root = tmp_path / "checkout"
    for name in (*preparation.PREPARATION_FILES, "rust/Cargo.toml", "rust/crate/Cargo.toml"):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(name + "\n")
    leaf = root / "rust/crate/src/main.rs"
    leaf.parent.mkdir()
    leaf.write_text("fn main() {}\n")
    for name in ("services/Dockerfile.passport-watch", "services/Dockerfile.passport-watch.dockerignore"):
        (root / name).write_bytes((ROOT / name).read_bytes())
    subprocess.run(["git", "init", "--quiet", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "add", "--all"], check=True)
    return root


@pytest.fixture
def reader(tmp_path):
    path = tmp_path / "private-reader"
    path.write_text("test-reader-not-an-actual-credential\n")
    path.chmod(0o600)
    return path


def image_row(source, image_id=IMAGE_ID):
    seed, lock = preparation.seed_identity(source)
    return {"Id": image_id, "Config": {"Labels": {
        preparation.SEED_LABEL: seed, preparation.LOCK_LABEL: lock,
    }}}


def test_seed_ignores_ordinary_rust_edits_but_binds_dependency_and_recipe_inputs(source):
    original = preparation.seed_identity(source)
    (source / "rust/crate/src/main.rs").write_text("fn main() { println!(\"changed\"); }\n")
    assert preparation.seed_identity(source) == original
    for name in ("rust/Cargo.lock", "rust/crate/Cargo.toml", *preparation.PREPARATION_FILES[1:]):
        path = source / name
        before = path.read_bytes()
        path.write_bytes(before + b"changed\n")
        assert preparation.seed_identity(source)[0] != original[0]
        path.write_bytes(before)


def test_seed_refuses_redirected_preparation_inputs(source, tmp_path):
    leaf = source / "rust/crate/Cargo.toml"
    leaf.unlink()
    foreign = tmp_path / "foreign-manifest"
    foreign.write_text("foreign")
    leaf.symlink_to(foreign)
    with pytest.raises(preparation.WatchPreparationError, match="redirected"):
        preparation.seed_identity(source)


@pytest.mark.parametrize("failure", ("missing", "empty", "public", "symlink", "inside", "multiline", "hardlink", "owner", "replaceable-parent"))
def test_reader_file_rejected_before_any_docker_or_cached_build(source, reader, tmp_path, monkeypatch, failure):
    path = reader
    if failure == "missing":
        reader.unlink()
    elif failure == "empty":
        reader.write_text("")
    elif failure == "public":
        reader.chmod(0o644)
    elif failure == "symlink":
        path = tmp_path / "reader-link"
        path.symlink_to(reader)
    elif failure == "inside":
        path = source / "reader"
        reader.rename(path)
    elif failure == "multiline":
        reader.write_text("first\nsecond\n")
    elif failure == "hardlink":
        os.link(reader, tmp_path / "reader-hardlink")
    elif failure == "owner":
        monkeypatch.setattr(preparation.os, "getuid", lambda: reader.stat().st_uid + 1)
        monkeypatch.setattr(preparation.os, "geteuid", lambda: reader.stat().st_uid + 1)
    elif failure == "replaceable-parent":
        parent = tmp_path / "replaceable"
        parent.mkdir(mode=0o777)
        parent.chmod(0o777)
        path = parent / "reader"
        reader.rename(path)
    monkeypatch.setattr(preparation, "inspect_docker", lambda *args: pytest.fail("must reject before Docker"))
    with pytest.raises(preparation.WatchPreparationError):
        preparation.prepare(source, path, {})


def test_source_reader_and_remote_builder_environment_are_removed():
    original = {
        "PRIVATE_FORKS_READ_TOKEN": "secret", "PRIVATE_FORKS_TOKEN_FILE": "/private/reader",
        "BUILDX_BUILDER": "paid-remote", "BUILDKIT_HOST": "tcp://remote.invalid:1234",
        "BUILDX_CONFIG": "/remote/config", "COMPOSE_BAKE": "true",
        "COMPOSE_DOCKER_CLI_BUILD": "1", "DOCKER_BUILDKIT": "0",
        "DOCKER_HOST": "ssh://foreign.invalid", "DOCKER_CONTEXT": "foreign",
        "KEEP": "value",
    }
    command, selected = preparation._command(["build", "--builder", "default", "."], original)
    assert command == ["docker", "--host", "unix:///var/run/docker.sock", "build", "--builder", "default", "."]
    assert selected == {"DOCKER_HOST": "unix:///var/run/docker.sock", "KEEP": "value"}
    assert original["PRIVATE_FORKS_READ_TOKEN"] == "secret"


@pytest.mark.parametrize("builder", (
    BUILDER.replace("Driver: docker", "Driver: remote"),
    BUILDER.replace("Endpoint: default", "Endpoint: tcp://remote.invalid:1234"),
    BUILDER + "Name: second\nEndpoint: default\nStatus: running\n",
    BUILDER.replace("Status: running", "Status: stopped"),
))
def test_nonlocal_or_unavailable_default_builder_is_refused(monkeypatch, builder):
    monkeypatch.setattr(preparation, "inspect_docker", lambda *args: builder)
    with pytest.raises(preparation.WatchPreparationError, match="default local builder"):
        preparation.require_local_builder({})


def test_copy_only_builder_does_not_trust_buildkit_resource_advertising(monkeypatch):
    def inspect(args, env):
        assert args == ["buildx", "inspect", "default"]
        return BUILDER
    monkeypatch.setattr(preparation, "inspect_docker", inspect)
    preparation.require_local_builder({})


@pytest.mark.parametrize("key,value", (
    ("MemoryLimit", False), ("SwapLimit", False), ("CpuCfsPeriod", False),
    ("CpuCfsQuota", False), ("PidsLimit", False), ("CgroupVersion", "1"), ("CgroupDriver", "cgroupfs"),
))
def test_missing_resource_delegation_fails_before_build(monkeypatch, key, value):
    monkeypatch.setattr(preparation, "inspect_docker", lambda *args: json.dumps({**INFO, key: value}))
    with pytest.raises(preparation.WatchPreparationError, match="enforced Linux"):
        preparation.require_resource_limits({})


@pytest.fixture
def engine(source, monkeypatch):
    state = SimpleNamespace(calls=[], containers={}, removed=[], starts=[], created=[],
                            inspect_hook=None, start_hook=None, build_context=None, interrupt_create=False)
    base = {"Id": "sha256:" + "d" * 64, "Config": {"Env": ["PATH=/usr/bin:/usr/local/cargo/bin",
            "CARGO_HOME=/usr/local/cargo", "RUSTUP_HOME=/usr/local/rustup"], "OnBuild": None, "Volumes": None}}
    state.base = base
    original_run = subprocess.run

    def inspect(args, env):
        assert not any(name in env for name in preparation.SOURCE_READER_ENV)
        if args[0] == "info":
            return json.dumps(INFO)
        if args[0] == "buildx":
            return BUILDER
        if args[:2] == ["image", "inspect"]:
            return json.dumps([base if args[2] == preparation.BASE_IMAGE else image_row(source)])
        if args[:2] == ["container", "ls"]:
            owner = args[-1].split("=", 2)[-1]
            return "\n".join(key for key, row in state.containers.items()
                             if row.get("Config", {}).get("Labels", {}).get(preparation.PREPARATION_LABEL) == owner)
        assert args[:2] == ["container", "inspect"]
        row = copy.deepcopy(state.containers[args[2]])
        if state.inspect_hook:
            state.inspect_hook(row)
        return json.dumps([row])

    def run(command, **kwargs):
        if command[0] == "git":
            return original_run(command, **kwargs)
        assert command[:3] == ["docker", "--host", "unix:///var/run/docker.sock"]
        args = command[3:]
        state.calls.append((args, kwargs["env"]))
        value = lambda flag: args[args.index(flag) + 1]
        if args[0] == "create":
            container_id = str(len(state.created) + 1) * 64
            values = dict(entry.split("=", 1) for entry in base["Config"]["Env"])
            values.update(args[index + 1].split("=", 1) for index, flag in enumerate(args) if flag == "--env")
            mounts = []
            for index, flag in enumerate(args):
                if flag == "--mount":
                    fields = dict(part.split("=", 1) if "=" in part else (part, "")
                                  for part in args[index + 1].split(","))
                    mounts.append({"Type": fields["type"], "Source": fields["src"], "Destination": fields["dst"],
                                   "RW": "readonly" not in fields, "Propagation": "rprivate"})
            record = {"Id": container_id, "Name": "/" + value("--name"), "Image": base["Id"],
                "Config": {"Image": preparation.BASE_IMAGE, "Entrypoint": [value("--entrypoint")],
                    "Cmd": args[args.index(preparation.BASE_IMAGE) + 1:], "WorkingDir": value("--workdir"), "User": "",
                    "Env": [key + "=" + val for key, val in values.items()],
                    "Labels": dict([value("--label").split("=", 1)])},
                "HostConfig": {"Memory": int(value("--memory")), "MemorySwap": int(value("--memory-swap")),
                    "CpuPeriod": int(value("--cpu-period")), "CpuQuota": int(value("--cpu-quota")),
                    "PidsLimit": int(value("--pids-limit")), "ReadonlyRootfs": "--read-only" in args,
                    "Privileged": "--privileged" in args, "CapAdd": None, "CapDrop": [value("--cap-drop")],
                    "SecurityOpt": [value("--security-opt")], "NetworkMode": value("--network"),
                    "CgroupnsMode": value("--cgroupns"), "PidMode": "", "PortBindings": {},
                    "PublishAllPorts": False, "Devices": [], "DeviceRequests": None,
                    "Tmpfs": dict([value("--tmpfs").split(":", 1)]), "RestartPolicy": {"Name": value("--restart")}},
                "Mounts": mounts, "State": {"Status": "created"}}
            state.containers[container_id] = record
            state.created.append(copy.deepcopy(record))
            if state.interrupt_create:
                raise subprocess.TimeoutExpired("synthetic create", 30)
            Path(value("--cidfile")).write_text(container_id)
        elif args[0] == "start":
            container_id = args[-1]
            state.starts.append(container_id)
            row = state.containers[container_id]
            if state.start_hook:
                state.start_hook(row)
            cargo = Path(next(entry["Source"] for entry in row["Mounts"] if entry["Destination"] == "/cargo-cache"))
            values = dict(entry.split("=", 1) for entry in row["Config"]["Env"])
            if "--probe-dependencies" not in row["Config"]["Cmd"][-1]:
                for name in ("registry", "git"):
                    (cargo / name).mkdir(exist_ok=True)
                    (cargo / name / "dependency-source").write_text("synthetic dependency")
                    if row["HostConfig"]["NetworkMode"] == "none":
                        (cargo / name / ".marty-passport-watch-seed").write_text(values["PASSPORT_WATCH_SEED_ID"])
            row["State"] = {"Status": "exited", "ExitCode": 0, "OOMKilled": False}
        elif args[0] == "rm":
            state.removed.append(args[-1])
            del state.containers[args[-1]]
        elif args[0] == "build":
            state.build_context = Path(args[-1])
            assert state.build_context != source
            assert (state.build_context / "Dockerfile").read_bytes() == (source / "services/Dockerfile.passport-watch").read_bytes()
            Path(value("--iidfile")).write_text(IMAGE_ID + "\n")
        else:
            assert args == ["pull", preparation.BASE_IMAGE]
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(preparation, "inspect_docker", inspect)
    monkeypatch.setattr(preparation.subprocess, "run", run)
    return state


def test_prepare_uses_reader_only_in_bounded_fetch_then_offline_and_copy_only_image(source, reader, engine):
    result, log = preparation.prepare(source, reader, {
        "PRIVATE_FORKS_READ_TOKEN": "foreign-reader", "BUILDX_BUILDER": "foreign",
        "BUILDKIT_HOST": "tcp://foreign.invalid", "DOCKER_HOST": "ssh://foreign.invalid",
    })
    assert result["PASSPORT_WATCH_IMAGE"] == IMAGE_ID
    assert log.stat().st_mode & 0o777 == 0o600
    assert log.parent.stat().st_mode & 0o777 == 0o700
    assert engine.starts == engine.removed == ["1" * 64, "2" * 64, "3" * 64]
    assert engine.containers == {}
    assert not (log.parent / "source").exists() and not engine.build_context.exists()
    probe, fetch, offline = engine.created
    assert probe["HostConfig"]["NetworkMode"] == "none"
    assert not any(entry["Source"] == str(reader) or entry["RW"] for entry in probe["Mounts"])
    reader_mounts = [entry for entry in fetch["Mounts"] if entry["Destination"] == preparation.TOKEN_TARGET]
    assert reader_mounts == [{"Type": "bind", "Source": str(reader), "Destination": preparation.TOKEN_TARGET,
                              "RW": False, "Propagation": "rprivate"}]
    assert not any(entry["Source"] == str(reader) for entry in offline["Mounts"])
    assert offline["HostConfig"]["NetworkMode"] == "none"
    for command, environment in engine.calls:
        assert not any(name.startswith(("BUILDX_", "BUILDKIT_", "PRIVATE_FORKS_")) for name in environment)
        assert "test-reader-not-an-actual-credential" not in json.dumps([command, environment])
        assert "--push" not in command and "--cache-to" not in command and "--cache-from" not in command
        if command[0] == "build":
            assert command[1:5] == ["--builder", "default", "--network", "none"]
            assert "--secret" not in command and str(reader) not in " ".join(command)


def test_private_context_stays_outside_checkout_despite_ambient_temp_directory(source, reader, engine, monkeypatch):
    monkeypatch.setattr(preparation.tempfile, "tempdir", str(source))
    _, log = preparation.prepare(source, reader, {})
    assert log.parent.parent == Path("/tmp") and not log.is_relative_to(source)


@pytest.mark.parametrize("changed", ("memory", "cpu", "pids", "network", "reader-write", "extra-mount", "privileged", "image", "environment"))
def test_created_container_drift_is_refused_before_reader_bearing_start_and_cleaned(source, reader, engine, changed):
    def drift(row):
        if changed == "memory":
            row["HostConfig"]["Memory"] = 0
        elif changed == "cpu":
            row["HostConfig"]["CpuQuota"] = 0
        elif changed == "pids":
            row["HostConfig"]["PidsLimit"] = 0
        elif changed == "network":
            row["HostConfig"]["NetworkMode"] = "host"
        elif changed == "reader-write":
            row["Mounts"][-1]["RW"] = True
        elif changed == "extra-mount":
            row["Mounts"].append({"Type": "volume", "Source": "/foreign", "Destination": "/foreign", "RW": True})
        elif changed == "privileged":
            row["HostConfig"]["Privileged"] = True
        elif changed == "image":
            row["Image"] = "sha256:" + "a" * 64
        elif changed == "environment":
            row["Config"]["Env"].append("PRIVATE_FORKS_READ_TOKEN=foreign")
    engine.inspect_hook = drift
    with pytest.raises(preparation.WatchPreparationError, match="bounded isolated configuration"):
        preparation.prepare(source, reader, {})
    assert engine.starts == [] and engine.removed == ["1" * 64]
    assert engine.containers == {}


@pytest.mark.parametrize("phase", ("fetch", "offline"))
def test_timed_out_preparation_removes_only_its_created_containers(source, reader, engine, phase):
    foreign_id = "f" * 64
    engine.containers[foreign_id] = {"foreign": True}
    def timeout(row):
        if f"--{phase}-dependencies" in row["Config"]["Cmd"][-1]:
            raise subprocess.TimeoutExpired("synthetic preparation", 900)
    engine.start_hook = timeout
    with pytest.raises(preparation.WatchPreparationError, match="interrupted"):
        preparation.prepare(source, reader, {})
    assert engine.containers == {foreign_id: {"foreign": True}}
    assert engine.removed == (["1" * 64, "2" * 64] if phase == "fetch" else ["1" * 64, "2" * 64, "3" * 64])


def test_interrupted_create_before_id_file_uses_exact_owned_identity_for_cleanup(source, reader, engine):
    engine.interrupt_create = True
    engine.containers["f" * 64] = {"foreign": True}
    with pytest.raises(preparation.WatchPreparationError, match="interrupted"):
        preparation.prepare(source, reader, {})
    assert engine.starts == [] and engine.removed == ["1" * 64]
    assert engine.containers == {"f" * 64: {"foreign": True}}


@pytest.mark.parametrize("changed", ("foreign-label", "malformed-config"))
def test_replaced_container_is_never_removed(source, reader, engine, changed):
    def foreign(row):
        if changed == "foreign-label":
            row["Config"]["Labels"][preparation.PREPARATION_LABEL] = "foreign"
        else:
            row["Config"] = None
    engine.inspect_hook = foreign
    with pytest.raises(preparation.WatchPreparationCleanupError, match="cleanup requires inspection"):
        preparation.prepare(source, reader, {})
    assert engine.starts == engine.removed == []
    # Private paths remain when an unexpected container cannot be safely removed.
    for mount in engine.created[0]["Mounts"]:
        assert Path(mount["Source"]).exists()


def test_endpoint_drift_during_cleanup_retains_paths_for_the_owned_running_container(source, reader, engine, monkeypatch):
    select = preparation.docker_environment
    changed = False
    def selected(environment):
        if changed:
            raise ValueError("synthetic pinned socket replacement")
        return select(environment)
    def interrupted(row):
        nonlocal changed
        if row["HostConfig"]["NetworkMode"] == "bridge":
            row["State"] = {"Status": "running"}
            changed = True
            raise subprocess.TimeoutExpired("synthetic fetch", 900)
    engine.start_hook = interrupted
    monkeypatch.setattr(preparation, "docker_environment", selected)
    with pytest.raises(preparation.WatchPreparationCleanupError, match="cleanup requires inspection"):
        preparation.prepare(source, reader, {})
    assert engine.removed == ["1" * 64] and set(engine.containers) == {"2" * 64}
    for mount in engine.containers["2" * 64]["Mounts"]:
        assert Path(mount["Source"]).exists()


@pytest.mark.parametrize("changed", ("reader", "manifest"))
def test_preparation_rechecks_reader_and_dependency_identity_before_start(source, reader, engine, changed):
    def change(row):
        engine.inspect_hook = None
        target = reader if changed == "reader" else source / "rust/crate/Cargo.toml"
        target.write_text(target.read_text().rstrip() + "changed\n")
    engine.inspect_hook = change
    with pytest.raises(preparation.WatchPreparationError, match="changed before preparation"):
        preparation.prepare(source, reader, {})
    assert engine.starts == ([] if changed == "manifest" else ["1" * 64])
    assert engine.removed == (["1" * 64] if changed == "manifest" else ["1" * 64, "2" * 64])


def test_source_snapshot_excludes_local_state_and_untracked_files(source, tmp_path):
    for name in ("rust/crate/.env.local", "rust/crate/.cargo/config.toml", "rust/target/artifact", "rust/diagnostic.log"):
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("private local state")
        subprocess.run(["git", "-C", str(source), "add", "--force", name], check=True)
    (source / "rust/untracked-note").write_text("untracked")
    target = tmp_path / "snapshot"
    preparation.snapshot_source(source, target, {})
    assert (target / "rust/crate/src/main.rs").read_bytes() == (source / "rust/crate/src/main.rs").read_bytes()
    assert not any(path.name in (".git", ".cargo", "target", ".env.local", "diagnostic.log", "untracked-note")
                   for path in target.rglob("*"))
    assert preparation.seed_identity(target) == preparation.seed_identity(source)


def test_snapshot_discards_ambient_git_index_worktree_and_config_routing(source, tmp_path):
    target = tmp_path / "snapshot"
    preparation.snapshot_source(source, target, {
        "GIT_DIR": "/foreign/repository", "GIT_WORK_TREE": "/foreign/worktree",
        "GIT_INDEX_FILE": "/foreign/index", "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "core.worktree", "GIT_CONFIG_VALUE_0": "/foreign/worktree",
        "GIT_CONFIG_PARAMETERS": "invalid foreign configuration",
        "GIT_CONFIG_GLOBAL": "/foreign/config", "GIT_COMMON_DIR": "/foreign/common",
    })
    assert preparation.seed_identity(target) == preparation.seed_identity(source)
    assert (target / "rust/crate/src/main.rs").is_file()


def test_untracked_manifest_is_rejected_before_fetch(source, tmp_path):
    path = source / "rust/new-crate/Cargo.toml"
    path.parent.mkdir()
    path.write_text("new crate")
    with pytest.raises(preparation.WatchPreparationError, match="stage new Cargo manifests"):
        preparation.snapshot_source(source, tmp_path / "snapshot", {})


def test_snapshot_refuses_tracked_source_symlink(source, tmp_path):
    path = source / "rust/crate/src/main.rs"
    path.unlink()
    path.symlink_to(tmp_path / "outside")
    with pytest.raises(preparation.WatchPreparationError, match="redirected"):
        preparation.snapshot_source(source, tmp_path / "snapshot", {})


@pytest.mark.parametrize("instruction", ("RUN echo unbounded", "ADD https://foreign.invalid/file /file", "COPY ../source/ /workspace/", "ONBUILD RUN true"))
def test_assembly_rejects_execution_network_and_source_inputs(source, tmp_path, instruction):
    recipe = source / "services/Dockerfile.passport-watch"
    recipe.write_text(recipe.read_text() + instruction + "\n")
    with pytest.raises(preparation.WatchPreparationError, match="only copy"):
        preparation.assembly_context(source, tmp_path / "context")


@pytest.mark.parametrize("directive", ("#syntax=foreign/frontend", "# SYNTAX=foreign/frontend",
    "#  SyNtAx  = foreign/frontend", "#\tescape\t= `", "#ESCAPE=\\"))
def test_assembly_rejects_alternate_frontend_and_escape_directive_spellings(source, tmp_path, directive):
    recipe = source / "services/Dockerfile.passport-watch"
    recipe.write_text(directive + "\n" + recipe.read_text())
    with pytest.raises(preparation.WatchPreparationError, match="only copy"):
        preparation.assembly_context(source, tmp_path / "context")


@pytest.fixture
def dependency_phase(source, tmp_path, monkeypatch):
    cgroup, cargo = tmp_path / "cgroup", tmp_path / "cargo"
    cgroup.mkdir()
    for name, value in {"memory.max": "2147483648", "memory.swap.max": "0",
                        "cpu.max": "100000 100000", "pids.max": "128"}.items():
        (cgroup / name).write_text(value)
    cargo.mkdir()
    for name in ("registry", "git"):
        (cargo / name).mkdir()
    seed, lock = preparation.seed_identity(source)
    env = {"CARGO_HOME": str(cargo), "PASSPORT_WATCH_SEED_ID": seed,
           "PASSPORT_WATCH_LOCK_SHA256": lock, "CARGO_NET_OFFLINE": "true"}
    calls = []
    monkeypatch.setattr(preparation.shutil, "which", lambda name: "/pinned/" + name)
    monkeypatch.setattr(preparation.os, "umask", lambda value: 0o077)
    monkeypatch.setattr(preparation.subprocess, "run", lambda command, **kwargs: calls.append((command, kwargs)))
    return cargo, cgroup, env, calls


@pytest.mark.parametrize("changed,value", (("memory.max", "max"), ("memory.swap.max", "max"),
    ("cpu.max", "max 100000"), ("pids.max", "max"), ("memory.max", None)))
@pytest.mark.parametrize("phase", ("probe", "fetch", "offline"))
def test_actual_fetch_limits_are_required_before_canonical_helper_runs(source, dependency_phase, changed, value, phase):
    cargo, cgroup, env, calls = dependency_phase
    if value is None:
        (cgroup / changed).unlink()
    else:
        (cgroup / changed).write_text(value)
    with pytest.raises(preparation.WatchPreparationError, match="limits cannot be read|not enforced"):
        preparation.container_dependencies(phase, source, cargo, env, cgroup)
    assert calls == []


def test_probe_is_credential_free_and_does_not_fetch_or_write_cache(source, dependency_phase):
    cargo, cgroup, env, calls = dependency_phase
    preparation.container_dependencies("probe", source, cargo, env, cgroup)
    assert calls == []
    assert list((cargo / "registry").iterdir()) == list((cargo / "git").iterdir()) == []


def test_fetch_is_canonical_fetch_only_and_offline_phase_creates_exact_seed_markers(source, dependency_phase):
    cargo, cgroup, env, calls = dependency_phase
    preparation.container_dependencies("fetch", source, cargo, env, cgroup)
    assert calls[0][0][1:] == [str(source / ".github/scripts/private-forks.py"), "fetch", "--container",
        "--token-file", "/run/secrets/private_forks_read_token", "--manifest-path", str(source / "rust/Cargo.toml")]
    assert not (cargo / "registry/.marty-passport-watch-seed").exists()
    preparation.container_dependencies("offline", source, cargo, env, cgroup)
    assert calls[1][0] == ["cargo", "fetch", "--offline", "--locked", "--manifest-path", str(source / "rust/Cargo.toml")]
    assert all(not any(name in kwargs["env"] for name in preparation.SOURCE_READER_ENV) for _, kwargs in calls)
    preparation.check_seed(source, cargo, env)


def test_offline_phase_refuses_an_unexpected_reader_mount(source, dependency_phase, tmp_path, monkeypatch):
    cargo, cgroup, env, calls = dependency_phase
    secret = tmp_path / "unexpected-reader"
    secret.write_text("not-a-real-credential")
    monkeypatch.setattr(preparation, "TOKEN_TARGET", str(secret))
    with pytest.raises(preparation.WatchPreparationError, match="must not receive a source reader"):
        preparation.container_dependencies("offline", source, cargo, env, cgroup)
    assert calls == []


@pytest.mark.parametrize("changed", ("seed", "lock", "image_id"))
def test_prepared_image_requires_current_seed_and_full_image_id(source, monkeypatch, changed):
    row = image_row(source)
    if changed == "image_id":
        row["Id"] = "mutable:tag"
    else:
        row["Config"]["Labels"][preparation.SEED_LABEL if changed == "seed" else preparation.LOCK_LABEL] = "0" * 64
    monkeypatch.setattr(preparation, "inspect_docker", lambda *args: json.dumps([row]))
    with pytest.raises(preparation.WatchPreparationError, match="unprepared or stale"):
        preparation.prepared_image(source, {})


def volume_rows(project, seed):
    return [{"Name": f"{project}_{name}", "Driver": "local", "Scope": "local", "Options": None, "Labels": {
        "com.docker.compose.project": project, "com.docker.compose.volume": name,
        preparation.SEED_LABEL: seed,
    }} for name in preparation.CACHE_VOLUMES]


@pytest.mark.parametrize("changed", ("seed", "project", "driver", "scope", "nfs-options", "bind-options", "partial", "unexpected"))
def test_resume_never_adopts_stale_or_foreign_cargo_volumes(monkeypatch, changed):
    project, seed = "marty-passport-unit-test", "a" * 64
    rows = volume_rows(project, seed)
    if changed == "seed":
        rows[0]["Labels"][preparation.SEED_LABEL] = "b" * 64
    elif changed == "project":
        rows[0]["Labels"]["com.docker.compose.project"] = "foreign"
    elif changed == "driver":
        rows[0]["Driver"] = "nfs"
    elif changed == "scope":
        rows[0]["Scope"] = "global"
    elif changed == "nfs-options":
        rows[0]["Options"] = {"type": "nfs", "o": "addr=foreign.invalid", "device": ":/foreign"}
    elif changed == "bind-options":
        rows[0]["Options"] = {"type": "none", "o": "bind", "device": "/foreign/cache"}
    elif changed == "partial":
        rows.pop()
    elif changed == "unexpected":
        rows.append({"Name": project + "_passport_watch_foreign"})
    monkeypatch.setattr(preparation, "inspect_docker", lambda args, env:
                        "\n".join(row["Name"] for row in rows) if args[1] == "ls" else json.dumps(rows))
    with pytest.raises(preparation.WatchPreparationError):
        preparation.require_current_volumes(project, seed, {})


def test_runtime_seed_check_is_pure_and_refuses_dependency_changes(source, tmp_path, monkeypatch):
    seed, lock = preparation.seed_identity(source)
    cargo = tmp_path / "cargo"
    for name in ("registry", "git"):
        (cargo / name).mkdir(parents=True)
        (cargo / name / ".marty-passport-watch-seed").write_text(seed)
    env = {"PASSPORT_WATCH_SEED_ID": seed, "PASSPORT_WATCH_LOCK_SHA256": lock}
    monkeypatch.setattr(preparation.subprocess, "run", lambda *args, **kwargs: pytest.fail("pure check must not start tools"))
    preparation.check_seed(source, cargo, env)
    manifest = source / "rust/crate/Cargo.toml"
    manifest.write_text(manifest.read_text() + "changed")
    with pytest.raises(preparation.WatchPreparationError, match="dependency inputs changed"):
        preparation.check_seed(source, cargo, env)


def test_runtime_seed_check_rejects_nonempty_stale_volume(source, tmp_path):
    seed, lock = preparation.seed_identity(source)
    cargo = tmp_path / "cargo"
    for name in ("registry", "git"):
        (cargo / name).mkdir(parents=True)
        (cargo / name / ".marty-passport-watch-seed").write_text("stale")
    with pytest.raises(preparation.WatchPreparationError, match="cache seed is stale"):
        preparation.check_seed(source, cargo, {"PASSPORT_WATCH_SEED_ID": seed, "PASSPORT_WATCH_LOCK_SHA256": lock})


@pytest.mark.parametrize("changed,value", (
    (None, None), ("memory.max", "max"), ("memory.swap.max", "max"),
    ("cpu.max", "max 100000"), ("memory.max", str(8 * 1024 ** 3)),
))
def test_actual_runtime_cgroup_limits_are_required(tmp_path, changed, value):
    values = {"memory.max": str(4 * 1024 ** 3), "memory.swap.max": "0", "cpu.max": "100000 100000"}
    if changed:
        values[changed] = value
    for name, content in values.items():
        (tmp_path / name).write_text(content + "\n")
    if changed:
        with pytest.raises(preparation.WatchPreparationError, match="not enforced"):
            preparation.require_runtime_resources(tmp_path)
    else:
        preparation.require_runtime_resources(tmp_path)


@pytest.fixture
def launcher(monkeypatch, tmp_path):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    loaded = runpy.run_path(str(ROOT / "scripts/passport_local_watch.py"))
    scope = loaded["main"].__globals__
    # All plans and Docker observations in these sequencing tests are synthetic.
    # No staged inputs, native policy, daemon, or release is invoked.
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps({"components": [{"name": "marty-ui", "commit": "a" * 40}]}))
    now = datetime.now(timezone.utc)
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps({"surface": "base", "source_commit": "a" * 40,
        "stack_manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "created_at": (now - timedelta(minutes=5)).isoformat(),
        "expires_at": (now + timedelta(minutes=90)).isoformat(), "project": "marty-passport-unit-test"}))
    argv = ["passport_local_watch.py", "--plan", str(plan_path), "--manifest", str(manifest_path)]
    monkeypatch.setattr(scope["sys"], "argv", argv)
    monkeypatch.setattr(scope["os"], "environ", {"PRIVATE_FORKS_READ_TOKEN": "foreign-reader", "BUILDX_BUILDER": "remote"})
    monkeypatch.setitem(scope, "stage_disposable_inputs", lambda *args, **kwargs: pytest.fail("staging must not run"))
    monkeypatch.setattr(scope["preparation"], "require_resource_limits", lambda env: None)
    monkeypatch.setitem(scope, "Path", lambda value: tmp_path if str(value) == "/tmp" else Path(value))
    return scope, argv, tmp_path


def test_unprepared_image_stops_launcher_before_staging_or_native_policy(launcher, monkeypatch):
    scope, _, _ = launcher

    def unprepared(*args):
        raise scope["preparation"].WatchPreparationError("unprepared")

    monkeypatch.setattr(scope["preparation"], "prepared_image", unprepared)
    with pytest.raises(SystemExit, match="unprepared"):
        scope["main"]()
    assert "PRIVATE_FORKS_READ_TOKEN" not in scope["os"].environ


def test_prepare_does_not_require_or_read_a_plan(launcher, reader, monkeypatch):
    scope, _, _ = launcher
    monkeypatch.setattr(scope["sys"], "argv", ["passport_local_watch.py", "--prepare", "--private-forks-token-file", str(reader)])
    calls = []

    def prepare(root, token, environment):
        calls.append((root, token, environment))
        return {"PASSPORT_WATCH_IMAGE": IMAGE_ID}, Path("/private/prepare.log")

    monkeypatch.setattr(scope["preparation"], "prepare", prepare)
    assert scope["main"]() == 0
    assert len(calls) == 1 and calls[0][1] == reader
    assert "PRIVATE_FORKS_READ_TOKEN" not in calls[0][2]
    assert "BUILDX_BUILDER" not in calls[0][2]


def test_resume_uses_prepared_image_without_build_or_reader(launcher, monkeypatch):
    scope, argv, directory = launcher
    argv.extend(["--resume", "--watch-only"])
    project = directory / "marty-passport-unit-test"
    project.mkdir()
    (project / "acceptance.env").write_text("unused fixture")
    expected = {"PASSPORT_WATCH_IMAGE": IMAGE_ID, "PASSPORT_WATCH_SEED_ID": "a" * 64,
                "PASSPORT_WATCH_LOCK_SHA256": "b" * 64}
    monkeypatch.setattr(scope["preparation"], "prepared_image", lambda *args: expected)
    validated = []
    monkeypatch.setattr(scope["preparation"], "require_current_volumes", lambda *args: validated.append(args))
    monkeypatch.setitem(scope, "_staged_environment", lambda path: {
        "PASSPORT_ACCEPTANCE_GATEWAY_PORT": "29979", "PRIVATE_FORKS_READ_TOKEN": "foreign",
    })
    monkeypatch.setitem(scope, "_compose_args", lambda *args: ["docker", "compose"])
    monkeypatch.setitem(scope, "_bootstrap_args", lambda *args: [])
    calls = []
    monkeypatch.setitem(scope, "run", lambda command, env, *args: calls.append((command, env)) or True)
    assert scope["main"]() == 0
    assert len(validated) == 1 and len(calls) == 1
    command, env = calls[0]
    assert "--no-build" in command and "--build" not in command
    assert all(env[key] == value for key, value in expected.items())
    assert "PRIVATE_FORKS_READ_TOKEN" not in env


def test_stale_resume_seed_is_rejected_before_staging_or_start(launcher, monkeypatch):
    scope, argv, _ = launcher
    argv.append("--resume")
    monkeypatch.setattr(scope["preparation"], "prepared_image", lambda *args: {
        "PASSPORT_WATCH_IMAGE": IMAGE_ID, "PASSPORT_WATCH_SEED_ID": "a" * 64,
        "PASSPORT_WATCH_LOCK_SHA256": "b" * 64,
    })

    def stale(*args):
        raise scope["preparation"].WatchPreparationError("Watcher cache seed changed")

    monkeypatch.setattr(scope["preparation"], "require_current_volumes", stale)
    monkeypatch.setitem(scope, "run", lambda *args: pytest.fail("startup must not run"))
    with pytest.raises(SystemExit, match="cache seed changed"):
        scope["main"]()


def test_old_project_teardown_does_not_require_prepared_image(launcher, monkeypatch):
    scope, argv, directory = launcher
    argv.extend(["--resume", "--stop"])
    project = directory / "marty-passport-unit-test"
    project.mkdir()
    (project / "acceptance.env").write_text("unused fixture")
    monkeypatch.setattr(scope["preparation"], "prepared_image", lambda *args: pytest.fail("teardown must not require an image"))
    monkeypatch.setattr(scope["preparation"], "require_resource_limits", lambda *args: pytest.fail("teardown must not require compiler limits"))
    monkeypatch.setitem(scope, "_staged_environment", lambda path: {"PASSPORT_ACCEPTANCE_GATEWAY_PORT": "29979"})
    monkeypatch.setitem(scope, "_compose_args", lambda *args: ["docker", "compose"])
    monkeypatch.setitem(scope, "_inspect_local", lambda *args: "")
    monkeypatch.setitem(scope, "_remove_bootstrap_output", lambda *args: None)
    monkeypatch.setitem(scope, "_remove_staged_inputs", lambda *args: None)
    calls = []
    monkeypatch.setitem(scope, "run", lambda command, *args: calls.append(command) or True)
    assert scope["main"]() == 0
    assert len(calls) == 1 and "down" in calls[0] and "--volumes" in calls[0]


def test_watcher_recipe_only_copies_verified_caches_and_runtime_stays_offline():
    dockerfile = (ROOT / "services/Dockerfile.passport-watch").read_text()
    instructions = [line.strip() for line in dockerfile.splitlines() if line.strip() and not line.startswith("#")]
    assert not any(line.startswith(("RUN ", "ADD ", "ONBUILD ")) for line in instructions)
    assert "COPY --chown=0:0 cargo/registry/ /usr/local/cargo/registry/" in instructions
    assert "COPY --chown=0:0 cargo/git/ /usr/local/cargo/git/" in instructions
    assert "--secret" not in dockerfile and "PRIVATE_FORKS" not in dockerfile
    overlay = yaml.safe_load((ROOT / "deploy/compose/development/docker-compose.passport-supported-disposable-watch.yml").read_text())
    for service in overlay["services"].values():
        assert service["pull_policy"] == "never"
        assert service["cpus"] == 1.0 and service["mem_limit"] == service["memswap_limit"] == "4g"
        assert service["environment"]["CARGO_BUILD_JOBS"] == "1"
        assert service["environment"]["CARGO_NET_OFFLINE"] == "true"
        assert not any("private_forks" in str(mount) for mount in service["volumes"])
