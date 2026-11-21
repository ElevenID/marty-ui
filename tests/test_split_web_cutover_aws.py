"""Fail-closed source, resource ownership, and deadline behavior without Docker."""
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import qualify_split_web_cutover_aws as qualification


def git(root, *arguments):
    return subprocess.check_output(["git", "-C", str(root), *arguments], text=True).strip()


@pytest.fixture
def repository(tmp_path):
    root = tmp_path / "product"
    root.mkdir()
    git(root, "init", "-q", "--object-format=sha1")
    git(root, "config", "user.name", "Source test")
    git(root, "config", "user.email", "source@example.invalid")
    git(root, "config", "commit.gpgSign", "false")
    git(root, "config", "core.autocrlf", "false")
    (root / ".gitignore").write_text(".env.secret\n")
    (root / "source.txt").write_text("original source\n")
    for path in root.iterdir():
        if path.is_file():
            path.chmod(0o644)
    git(root, "add", ".")
    git(root, "commit", "-qm", "Exact source")
    return root, git(root, "rev-parse", "HEAD")


def test_exact_git_snapshot_excludes_ignored_host_configuration(repository, tmp_path):
    root, revision = repository
    (root / ".env.secret").write_text("HOST_ONLY=value\n")
    identity, inventory = qualification.source_inventory(root, revision, dict(os.environ))
    destination = tmp_path / "snapshot"
    qualification.materialize_source(root, destination, inventory)
    assert identity["commit"] == revision
    assert identity["tracked_blob_bytes_and_modes_verified"] is True
    assert (destination / "source.txt").read_text() == "original source\n"
    assert not (destination / ".env.secret").exists()
    assert not (destination / ".git").exists()


def test_assume_unchanged_cannot_hide_different_build_bytes(repository):
    root, revision = repository
    git(root, "update-index", "--assume-unchanged", "source.txt")
    (root / "source.txt").write_text("changed outside Git status\n")
    assert git(root, "status", "--porcelain") == ""
    with pytest.raises(ValueError, match="Source blob changed"):
        qualification.source_inventory(root, revision, dict(os.environ))


@pytest.mark.parametrize("change", ["mode", "symlink", "untracked", "moving-ref", "wrong-head"])
def test_source_changes_are_rejected_before_build(repository, change):
    root, revision = repository
    if change == "mode":
        git(root, "config", "core.filemode", "false")
        (root / "source.txt").chmod(0o600)
    elif change == "symlink":
        (root / "source.txt").unlink()
        (root / "source.txt").symlink_to(root / ".gitignore")
    elif change == "untracked":
        (root / "unexpected").write_text("host file")
    else:
        revision = "HEAD" if change == "moving-ref" else "0" * 40
    with pytest.raises(ValueError):
        qualification.source_inventory(root, revision, dict(os.environ))


def test_git_replacement_does_not_redefine_the_selected_tree(repository):
    root, revision = repository
    tree = git(root, "rev-parse", "HEAD^{tree}")
    (root / "source.txt").write_text("replacement source\n")
    git(root, "commit", "-qam", "New source")
    replacement = git(root, "rev-parse", "HEAD")
    git(root, "checkout", "-q", "--detach", revision)
    git(root, "replace", revision, replacement)
    assert git(root, "rev-parse", "HEAD^{tree}") != tree
    identity, _ = qualification.source_inventory(root, revision, dict(os.environ))
    assert identity["tree"] == tree


def test_actual_recipe_has_two_closed_local_only_builds():
    inputs = qualification.recipe(ROOT)
    plan = qualification.stages(Path("/tmp/cq/e"), "a" * 40, inputs["build_arguments"], "b" * 32, {})
    assert len(plan) == 4
    assert [step["name"] for step in plan] == ["application-docker-build", "selfhost-docker-build", "built-image-http-smoke", "application-customer-nginx-matrix"]
    for kind, step in zip(("application", "selfhost"), plan):
        command = step["argv"]
        assert command[command.index("--target") + 1] == kind
        assert "--load" in command and "--push" not in command
        assert "--platform=linux/amd64" in command
        assert "UI_SURFACE=application" in command
        assert "MARTY_PRODUCTION_PAGES=public" in command
        assert "MARTY_UI_SHA=" + "a" * 40 in command
        assert command[-1] == "."
    assert "UI_VARIANT=selfhost" in plan[1]["argv"]
    assert "NGINX_CONFIG=nginx.spa.conf" in plan[1]["argv"]
    assert inputs["bases"] == [qualification.BUN_IMAGE, qualification.NGINX_IMAGE]


@pytest.mark.parametrize("change", ["base", "target", "manager", "repository", "uri", "digest", "duplicate"])
def test_recipe_rejects_unreviewed_sources(tmp_path, change):
    for name in ("docker/ui.Dockerfile", "ui/package.json", "release/stack-lock.json"):
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / name).read_bytes())
    if change in {"base", "target"}:
        path = tmp_path / "docker/ui.Dockerfile"
        path.write_text(path.read_text().replace(qualification.BUN_IMAGE, "oven/bun:latest") if change == "base"
                        else path.read_text().replace("AS application", "AS public"))
    elif change == "manager":
        path = tmp_path / "ui/package.json"
        data = json.loads(path.read_text())
        data["packageManager"] = "npm@11.0.0"
        path.write_text(json.dumps(data))
    else:
        path = tmp_path / "release/stack-lock.json"
        data = json.loads(path.read_text())
        component = next(row for row in data["components"] if row["name"] == "marty-api-core")
        if change == "repository":
            component["repository"] = "unreviewed/repository"
        elif change == "duplicate":
            data["components"].append(component)
        else:
            component["artifacts"][0][change] = "https://registry.invalid/latest.tgz" if change == "uri" else "latest"
        path.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        qualification.recipe(tmp_path)


class ResourceDocker(qualification.OwnedDocker):
    def __init__(self):
        super().__init__("docker", {"DOCKER_HOST": "unix:///run/user/1000/docker.sock"}, "b" * 32)
        self.resources = {"container": {"a" * 64}, "network": {"c" * 64}, "image": {"sha256:" + "d" * 64, "sha256:" + "e" * 64}}
        self.calls = []
        self.foreign = False

    def call(self, *args, check=True):
        self.calls.append(args)
        if args[1] == "ls":
            assert "label=" + self.label in args
            return subprocess.CompletedProcess(args, 0, "\n".join(self.resources[args[0]]), "")
        if args[1] == "inspect":
            value = {qualification.OWNER_LABEL: "foreign" if self.foreign else self.owner}
            data = {"Labels": value} if args[0] == "network" else {"Config": {"Labels": value}}
            return subprocess.CompletedProcess(args, 0, json.dumps(data), "")
        if args[1] == "rm":
            self.resources[args[0]].remove(args[-1])
        return subprocess.CompletedProcess(args, 0, "", "")


def test_cleanup_keeps_output_images_and_never_touches_existing_containers():
    docker = ResourceDocker()
    retained = "sha256:" + "e" * 64
    removed = docker.cleanup(["f" * 64], {retained})
    assert removed == {"container": ["a" * 64], "network": ["c" * 64], "image": ["sha256:" + "d" * 64]}
    assert docker.resources["image"] == {retained}
    assert all("f" * 64 not in command for command in docker.calls)
    assert not any("prune" in command or "stop" in command for command in docker.calls)


def test_cleanup_refuses_a_foreign_or_preexisting_resource():
    docker = ResourceDocker()
    docker.foreign = True
    with pytest.raises(ValueError, match="unowned"):
        docker.remove("container", "a" * 64)
    assert not any("rm" in command for command in docker.calls)
    docker.foreign = False
    with pytest.raises(ValueError, match="preexisting"):
        docker.cleanup(["a" * 64], set())
    assert not any("rm" in command for command in docker.calls)


def test_test_transport_adds_ownership_and_rejects_broad_operations():
    docker = ResourceDocker()
    docker.fixture("run", "--name", "marty-application-012345abcdef-selfhost-console", "--network", "marty-application-012345abcdef", "fixture")
    assert ("--label", docker.label) == docker.calls[-1][1:3]
    assert "--memory=192m" in docker.calls[-1]
    docker.fixture("network", "create", "marty-application-012345abcdef")
    assert docker.calls[-1][2:4] == ("--label", docker.label)
    for args in (("system", "prune", "--all"), ("stop", "customer"), ("run", "--name", "customer", "fixture")):
        with pytest.raises(ValueError):
            docker.fixture(*args)


def test_environment_discards_host_registry_and_runtime_overrides(monkeypatch):
    for name in ("DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CONTEXT", "NODE_OPTIONS", "BUN_OPTIONS", "GH_TOKEN"):
        monkeypatch.setenv(name, "unreviewed")
    options = argparse_options(docker_socket="/run/user/1000/docker.sock")
    env = qualification.common.environment(options, Path("/tmp/cq/e"))
    assert env["DOCKER_HOST"] == "unix:///run/user/1000/docker.sock"
    assert env["DOCKER_CONFIG"] == "/tmp/cq/e/docker-config"
    assert not any(name in env for name in ("DOCKER_CONTEXT", "NODE_OPTIONS", "BUN_OPTIONS", "GH_TOKEN"))


def argparse_options(**values):
    from argparse import Namespace
    return Namespace(**values)


def test_short_utf8_temporary_path_required_before_any_host_probe(tmp_path):
    options = argparse_options(marty_root=str(ROOT), evidence_root="/tmp/" + "é" * 40, docker_socket="/run/user/1000/docker.sock")
    with pytest.raises(ValueError, match="UTF-8 bytes"):
        qualification.checked_paths(options)


@pytest.mark.parametrize("failure", ["exit", "timeout"])
def test_failed_stage_stops_progress_and_still_cleans_only_owned_resources(repository, monkeypatch, failure):
    root, revision = repository
    source, inventory = qualification.source_inventory(root, revision, dict(os.environ))
    docker = ResourceDocker()
    docker.resources = {kind: set() for kind in docker.resources}
    monkeypatch.setattr(qualification, "OwnedDocker", lambda *_: docker)
    monkeypatch.setattr(qualification.common, "container_ids", lambda *_: ["f" * 64])
    commands = []

    def execute(command, **kwargs):
        commands.append(command)
        if command[0] == "systemd-run" and failure == "timeout":
            raise subprocess.TimeoutExpired(command, 1)
        return subprocess.CompletedProcess(command, 0 if command[0] == "systemctl" else 1)

    monkeypatch.setattr(qualification.subprocess, "run", execute)
    tools = {name: name for name in ("docker", "python", "systemd-run", "systemctl", "env")}
    initial = {"source": source, "recipe": {"build_arguments": {}}, "docker": {"initial_containers": ["f" * 64]}}
    options = argparse_options(source_commit=revision, deadline_utc=(datetime.now(timezone.utc) + timedelta(minutes=20)).strftime("%Y-%m-%dT%H:%M:%SZ"))
    with tempfile.TemporaryDirectory(prefix="cq-") as directory:
        evidence = Path(directory) / "e"
        report = qualification.run(options, (root, evidence), initial, inventory, tools, docker.env)
        assert report["status"] == "failed"
        assert len(report["steps"]) == 1
        assert report["existing_container_identities_preserved"] is True
        assert report["diagnostic_containers_remaining"] is False
        assert (evidence / "qualification.json").is_file()
    stops = [command for command in commands if command[0] == "systemctl"]
    assert len(stops) == (1 if failure == "timeout" else 0)
    if stops:
        assert stops[0][:3] == ["systemctl", "--user", "stop"]
        assert stops[0][3].startswith("marty-cutover-")
