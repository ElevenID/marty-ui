from __future__ import annotations

import copy
import importlib.util
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts/ci/write_pr_rust_checkout_attestation.py"
spec = importlib.util.spec_from_file_location("pr_rust_checkout_attestation", SCRIPT)
assert spec is not None and spec.loader is not None
attestation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(attestation)


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    ).stdout.strip()


@pytest.fixture
def source(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-b", "main")
    git(repo, "config", "user.name", "CI Test")
    git(repo, "config", "user.email", "ci-test@example.invalid")
    (repo / ".github/workflows").mkdir(parents=True)
    (repo / "scripts/ci").mkdir(parents=True)
    (repo / ".github/workflows/ci.yml").write_text("name: CI\n", encoding="utf-8")
    (repo / "scripts/ci/write_pr_rust_checkout_attestation.py").write_text(
        "# producer\n", encoding="utf-8"
    )
    git(repo, "add", ".")
    git(repo, "commit", "-m", "base")
    base_sha = git(repo, "rev-parse", "HEAD")
    git(repo, "checkout", "-b", "feature")
    (repo / "feature.txt").write_text("feature\n", encoding="utf-8")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "feature")
    head_sha = git(repo, "rev-parse", "HEAD")
    git(repo, "checkout", "main")
    git(repo, "merge", "--no-ff", "feature", "-m", "PR merge")
    checkout_sha = git(repo, "rev-parse", "HEAD")
    env = {
        "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_JOB": "test-rust-services",
        "MARTY_RUST_ATTESTATION_LANE": "canvas",
        "GITHUB_WORKFLOW": "CI",
        "GITHUB_REPOSITORY": "ElevenID/marty-ui",
        "GITHUB_REPOSITORY_ID": "123",
        "GITHUB_RUN_ID": "456",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_REF": "refs/pull/789/merge",
        "GITHUB_WORKFLOW_REF": "ElevenID/marty-ui/.github/workflows/ci.yml@refs/pull/789/merge",
        "GITHUB_WORKFLOW_SHA": checkout_sha,
        "GITHUB_SHA": checkout_sha,
    }
    event = {
        "number": 789,
        "repository": {"id": 123, "full_name": "ElevenID/marty-ui"},
        "pull_request": {
            "number": 789,
            "base": {"ref": "main", "sha": base_sha, "repo": {"id": 123}},
            "head": {"sha": head_sha},
        },
    }
    return repo, env, event


@pytest.mark.parametrize("lane", ["canvas", "contracts"])
def test_records_actual_merge_checkout_and_workflow_blob(source, lane: str) -> None:
    repo, env, event = source
    env["MARTY_RUST_ATTESTATION_LANE"] = lane
    record = attestation.build_attestation(env, event, repo)
    assert record == {
        "schema": "marty-ci-pr-rust-checkout-v1",
        "repository": "ElevenID/marty-ui",
        "repository_id": 123,
        "workflow_path": ".github/workflows/ci.yml",
        "workflow_ref": env["GITHUB_WORKFLOW_REF"],
        "workflow_context_sha_unverified": env["GITHUB_WORKFLOW_SHA"],
        "workflow_blob_sha": git(repo, "rev-parse", "HEAD:.github/workflows/ci.yml"),
        "producer_blob_sha": git(
            repo, "rev-parse", "HEAD:scripts/ci/write_pr_rust_checkout_attestation.py"
        ),
        "run_id": 456,
        "run_attempt": 1,
        "job_id": "test-rust-services",
        "lane": lane,
        "event": "pull_request",
        "pull_request_number": 789,
        "pull_request_base_sha": event["pull_request"]["base"]["sha"],
        "checkout_base_parent_sha": event["pull_request"]["base"]["sha"],
        "pull_request_head_sha": event["pull_request"]["head"]["sha"],
        "checkout_ref": "refs/pull/789/merge",
        "checkout_sha": env["GITHUB_SHA"],
        "checkout_tree_sha": git(repo, "rev-parse", "HEAD^{tree}"),
    }


@pytest.mark.parametrize(
    "field,value",
    [
        ("GITHUB_EVENT_NAME", "merge_group"),
        ("GITHUB_JOB", "ci-gate"),
        ("MARTY_RUST_ATTESTATION_LANE", "worker"),
        ("GITHUB_WORKFLOW", "Other"),
        ("GITHUB_REPOSITORY_ID", "0"),
        ("GITHUB_RUN_ID", "not-a-run"),
        ("GITHUB_RUN_ATTEMPT", "0"),
        ("GITHUB_REF", "refs/pull/788/merge"),
        (
            "GITHUB_WORKFLOW_REF",
            "ElevenID/marty-ui/.github/workflows/other.yml@refs/pull/789/merge",
        ),
        ("GITHUB_WORKFLOW_SHA", "missing"),
        ("GITHUB_SHA", "0" * 40),
    ],
)
def test_rejects_spoofed_or_incomplete_runner_identity(source, field, value) -> None:
    repo, env, event = source
    env[field] = value
    with pytest.raises(ValueError):
        attestation.build_attestation(env, event, repo)


@pytest.mark.parametrize(
    "change",
    [
        lambda e: e.update(number=790),
        lambda e: e["repository"].update(id=124),
        lambda e: e["pull_request"]["base"].update(ref="release"),
        lambda e: e["pull_request"]["base"].update(sha="0" * 40),
        lambda e: e["pull_request"]["head"].update(sha="0" * 40),
        lambda e: e["pull_request"]["base"]["repo"].update(id=124),
    ],
)
def test_rejects_stale_or_mismatched_pr_provenance(source, change) -> None:
    repo, env, event = source
    altered = copy.deepcopy(event)
    change(altered)
    with pytest.raises(ValueError):
        attestation.build_attestation(env, altered, repo)


@pytest.mark.parametrize(
    "path",
    [
        ".github/workflows/ci.yml",
        "scripts/ci/write_pr_rust_checkout_attestation.py",
        "feature.txt",
    ],
)
def test_rejects_any_modified_tracked_input_after_checkout(source, path: str) -> None:
    repo, env, event = source
    with (repo / path).open("a", encoding="utf-8") as file:
        file.write("# changed\n")
    with pytest.raises(ValueError, match="tracked checkout changed"):
        attestation.build_attestation(env, event, repo)


def test_rejects_staged_tracked_mutation(source) -> None:
    repo, env, event = source
    (repo / "feature.txt").write_text("staged change\n", encoding="utf-8")
    git(repo, "add", "feature.txt")
    with pytest.raises(ValueError, match="tracked checkout changed"):
        attestation.build_attestation(env, event, repo)


def test_untracked_build_output_does_not_change_recorded_tree(source) -> None:
    repo, env, event = source
    (repo / "rust/target").mkdir(parents=True)
    (repo / "rust/target/build-output").write_text("generated", encoding="utf-8")
    assert attestation.build_attestation(env, event, repo)["checkout_tree_sha"] == git(
        repo, "rev-parse", "HEAD^{tree}"
    )


def test_workflow_context_sha_is_explicitly_unverified(source) -> None:
    repo, env, event = source
    env["GITHUB_WORKFLOW_SHA"] = "a" * 40
    record = attestation.build_attestation(env, event, repo)
    assert record["workflow_context_sha_unverified"] == "a" * 40
    assert "workflow_sha" not in record


def test_shallow_merge_checkout_retains_raw_parent_identity(
    source, tmp_path: Path
) -> None:
    repo, env, event = source
    shallow = tmp_path / "shallow"
    subprocess.run(
        [
            "git",
            "clone",
            "--depth",
            "1",
            "--no-local",
            repo.resolve().as_uri(),
            str(shallow),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert git(shallow, "rev-parse", "--is-shallow-repository") == "true"
    # Traversal intentionally omits parents here; the actual object still has both.
    assert git(shallow, "rev-list", "--parents", "-n", "1", "HEAD").split() == [
        env["GITHUB_SHA"]
    ]
    record = attestation.build_attestation(env, event, shallow)
    assert record["pull_request_base_sha"] == event["pull_request"]["base"]["sha"]
    assert record["pull_request_head_sha"] == event["pull_request"]["head"]["sha"]


def test_commit_message_cannot_inject_parent_headers(source) -> None:
    repo, env, event = source
    git(repo, "commit", "--amend", "-m", "PR merge\n\nparent " + "a" * 40)
    env["GITHUB_SHA"] = git(repo, "rev-parse", "HEAD")
    record = attestation.build_attestation(env, event, repo)
    assert record["pull_request_base_sha"] == event["pull_request"]["base"]["sha"]


def test_workflow_preserves_full_merge_group_and_required_gate() -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    )
    jobs = workflow["jobs"]
    rust_steps = jobs["test-rust-services"]["steps"]
    checkout = next(
        step
        for step in rust_steps
        if str(step.get("uses", "")).startswith("actions/checkout@")
    )
    assert checkout["with"]["ref"] == "${{ github.sha }}"
    assert checkout["with"]["persist-credentials"] is False
    record = next(
        s
        for s in rust_steps
        if s.get("name") == "Record successful PR Rust checkout identity"
    )
    upload = next(
        s
        for s in rust_steps
        if s.get("name") == "Upload successful PR Rust checkout identity"
    )
    assert record["if"] == upload["if"]
    assert "github.event_name == 'pull_request'" in record["if"]
    assert "success()" in record["if"]
    assert "matrix.lane == 'canvas'" in record["if"]
    assert "matrix.lane == 'contracts'" in record["if"]
    assert rust_steps.index(record) > next(
        i
        for i, step in enumerate(rust_steps)
        if step.get("name") == "Remove owned Rust test services and volumes"
    )
    assert upload["with"]["if-no-files-found"] == "error"
    assert "${{ github.run_id }}-${{ github.run_attempt }}" in upload["with"]["name"]
    assert "merge_group" in workflow.get("on", workflow.get(True, {}))
    assert "test-rust-services" in jobs["ci-gate"]["needs"]


def advance_merge_base(source):
    repo, env, event = source
    base_sha = event["pull_request"]["base"]["sha"]
    head_sha = event["pull_request"]["head"]["sha"]
    tree = git(repo, "rev-parse", "HEAD^{tree}")
    actual_base = git(repo, "commit-tree", tree, "-p", base_sha, "-m", "new main base")
    merge = git(repo, "commit-tree", tree, "-p", actual_base, "-p", head_sha, "-m", "event merge")
    git(repo, "checkout", "--detach", merge)
    env["GITHUB_SHA"] = merge
    env["GITHUB_WORKFLOW_SHA"] = merge
    return repo, env, event, actual_base


def test_records_event_base_separately_from_advanced_actual_merge_parent(source):
    repo, env, event, actual_base = advance_merge_base(source)
    record = attestation.build_attestation(env, event, repo)
    assert record["pull_request_base_sha"] == event["pull_request"]["base"]["sha"]
    assert record["checkout_base_parent_sha"] == actual_base
    assert record["checkout_sha"] == env["GITHUB_SHA"]


def test_advanced_merge_rejects_wrong_second_parent(source):
    repo, env, event, _ = advance_merge_base(source)
    event["pull_request"]["head"]["sha"] = event["pull_request"]["base"]["sha"]
    with pytest.raises(ValueError, match="head parent mismatch"):
        attestation.build_attestation(env, event, repo)


def test_rejects_existing_nonancestor_event_base(source):
    repo, env, event, _ = advance_merge_base(source)
    tree = git(repo, "rev-parse", "HEAD^{tree}")
    event["pull_request"]["base"]["sha"] = git(repo, "commit-tree", tree, "-m", "unrelated")
    with pytest.raises(ValueError):
        attestation.build_attestation(env, event, repo)


@pytest.mark.parametrize("parent_count", [1, 3])
def test_rejects_nonmerge_or_octopus_checkout(source, parent_count):
    repo, env, event = source
    tree = git(repo, "rev-parse", "HEAD^{tree}")
    args = ["commit-tree", tree, "-p", event["pull_request"]["base"]["sha"]]
    if parent_count == 3:
        extra = git(repo, "commit-tree", tree, "-m", "extra")
        args += ["-p", event["pull_request"]["head"]["sha"], "-p", extra]
    checkout = git(repo, *args, "-m", "malformed merge")
    git(repo, "checkout", "--detach", checkout)
    env["GITHUB_SHA"] = checkout
    with pytest.raises(ValueError, match="exactly two parents"):
        attestation.build_attestation(env, event, repo)


def test_shallow_advanced_merge_fetches_only_immutable_event_shas(
    source, tmp_path, monkeypatch
):
    repo, env, event, actual_base = advance_merge_base(source)
    shallow = tmp_path / "shallow-advanced"
    subprocess.run(["git", "clone", "--depth", "1", "--no-local",
                    repo.resolve().as_uri(), str(shallow)], check=True, capture_output=True)
    original = attestation.git
    calls = []
    def observed_git(repo_arg, *args, **kwargs):
        if args[0] == "fetch":
            calls.append((repo_arg, args, kwargs))
        return original(repo_arg, *args, **kwargs)
    monkeypatch.setattr(attestation, "git", observed_git)
    record = attestation.build_attestation(env, event, shallow)
    assert record["checkout_base_parent_sha"] == actual_base
    assert calls == [(shallow, ("fetch", "--no-tags", "--no-recurse-submodules",
                              "--unshallow", "origin", env["GITHUB_SHA"],
                              event["pull_request"]["base"]["sha"]), {"timeout": 120})]


@pytest.mark.parametrize("failure", ["unavailable", "timeout"])
def test_missing_event_base_or_failed_immutable_fetch_refuses(source, monkeypatch, failure):
    repo, env, event, _ = advance_merge_base(source)
    event["pull_request"]["base"]["sha"] = "f" * 40
    original = attestation.git
    calls = []
    def failed_fetch(repo_arg, *args, **kwargs):
        if args[0] == "fetch":
            calls.append((repo_arg, args, kwargs))
            if failure == "timeout":
                raise subprocess.TimeoutExpired(args, kwargs["timeout"])
            raise subprocess.CalledProcessError(128, args)
        return original(repo_arg, *args, **kwargs)
    monkeypatch.setattr(attestation, "git", failed_fetch)
    with pytest.raises(ValueError, match="base ancestry unavailable"):
        attestation.build_attestation(env, event, repo)
    assert calls == [(repo, ("fetch", "--no-tags", "--no-recurse-submodules", "origin",
                           env["GITHUB_SHA"], "f" * 40), {"timeout": 120})]


def test_rechecks_exact_head_after_ancestry_object_read(source, monkeypatch):
    repo, env, event, _ = advance_merge_base(source)
    original = attestation.require_base_ancestry
    def changed_head(repo_arg, event_base, checkout_base, checkout):
        original(repo_arg, event_base, checkout_base, checkout)
        git(repo_arg, "checkout", "--detach", event["pull_request"]["head"]["sha"])
    monkeypatch.setattr(attestation, "require_base_ancestry", changed_head)
    with pytest.raises(ValueError, match="HEAD changed during ancestry read"):
        attestation.build_attestation(env, event, repo)
