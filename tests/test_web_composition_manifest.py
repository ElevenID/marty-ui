"""Exercise manifest admission using the real CLI and temporary Git histories."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import web_composition_manifest as manifest

SCRIPT = ROOT / "scripts/web_composition_manifest.py"


def git(directory: Path, *arguments: str) -> str:
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT="0")
    result = subprocess.run(["git", "-c", "user.name=Composition fixture", "-c",
                             "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", *arguments],
                            cwd=directory, env=environment, capture_output=True, text=True, check=True)
    return result.stdout.strip()


@pytest.fixture
def checkout(tmp_path):
    git(tmp_path, "init", "--initial-branch=main")
    (tmp_path / "source.txt").write_text("previous reviewed source\n")
    git(tmp_path, "add", "source.txt")
    git(tmp_path, "commit", "-m", "Previous protected main")
    parent = git(tmp_path, "rev-parse", "HEAD")
    value = {
        "expected_parent_sha": parent,
        "website_repository": "ElevenID/website",
        "website_run_id": "44449706828",
        "website_run_attempt": "2",
        "application_run_id": "42385654811",
        "application_run_attempt": "1",
    }
    path = tmp_path / manifest.MANIFEST_PATH
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(value))
    git(tmp_path, "add", str(manifest.MANIFEST_PATH))
    git(tmp_path, "commit", "-m", "Reviewed composition selection")
    source = git(tmp_path, "rev-parse", "HEAD")
    git(tmp_path, "update-ref", "refs/remotes/origin/main", source)
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(("GIT_", "GITHUB_", "COMPOSITION_"))}
    environment.update(manifest.EVENT, GITHUB_SHA=source, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    return tmp_path, path, value, environment


def run(checkout, *arguments):
    directory, path, _, environment = checkout
    return subprocess.run([sys.executable, str(SCRIPT), "--manifest", str(path), *arguments], cwd=directory,
                          env=environment, capture_output=True, text=True, check=False, timeout=15)


def commit_manifest(checkout):
    directory, _, _, environment = checkout
    git(directory, "add", str(manifest.MANIFEST_PATH))
    git(directory, "commit", "--amend", "--no-edit")
    source = git(directory, "rev-parse", "HEAD")
    git(directory, "update-ref", "refs/remotes/origin/main", source)
    environment["GITHUB_SHA"] = source


def refused(result):
    assert result.returncode != 0
    assert result.stdout == ""
    assert "Composition manifest rejected" in result.stderr
    assert len(result.stderr) < 200


def test_actual_cli_accepts_reviewed_push_and_emits_only_complete_selection(checkout):
    result = run(checkout)
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    assert result.stdout == (
        "website_repository=ElevenID/website\n"
        "website_run_id=44449706828\n"
        "website_run_attempt=2\n"
        "application_run_id=42385654811\n"
        "application_run_attempt=1\n"
    )


@pytest.mark.parametrize("field", sorted(manifest.EVENT) + ["GITHUB_SHA"])
def test_missing_trusted_event_field_emits_no_outputs(checkout, field):
    del checkout[3][field]
    refused(run(checkout))


@pytest.mark.parametrize("field,value", [
    ("GITHUB_EVENT_NAME", "workflow_dispatch"), ("GITHUB_EVENT_NAME", "pull_request"),
    ("GITHUB_EVENT_NAME", "merge_group"), ("GITHUB_REPOSITORY", "attacker/marty-ui"),
    ("GITHUB_REPOSITORY_ID", "1459542519"), ("GITHUB_REF", "refs/heads/release"),
    ("GITHUB_REF", "refs/pull/1999/merge"), ("GITHUB_REF_PROTECTED", "false"),
    ("GITHUB_REF_PROTECTED", "True"), ("COMPOSITION_PUSH_DELETED", "true"),
    ("COMPOSITION_PUSH_DELETED", "False"), ("GITHUB_SHA", "main"),
    ("GITHUB_SHA", "A" * 40), ("GITHUB_SHA", "a" * 40 + "\n"),
])
def test_wrong_event_or_source_identity_emits_no_outputs(checkout, field, value):
    checkout[3][field] = value
    refused(run(checkout))


def test_actual_git_head_must_equal_pushed_source(checkout):
    checkout[3]["GITHUB_SHA"] = checkout[2]["expected_parent_sha"]
    refused(run(checkout))


def test_stale_parent_after_another_main_commit_emits_no_outputs(checkout):
    directory, _, _, environment = checkout
    (directory / "source.txt").write_text("main advanced after selection\n")
    git(directory, "add", "source.txt")
    git(directory, "commit", "-m", "Another reviewed main commit")
    source = git(directory, "rev-parse", "HEAD")
    git(directory, "update-ref", "refs/remotes/origin/main", source)
    environment["GITHUB_SHA"] = source
    refused(run(checkout))


def test_selected_source_must_be_in_origin_main_lineage(checkout):
    directory, _, value, _ = checkout
    git(directory, "update-ref", "refs/remotes/origin/main", value["expected_parent_sha"])
    refused(run(checkout))


def test_missing_origin_main_fails_closed(checkout):
    git(checkout[0], "update-ref", "-d", "refs/remotes/origin/main")
    refused(run(checkout))


def test_later_origin_main_is_allowed_for_the_exact_pushed_commit(checkout):
    directory, _, _, environment = checkout
    selected = environment["GITHUB_SHA"]
    (directory / "later.txt").write_text("later reviewed source\n")
    git(directory, "add", "later.txt")
    git(directory, "commit", "-m", "Later main")
    git(directory, "update-ref", "refs/remotes/origin/main", "HEAD")
    git(directory, "checkout", "--detach", selected)
    assert run(checkout).returncode == 0


@pytest.mark.parametrize("field", manifest.OUTPUT_FIELDS[1:])
@pytest.mark.parametrize("value", ["0", "01", "-1", "+1", "1.0", "1e3", " 1", "1\n",
                                  "１", "1" * 21, 1, True, None, [], {}])
def test_noncanonical_run_or_attempt_refused_without_outputs(checkout, field, value):
    checkout[2][field] = value
    checkout[1].write_text(json.dumps(checkout[2]))
    refused(run(checkout))


@pytest.mark.parametrize("field", manifest.OUTPUT_FIELDS[1:])
def test_twenty_digit_canonical_invocations_remain_accepted(checkout, field):
    checkout[2][field] = "9" * 20
    checkout[1].write_text(json.dumps(checkout[2]))
    commit_manifest(checkout)
    result = run(checkout)
    assert result.returncode == 0, result.stderr
    assert f"{field}={'9' * 20}\n" in result.stdout


@pytest.mark.parametrize("staged", [False, True])
def test_working_or_staged_manifest_cannot_replace_reviewed_source(checkout, staged):
    checkout[2]["website_run_id"] = "44449706829"
    checkout[1].write_text(json.dumps(checkout[2]))
    if staged:
        git(checkout[0], "add", str(manifest.MANIFEST_PATH))
    refused(run(checkout))


def test_alternate_file_is_refused_even_with_identical_reviewed_bytes(checkout):
    directory, path, value, environment = checkout
    alternate = directory / "other-manifest.json"
    alternate.write_bytes(path.read_bytes())
    refused(run((directory, alternate, value, environment)))


def test_manifest_must_be_present_in_the_selected_commit(checkout):
    directory, path, _, _ = checkout
    raw = path.read_bytes()
    git(directory, "rm", str(manifest.MANIFEST_PATH))
    git(directory, "commit", "--amend", "--no-edit", "--allow-empty")
    source = git(directory, "rev-parse", "HEAD")
    git(directory, "update-ref", "refs/remotes/origin/main", source)
    checkout[3]["GITHUB_SHA"] = source
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    refused(run(checkout))


@pytest.mark.parametrize("value", ["main", "A" * 40, "a" * 39, "a" * 40 + "\n", 1, None, {}])
def test_invalid_parent_identity_refused_without_outputs(checkout, value):
    checkout[2]["expected_parent_sha"] = value
    checkout[1].write_text(json.dumps(checkout[2]))
    refused(run(checkout))


@pytest.mark.parametrize("value", ["ElevenID/marty-ui", "attacker/website", None, [], {}])
def test_only_standalone_website_repository_is_allowed(checkout, value):
    checkout[2]["website_repository"] = value
    checkout[1].write_text(json.dumps(checkout[2]))
    refused(run(checkout))


@pytest.mark.parametrize("field", sorted(manifest.FIELDS))
def test_missing_manifest_field_refused_without_outputs(checkout, field):
    del checkout[2][field]
    checkout[1].write_text(json.dumps(checkout[2]))
    refused(run(checkout))


def test_unknown_field_refused_without_outputs(checkout):
    checkout[2]["token"] = "must-not-appear-in-errors"
    checkout[1].write_text(json.dumps(checkout[2]))
    result = run(checkout)
    refused(result)
    assert "must-not-appear-in-errors" not in result.stderr


@pytest.mark.parametrize("field", sorted(manifest.FIELDS))
def test_duplicate_keys_refused_even_when_values_match(checkout, field):
    encoded = json.dumps(checkout[2])
    checkout[1].write_text(encoded[:-1] + ", " + json.dumps(field) + ": " + json.dumps(checkout[2][field]) + "}")
    refused(run(checkout))


@pytest.mark.parametrize("raw", [b"", b"{", b"null", b"[]", b"true", b"42", b"{}\n{}", b"\xff",
                                b"{\"website_run_id\": NaN}", b"{\"website_run_id\": Infinity}",
                                b"{\"website_run_id\": -Infinity}", b"[" * 1500 + b"]" * 1500])
def test_invalid_json_refused_without_outputs(checkout, raw):
    checkout[1].write_bytes(raw)
    refused(run(checkout))


def test_oversized_manifest_refused_even_with_valid_json(checkout):
    checkout[1].write_text(json.dumps(checkout[2]) + " " * manifest.MAX_MANIFEST_BYTES)
    refused(run(checkout))


@pytest.mark.parametrize("kind", ["missing", "symlink", "directory", "fifo"])
def test_nonregular_manifest_cannot_block_or_emit_outputs(checkout, kind):
    directory, path, value, _ = checkout
    path.unlink()
    if kind == "symlink":
        target = directory / "other-manifest.json"
        target.write_text(json.dumps(value))
        path.symlink_to(target)
    elif kind == "directory":
        path.mkdir()
    elif kind == "fifo":
        os.mkfifo(path)
    refused(run(checkout))


def run_integration(checkout, *, event="pull_request", base=None):
    directory, path, value, original_environment = checkout
    environment = {key: item for key, item in original_environment.items() if key not in manifest.EVENT}
    environment["GITHUB_EVENT_NAME"] = event
    if base is not None:
        environment["COMPOSITION_INTEGRATION_BASE"] = base
    return run((directory, path, value, environment), "--check-integration")


def refresh_source(checkout):
    source = git(checkout[0], "rev-parse", "HEAD")
    git(checkout[0], "update-ref", "refs/remotes/origin/main", source)
    checkout[3]["GITHUB_SHA"] = source
    return source


def append_unrelated_commit(checkout, message="Unrelated later PR"):
    directory = checkout[0]
    (directory / "later-source.txt").write_text(message + "\n")
    git(directory, "add", "later-source.txt")
    git(directory, "commit", "-m", message)
    return refresh_source(checkout)


def test_actual_pull_request_merge_validates_first_parent_without_release_authority(checkout):
    directory, _, value, environment = checkout
    selected = environment["GITHUB_SHA"]
    git(directory, "checkout", "-b", "integration", value["expected_parent_sha"])
    git(directory, "merge", "--no-ff", "--no-edit", selected)
    refresh_source(checkout)
    git(directory, "update-ref", "-d", "refs/remotes/origin/main")
    # A PR must use its actual first parent even if an event base value is stale.
    result = run_integration(checkout, base="not-the-actual-pr-base")
    assert result.returncode == 0, result.stderr
    assert result.stdout == result.stderr == ""


def test_changed_pr_manifest_rejects_stale_parent_after_main_advances(checkout):
    directory, _, value, environment = checkout
    selected = environment["GITHUB_SHA"]
    git(directory, "checkout", "-b", "advanced-main", value["expected_parent_sha"])
    append_unrelated_commit(checkout)
    git(directory, "merge", "--no-ff", "--no-edit", selected)
    refresh_source(checkout)
    refused(run_integration(checkout, base=value["expected_parent_sha"]))


def test_merge_group_with_matching_parent_and_changed_manifest_is_accepted(checkout):
    result = run_integration(checkout, event="merge_group", base=checkout[2]["expected_parent_sha"])
    assert result.returncode == 0, result.stderr
    assert result.stdout == result.stderr == ""


def test_later_unrelated_pr_skips_unchanged_manifest_with_old_parent_pin(checkout):
    append_unrelated_commit(checkout)
    result = run_integration(checkout)
    assert result.returncode == 0, result.stderr
    assert result.stdout == result.stderr == ""


def test_queue_batch_detects_manifest_introduced_before_its_last_commit(checkout):
    batch_base = checkout[2]["expected_parent_sha"]
    append_unrelated_commit(checkout)
    # HEAD's parent has the same manifest, but the entire queue batch changes it.
    refused(run_integration(checkout, event="merge_group", base=batch_base))


@pytest.mark.parametrize("event", ["workflow_dispatch", "schedule", "push"])
def test_check_mode_skips_nonintegration_events_without_touching_manifest(checkout, event):
    checkout[1].unlink()
    del checkout[3]["GITHUB_SHA"]
    result = run_integration(checkout, event=event)
    assert result.returncode == 0
    assert result.stdout == result.stderr == ""


@pytest.mark.parametrize("base", [None, "", "main", "A" * 40, "a" * 40 + "\n", "--all"])
def test_merge_group_base_must_be_present_and_canonical(checkout, base):
    refused(run_integration(checkout, event="merge_group", base=base))


def test_merge_group_base_cannot_equal_its_source(checkout):
    refused(run_integration(checkout, event="merge_group", base=checkout[3]["GITHUB_SHA"]))


@pytest.mark.parametrize("source", [None, "main", "A" * 40, "a" * 40 + "\n", "0" * 40])
def test_integration_source_must_match_exact_checked_out_commit(checkout, source):
    if source is None:
        del checkout[3]["GITHUB_SHA"]
    else:
        checkout[3]["GITHUB_SHA"] = source
    refused(run_integration(checkout))


@pytest.mark.parametrize("mutation", ["dirty", "staged", "committed-extra-field"])
def test_changed_integration_manifest_retains_schema_and_source_blob_checks(checkout, mutation):
    checkout[2]["website_run_id"] = "44449706829"
    if mutation == "committed-extra-field":
        checkout[2]["unreviewed_authority"] = True
    checkout[1].write_text(json.dumps(checkout[2]))
    if mutation == "staged":
        git(checkout[0], "add", str(manifest.MANIFEST_PATH))
    elif mutation == "committed-extra-field":
        commit_manifest(checkout)
    refused(run_integration(checkout))


def test_removing_an_existing_manifest_fails_closed_before_merge(checkout):
    git(checkout[0], "rm", str(manifest.MANIFEST_PATH))
    git(checkout[0], "commit", "-m", "Remove selected manifest")
    refresh_source(checkout)
    refused(run_integration(checkout))


def test_check_mode_never_emits_or_appends_release_outputs(checkout):
    output = checkout[0] / "step-output"
    output.write_text("unrelated=existing\n")
    checkout[3]["GITHUB_OUTPUT"] = str(output)
    result = run_integration(checkout)
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    assert output.read_text() == "unrelated=existing\n"


def test_unavailable_exact_queue_base_fails_closed(checkout):
    refused(run_integration(checkout, event="merge_group", base="a" * 40))


def test_shallow_queue_fetches_only_its_missing_exact_base_and_skips_unchanged_manifest(checkout):
    directory, _, value, environment = checkout
    batch_base = environment["GITHUB_SHA"]
    append_unrelated_commit(checkout, "First unrelated queued PR")
    append_unrelated_commit(checkout, "Second unrelated queued PR")
    remote = directory / "origin.git"
    shallow = directory / "shallow"
    git(directory, "clone", "--bare", str(directory), str(remote))
    git(directory, "clone", "--depth=2", remote.as_uri(), str(shallow))
    missing = subprocess.run(["git", "cat-file", "-e", f"{batch_base}^{{commit}}"], cwd=shallow,
                             capture_output=True, check=False)
    assert missing.returncode != 0
    fetch_head = shallow / ".git/FETCH_HEAD"
    fetch_head.write_text("retain prior fetch metadata\n")
    binary = shutil.which("git")
    assert binary is not None
    probe = directory / "fetch-calls.jsonl"
    bin_directory = directory / "probe-bin"
    bin_directory.mkdir()
    wrapper = bin_directory / "git"
    wrapper.write_text(
        f"#!{sys.executable}\nimport json, os, sys\n"
        f"if sys.argv[1:2] == ['fetch']:\n"
        f"    with open({str(probe)!r}, 'a') as stream: stream.write(json.dumps(sys.argv[1:]) + '\\n')\n"
        f"os.execv({binary!r}, [{binary!r}, *sys.argv[1:]])\n"
    )
    wrapper.chmod(0o700)
    selected_environment = {**environment, "PATH": str(bin_directory) + os.pathsep + environment["PATH"]}
    selected = (shallow, shallow / manifest.MANIFEST_PATH, value, selected_environment)
    result = run_integration(selected, event="merge_group", base=batch_base)
    assert result.returncode == 0, result.stderr
    assert result.stdout == result.stderr == ""
    assert probe.read_text().splitlines() == [json.dumps([
        "fetch", "--no-tags", "--no-write-fetch-head", "--depth=1", "origin", batch_base,
    ])]
    assert fetch_head.read_text() == "retain prior fetch metadata\n"
    assert git(shallow, "cat-file", "-t", batch_base) == "commit"
    # A second check must reuse that exact object instead of fetching again.
    assert run_integration(selected, event="merge_group", base=batch_base).returncode == 0
    assert len(probe.read_text().splitlines()) == 1
    # Malformed bases cannot reach the fetch operation.
    refused(run_integration(selected, event="merge_group", base="--all"))
    assert len(probe.read_text().splitlines()) == 1


def test_ci_runs_integration_check_in_mandatory_preflight_without_credentials():
    import yaml

    workflow = yaml.load((ROOT / ".github/workflows/ci.yml").read_text(), Loader=yaml.BaseLoader)
    job = workflow["jobs"]["release-preflight"]
    assert job.get("if") is None and job.get("continue-on-error") is None
    checkout_step = job["steps"][0]
    assert checkout_step["uses"].startswith("actions/checkout@")
    assert checkout_step["with"]["fetch-depth"] == "2"
    assert checkout_step["with"]["persist-credentials"] == "false"
    checks = [step for step in job["steps"] if "--check-integration" in step.get("run", "")]
    assert len(checks) == 1
    step = checks[0]
    assert step["run"] == "python3 scripts/web_composition_manifest.py --check-integration"
    assert step["env"] == {"COMPOSITION_INTEGRATION_BASE": "${{ github.event.merge_group.base_sha || '' }}"}
    assert step.get("if") is None and step.get("continue-on-error") is None
    assert "secrets." not in json.dumps(job)
    assert job["steps"][-1]["run"].startswith("python3 scripts/ci/check_release_preflight.py")
    assert "release-preflight" in workflow["jobs"]["ci-gate"]["needs"]
    gate_commands = "\n".join(item.get("run", "") for item in workflow["jobs"]["ci-gate"]["steps"])
    assert 'require_result release-preflight "$PREFLIGHT_RESULT" success' in gate_commands
