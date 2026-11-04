"""Execute source-bound classification and reject malformed aggregate evidence."""
from __future__ import annotations

from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("affected", ROOT / "scripts/ci/affected_components.py")
CI = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CI)
sys.path.insert(0, str(ROOT / "scripts/ci"))
try:
    from codeql_scope import parse_diff
finally:
    sys.path.pop(0)


def environment(event="pull_request"):
    return {"EVENT_NAME": event, "SOURCE_SHA": "a" * 40, "HEAD_SHA": "a" * 40,
            "BASE_SHA": "b" * 40 if event in {"pull_request", "merge_group"} else ""}


def plan(event="pull_request", website=False):
    flags = {f: "false" for f in CI.FLAGS}
    if website:
        flags.update(website="true", website_only="true")
    else:
        flags.update({f: "true" for f in ("all", "ui", "website", "python", "rust", "rust_runtime",
                                        "openbao", "release", "verification", "security")})
    return CI.make_plan({**flags, "rust_matrix": json.dumps(CI.FULL_MATRIX)}, environment(event))


def results(value):
    needs = {j: {"result": "success" if j in value["selected_jobs"] else "skipped", "outputs": {}}
             for j in CI.JOB_FLAGS}
    needs["changes"]["outputs"] = {f: str(v).lower() for f, v in value["flags"].items()}
    needs["changes"]["outputs"]["rust_matrix"] = json.dumps(value["rust_matrix"])
    return needs


@pytest.mark.parametrize("event", ["pull_request", "merge_group", "schedule", "workflow_dispatch"])
def test_exact_full_plan_satisfies_every_known_job(event):
    value = plan(event)
    CI.check_results(value, results(value), environment(event))
    assert value["unselected_jobs"] == []


@pytest.mark.parametrize("event", ["pull_request", "merge_group"])
def test_website_plan_requires_only_source_and_website_checks(event):
    value = plan(event, website=True)
    assert value["selected_jobs"] == ["changes", "lint", "release-preflight", "test-website"]
    CI.check_results(value, results(value), environment(event))


@pytest.mark.parametrize("key", ["event", "source_sha", "base_sha", "head_sha"])
def test_plan_cannot_be_replayed_for_another_event_or_tree(key):
    value = plan()
    value[key] = "schedule" if key == "event" else "c" * 40
    with pytest.raises(ValueError, match="event/base/head/source"):
        CI.check_results(value, results(value), environment())


@pytest.mark.parametrize("mutation", ["extra", "missing", "bool-version", "flag", "flag-type", "roster", "matrix", "mixed-website", "full-omission"])
def test_plan_is_closed_and_self_consistent(mutation):
    value = plan(website=mutation == "mixed-website")
    if mutation == "extra": value["unexpected"] = True
    elif mutation == "missing": del value["head_sha"]
    elif mutation == "bool-version": value["schema_version"] = True
    elif mutation == "flag": value["flags"]["unexpected"] = False
    elif mutation == "flag-type": value["flags"]["rust"] = "true"
    elif mutation == "roster": value["selected_jobs"].remove("test-rust-services")
    elif mutation == "matrix": value["rust_matrix"] = ["contracts"]
    elif mutation == "mixed-website": value["flags"]["ui"] = True
    elif mutation == "full-omission": value["flags"]["security"] = False
    with pytest.raises(ValueError): CI.validate_plan(value, environment())


@pytest.mark.parametrize("job", sorted(CI.JOB_FLAGS))
@pytest.mark.parametrize("result", ["failure", "cancelled", "skipped", ""])
def test_selected_jobs_must_complete_successfully(job, result):
    value = plan()
    needs = results(value)
    needs[job]["result"] = result
    with pytest.raises(ValueError): CI.check_results(value, needs, environment())


@pytest.mark.parametrize("mutation", ["extra-job", "missing-job", "unexpected-success", "flag-output", "matrix-output"])
def test_result_roster_and_outputs_match_the_plan(mutation):
    value = plan(website=True)
    needs = results(value)
    if mutation == "extra-job": needs["unreviewed"] = {"result": "success"}
    elif mutation == "missing-job": del needs["security"]
    elif mutation == "unexpected-success": needs["test-rust-services"]["result"] = "success"
    elif mutation == "flag-output": needs["changes"]["outputs"]["rust"] = "true"
    elif mutation == "matrix-output": needs["changes"]["outputs"]["rust_matrix"] = '["contracts"]'
    with pytest.raises(ValueError): CI.check_results(value, needs, environment())


@pytest.mark.parametrize("key", ["SOURCE_SHA", "HEAD_SHA", "BASE_SHA", "EVENT_NAME"])
def test_comparison_identity_is_required(key):
    env = environment()
    env[key] = ""
    with pytest.raises(ValueError): CI.identity(env)


def test_duplicate_json_keys_are_rejected():
    with pytest.raises(ValueError, match="duplicate"):
        CI.load_json('{"schema_version":1,"schema_version":1}')


def test_exact_roster_members_and_dedicated_modules_have_one_surface_owner():
    roster = json.loads((ROOT / "contracts/website-source-ownership.json").read_text())
    for path in roster["modules"]:
        assert CI.website_only(ROOT, path.encode() + b"\0"), path
    for path in ["ui/src/App.jsx", "ui/src/components/LandingPage.jsx", "ui/src/auth/AuthProvider.jsx",
                 "ui/src/locales/en.json", "ui/public/favicon.svg", "ui/package-lock.json",
                 "ui/vite.config.ts", "contracts/website-source-ownership.json",
                 "ui/scripts/web-surface-build-contract.mjs", "new-unowned-input"]:
        assert not CI.website_only(ROOT, path.encode() + b"\0"), path
    first = roster["modules"][0].encode()
    for data in [b"", first, first + b"\0" + first + b"\0", first + b"\0ui/src/App.jsx\0"]:
        assert not CI.website_only(ROOT, data)


def fixture_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    for name in ("affected_components.sh", "affected_components.py", "codeql_scope.py"):
        target = repo / "scripts/ci" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / "scripts/ci" / name).read_bytes())
    roster = {"schema_version": 1, "modules": ["ui/src/components/Marketing.jsx"]}
    (repo / "contracts").mkdir()
    (repo / "contracts/website-source-ownership.json").write_text(json.dumps(roster))
    for name in ("ui/src/components/Marketing.jsx", "ui/src/App.jsx"):
        target = repo / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("initial\n")
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=repo, text=True).strip()
    git("init", "-q")
    git("config", "user.name", "CI fixture")
    git("config", "user.email", "ci@example.invalid")
    git("add", ".")
    git("commit", "-qm", "base")
    base = git("rev-parse", "HEAD")
    git("remote", "add", "origin", str(repo))
    return repo, git, base


@pytest.mark.parametrize("event", ["pull_request", "merge_group"])
@pytest.mark.parametrize("change", ["marketing", "shared", "rename", "delete", "symlink", "newline"])
def test_real_git_diff_narrows_only_regular_owned_marketing(tmp_path, event, change):
    repo, git, base = fixture_repo(tmp_path)
    source = repo / "ui/src/components/Marketing.jsx"
    if change == "marketing": source.write_text("updated\n")
    elif change == "shared": (repo / "ui/src/App.jsx").write_text("updated\n")
    elif change == "rename": source.rename(repo / "ui/src/components/Moved.jsx")
    elif change == "delete": source.unlink()
    elif change == "symlink":
        source.unlink()
        source.symlink_to("../App.jsx")
    else:
        path = repo / "ui/src/apps/website/bad\nmodule.jsx"
        path.parent.mkdir(parents=True)
        path.write_text("updated\n")
    git("add", "-A")
    git("commit", "-qm", "change")
    sha = git("rev-parse", "HEAD")
    output = tmp_path / "outputs"
    output.write_text("")
    env = {**os.environ, **environment(event), "SOURCE_SHA": sha, "HEAD_SHA": sha,
           "BASE_SHA": base, "RUNNER_TEMP": str(tmp_path), "GITHUB_OUTPUT": str(output)}
    subprocess.run(["bash", "scripts/ci/affected_components.sh"], cwd=repo, env=env,
                   check=True, capture_output=True, text=True)
    raw = dict(line.split("=", 1) for line in output.read_text().splitlines())
    value = json.loads(raw.pop("plan"))
    CI.validate_plan(value, env)
    assert value["flags"]["website_only"] is (change == "marketing")
    if event == "merge_group" and change != "marketing": assert value["flags"]["all"]
    scope_file = tmp_path / "codeql.json"
    subprocess.run([sys.executable, "scripts/ci/codeql_scope.py"], cwd=repo,
                   env={**env, "CODEQL_SCOPE_FILE": str(scope_file)}, check=True, capture_output=True)
    scope = json.loads(scope_file.read_text())
    assert scope["source_sha"] == sha and scope["base_sha"] == base
    assert scope["website_only"] is (change == "marketing")
    if change == "rename":
        assert {item["filename"] for item in scope["files"]} == {
            "ui/src/components/Marketing.jsx", "ui/src/components/Moved.jsx"}


def test_codeql_diff_is_complete_and_preserves_status_without_api_limits():
    raw = b"".join(f"M\0rust/src/input{index}.rs\0".encode() for index in range(3501))
    files = parse_diff(raw)
    assert len(files) == 3501 and files[-1]["filename"] == "rust/src/input3500.rs"
    assert parse_diff(b"D\0old.rs\0A\0new.rs\0") == [
        {"filename": "old.rs", "status": "changed"}, {"filename": "new.rs", "status": "changed"}]
    for broken in (b"M\0path", b"M\0", b"R100\0old\0new\0", b"M\0path\0M\0path\0"):
        with pytest.raises(ValueError): parse_diff(broken)


@pytest.mark.parametrize("language", ["actions", "rust"])
@pytest.mark.parametrize("event,website,expected", [("merge_group", True, "false"),
                                                   ("merge_group", False, "true"),
                                                   ("schedule", False, "true")])
def test_codeql_required_check_skips_only_proved_website_merge_groups(language, event, website, expected):
    workflow = yaml.safe_load((ROOT / f".github/workflows/codeql-{language}.yml").read_text())
    steps = workflow["jobs"][f"analyze-{language}"]["steps"]
    scope = next(step for step in steps if step.get("id") == "scope")["with"]["script"]
    harness = """
const payload = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));
const output = {};
const fakeRequire = name => {
  if (name !== 'node:fs') throw new Error('unexpected import');
  return {readFileSync: () => JSON.stringify(payload.record)};
};
const AsyncFunction = Object.getPrototypeOf(async function(){}).constructor;
new AsyncFunction('core','context','require','process',payload.script)(
  {setOutput:(key,value)=>output[key]=value,info:()=>{}},
  {eventName:payload.event},fakeRequire,{env:{CODEQL_SCOPE_FILE:'verified.json'}}
).then(()=>process.stdout.write(JSON.stringify(output))).catch(error=>{console.error(error);process.exit(1)});
"""
    response = subprocess.run(["node", "-e", harness], text=True, capture_output=True, check=True,
                              input=json.dumps({"script": scope, "event": event,
                                                "record": {"event": event, "website_only": website, "files": []}}))
    assert json.loads(response.stdout)["analyze"] == expected


def test_workflow_closes_the_same_roster_and_builds_every_surface():
    jobs = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"]
    assert set(jobs["ci-gate"]["needs"]) == set(CI.JOB_FLAGS)
    assert jobs["test-website"]["needs"] == ["changes", "release-preflight"]
    assert jobs["test-website"]["if"] == "needs.changes.outputs.website == 'true'"
    commands = "\n".join(step.get("run", "") for step in jobs["test-website"]["steps"])
    for command in ("bun run test:website", "bun run build:website", "bun run build:application",
                    "bun run build:selfhost", "node scripts/assert-website-dist.mjs dist-website"):
        assert command in commands
    guard = next(step for step in jobs["ci-gate"]["steps"] if "CI_PLAN" in step.get("env", {}))
    assert guard["env"]["CI_NEEDS_JSON"] == "${{ toJSON(needs) }}"
    assert "continue-on-error" not in guard and "if" not in guard
