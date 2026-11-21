"""Only exact successful release attempts may supply inert, signed receipts."""
from __future__ import annotations

import copy
import io
import json
from pathlib import Path
import shlex
import stat
import subprocess
import sys
import zipfile

import pytest
import yaml

from tests.test_package_web_composition import candidate, standalone_website, write_json
import package_web_composition as composition
import ui_release as ui
import web_release_intake as intake
import website_release as web
import website_producer_policy as policy


@pytest.fixture(params=["legacy", "standalone"])
def producer_artifact(candidate, tmp_path, request):
    kwargs, calls, _, _ = candidate
    release = web.read(kwargs["website_assets"] / "website-release.json")
    if request.param == "standalone":
        release = standalone_website(release["source_sha"], web.read(kwargs["website_assets"] / "web-surface-routes.json"))
        write_json(kwargs["website_assets"] / "website-release.json", release)
    producer = release["producer"]
    run = {"id": int(producer["run_id"]), "run_attempt": int(producer["run_attempt"]), "status": "completed",
           "conclusion": "success", "event": "workflow_dispatch", "head_branch": "main", "head_sha": producer["source_sha"],
           "path": producer["workflow"] + "@main", "repository": {"full_name": producer["repository"],
           "id": int(policy.repositories_for("website")[producer["repository"]])}}
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for name in composition.WEBSITE_FILES:
            archive.writestr(name, (kwargs["website_assets"] / name).read_bytes())
    raw = stream.getvalue()
    listed = {"total_count": 1, "artifacts": [{"id": 55, "name": "web-website-124-2", "expired": False,
              "size_in_bytes": len(raw), "digest": ui.digest(raw), "workflow_run": {"id": run["id"],
              "head_sha": run["head_sha"], "head_branch": "main", "repository_id": run["repository"]["id"]}}]}
    kwargs["gh"].write_bytes(b"pinned verifier fixture")
    return kwargs, producer, run, listed, raw, calls


def fetch(producer_artifact, tmp_path):
    kwargs, producer, run, listed, raw, calls = producer_artifact
    api_calls = []
    def api(args):
        api_calls.append(args)
        return json.dumps(run if "/attempts/" in args[-1] else listed)
    downloads = []
    def download(args):
        downloads.append(args)
        return raw
    prefix = f"repos/{producer['repository']}/actions"
    class Reader:
        def attempt(self):
            return api([f"{prefix}/runs/{producer['run_id']}/attempts/{producer['run_attempt']}"])
        def artifacts(self):
            return api([f"{prefix}/runs/{producer['run_id']}/artifacts?name=web-website-124-2&per_page=100"])
        def archive(self, artifact_id, *, maximum):
            assert maximum == listed["artifacts"][0]["size_in_bytes"]
            return download([f"{prefix}/artifacts/{artifact_id}/zip"])
    result = intake.fetch("website", repository=producer["repository"], run_id=producer["run_id"],
                          attempt=producer["run_attempt"], destination=tmp_path / "intake", gh=kwargs["gh"],
                          cosign=kwargs["cosign"], reader=Reader())
    return result, api_calls, downloads


def test_intake_matches_api_attempt_and_reverifies_original_receipt(producer_artifact, tmp_path):
    result, calls, downloads = fetch(producer_artifact, tmp_path)
    assert result["producer"] == producer_artifact[1]
    assert calls[0][-1].endswith("/runs/124/attempts/2")
    assert "name=web-website-124-2" in calls[1][-1]
    assert downloads[0][-1].endswith("/artifacts/55/zip")
    assert {p.name for p in (tmp_path / "intake").iterdir()} == set(composition.WEBSITE_FILES)
    assert [call[0] for call in producer_artifact[-1]] == ["subject", "image"]


@pytest.mark.parametrize("field,value", [("status", "in_progress"), ("conclusion", "failure"), ("event", "pull_request"),
    ("head_branch", "feature"), ("run_attempt", 1), ("id", 999), ("path", ".github/workflows/attacker.yml"),
    ("repository", {"full_name": "Elsewhere/repo", "id": 1}), ("head_sha", "main")])
def test_wrong_attempt_metadata_rejected_before_download(producer_artifact, tmp_path, field, value):
    producer_artifact[2][field] = value
    with pytest.raises(ValueError):
        fetch(producer_artifact, tmp_path)
    assert not (tmp_path / "intake").exists() and producer_artifact[-1] == []


@pytest.mark.parametrize("field,value", [("name", "web-website-124-1"), ("expired", True), ("size_in_bytes", 0),
    ("size_in_bytes", intake.MAX_ARCHIVE + 1), ("digest", "sha256:" + "9" * 64), ("id", 0),
    ("workflow_run", {"id": 1})])
def test_wrong_artifact_identity_bounds_or_digest_fail_closed(producer_artifact, tmp_path, field, value):
    producer_artifact[3]["artifacts"][0][field] = value
    with pytest.raises(ValueError):
        fetch(producer_artifact, tmp_path)
    assert not (tmp_path / "intake").exists()


def test_valid_signed_receipt_from_another_source_cannot_substitute_selected_attempt(producer_artifact, tmp_path):
    producer_artifact[2]["head_sha"] = "9" * 40
    producer_artifact[3]["artifacts"][0]["workflow_run"]["head_sha"] = "9" * 40
    with pytest.raises(ValueError, match="selected producer attempt"):
        fetch(producer_artifact, tmp_path)
    assert not (tmp_path / "intake").exists()


@pytest.mark.parametrize("fault", ["duplicate", "traversal", "symlink", "extra", "oversize"])
def test_intake_zip_never_accepts_executable_or_ambiguous_payload(producer_artifact, tmp_path, fault):
    with zipfile.ZipFile(io.BytesIO(producer_artifact[4])) as source:
        entries = [(entry, source.read(entry)) for entry in source.infolist()]
    if fault == "duplicate":
        entries.append(entries[0])
    elif fault in {"traversal", "extra"}:
        entries.append((zipfile.ZipInfo("../run.py" if fault == "traversal" else "run.py"), b"print('injected')"))
    elif fault == "symlink":
        entries[0][0].external_attr = (stat.S_IFLNK | 0o777) << 16
    else:
        entries[0] = (entries[0][0], b"x" * (intake.proof.JSON_LIMIT + 1))
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for entry, raw in entries:
            archive.writestr(entry, raw)
    with pytest.raises(ValueError):
        intake.extract_receipt(output.getvalue(), kind="website", destination=tmp_path / "intake")
    assert not (tmp_path / "intake").exists()


def test_backend_download_uses_fixed_public_subjects_without_credentials(tmp_path):
    requests = []
    def opener(request, **_kwargs):
        requests.append(request)
        return io.BytesIO(b"fixture bytes; original verification is a separate gate")
    intake.backend("v1.2.3", destination=tmp_path / "backend", opener=opener)
    assert {Path(r.full_url).name for r in requests} == set(composition.BACKEND_FILES)
    assert all(r.full_url.startswith("https://github.com/ElevenID/marty-ui/releases/download/v1.2.3/") for r in requests)
    assert all(not r.has_header("Authorization") for r in requests)


@pytest.mark.parametrize("kind", ["website", "application"])
@pytest.mark.parametrize("selected", [None, "GITHUB_TOKEN"])
def test_actions_cli_preserves_existing_gh_token_default_and_explicit_override(tmp_path, monkeypatch, kind, selected):
    args = ["web_release_intake.py", kind, "--repository", ui.REPOSITORY,
            "--run-id", "21", "--run-attempt", "2", "--assets", str(tmp_path / "assets"),
            "--gh", str(tmp_path / "gh"), "--cosign", str(tmp_path / "cosign")]
    if selected:
        args.extend(["--github-token-env", selected])
    calls = []
    monkeypatch.setattr("sys.argv", args)
    monkeypatch.setattr(intake, "fetch", lambda kind, **kwargs: calls.append((kind, kwargs)))
    intake.main()
    assert len(calls) == 1 and calls[0][0] == kind
    assert calls[0][1]["github_token_env"] == (selected or "GH_TOKEN")
    assert calls[0][1]["registry_config"] is None


def test_backend_cli_never_selects_actions_credentials_by_default(tmp_path, monkeypatch):
    monkeypatch.setenv("GH_TOKEN", "synthetic-token-that-backend-must-not-read")
    monkeypatch.setattr("sys.argv", ["web_release_intake.py", "backend", "--tag", "v1.2.3",
                        "--source-sha", "a" * 40, "--assets", str(tmp_path / "assets"),
                        "--gh", str(tmp_path / "gh")])
    calls = []
    monkeypatch.setattr(intake, "backend", lambda tag, **kwargs: calls.append("download"))
    monkeypatch.setattr(intake.stable, "verify_published", lambda *args, **kwargs: calls.append("verify"))
    monkeypatch.setattr(intake.auth, "GitHubReader", lambda **kwargs: pytest.fail("backend selected API credentials"))
    intake.main()
    assert calls == ["download", "verify"]


def test_standalone_application_intake_fails_before_any_network_or_credentials(tmp_path, monkeypatch):
    class Reader:
        def attempt(self):
            pytest.fail("unauthorized application read reached network")
    monkeypatch.setattr(intake.auth, "GitHubReader", lambda **_kwargs: pytest.fail("unauthorized role selected credentials"))
    for reader in (None, Reader()):
        with pytest.raises(ValueError, match="producer role"):
            intake.fetch("application", repository=policy.STANDALONE_REPOSITORY, run_id="124", attempt="2",
                         destination=tmp_path / "must-not-create", gh=tmp_path / "gh", cosign=tmp_path / "cosign",
                         reader=reader)
    assert not (tmp_path / "must-not-create").exists()


def test_api_repository_numeric_id_cannot_be_substituted_by_another_authorized_owner(producer_artifact, tmp_path):
    _, producer, run, _, _, calls = producer_artifact
    run["repository"]["id"] = int(web.REPOSITORIES[ui.REPOSITORY]
                                    if producer["repository"] == policy.STANDALONE_REPOSITORY
                                    else policy.STANDALONE_REPOSITORY_ID)
    with pytest.raises(ValueError, match="repository differs"):
        fetch(producer_artifact, tmp_path)
    assert calls == [] and not (tmp_path / "intake").exists()


@pytest.fixture
def composer_workflow():
    workflow = yaml.safe_load((Path(__file__).resolve().parents[1] / ".github/workflows/production-web-release.yml").read_text())
    compose = workflow["jobs"]["compose"]
    website = next(item for item in compose["steps"] if item.get("name") == "Authenticate the selected original website producer")
    application = next(item for item in compose["steps"] if item.get("name") == "Authenticate application and backend and compose unchanged artifacts")
    return workflow, compose, website, application


def test_composer_workflow_keeps_legacy_default_and_scopes_external_credentials_to_website(composer_workflow):
    workflow, compose, website, application = composer_workflow
    dispatch = workflow.get("on", workflow.get(True))["workflow_dispatch"]
    selection = dispatch["inputs"]["website_repository"]
    assert selection["type"] == "choice"
    assert selection["default"] == ui.REPOSITORY
    assert selection["options"] == [ui.REPOSITORY, policy.STANDALONE_REPOSITORY]
    assert "github.repository == 'ElevenID/marty-ui'" in compose["if"]
    assert compose["steps"].index(website) < compose["steps"].index(application)
    assert website["env"] == {
        "GH_TOKEN": "${{ github.token }}",
        "WEBSITE_ARTIFACT_READ_TOKEN": "${{ secrets.WEBSITE_RELEASE_READ_TOKEN }}",
        "WEBSITE_RUN": "${{ inputs.website_run_id || steps.composition_manifest.outputs.website_run_id }}",
        "WEBSITE_ATTEMPT": "${{ inputs.website_run_attempt || steps.composition_manifest.outputs.website_run_attempt }}",
        "WEBSITE_REPOSITORY": "${{ inputs.website_repository || steps.composition_manifest.outputs.website_repository || 'ElevenID/marty-ui' }}",
    }
    assert application["env"] == {
        "GH_TOKEN": "${{ github.token }}",
        "APPLICATION_RUN": "${{ inputs.application_run_id || steps.composition_manifest.outputs.application_run_id }}",
        "APPLICATION_ATTEMPT": "${{ inputs.application_run_attempt || steps.composition_manifest.outputs.application_run_attempt }}",
    }
    for step in compose["steps"]:
        if step is not website:
            assert "WEBSITE_ARTIFACT_READ_TOKEN" not in str(step)
            assert "secrets.WEBSITE_RELEASE_READ_TOKEN" not in str(step)
    website_commands = [shlex.split(line) for line in website["run"].replace("\\\n", " ").splitlines()
                        if line.strip().startswith("python ")]
    assert len(website_commands) == 1
    assert website_commands[0][:3] == ["python", "scripts/web_release_intake.py", "website"]
    commands = website_commands + [shlex.split(line) for line in application["run"].replace("\\\n", " ").splitlines()
                if line.strip().startswith("python scripts/web_release_intake.py ")]
    selected = {command[2]: command for command in commands}
    assert selected["website"][selected["website"].index("--repository") + 1] == "$WEBSITE_REPOSITORY"
    assert selected["application"][selected["application"].index("--repository") + 1] == ui.REPOSITORY
    assert "--repository" not in selected["backend"]
    assert sum("$WEBSITE_REPOSITORY" in command for command in commands) == 1


@pytest.fixture
def workflow_shell(tmp_path):
    """Run the actual workflow shell with inert tools and synthetic credentials."""
    tools = tmp_path / "bin"
    tools.mkdir()
    runner = tmp_path / "runner"
    verifiers = runner / "web-verifiers"
    verifiers.mkdir(parents=True)
    capture = tmp_path / "workflow-calls.jsonl"
    recorder = "#!" + sys.executable + "\n" + '''import json, os, sys
from pathlib import Path
program = Path(sys.argv[0]).name
credentials = {key: os.environ[key] for key in
               ("GH_TOKEN", "GITHUB_TOKEN", "WEBSITE_ARTIFACT_READ_TOKEN") if key in os.environ}
with open(os.environ["WORKFLOW_CALLS"], "a") as stream:
    stream.write(json.dumps({"program": program, "argv": sys.argv[1:], "env": credentials}) + "\\n")
if program == "jq":
    print({".source_sha": "b" * 40, ".version": "1.2.3"}[sys.argv[2]])
'''
    for executable in (tools / "python", tools / "jq", verifiers / "cosign"):
        executable.write_text(recorder)
        executable.chmod(0o700)

    def run(step, *, repository=None, artifact_token="", event="workflow_dispatch"):
        assert event in {"workflow_dispatch", "push"}
        inputs = {
            "website_repository": repository or "",
            "website_run_id": "124", "website_run_attempt": "2",
            "application_run_id": "125", "application_run_attempt": "1",
        } if event == "workflow_dispatch" else {}
        outputs = {
            "website_repository": repository or policy.STANDALONE_REPOSITORY,
            "website_run_id": "224", "website_run_attempt": "3",
            "application_run_id": "225", "application_run_attempt": "4",
        } if event == "push" else {}
        values = {
            "github.token": "synthetic-job-token",
            "secrets.WEBSITE_RELEASE_READ_TOKEN": artifact_token,
            **{f"inputs.{key}": value for key, value in inputs.items()},
            **{f"steps.composition_manifest.outputs.{key}": value for key, value in outputs.items()},
        }

        def resolve(expression):
            # Resolve only the declared string selections, including Actions' OR
            # fallback for absent dispatch inputs. Never interpolate shell text.
            assert expression.startswith("${{ ") and expression.endswith(" }}")
            for term in expression[4:-3].split(" || "):
                if term.startswith("'") and term.endswith("'"):
                    value = term[1:-1]
                else:
                    assert term in values or term.startswith(("inputs.", "steps.composition_manifest.outputs."))
                    value = values.get(term, "")
                if value:
                    return value
            return ""

        # Each Actions step starts with its own declared environment. Never copy
        # the test process environment, which may contain actual CI credentials.
        env = {
            "PATH": str(tools) + ":/usr/bin:/bin",
            "RUNNER_TEMP": str(runner), "WORKFLOW_CALLS": str(capture),
            "GITHUB_REPOSITORY": ui.REPOSITORY, "GITHUB_SHA": "c" * 40,
            "GITHUB_RUN_ID": "999", "GITHUB_RUN_ATTEMPT": "1",
            **{name: resolve(value) for name, value in step["env"].items()},
        }
        capture.unlink(missing_ok=True)
        result = subprocess.run(["/bin/bash", "--noprofile", "--norc", "-c", step["run"]],
                                cwd=tmp_path, env=env, capture_output=True, text=True, timeout=15)
        calls = [json.loads(line) for line in capture.read_text().splitlines()] if capture.exists() else []
        for token in ("synthetic-job-token", artifact_token):
            if token:
                assert token not in result.stdout + result.stderr
        return result, calls
    return run


@pytest.mark.parametrize("event,repository,artifact_token,expected_token", [
    ("workflow_dispatch", None, "", "synthetic-job-token"),
    ("workflow_dispatch", ui.REPOSITORY, "synthetic-website-token", "synthetic-job-token"),
    ("workflow_dispatch", policy.STANDALONE_REPOSITORY, "synthetic-website-token", "synthetic-website-token"),
    ("push", policy.STANDALONE_REPOSITORY, "synthetic-website-token", "synthetic-website-token"),
])
def test_website_intake_shell_selects_only_the_required_token(composer_workflow, workflow_shell, tmp_path,
                                                            event, repository, artifact_token, expected_token):
    result, calls = workflow_shell(composer_workflow[2], repository=repository,
                                  artifact_token=artifact_token, event=event)
    assert result.returncode == 0, result.stderr
    run_id, attempt = ("124", "2") if event == "workflow_dispatch" else ("224", "3")
    assert calls == [{
        "program": "python",
        "argv": ["scripts/web_release_intake.py", "website", "--repository", repository or ui.REPOSITORY,
                 "--run-id", run_id, "--run-attempt", attempt, "--assets", str(tmp_path / "runner/selected-website"),
                 "--gh", str(tmp_path / "runner/web-verifiers/gh"),
                 "--cosign", str(tmp_path / "runner/web-verifiers/cosign")],
        "env": {"GH_TOKEN": expected_token},
    }]


@pytest.mark.parametrize("event", ["workflow_dispatch", "push"])
def test_standalone_intake_shell_requires_external_token_before_any_tool(composer_workflow, workflow_shell, event):
    result, calls = workflow_shell(composer_workflow[2], repository=policy.STANDALONE_REPOSITORY, event=event)
    assert result.returncode != 0
    assert "requires WEBSITE_RELEASE_READ_TOKEN" in result.stderr
    assert calls == []


@pytest.mark.parametrize("repository", [ui.COMMERCE_REPOSITORY, "Elsewhere/website", "ElevenID/website/extra"])
@pytest.mark.parametrize("event", ["workflow_dispatch", "push"])
def test_website_intake_shell_rejects_unlisted_owner_before_any_tool(composer_workflow, workflow_shell, repository, event):
    result, calls = workflow_shell(composer_workflow[2], repository=repository,
                                  artifact_token="synthetic-website-token", event=event)
    assert result.returncode != 0
    assert "Unsupported website producer repository" in result.stderr
    assert calls == []


@pytest.mark.parametrize("event", ["workflow_dispatch", "push"])
def test_external_website_token_does_not_reach_application_backend_composer_or_signer(composer_workflow, workflow_shell, event):
    result, website_calls = workflow_shell(composer_workflow[2], repository=policy.STANDALONE_REPOSITORY,
                                         artifact_token="synthetic-website-token", event=event)
    assert result.returncode == 0, result.stderr
    assert website_calls[0]["env"] == {"GH_TOKEN": "synthetic-website-token"}
    result, calls = workflow_shell(composer_workflow[3], repository=policy.STANDALONE_REPOSITORY,
                                  artifact_token="synthetic-website-token", event=event)
    assert result.returncode == 0, result.stderr
    assert [call["program"] for call in calls] == ["python", "jq", "jq", "python", "python", "cosign", "cosign"]
    assert all(call["env"] == {"GH_TOKEN": "synthetic-job-token"} for call in calls)
    python_calls = [call["argv"] for call in calls if call["program"] == "python"]
    assert python_calls[0][:4] == ["scripts/web_release_intake.py", "application", "--repository", ui.REPOSITORY]
    run_id, attempt = ("125", "1") if event == "workflow_dispatch" else ("225", "4")
    assert python_calls[0][4:8] == ["--run-id", run_id, "--run-attempt", attempt]
    assert python_calls[1][:6] == ["scripts/web_release_intake.py", "backend", "--source-sha", "b" * 40, "--tag", "v1.2.3"]
    assert python_calls[2][0] == "scripts/package_web_composition.py"
    assert python_calls[2][python_calls[2].index("--producer-repository") + 1] == ui.REPOSITORY
    assert [call["argv"][-1] for call in calls if call["program"] == "cosign"] == [
        "web-composition/web-composition.json", "web-composition/web-composition.zip"]
