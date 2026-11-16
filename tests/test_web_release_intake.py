"""Only exact successful release attempts may supply inert, signed receipts."""
from __future__ import annotations

import copy
import io
import json
from pathlib import Path
import stat
import zipfile

import pytest

from tests.test_package_web_composition import candidate
import package_web_composition as composition
import ui_release as ui
import web_release_intake as intake
import website_release as web


@pytest.fixture
def producer_artifact(candidate, tmp_path):
    kwargs, calls, _, _ = candidate
    release = web.read(kwargs["website_assets"] / "website-release.json")
    producer = release["producer"]
    run = {"id": int(producer["run_id"]), "run_attempt": int(producer["run_attempt"]), "status": "completed",
           "conclusion": "success", "event": "workflow_dispatch", "head_branch": "main", "head_sha": producer["source_sha"],
           "path": producer["workflow"] + "@main", "repository": {"full_name": producer["repository"],
           "id": int(web.REPOSITORIES[producer["repository"]])}}
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
