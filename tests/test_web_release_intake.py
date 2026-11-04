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
    result = intake.fetch("website", repository=producer["repository"], run_id=producer["run_id"],
                          attempt=producer["run_attempt"], destination=tmp_path / "intake", gh=kwargs["gh"],
                          cosign=kwargs["cosign"], runner=api, downloader=download)
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
