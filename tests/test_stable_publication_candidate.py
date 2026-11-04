"""Data-only v2 candidate admission; synthetic signatures are never accepted."""
import copy
import io
import json
import sys
import zipfile
from datetime import timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import stable_publication_candidate as candidate
import stable_publication_checkpoint as checkpoint
import test_stable_publication_checkpoint as fixtures


@pytest.fixture
def sealed():
    fixture = fixtures.CheckpointTests()
    fixture.setUp()
    fixture.prepare()
    admission = {"operator_run_id": 991, "operator_run_attempt": 1, "result_artifact_id": 992,
                 "result_artifact_sha256": "sha256:" + "d" * 64, "result_sha256": "sha256:" + "e" * 64,
                 "tag_object_sha": "f" * 40}
    path = fixture.base / "admission.json"
    path.write_bytes(candidate.h.encoded(admission))
    output = fixture.base / "candidate"
    manifest = candidate.seal(fixture.output, path, output, environment=fixture.environment,
                              now=fixtures.NOW + timedelta(seconds=5))
    try:
        yield fixture, output, manifest, path
    finally:
        fixture.doCleanups()


def test_v2_preserves_exact_signed_bytes_without_extending_legacy_authority(sealed):
    fixture, output, manifest, _ = sealed
    later = fixtures.NOW + timedelta(hours=1)
    result, request, _ = candidate.load_candidate(output, now=later)
    assert result == manifest
    assert request == fixture.request()
    for name in checkpoint.ASSET_NAMES:
        assert (output / "checkpoint/assets" / name).read_bytes() == (fixture.assets / name).read_bytes()
    with pytest.raises(ValueError, match="expired"):
        checkpoint.load_checkpoint(fixture.output, now=later)


def test_v2_creation_still_requires_original_active_checkpoint_and_first_attempt(sealed):
    fixture, _, _, path = sealed
    with pytest.raises(ValueError, match="expired"):
        candidate.seal(fixture.output, path, fixture.base / "late", environment=fixture.environment,
                       now=fixtures.NOW + timedelta(minutes=16))
    with pytest.raises(ValueError, match="first-attempt"):
        candidate.seal(fixture.output, path, fixture.base / "rerun",
                       environment={**fixture.environment, "GITHUB_RUN_ATTEMPT": "2"}, now=fixtures.NOW)


@pytest.mark.parametrize("field,value", [("schema", checkpoint.SCHEMA), ("run_attempt", True),
    ("run_attempt", 2), ("run_id", True), ("repository", "foreign/repo"),
    ("producer_workflow", candidate.PUBLISHER_WORKFLOW), ("source_sha", "main"),
    ("tag", "v1.2.3/foreign"), ("unexpected", "value")])
def test_closed_candidate_identity(sealed, field, value):
    _, _, manifest, _ = sealed
    changed = copy.deepcopy(manifest); changed[field] = value
    changed["candidate_id"] = candidate.candidate_identity(changed)
    with pytest.raises(ValueError):
        candidate.validate_manifest(changed, now=fixtures.NOW + timedelta(seconds=5))


def test_candidate_expiry_is_fixed_and_future_creation_is_rejected(sealed):
    _, _, manifest, _ = sealed
    for clock in (fixtures.NOW, fixtures.NOW + timedelta(days=1, seconds=5)):
        with pytest.raises(ValueError):
            candidate.validate_manifest(manifest, now=clock)
    changed = copy.deepcopy(manifest); changed["not_after"] = "2026-11-06T01:02:08Z"
    changed["candidate_id"] = candidate.candidate_identity(changed)
    with pytest.raises(ValueError):
        candidate.validate_manifest(changed, now=fixtures.NOW + timedelta(seconds=5))


@pytest.mark.parametrize("operation", ["asset", "request", "gate", "extra", "symlink", "hardlink"])
def test_candidate_files_fail_closed(sealed, operation):
    _, output, _, _ = sealed
    path = output / "checkpoint/assets/marty-ui-sbom.cdx.json"
    if operation == "asset":
        path.write_bytes(b"changed signed bytes")
    elif operation == "request":
        (output / "checkpoint/request.json").write_bytes(b"{}")
    elif operation == "gate":
        (output / "checkpoint/official-interoperability.json").write_bytes(b"{}")
    elif operation == "extra":
        (output / "extra").write_text("foreign")
    elif operation == "symlink":
        path.unlink(); path.symlink_to(output / "candidate.json")
    else:
        import os
        os.link(path, output.parent / "linked")
    with pytest.raises((ValueError, OSError)):
        candidate.load_candidate(output, now=fixtures.NOW + timedelta(seconds=5))


def test_existing_candidate_cannot_be_reopened_to_refresh_lifetime(sealed):
    fixture, output, manifest, path = sealed
    with pytest.raises((ValueError, OSError)):
        candidate.seal(fixture.output, path, output, environment=fixture.environment,
                       now=fixtures.NOW + timedelta(seconds=20))
    assert candidate.load_candidate(output, now=fixtures.NOW + timedelta(seconds=20))[0] == manifest


class API(candidate.h.GitHub):
    def __init__(self, directory, manifest):
        super().__init__()
        self.run_value = {"id": fixtures.RUN, "path": candidate.h.CD_WORKFLOW,
            "event": "workflow_dispatch", "head_branch": "main", "head_sha": fixtures.SOURCE,
            "run_attempt": 1, "repository": {"id": candidate.h.REPOSITORY_ID, "full_name": candidate.h.REPOSITORY},
            "status": "completed", "conclusion": "success"}
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            for path in directory.rglob("*"):
                if path.is_file():
                    archive.writestr(str(path.relative_to(directory)), path.read_bytes())
        self.archive = stream.getvalue()
        self.items = [{"id": 123, "name": candidate.artifact_name(fixtures.RUN, fixtures.TAG), "expired": False,
                       "digest": candidate.h.sha256(self.archive), "size_in_bytes": len(self.archive),
                       "workflow_run": {"id": fixtures.RUN, "head_sha": fixtures.SOURCE, "head_branch": "main", "run_attempt": 1}}]

    def json(self, path, **kwargs):
        assert path == f"repos/{candidate.h.REPOSITORY}/actions/runs/{fixtures.RUN}"
        return copy.deepcopy(self.run_value)

    def artifacts(self, run_id):
        assert run_id == fixtures.RUN
        return copy.deepcopy(self.items)

    def download(self, artifact, path):
        path.write_bytes(self.archive)


def test_fetch_binds_original_successful_cd_and_exact_artifact(sealed):
    fixture, output, manifest, _ = sealed
    api = API(output, manifest)
    actual, request, _, artifact = candidate.fetch(api, fixtures.RUN, fixture.base / "download",
                                                 now=fixtures.NOW + timedelta(hours=1))
    assert actual == manifest and request == fixture.request() and artifact["id"] == 123


@pytest.mark.parametrize("key,value", [("conclusion", "failure"), ("status", "in_progress"),
    ("run_attempt", 2), ("run_attempt", True), ("path", candidate.PUBLISHER_WORKFLOW),
    ("event", "pull_request"), ("head_branch", "foreign")])
def test_failed_rerun_or_foreign_original_producer_is_refused(sealed, key, value):
    fixture, output, manifest, _ = sealed
    api = API(output, manifest); api.run_value[key] = value
    with pytest.raises(ValueError):
        candidate.fetch(api, fixtures.RUN, fixture.base / "download", now=fixtures.NOW + timedelta(seconds=5))


def test_only_automatic_legacy_completion_may_skip_absent_candidate(sealed):
    _, output, manifest, _ = sealed
    api = API(output, manifest); api.items = []
    assert candidate.find_artifact(api, fixtures.RUN, allow_absent=True) is None
    with pytest.raises(ValueError):
        candidate.find_artifact(api, fixtures.RUN)
    api = API(output, manifest); api.items *= 2
    with pytest.raises(ValueError):
        candidate.find_artifact(api, fixtures.RUN, allow_absent=True)


def test_reindexed_signed_asset_cannot_evade_original_checkpoint_semantics(sealed):
    _, output, manifest, _ = sealed
    path = output / "checkpoint/assets/install.sh"
    path.write_bytes(b"foreign installer")
    changed = copy.deepcopy(manifest)
    changed["files"]["checkpoint/assets/install.sh"] = {"size": path.stat().st_size, "sha256": candidate.h.file_digest(path)}
    changed["candidate_id"] = candidate.candidate_identity(changed)
    (output / "candidate.json").write_bytes(candidate.h.encoded(changed))
    with pytest.raises(ValueError):
        candidate.load_candidate(output, now=fixtures.NOW + timedelta(seconds=5))
