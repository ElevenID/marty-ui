"""Security boundaries for hosted independent-product report intake."""

import importlib.util
import io
import json
import sys
import tarfile
from pathlib import Path
from unittest import mock

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location(
    "authenticate_product_verification",
    ROOT / "scripts/authenticate_product_verification.py",
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def run(workflow=MODULE.VERIFIER_WORKFLOW):
    return {
        "id": 4001,
        "repository": {"full_name": MODULE.REPO},
        "path": workflow,
        "head_branch": "main",
        "event": "workflow_dispatch",
        "status": "completed",
        "conclusion": "success",
        "run_attempt": 1,
        "head_sha": "a" * 40,
    }


def artifact():
    return {
        "id": 55,
        "name": "expected",
        "expired": False,
        "digest": "sha256:" + "b" * 64,
        "workflow_run": {
            "id": 4001,
            "head_sha": "a" * 40,
            "head_branch": "main",
        },
    }


def test_run_rejects_successful_foreign_or_non_main_workflow():
    with mock.patch.object(MODULE, "api", return_value=run()):
        assert MODULE.exact_run("4001", MODULE.VERIFIER_WORKFLOW)["id"] == 4001
    for change in (
        {"head_branch": "feature"},
        {"path": MODULE.PRODUCER_WORKFLOW},
        {"repository": {"full_name": "someone/else"}},
        {"conclusion": "failure"},
    ):
        with mock.patch.object(MODULE, "api", return_value={**run(), **change}):
            with pytest.raises(ValueError):
                MODULE.exact_run("4001", MODULE.VERIFIER_WORKFLOW)


def test_artifact_requires_same_run_source_and_exact_name():
    with mock.patch.object(MODULE, "api", return_value={"artifacts": [artifact()]}):
        assert MODULE.exact_artifact(run(), "expected")["id"] == 55
        with pytest.raises(ValueError):
            MODULE.exact_artifact(run(), "other")
    changed = artifact()
    changed["workflow_run"]["head_sha"] = "c" * 40
    with mock.patch.object(MODULE, "api", return_value={"artifacts": [changed]}):
        with pytest.raises(ValueError):
            MODULE.exact_artifact(run(), "expected")


def test_signed_subject_rejects_different_verifier_invocation(tmp_path):
    path = tmp_path / "verification.json"
    path.write_bytes(b"exact report\n")
    digest = MODULE.hashlib.sha256(path.read_bytes()).hexdigest()
    certificate = {
        "runInvocationURI": "https://github.com/ElevenID/marty-ui/actions/runs/4001/attempts/1",
        "subjectAlternativeName": (
            "https://github.com/ElevenID/marty-ui/"
            ".github/workflows/product-verification.yml@refs/heads/main"
        ),
        "githubWorkflowSHA": "a" * 40,
        "githubWorkflowRepository": MODULE.REPO,
        "githubWorkflowRef": "refs/heads/main",
        "runnerEnvironment": "github-hosted",
    }
    item = {
        "verificationResult": {
            "signature": {"certificate": certificate},
            "statement": {
                "subject": [{"name": path.name, "digest": {"sha256": digest}}]
            },
        }
    }
    with mock.patch.object(MODULE, "gh", return_value=json.dumps([item]).encode()):
        assert MODULE.signed_subject(path, run()) == "sha256:" + digest
        wrong_run = {**run(), "id": 4002}
        with pytest.raises(ValueError):
            MODULE.signed_subject(path, wrong_run)
        path.write_bytes(b"tampered report\n")
        with pytest.raises(ValueError):
            MODULE.signed_subject(path, run())


def test_archive_manifest_read_does_not_extract_other_entries(tmp_path):
    archive = tmp_path / "candidate.tar.gz"
    with tarfile.open(archive, "w:gz") as target:
        manifest = b'{"product":"marty-server"}'
        entry = tarfile.TarInfo("product-package.json")
        entry.size = len(manifest)
        target.addfile(entry, io.BytesIO(manifest))
        other = tarfile.TarInfo("../../escape")
        other.size = 5
        target.addfile(other, io.BytesIO(b"never"))
    result = MODULE.package_from_archive(archive, tmp_path / "manifest.json")
    assert result.read_bytes() == manifest
    assert not (tmp_path.parent / "escape").exists()
