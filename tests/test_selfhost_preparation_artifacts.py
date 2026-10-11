"""A producer run ID cannot substitute another candidate's bundle."""

from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from check_selfhost_preparation_artifacts import verify  # noqa: E402

RUN_ID = "38108653408"
SOURCE_SHA = "a" * 40
REPOSITORY_ID = 1140864197


def inputs() -> tuple[dict, dict, dict]:
    run = {
        "id": int(RUN_ID), "repository": {"full_name": "ElevenID/marty-ui", "id": REPOSITORY_ID},
        "head_repository": {"full_name": "ElevenID/marty-ui", "id": REPOSITORY_ID},
        "path": ".github/workflows/cd.yml", "event": "workflow_dispatch",
        "head_branch": "main", "head_sha": SOURCE_SHA, "status": "completed",
        "conclusion": "success", "run_attempt": 1,
    }

    def artifact(name: str, artifact_id: int) -> dict:
        return {"total_count": 1, "artifacts": [{
            "id": artifact_id, "name": name, "expired": False,
            "digest": "sha256:" + "b" * 64,
            "workflow_run": {"id": int(RUN_ID), "repository_id": REPOSITORY_ID,
                             "head_repository_id": REPOSITORY_ID,
                             "head_branch": "main", "head_sha": SOURCE_SHA},
        }]}

    return (run, artifact(f"selfhost-lock-preparation-unqualified-{RUN_ID}", 1),
            artifact(f"stack-release-qualified-{RUN_ID}", 2))


def test_accepts_exact_successful_first_attempt() -> None:
    result = verify(*inputs(), RUN_ID, SOURCE_SHA)
    assert result["schema"] == "marty.selfhost-preparation-artifact-binding/v1"
    assert result["bundle"]["id"] == 1
    assert result["transaction"]["id"] == 2


@pytest.mark.parametrize("path,value", [
    ((0, "id"), 1), ((0, "event"), "pull_request"),
    ((0, "path"), ".github/workflows/ci.yml"),
    ((0, "head_branch"), "feature"), ((0, "head_sha"), "c" * 40),
    ((0, "run_attempt"), 2), ((0, "status"), "in_progress"),
    ((0, "conclusion"), "failure"),
    ((1, "total_count"), 2), ((1, "artifacts"), []),
])
def test_rejects_wrong_producer_or_ambiguous_artifact(path, value) -> None:
    data = list(copy.deepcopy(inputs()))
    data[path[0]][path[1]] = value
    with pytest.raises(ValueError):
        verify(*data, RUN_ID, SOURCE_SHA)


@pytest.mark.parametrize("key,value", [
    ("name", "selfhost-lock-preparation-unqualified-1"),
    ("expired", True), ("digest", "sha256:" + "0" * 63),
    ("workflow_run", {"id": 1}),
])
def test_rejects_replaced_or_stale_bundle(key, value) -> None:
    data = list(copy.deepcopy(inputs()))
    data[1]["artifacts"][0][key] = value
    with pytest.raises(ValueError):
        verify(*data, RUN_ID, SOURCE_SHA)


def test_rejects_artifact_from_different_source_or_repository() -> None:
    for field, value in (("head_sha", "f" * 40), ("repository_id", 1),
                         ("head_repository_id", 2)):
        data = list(copy.deepcopy(inputs()))
        data[2]["artifacts"][0]["workflow_run"][field] = value
        with pytest.raises(ValueError):
            verify(*data, RUN_ID, SOURCE_SHA)


def test_downstream_workflow_is_separate_unqualified_and_cannot_publish() -> None:
    document = yaml.safe_load(
        (ROOT / ".github/workflows/selfhost-prepared-consumer.yml").read_text(encoding="utf-8")
    )
    trigger = document.get("on", document.get(True))
    assert set(trigger) == {"workflow_run"}
    assert trigger["workflow_run"] == {
        "workflows": ["Stack release"],
        "types": ["completed"],
    }
    assert document["permissions"] == {"contents": "read"}
    assert "cache-mode" not in document  # workflow_run defaults to read-only cache access
    assert set(document["jobs"]) == {"installed-migrations"}
    job = document["jobs"]["installed-migrations"]
    assert "workflow_run.conclusion == 'success'" in job["if"]
    assert "workflow_run.event == 'workflow_dispatch'" in job["if"]
    assert "workflow_run.head_branch == 'main'" in job["if"]
    assert job["runs-on"] == "ubuntu-24.04"
    assert job["permissions"] == {"actions": "read", "contents": "read"}
    assert job["steps"][0]["id"] == "select"
    assert "artifacts?name=$bundle_name" in job["steps"][0]["run"]
    assert ".total_count == 0" in job["steps"][0]["run"]
    assert all(
        step.get("if") == "steps.select.outputs.present == 'true'"
        for step in job["steps"][1:]
    )
    source = "\n".join(step.get("run", "") for step in job["steps"])
    assert "check_selfhost_preparation_artifacts.py" in source
    assert "run_attempt" not in source  # enforced by the tested checker
    assert "check_prepared_selfhost_consumer.py" in source
    assert source.index("--verify-archive-only") < source.index("unzip -q")
    assert "probe_selfhost_installed_signing_keys.py" in source
    assert "probe_selfhost_installed_migrations.py" not in source
    assert '"marty.selfhost-signing-runtime-probe/v1"' in source
    assert ".runtime.public_jwk_count >= 2" in source
    assert ".runtime.unknown_organization_keys == 0" in source
    assert "selfhost-installed-signing-unqualified-" in str(job)
    assert "publish-manifest" not in str(job)
    assert "cosign sign" not in source
