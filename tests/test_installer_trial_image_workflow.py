"""Keep PR-built capacity images outside the signed installer release path."""

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def test_engineering_image_is_exact_head_nonpublishing_and_unqualified() -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    )
    job = workflow["jobs"]["installer-trial-image"]
    guard = job["if"]
    assert "github.event_name == 'pull_request'" in guard
    assert "github.event.pull_request.head.repo.full_name == github.repository" in guard
    assert "github.event.pull_request.head.ref == 'feat/github-installer-release'" in guard
    assert job["permissions"] == {"contents": "read"}

    steps = job["steps"]
    checkout = next(step for step in steps if step.get("name") == "Check out the exact PR head")
    assert checkout["with"] == {
        "ref": "${{ github.event.pull_request.head.sha }}",
        "persist-credentials": False,
    }
    source = next(step for step in steps if step.get("name") == "Bind this disposable build to its source")
    assert 'test "$(git rev-parse HEAD)" = "$EXPECTED_SHA"' in source["run"]

    build = next(step for step in steps if step.get("name", "").startswith("Build exact-head gateway image"))
    config = build["with"]
    assert config["file"] == "services/Dockerfile"
    assert config["push"] is False
    assert config["platforms"] == "linux/amd64"
    assert "SERVICE_NAME=gateway" in config["build-args"]
    assert "MARTY_UI_SHA=${{ github.event.pull_request.head.sha }}" in config["build-args"]
    assert config["outputs"].startswith("type=oci,dest=")
    assert config["provenance"] is False
    assert config["sbom"] is False

    identity = next(step for step in steps if step.get("name") == "Record archive identity without claiming release provenance")
    assert "hashlib.file_digest" in identity["run"]
    assert "'qualified': False" in identity["run"]
    upload = next(step for step in steps if step.get("name") == "Upload short-lived engineering image")
    assert upload["with"]["retention-days"] == 3
    assert upload["with"]["compression-level"] == 0
