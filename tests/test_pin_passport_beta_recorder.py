"""The scanner must run at the recorder revision bound to the beta deployment."""

import hashlib
import json

import pytest

from scripts.pin_passport_beta_recorder import recorder_commit


UI = "a" * 40
RECORDER = "b" * 40


def write(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")


def fixture(tmp_path):
    source = {
        "source_kind": "official-stack-release", "marty_ui_sha": UI,
        "component_revisions": [{
            "component": "marty-demo-recorder",
            "repository": "https://github.com/ElevenID/marty-demo-recorder",
            "revision": RECORDER,
        }],
        "repositories": {"marty-demo-recorder": {
            "repository": "https://github.com/ElevenID/marty-demo-recorder",
            "revision": RECORDER, "source": "explicit-recorder-revision",
        }},
    }
    demo = {
        "demo_application_revision": UI,
        "recorder_revision": {"kind": "git", "value": RECORDER},
        "release_evidence": {"source_marker": UI},
    }
    write(tmp_path / "source-manifest.json", source)
    write(tmp_path / "deployed-demo-manifest.json", demo)
    deployment = {
        "source_kind": "official-stack-release", "marty_ui_sha": UI,
        "source_manifest": "source-manifest.json",
        "deployed_demo_manifest": "deployed-demo-manifest.json",
        "deployed_demo_manifest_sha256": hashlib.sha256(
            (tmp_path / "deployed-demo-manifest.json").read_bytes()).hexdigest(),
        "component_revisions": {"marty-demo-recorder": RECORDER},
    }
    write(tmp_path / "local-deployment-manifest.json", deployment)
    return source, deployment, demo


def test_recorder_pin_requires_consistent_deployed_manifests(tmp_path):
    fixture(tmp_path)
    assert recorder_commit(tmp_path, UI) == RECORDER
    with pytest.raises(ValueError, match="governed beta deployment"):
        recorder_commit(tmp_path, "c" * 40)


def test_recorder_pin_rejects_revision_drift_and_duplicate(tmp_path):
    source, deployment, _ = fixture(tmp_path)
    deployment["component_revisions"]["marty-demo-recorder"] = "c" * 40
    write(tmp_path / "local-deployment-manifest.json", deployment)
    with pytest.raises(ValueError, match="governed beta deployment"):
        recorder_commit(tmp_path, UI)
    deployment["component_revisions"]["marty-demo-recorder"] = RECORDER
    write(tmp_path / "local-deployment-manifest.json", deployment)
    source["component_revisions"].append({
        "component": "marty-demo-recorder", "repository": "invalid", "revision": RECORDER,
    })
    write(tmp_path / "source-manifest.json", source)
    with pytest.raises(ValueError, match="ambiguous"):
        recorder_commit(tmp_path, UI)
