"""Release-marker evidence uses the production portability contract."""
import copy
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import complete_local_beta_startup as startup
from scripts.check_canvas_oss_portability import ContractError, validate_runtime_binding
from tests.test_check_canvas_oss_portability import runtime_binding_fixture


def current(role, image, source_id, release, index):
    return {"Id": str(index) * 64, "Name": f"/elevenid-beta-{role}-1", "Image": image,
            "Config": {"Image": image, "Labels": {"com.docker.compose.project": "elevenid-beta",
                "com.docker.compose.service": role}, "Env": [f"MARTY_UI_SHA={source_id}",
                f"MARTY_RELEASE_VERSION={release}", "BAO_TOKEN=never-project-this"]},
            "State": {"Status": "running", "Running": True, "StartedAt": "fixed-start",
                      "Health": {"Status": "healthy"}}}


def test_shared_writer_satisfies_actual_portability_validator(tmp_path):
    deployment, context_path, source_id = runtime_binding_fixture(tmp_path)
    manifest = json.loads(deployment.read_text())
    context = json.loads(context_path.read_text())
    image = "sha256:" + "4" * 64
    manifest["compose_project"] = "elevenid-beta"
    manifest["images"] = [startup.record(role, current(role, image, source_id,
        context["release_version"], index)) for index, role in enumerate(
            ("gateway", "issuance", "canvas-sync-worker"), 1)]
    context["service_image_digests"] = {row["service"]: image for row in manifest["images"]}
    manifest["services_marker"]["image_digests"] = context["service_image_digests"]
    context_path.write_text(json.dumps(context))
    prior = copy.deepcopy(manifest)
    for row in prior["images"]:
        row.pop("runtime_marker_environment")
    deployment.write_text(json.dumps(prior))
    with pytest.raises(ContractError, match="runtime source or release differs"):
        validate_runtime_binding(deployment, context_path, source_id)
    deployment.write_text(json.dumps(manifest))
    validate_runtime_binding(deployment, context_path, source_id)
    assert "never-project-this" not in json.dumps(manifest)


def test_marker_projection_whitelist_and_duplicate_rejection():
    observed = current("gateway", "image", "source", "release", 1)
    assert startup.marker_environment(observed) == {"MARTY_UI_SHA": "source", "MARTY_RELEASE_VERSION": "release"}
    observed["Config"]["Env"].append("MARTY_UI_SHA=other")
    with pytest.raises(RuntimeError, match="Duplicate runtime marker"):
        startup.marker_environment(observed)


def refresh_fixture(tmp_path, monkeypatch):
    root = tmp_path / "ui"
    artifacts = root / "tests/artifacts/local"
    artifacts.mkdir(parents=True)
    (root / "VERSION").write_text("stack")
    source = {"marty_ui_sha": "c" * 40, "release_version": "local", "component_revisions": [
        {"component": "marty-ui", "revision": "d" * 40}]}
    images = {"gateway": "sha256:" + "4" * 64}
    observed = current("gateway", images["gateway"], source["marty_ui_sha"], "local", 1)
    original = {"marty_ui_sha": source["marty_ui_sha"], "release_version": "local",
        "component_revisions": {"marty-ui": "d" * 40}, "images": [startup.record("gateway", observed)]}
    original["images"][0].pop("runtime_marker_environment")
    for name, value in (("source-manifest.json", source), ("image-digests.json", images),
                        ("local-deployment-manifest.json", original)):
        (artifacts / name).write_text(json.dumps(value))
    proof = tmp_path / "proof.json"
    proof.write_text(json.dumps({"scope": "LOCAL_BETA_FORWARD_STARTUP", "applied": True,
        "betaDeployed": True, "apiAndUiBindingsVerified": True, "nativeIssuanceProbes": "PASS",
        "deploymentManifest": str(artifacts / "local-deployment-manifest.json"),
        "deploymentManifestSha256": startup.sha(artifacts / "local-deployment-manifest.json"),
        "sourceManifestSha256": startup.sha(artifacts / "source-manifest.json"),
        "sourceId": source["marty_ui_sha"], "sourceRevision": "d" * 40, "release": "local"}))
    monkeypatch.setattr(startup, "observe", lambda role, image: observed)
    calls = []
    monkeypatch.setattr(startup.subprocess, "run", lambda args, **kw: calls.append(args))
    return root, artifacts, proof, observed, original, calls


@pytest.mark.parametrize("changed", [None, "container", "marker", "proof"])
def test_refresh_preserves_originals_and_rejects_stale_evidence(tmp_path, monkeypatch, changed):
    root, artifacts, proof, observed, original, calls = refresh_fixture(tmp_path, monkeypatch)
    before = {path: path.read_bytes() for path in artifacts.iterdir()}
    before[proof] = proof.read_bytes()
    proof_hash = startup.sha(proof)
    if changed == "container":
        observed["Id"] = "9" * 64
    elif changed == "marker":
        observed["Config"]["Env"][0] = "MARTY_UI_SHA=wrong"
    elif changed == "proof":
        proof_hash = "0" * 64
    if changed:
        with pytest.raises(RuntimeError):
            startup.refresh_runtime_evidence(root, artifacts, proof, proof_hash)
    else:
        manifest, receipt = startup.refresh_runtime_evidence(root, artifacts, proof, proof_hash)
        expected = copy.deepcopy(original)
        expected["images"][0]["runtime_marker_environment"] = startup.marker_environment(observed)
        assert manifest == expected
        assert receipt["betaMutationPerformed"] is False
        assert receipt["startupReplayed"] is False
        assert receipt["productionDemoQualified"] is False
        assert len(calls) == 1 and "--verify-manifest" in calls[0]
    assert all(path.read_bytes() == value for path, value in before.items())

