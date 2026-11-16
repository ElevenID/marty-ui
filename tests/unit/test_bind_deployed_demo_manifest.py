from __future__ import annotations

import copy
import json
import sys

import pytest

from scripts.bind_deployed_demo_manifest import bind_manifest, main
from scripts.create_demo_manifest_draft import build_manifest
from scripts.validate_demo_manifests import validate_manifest


COMPONENTS = {
    "marty-ui": "a" * 40,
    "marty-demo-recorder": "b" * 40,
    "marty-verifier": "c" * 40,
}


def source_manifest() -> dict[str, object]:
    return {
        "release_version": "mip-0.5.0-local-test",
        "mip_version": "0.5.0",
        "marty_ui_sha": "d" * 40,
        "repositories": {
            name: {"head_sha": revision} for name, revision in COMPONENTS.items()
        },
        "component_revisions": [
            {
                "component": name,
                "repository": f"https://github.com/ElevenID/{name}",
                "revision": revision,
            }
            for name, revision in COMPONENTS.items()
        ],
    }


def test_binds_pending_template_to_exact_deployment_without_claiming_recording() -> (
    None
):
    bound = bind_manifest(
        build_manifest(),
        source_manifest(),
        {"gateway": f"sha256:{'1' * 64}", "ui-prod": f"sha256:{'2' * 64}"},
    )

    validate_manifest(bound)
    assert bound["binding_state"] == "DEPLOYED_PENDING_EVIDENCE"
    assert bound["deployment_release_marker"] == "mip-0.5.0-local-test"
    assert bound["release_evidence"] == {
        "environment": "beta",
        "recorded_at": None,
        "displayed_offers_invalidated_at": None,
        "source_marker": "d" * 40,
        "artifacts": [],
    }
    assert bound["recorder_revision"] == {"kind": "git", "value": "b" * 40}
    assert bound["demo_application_revision"] == "a" * 40
    assert [entry["component"] for entry in bound["component_revisions"]] == sorted(
        COMPONENTS
    )
    assert [entry["component"] for entry in bound["image_digests"]] == [
        "gateway",
        "ui-prod",
    ]


def test_rejects_incomplete_component_set_and_invalid_image_digest() -> None:
    source = source_manifest()
    source["component_revisions"] = copy.deepcopy(source["component_revisions"][:-1])
    with pytest.raises(RuntimeError, match="exact repository set"):
        bind_manifest(build_manifest(), source, {"gateway": f"sha256:{'1' * 64}"})

    with pytest.raises(RuntimeError, match="image digest is invalid"):
        bind_manifest(build_manifest(), source_manifest(), {"gateway": "latest"})


def test_cli_fails_cleanly_when_bound_manifest_validation_fails(
    tmp_path, monkeypatch, capsys
) -> None:
    template_path = tmp_path / "template.json"
    source_path = tmp_path / "source.json"
    output_path = tmp_path / "bound.json"
    source = source_manifest()
    next(
        entry
        for entry in source["component_revisions"]
        if entry["component"] == "marty-demo-recorder"
    )["revision"] = "invalid"
    template_path.write_text(json.dumps(build_manifest()), encoding="utf-8")
    source_path.write_text(json.dumps(source), encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "bind_deployed_demo_manifest.py",
            "--template",
            str(template_path),
            "--source-manifest",
            str(source_path),
            "--image-digests-json",
            json.dumps({"gateway": f"sha256:{'1' * 64}"}),
            "--output",
            str(output_path),
        ],
    )

    assert main() == 1
    assert not output_path.exists()
    assert "Demo deployment binding failed" in capsys.readouterr().out


def test_cli_reads_image_digests_from_utf8_bom_file(tmp_path, monkeypatch) -> None:
    template_path = tmp_path / "template.json"
    source_path = tmp_path / "source.json"
    image_digests_path = tmp_path / "image-digests.json"
    output_path = tmp_path / "bound.json"
    template_path.write_text(json.dumps(build_manifest()), encoding="utf-8")
    source_path.write_text(json.dumps(source_manifest()), encoding="utf-8")
    image_digests_path.write_text(
        json.dumps({"gateway": f"sha256:{'1' * 64}"}),
        encoding="utf-8-sig",
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "bind_deployed_demo_manifest.py",
            "--template",
            str(template_path),
            "--source-manifest",
            str(source_path),
            "--image-digests-file",
            str(image_digests_path),
            "--output",
            str(output_path),
        ],
    )

    assert main() == 0
    assert json.loads(output_path.read_text(encoding="utf-8"))["binding_state"] == (
        "DEPLOYED_PENDING_EVIDENCE"
    )


def nightly_source_manifest() -> dict[str, object]:
    source = source_manifest()
    source.update(
        source_kind="signed-nightly-deployment",
        scope="FUNCTIONAL_ONLY",
        promotion_eligible=False,
        release_ready=False,
        capture_recorder_revision="b" * 40,
        marty_ui_sha="a" * 40,
    )
    source["component_revisions"] = [
        r
        for r in source["component_revisions"]
        if r["component"] != "marty-demo-recorder"
    ]
    del source["repositories"]["marty-demo-recorder"]
    return source


def test_signed_nightly_binds_capture_without_claiming_deployed_recorder() -> None:
    source = nightly_source_manifest()
    bound = bind_manifest(build_manifest(), source, {"gateway": "sha256:" + "1" * 64})
    validate_manifest(bound)
    assert bound["recorder_revision"]["value"] == source["capture_recorder_revision"]
    assert "marty-demo-recorder" not in {
        r["component"] for r in bound["component_revisions"]
    }
    assert bound["demo_application_revision"] == source["marty_ui_sha"]
    assert not bound["release_ready"] and not bound["public_demo_ready"]
    assert bound["release_evidence"]["recorded_at"] is None


@pytest.mark.parametrize("mutation", ["missing", "deployed", "qualified", "source"])
def test_signed_nightly_refuses_unbound_capture_or_deployment_claims(
    mutation: str,
) -> None:
    source = nightly_source_manifest()
    if mutation == "missing":
        del source["capture_recorder_revision"]
    elif mutation == "deployed":
        source["component_revisions"].append(
            dict(component="marty-demo-recorder", revision="b" * 40)
        )
        source["repositories"]["marty-demo-recorder"] = {}
    elif mutation == "qualified":
        source["release_ready"] = True
    else:
        source["marty_ui_sha"] = "d" * 40
    with pytest.raises(RuntimeError):
        bind_manifest(build_manifest(), source, {"gateway": "sha256:" + "1" * 64})
