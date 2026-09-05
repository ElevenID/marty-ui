from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from scripts.prepare_official_beta_release import OfficialReleaseError, prepare_release


UI_SHA = "1" * 40
RECORDER_SHA = "2" * 40
UI_DIGEST = "sha256:" + "a" * 64
SERVICES_DIGEST = "sha256:" + "b" * 64
MIGRATIONS_DIGEST = "sha256:" + "c" * 64
ISSUANCE_DIGEST = "sha256:" + "d" * 64


def _artifact(kind: str, uri: str, digest: str = UI_DIGEST) -> dict[str, str]:
    return {"type": kind, "uri": uri, "digest": digest}


def _component(
    name: str,
    repository: str,
    artifacts: list[dict[str, str]],
    commit: str = "3" * 40,
    version: str = "1",
) -> dict:
    return {
        "name": name,
        "repository": repository,
        "version": version,
        "commit": commit,
        "artifacts": artifacts,
    }


def _manifest() -> dict:
    wheel = _artifact(
        "python",
        "https://github.com/ElevenID/component/releases/download/v1/component.whl",
    )
    package = _artifact(
        "npm",
        "https://github.com/ElevenID/component/releases/download/v1/component.tgz",
    )
    return {
        "schema": "marty.stack/v1",
        "release": "marty-ui@1.1.205",
        "generated_at": "2026-08-30T00:00:00+00:00",
        "components": [
            _component("marty-api-core", "ElevenID/marty-cli", [package]),
            _component("marty-cli", "ElevenID/marty-cli", [package]),
            _component("marty-blog", "ElevenID/marty-blog", [package]),
            _component("marty-core-python", "ElevenID/marty-core", [wheel]),
            _component("marty-verification-python", "ElevenID/marty-core", [wheel]),
            _component("marty-iso18013-python", "ElevenID/marty-core", [wheel]),
            _component("marty-common", "ElevenID/Marty", [wheel]),
            _component(
                "marty-credentials-issuance",
                "ElevenID/marty-credentials",
                [
                    _artifact(
                        "oci",
                        "ghcr.io/elevenid/marty-credentials-issuance",
                        ISSUANCE_DIGEST,
                    )
                ],
            ),
            _component(
                "marty-integration-tests",
                "ElevenID/marty-integration-tests",
                [_artifact("release", "https://example.test/tests.tar.gz")],
            ),
            _component(
                "marty-ui",
                "ElevenID/marty-ui",
                [
                    _artifact("oci", "ghcr.io/elevenid/marty-ui-oss/ui", UI_DIGEST),
                    _artifact(
                        "oci", "ghcr.io/elevenid/marty-ui-oss/services", SERVICES_DIGEST
                    ),
                    _artifact(
                        "oci",
                        "ghcr.io/elevenid/marty-ui-oss/migrations",
                        MIGRATIONS_DIGEST,
                    ),
                ],
                UI_SHA,
                "1.1.205",
            ),
        ],
    }


def _write_release(tmp_path: Path, manifest: dict) -> tuple[Path, Path]:
    manifest_path = tmp_path / "stack-manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    checksums = tmp_path / "SHA256SUMS"
    checksums.write_text(
        f"{digest}  stack-manifest.json\n{'b' * 64}  ./stack-manifest.json.sigstore.json\n",
        encoding="utf-8",
    )
    return manifest_path, checksums


def test_prepares_digest_only_official_beta_inputs(tmp_path: Path) -> None:
    manifest_path, checksums = _write_release(tmp_path, _manifest())
    plan = prepare_release(
        manifest_path,
        checksums,
        recorder_revision=RECORDER_SHA,
        expected_ui_revision=UI_SHA,
    )

    assert plan["release_version"] == "1.1.205"
    assert plan["images"]["services"]["reference"].endswith("@" + SERVICES_DIGEST)
    assert plan["source_manifest"]["source_kind"] == "official-stack-release"
    assert plan["source_manifest"]["promotion_eligible"] is True
    revisions = {
        entry["component"]: entry
        for entry in plan["source_manifest"]["component_revisions"]
    }
    assert revisions["marty-ui"]["revision"] == UI_SHA
    assert revisions["marty-demo-recorder"]["revision"] == RECORDER_SHA
    assert set(revisions) == set(plan["source_manifest"]["repositories"])
    repositories = plan["source_manifest"]["repositories"]
    assert repositories["marty-demo-recorder"]["source"] == "explicit-recorder-revision"
    assert repositories["marty-demo-recorder"]["revision"] == RECORDER_SHA
    assert all(
        record["source"] == "official-stack-manifest"
        for name, record in repositories.items() if name != "marty-demo-recorder"
    )
    assert "protected-recorder-main" not in json.dumps(plan)


def test_rejects_tampered_or_mismatched_release_inputs(tmp_path: Path) -> None:
    manifest = _manifest()
    manifest_path, checksums = _write_release(tmp_path, manifest)
    manifest_path.write_text(
        json.dumps({**manifest, "release": "marty-ui@9.9.9"}), encoding="utf-8"
    )
    with pytest.raises(OfficialReleaseError, match="checksum"):
        prepare_release(
            manifest_path,
            checksums,
            recorder_revision=RECORDER_SHA,
            expected_ui_revision=UI_SHA,
        )

    manifest_path, checksums = _write_release(tmp_path, manifest)
    with pytest.raises(OfficialReleaseError, match="UI commit"):
        prepare_release(
            manifest_path,
            checksums,
            recorder_revision=RECORDER_SHA,
            expected_ui_revision="4" * 40,
        )

    manifest = _manifest()
    next(
        component
        for component in manifest["components"]
        if component["name"] == "marty-ui"
    )["version"] = "1.1.204"
    manifest_path, checksums = _write_release(tmp_path, manifest)
    with pytest.raises(OfficialReleaseError, match="component version"):
        prepare_release(
            manifest_path,
            checksums,
            recorder_revision=RECORDER_SHA,
            expected_ui_revision=UI_SHA,
        )


def test_rejects_mutable_or_ambiguous_image_roles(tmp_path: Path) -> None:
    manifest = _manifest()
    ui = next(
        component
        for component in manifest["components"]
        if component["name"] == "marty-ui"
    )
    ui["artifacts"][0]["uri"] = "ghcr.io/elevenid/marty-ui-oss/ui:latest"
    manifest_path, checksums = _write_release(tmp_path, manifest)
    with pytest.raises(OfficialReleaseError, match="exactly one ui image"):
        prepare_release(
            manifest_path,
            checksums,
            recorder_revision=RECORDER_SHA,
            expected_ui_revision=UI_SHA,
        )

    manifest = _manifest()
    ui = next(
        component
        for component in manifest["components"]
        if component["name"] == "marty-ui"
    )
    ui["artifacts"][1]["digest"] = UI_DIGEST
    manifest_path, checksums = _write_release(tmp_path, manifest)
    with pytest.raises(OfficialReleaseError, match="unique digests"):
        prepare_release(
            manifest_path,
            checksums,
            recorder_revision=RECORDER_SHA,
            expected_ui_revision=UI_SHA,
        )


def test_rejects_conflicting_repository_revisions_and_bad_recorder_sha(
    tmp_path: Path,
) -> None:
    manifest = _manifest()
    next(
        component
        for component in manifest["components"]
        if component["name"] == "marty-cli"
    )["commit"] = "5" * 40
    manifest_path, checksums = _write_release(tmp_path, manifest)
    with pytest.raises(OfficialReleaseError, match="conflicting revisions"):
        prepare_release(
            manifest_path,
            checksums,
            recorder_revision=RECORDER_SHA,
            expected_ui_revision=UI_SHA,
        )

    manifest_path, checksums = _write_release(tmp_path, _manifest())
    with pytest.raises(OfficialReleaseError, match="Recorder revision"):
        prepare_release(
            manifest_path,
            checksums,
            recorder_revision="short",
            expected_ui_revision=UI_SHA,
        )
