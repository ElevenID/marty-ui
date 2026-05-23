from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPTS_DIR = REPO_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))
MODULE_PATH = SCRIPTS_DIR / "prepare-selfhost-release-artifacts.py"
SPEC = importlib.util.spec_from_file_location("prepare_selfhost_release_artifacts", MODULE_PATH)
release_artifacts = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules["prepare_selfhost_release_artifacts"] = release_artifacts
SPEC.loader.exec_module(release_artifacts)


DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64


def test_parse_imagetools_digest_uses_top_level_digest():
    output = f"""
Name:      ghcr.io/elevenid/marty-ui/services:2026.05.0
MediaType: application/vnd.oci.image.index.v1+json
Digest:    {DIGEST_A}

Manifests:
  Name:      ghcr.io/elevenid/marty-ui/services@{DIGEST_B}
  Digest:    {DIGEST_B}
  Platform:  linux/amd64
"""

    assert release_artifacts.parse_imagetools_digest(output) == DIGEST_A
    assert release_artifacts.parse_imagetools_platforms(output) == ["linux/amd64"]


def test_image_digest_ref_replaces_tag_with_digest():
    image_ref = "ghcr.io/elevenid/marty-ui/services:2026.05.0"

    assert release_artifacts.image_digest_ref(image_ref, DIGEST_A) == (
        f"ghcr.io/elevenid/marty-ui/services@{DIGEST_A}"
    )


def test_sign_and_verify_require_digest_refs_even_in_dry_run():
    with pytest.raises(release_artifacts.ReleaseError):
        release_artifacts.sign_image("ghcr.io/elevenid/marty-ui/services:2026.05.0", "cosign.key", True)

    release_artifacts.sign_image(f"ghcr.io/elevenid/marty-ui/services@{DIGEST_A}", "cosign.key", True)
    release_artifacts.verify_signature(f"ghcr.io/elevenid/marty-ui/services@{DIGEST_A}", "cosign.pub", True)


def test_write_manifest_records_digest_artifacts_and_signature_subject(tmp_path):
    record = release_artifacts.ImageReleaseRecord(
        name="services",
        ref="ghcr.io/elevenid/marty-ui/services:2026.05.0",
        digest=DIGEST_A,
        digest_ref=f"ghcr.io/elevenid/marty-ui/services@{DIGEST_A}",
        platforms=["linux/amd64"],
        artifacts={
            "sbom": "sbom/services.spdx.json",
            "scan": "scan/services.trivy.json",
            "digest_inspection": "digests/services.imagetools.txt",
        },
        signature={
            "signed": True,
            "verified": True,
            "subject": f"ghcr.io/elevenid/marty-ui/services@{DIGEST_A}",
        },
    )

    manifest_path = release_artifacts.write_manifest(
        output_dir=tmp_path,
        tag="2026.05.0",
        image_prefix="ghcr.io/elevenid/marty-ui",
        image_records=[record],
        actions={"sbom": True, "scan": True, "inspect_digests": True, "sign": True, "verify_signatures": True},
        artifacts={
            "sbom": ["sbom/services.spdx.json"],
            "scan": ["scan/services.trivy.json"],
            "digests": ["digests/services.imagetools.txt"],
            "signatures": [f"ghcr.io/elevenid/marty-ui/services@{DIGEST_A}"],
            "evidence": ["release-evidence.md"],
        },
        repo_root=tmp_path,
        workspace_root=tmp_path,
        dry_run=False,
    )

    payload = json.loads(manifest_path.read_text(encoding="utf-8"))

    assert payload["schema_version"] == 2
    assert payload["images"][0]["digest"] == DIGEST_A
    assert payload["images"][0]["digest_ref"] == f"ghcr.io/elevenid/marty-ui/services@{DIGEST_A}"
    assert payload["images"][0]["artifacts"]["digest_inspection"] == "digests/services.imagetools.txt"
    assert payload["images"][0]["signature"]["subject"] == f"ghcr.io/elevenid/marty-ui/services@{DIGEST_A}"


def test_write_release_evidence_contains_digest_table(tmp_path):
    record = release_artifacts.ImageReleaseRecord(
        name="services",
        ref="ghcr.io/elevenid/marty-ui/services:2026.05.0",
        digest=DIGEST_A,
        digest_ref=f"ghcr.io/elevenid/marty-ui/services@{DIGEST_A}",
        artifacts={"sbom": "sbom/services.spdx.json", "scan": "scan/services.trivy.json"},
        signature={"signed": True, "verified": False, "subject": f"ghcr.io/elevenid/marty-ui/services@{DIGEST_A}"},
    )

    evidence_path = release_artifacts.write_release_evidence(
        output_dir=tmp_path,
        tag="2026.05.0",
        image_records=[record],
        repo_root=tmp_path,
        workspace_root=tmp_path,
        dry_run=False,
    )

    evidence = evidence_path.read_text(encoding="utf-8")
    assert "# Marty self-host release 2026.05.0" in evidence
    assert f"`ghcr.io/elevenid/marty-ui/services@{DIGEST_A}`" in evidence
    assert "sbom/services.spdx.json" in evidence
