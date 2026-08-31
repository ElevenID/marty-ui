from __future__ import annotations

import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "verification-candidate-build.yml"
VERIFICATION_FLOOR = "b2b2953f9fe00d848761830623935773419bdf60"


def workflow() -> tuple[str, dict[str, object]]:
    source = WORKFLOW.read_text(encoding="utf-8")
    return source, yaml.safe_load(source)


def test_candidate_workflow_is_manual_nonpublishing_and_least_privilege() -> None:
    source, document = workflow()

    assert document[True] == {"workflow_dispatch": None}
    assert document["permissions"] == {"contents": "read"}
    build = document["jobs"]["build"]
    assert build["runs-on"] == "ubuntu-latest"
    assert build["env"] == {"DOCKER_BUILD_RECORD_UPLOAD": "false"}
    assert build["permissions"] == {
        "contents": "read",
        "id-token": "write",
        "attestations": "write",
        "artifact-metadata": "write",
    }
    assert "environment:" not in source
    assert "packages:" not in source
    assert "deployments:" not in source
    assert "secrets." not in source
    assert "docker/login-action" not in source
    assert "softprops/action-gh-release" not in source


def test_candidate_workflow_builds_only_a_local_bound_archive() -> None:
    source, _document = workflow()

    assert "push: false" in source
    assert "platforms: linux/amd64" in source
    assert "outputs: type=oci,dest=" in source
    assert "compression=gzip,force-compression=true" in source
    assert "SERVICE_NAME=verification" in source
    assert (
        'echo "version=0.0.0-candidate.${GITHUB_SHA:0:12}" >> "$GITHUB_OUTPUT"'
        in source
    )
    assert "MARTY_RELEASE_VERSION=${{ steps.source.outputs.version }}" in source
    assert "MARTY_UI_SHA=${{ github.sha }}" in source
    assert (
        "tags: docker.io/elevenid/marty-ui-verification-candidate:candidate-${{ github.sha }}"
        in source
    )
    assert 'test "$GITHUB_SHA" = "$(git rev-parse origin/main)"' in source
    assert f"git merge-base --is-ancestor {VERIFICATION_FLOOR}" in source


def test_candidate_floor_matches_roadmap_and_is_ancestor_when_available() -> None:
    roadmap = (ROOT / "docs" / "CONSOLIDATED_RUST_MIGRATION_ROADMAP.md").read_text(
        encoding="utf-8"
    )
    assert VERIFICATION_FLOOR in roadmap
    object_check = subprocess.run(
        ["git", "-C", str(ROOT), "cat-file", "-e", f"{VERIFICATION_FLOOR}^{{commit}}"],
        check=False,
    )
    if object_check.returncode != 0:
        shallow = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "--is-shallow-repository"],
            check=True,
            capture_output=True,
            text=True,
        )
        assert shallow.stdout.strip() == "true"
        return
    subprocess.run(
        [
            "git",
            "-C",
            str(ROOT),
            "merge-base",
            "--is-ancestor",
            VERIFICATION_FLOOR,
            "HEAD",
        ],
        check=True,
    )


def test_candidate_workflow_uses_fixed_actions_and_exact_five_file_bundle() -> None:
    source, _document = workflow()

    for action in (
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "docker/setup-buildx-action@37fe631027851001ddb9b187196cc803df7f5f0e",
        "docker/build-push-action@53b7df96c91f9c12dcc8a07bcb9ccacbed38856a",
        "anchore/sbom-action@e22c389904149dbc22b58101806040fa8d37a610",
        "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    ):
        assert source.count(action) == 1
    assert (
        source.count(
            "actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8"
        )
        == 2
    )
    assert "upload-artifact: false" in source
    assert "upload-release-assets: false" in source
    for asset in (
        "verification-candidate.json",
        "marty-ui-services.oci.tar",
        "marty-ui-services-sbom.cdx.json",
        "marty-ui-services-build-metadata.json",
        "marty-ui-services-provenance.json",
    ):
        assert asset in source
    assert "retention-days: 3" in source


def test_bundle_is_finalized_before_both_attestations_and_upload() -> None:
    source, _document = workflow()

    finalize = source.index("python scripts/build_verification_candidate.py")
    pin_attestation = source.index("name: Attest exact candidate pin")
    archive_attestation = source.index("name: Attest exact candidate OCI archive")
    upload = source.index("name: Upload short-lived nonpublishing candidate bundle")
    assert finalize < pin_attestation < archive_attestation < upload
    assert (
        "subject-path: ${{ runner.temp }}/verification-candidate/verification-candidate.json"
        in source
    )
    assert (
        "subject-path: ${{ runner.temp }}/verification-candidate/marty-ui-services.oci.tar"
        in source
    )
