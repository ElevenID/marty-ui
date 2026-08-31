from __future__ import annotations

import copy
import json
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "verification-candidate-build.yml"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
VERIFICATION_FLOOR = "b2b2953f9fe00d848761830623935773419bdf60"
SETUP_DOCKER = "docker/setup-docker-action@77e84dbf09b47d1e29270283c22f16145aa85ca1"
SETUP_BUILDX = "docker/setup-buildx-action@37fe631027851001ddb9b187196cc803df7f5f0e"
BUILDKIT_IMAGE = "moby/buildkit@sha256:28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8"


def workflow() -> tuple[str, dict[str, object]]:
    source = WORKFLOW.read_text(encoding="utf-8")
    return source, yaml.safe_load(source)


def assert_supported_backend(job: dict[str, object]) -> None:
    steps = job["steps"]
    assert isinstance(steps, list)
    setup_docker = next(step for step in steps if step.get("uses") == SETUP_DOCKER)
    assert setup_docker["with"]["version"] == "v29.7.2"
    assert json.loads(setup_docker["with"]["daemon-config"]) == {
        "features": {"containerd-snapshotter": True}
    }
    setup_buildx = next(step for step in steps if step.get("uses") == SETUP_BUILDX)
    assert setup_buildx["with"] == {
        "version": "v0.36.1",
        "driver": "docker-container",
        "driver-opts": f"image={BUILDKIT_IMAGE}",
    }
    commands = "\n".join(str(step.get("run", "")) for step in steps)
    assert "docker version --format '{{.Server.Version}}')\" = \"29.7.2" in commands
    assert "docker buildx version | awk '{print $2}')\" = \"v0.36.1" in commands
    assert "docker buildx inspect --bootstrap" in commands
    assert '$1 == "BuildKit" && $2 == "version:" { print $3 }' in commands
    assert '")" = "v0.32.2"' in commands
    assert "[[driver-type io.containerd.snapshotter.v1]]" in commands
    assert "docker info --format '{{ .DriverStatus }}'" in commands


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
        SETUP_DOCKER,
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


def test_manual_candidate_uses_the_exact_supported_oci_backend() -> None:
    _source, document = workflow()

    assert_supported_backend(document["jobs"]["build"])


def test_manual_candidate_backend_contract_rejects_single_field_drift() -> None:
    _source, document = workflow()
    job = document["jobs"]["build"]
    mutations = [
        lambda value: next(
            step for step in value["steps"] if step.get("uses") == SETUP_DOCKER
        ).update(uses="docker/setup-docker-action@main"),
        lambda value: next(
            step for step in value["steps"] if step.get("uses") == SETUP_DOCKER
        )["with"].update(version="latest"),
        lambda value: next(
            step for step in value["steps"] if step.get("uses") == SETUP_DOCKER
        )["with"].__setitem__("daemon-config", "{}"),
        lambda value: next(
            step for step in value["steps"] if step.get("uses") == SETUP_BUILDX
        ).update(uses="docker/setup-buildx-action@main"),
        lambda value: next(
            step for step in value["steps"] if step.get("uses") == SETUP_BUILDX
        )["with"].update(version="latest"),
        lambda value: next(
            step for step in value["steps"] if step.get("uses") == SETUP_BUILDX
        )["with"].update(driver="docker"),
        lambda value: next(
            step for step in value["steps"] if step.get("uses") == SETUP_BUILDX
        )["with"].__setitem__("driver-opts", "image=moby/buildkit:latest"),
        lambda value: next(
            step
            for step in value["steps"]
            if step.get("name") == "Require the exact supported OCI backend"
        ).update(run="true"),
    ]
    for mutation in mutations:
        mutated = copy.deepcopy(job)
        mutation(mutated)
        with pytest.raises((AssertionError, StopIteration)):
            assert_supported_backend(mutated)


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


def test_candidate_bundle_root_uses_an_exact_regular_file_allowlist() -> None:
    source, _document = workflow()

    assert "-maxdepth 1 -type f | wc -l" not in source
    assert "-mindepth 1 -maxdepth 1 -printf '%f:%y\\n'" in source
    for asset in (
        "marty-ui-services-build-metadata.json:f",
        "marty-ui-services-provenance.json:f",
        "marty-ui-services-sbom.cdx.json:f",
        "marty-ui-services.oci.tar:f",
        "verification-candidate.json:f",
    ):
        assert source.count(asset) == 1
    assert 'test "${candidate_entries[*]}" = "${expected_entries[*]}"' in source


def test_supported_containerd_candidate_contract_is_a_required_ci_lane() -> None:
    source = CI_WORKFLOW.read_text(encoding="utf-8")
    document = yaml.safe_load(source)
    job = document["jobs"]["verification-candidate-oci-contract"]

    assert job["name"] == "Verification Candidate OCI Contract"
    assert job["runs-on"] == "ubuntu-latest"
    assert job["timeout-minutes"] == 15
    assert job["permissions"] == {"contents": "read"}
    assert job["env"] == {"MARTY_RUN_VERIFICATION_CANDIDATE_DOCKER_TESTS": "1"}
    assert_supported_backend(job)
    steps = job["steps"]
    commands = "\n".join(str(step.get("run", "")) for step in steps)
    assert "uv pip install --system pytest==9.1.1 pyyaml==6.0.3" in commands
    assert (
        "python -m pytest -q tests/test_verification_candidate_build.py "
        "tests/test_verification_candidate_workflow.py"
    ) in commands
    assert "verification-candidate-oci-contract" in document["jobs"]["ci-gate"]["needs"]
