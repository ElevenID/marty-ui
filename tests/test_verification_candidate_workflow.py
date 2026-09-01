from __future__ import annotations

import copy
import json
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "verification-candidate-build.yml"
CONSUMER_WORKFLOW = (
    ROOT / ".github" / "workflows" / "verification-candidate-consumer.yml"
)
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
VERIFICATION_FLOOR = "b2b2953f9fe00d848761830623935773419bdf60"
INTEGRATION_HARNESS = "8ee3f4e43efd4f0b7583d6b0f3cafe513cc54710"
PRODUCER_WORKFLOW_ID = "346930832"
SETUP_DOCKER = "docker/setup-docker-action@77e84dbf09b47d1e29270283c22f16145aa85ca1"
SETUP_BUILDX = "docker/setup-buildx-action@37fe631027851001ddb9b187196cc803df7f5f0e"
BUILDKIT_IMAGE = "moby/buildkit@sha256:28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8"


def workflow() -> tuple[str, dict[str, object]]:
    source = WORKFLOW.read_text(encoding="utf-8")
    return source, yaml.safe_load(source)


def consumer_workflow() -> tuple[str, dict[str, object]]:
    source = CONSUMER_WORKFLOW.read_text(encoding="utf-8")
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
    assert setup_buildx["id"] == "buildx"
    assert setup_buildx["with"] == {
        "version": "v0.36.1",
        "driver": "docker-container",
        "driver-opts": f"image={BUILDKIT_IMAGE}",
    }
    probe = next(
        step
        for step in steps
        if step.get("name") == "Require the exact supported OCI backend"
    )
    assert probe["env"] == {
        "MARTY_BUILDX_DRIVER": "${{ steps.buildx.outputs.driver }}",
        "MARTY_BUILDX_NODES_JSON": "${{ steps.buildx.outputs.nodes }}",
    }
    assert probe["run"] == "python scripts/check_verification_candidate_backend.py"


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


def test_consumer_runs_only_for_the_authenticated_successful_producer() -> None:
    source, document = consumer_workflow()

    assert document[True] == {
        "workflow_run": {
            "workflows": ["Verification candidate build"],
            "types": ["completed"],
        }
    }
    assert document["permissions"] == {"contents": "read"}
    verify = document["jobs"]["verify"]
    assert verify["permissions"] == {
        "actions": "read",
        "attestations": "read",
        "contents": "read",
        "packages": "read",
    }
    for condition in (
        "workflow_run.conclusion == 'success'",
        "workflow_run.event == 'workflow_dispatch'",
        "workflow_run.head_branch == 'main'",
        "workflow_run.head_repository.full_name == 'ElevenID/marty-ui'",
    ):
        assert condition in verify["if"]
    steps = verify["steps"]
    gate = next(
        step
        for step in steps
        if step.get("name") == "Authenticate the triggering producer run"
    )["run"]
    expected_api_bindings = {
        ".id": "$TRIGGER_RUN_ID",
        ".run_attempt": "$TRIGGER_RUN_ATTEMPT",
        ".workflow_id": PRODUCER_WORKFLOW_ID,
        ".name": "Verification candidate build",
        ".path": ".github/workflows/verification-candidate-build.yml",
        ".event": "workflow_dispatch",
        ".status": "completed",
        ".conclusion": "success",
        ".head_repository.full_name": "$GITHUB_REPOSITORY",
        ".head_branch": "main",
        ".head_sha": "$TRIGGER_SHA",
    }
    for field, expected in expected_api_bindings.items():
        assert f"jq -er '{field}' trigger-run.json" in gate
        assert f'= "{expected}"' in gate
    assert 'git merge-base --is-ancestor "$TRIGGER_SHA" origin/main' in gate
    assert "environment:" not in source
    assert "secrets." not in source
    assert "id-token: write" not in source
    assert "attestations: write" not in source
    assert "deployments:" not in source


def test_consumer_downloads_and_authenticates_the_exact_five_file_bundle() -> None:
    source, _document = consumer_workflow()

    assert (
        source.count(
            "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093"
        )
        == 1
    )
    assert (
        "name: verification-candidate-${{ github.event.workflow_run.id }}-"
        "${{ github.event.workflow_run.run_attempt }}" in source
    )
    assert "run-id: ${{ github.event.workflow_run.id }}" in source
    assert "github-token: ${{ github.token }}" in source
    for asset in (
        "marty-ui-services-build-metadata.json:f",
        "marty-ui-services-provenance.json:f",
        "marty-ui-services-sbom.cdx.json:f",
        "marty-ui-services.oci.tar:f",
        "verification-candidate.json:f",
    ):
        assert source.count(asset) == 1
    for field, expected in (
        (".commit", "$TRIGGER_SHA"),
        (".source_ref", "refs/heads/main"),
        (".run.id", "$TRIGGER_RUN_ID"),
        (".run.attempt", "$TRIGGER_RUN_ATTEMPT"),
    ):
        assert f"jq -er '{field}'" in source
        assert expected in source
    assert source.count("gh attestation verify") == 4
    assert (
        source.count(
            "--signer-workflow github.com/ElevenID/marty-ui/.github/workflows/verification-candidate-build.yml"
        )
        == 2
    )
    producer_gate = source.index("name: Authenticate the triggering producer run")
    download = source.index("name: Download the exact triggering-run candidate")
    candidate_gate = source.index("name: Authenticate the exact candidate bundle")
    harness = source.index("name: Check out immutable public verification harness")
    execute = source.index(
        "name: Run candidate and oracle then compare fail-closed evidence"
    )
    assert producer_gate < download < candidate_gate < harness < execute


def test_consumer_uses_only_fixed_actions_and_drops_registry_credentials() -> None:
    source, document = consumer_workflow()

    expected_actions = {
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1": 2,
        "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093": 1,
        "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97": 1,
        "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a": 1,
    }
    assert {
        action: source.count(action) for action in expected_actions
    } == expected_actions
    uses = [
        step["uses"] for step in document["jobs"]["verify"]["steps"] if "uses" in step
    ]
    assert len(uses) == sum(expected_actions.values())
    assert "docker logout ghcr.io" in source
    execute = next(
        step
        for step in document["jobs"]["verify"]["steps"]
        if step.get("name")
        == "Run candidate and oracle then compare fail-closed evidence"
    )
    assert "env" not in execute


def test_consumer_uses_exact_public_harness_and_remains_fail_closed() -> None:
    source, _document = consumer_workflow()

    assert "repository: ElevenID/marty-integration-tests" in source
    assert f"ref: {INTEGRATION_HARNESS}" in source
    assert "requirements/official-py312.lock" in source
    assert "--require-hashes --only-binary=:all:" in source
    assert "run-candidate" in source
    assert "compare-candidate-evidence" in source
    assert "--oracle-pin config/credentials-verifier-oracle.json" in source
    assert (
        "test \"$(jq -er '.release_clearance' ../work/evidence/comparison.json)\" = blocked"
        in source
    )
    assert "retention-days: 3" in source


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
            step for step in value["steps"] if step.get("uses") == SETUP_BUILDX
        ).update(id="other"),
        lambda value: next(
            step
            for step in value["steps"]
            if step.get("name") == "Require the exact supported OCI backend"
        )["env"].update(MARTY_BUILDX_NODES_JSON="[]"),
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
        "tests/test_verification_candidate_backend.py "
        "tests/test_verification_candidate_workflow.py"
    ) in commands
    assert "verification-candidate-oci-contract" in document["jobs"]["ci-gate"]["needs"]
