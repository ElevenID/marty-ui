"""Keep the opt-in self-host preparation outside the stack publication gate."""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parents[1]
WORKFLOW = ROOT / ".github/workflows/cd.yml"


def workflow() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def test_only_explicit_official_dispatch_can_prepare_selfhost_lock() -> None:
    value = workflow()
    dispatch = value.get("on", value.get(True))["workflow_dispatch"]["inputs"]
    assert dispatch["prepare_selfhost_lock"]["type"] == "boolean"
    assert dispatch["prepare_selfhost_lock"]["default"] is False
    assert dispatch["selfhost_external_images_json"]["required"] is False
    jobs = value["jobs"]
    for job_name in ("build-selfhost-lock-roles", "prepare-selfhost-image-lock"):
        assert jobs[job_name]["if"] == "inputs.prepare_selfhost_lock == true"
        assert jobs[job_name]["runs-on"] == "ubuntu-latest"
    assert "qualify-release" in jobs["build-selfhost-lock-roles"]["needs"]
    assert "qualify-release" in jobs["prepare-selfhost-image-lock"]["needs"]
    assert jobs["publish-manifest"]["needs"] == [
        "resolve-transaction", "validate-stack", "build-ui",
        "build-services", "build-openbao-didcomm", "qualify-release", "build-operator-catalog",
    ]


def test_new_roles_are_digest_only_signed_and_not_promoted() -> None:
    jobs = workflow()["jobs"]
    build = jobs["build-selfhost-lock-roles"]
    steps = build["steps"]
    preflight = next(index for index, step in enumerate(steps)
                     if step.get("name") == "Reject incomplete independent image inputs before building")
    first_build = next(index for index, step in enumerate(steps)
                       if step.get("uses", "").startswith("docker/build-push-action@"))
    assert preflight < first_build
    assert "to_entries | map(select" in steps[preflight]["run"]
    images = [step for step in steps if step.get("uses", "").startswith("docker/build-push-action@")]
    assert len(images) == 2
    assert {step["with"]["file"] for step in images} == {
        "docker/ui.Dockerfile", "docker/cloudflared-wrapper.Dockerfile",
    }
    for step in images:
        assert "push-by-digest=true" in step["with"]["outputs"]
        assert ":${{" not in step["with"]["outputs"]
        assert step["with"]["provenance"] == "mode=max"
        assert step["with"]["sbom"] is True
    ui = next(step for step in images if step["with"]["file"] == "docker/ui.Dockerfile")
    assert ui["with"]["target"] == "selfhost"
    assert "UI_VARIANT=selfhost" in ui["with"]["build-args"]
    assert "NGINX_CONFIG=nginx.spa.conf" in ui["with"]["build-args"]
    assert len([step for step in steps if step.get("uses", "").startswith(
        "actions/attest-build-provenance@")]) == 2
    assert any("cosign sign" in step.get("run", "") for step in steps)
    assert all("imagetools create" not in step.get("run", "") for step in steps)


def test_selfhost_inputs_fail_before_expensive_release_builds() -> None:
    jobs = workflow()["jobs"]
    steps = jobs["validate-stack"]["steps"]
    preflight = next(index for index, step in enumerate(steps)
                     if step.get("name") == "Reject invalid self-host image inputs before release builds")
    provenance = next(index for index, step in enumerate(steps)
                      if step.get("name") == "Verify release artifact provenance")
    assert preflight < provenance
    assert steps[preflight]["if"] == "inputs.prepare_selfhost_lock == true"
    assert "exact registry-qualified independent image digests" in steps[preflight]["run"]
    assert "docker compose --profile '*'" in steps[preflight]["run"]
    assert "($external[0] | keys | sort)" in steps[preflight]["run"]
    for job_name in ("build-ui", "build-services", "build-openbao-didcomm",
                     "build-selfhost-lock-roles"):
        assert "validate-stack" in jobs[job_name]["needs"] or (
            job_name == "build-selfhost-lock-roles" and "qualify-release" in jobs[job_name]["needs"]
        )


@pytest.mark.skipif(shutil.which("jq") is None, reason="jq unavailable locally")
def test_early_selfhost_input_filter_rejects_both_dispatch_mistakes() -> None:
    steps = workflow()["jobs"]["validate-stack"]["steps"]
    source = next(step["run"] for step in steps if step.get("name") ==
                  "Reject invalid self-host image inputs before release builds")
    match = re.search(r"\| jq -e '(.*?)' > external-services\.json", source, re.S)
    assert match is not None
    image = "docker.io/library/nginx@sha256:" + "a" * 64
    valid = {"edge": image}
    for payload, passes in (
        (json.dumps(valid), True),
        (json.dumps({"edge": "nginx@sha256:" + "a" * 64}), False),
        ("{edge:" + image + "}", False),
    ):
        result = subprocess.run(["jq", "-e", match.group(1)], input=payload,
                                text=True, capture_output=True, check=False)
        assert (result.returncode == 0) is passes


def test_lock_staging_checks_exact_source_provenance_and_full_profile_closure() -> None:
    jobs = workflow()["jobs"]
    preparation = jobs["prepare-selfhost-image-lock"]
    source = "\n".join(step.get("run", "") for step in preparation["steps"])
    assert "git rev-parse 'HEAD^{commit}'" in source
    assert "refs/remotes/origin/main" in source
    assert "scripts/release_transaction.py validate" in source
    assert ".gates | length == 4" in source
    assert "docker compose --profile '*'" in source
    assert "scripts/build_selfhost_image_lock.py" in source
    assert "--source-repo ." in source
    assert "gh attestation verify" in source
    assert '.images.openbao_didcomm | .uri + "@" + .digest' in source
    assert "--source-digest \"$SOURCE_SHA\"" in source
    assert "docker logout ghcr.io" in source
    assert "docker pull \"$image\"" in source
    assert '.services[], .openbao_didcomm_image' in source
    assert "selfhost-lock-preparation-unqualified-" in str(preparation)
    assert "retention-days: 30" in WORKFLOW.read_text(encoding="utf-8")
    assert "selfhost-lock-preparation-unqualified-" not in str(jobs["publish-manifest"])


def test_prepared_consumer_is_separate_and_cannot_qualify_or_publish() -> None:
    jobs = workflow()["jobs"]
    consumer = jobs["preflight-selfhost-prepared-consumer"]
    assert consumer["if"] == "inputs.prepare_selfhost_lock == true"
    assert consumer["needs"] == ["prepare-selfhost-image-lock"]
    assert "preflight-selfhost-prepared-consumer" not in jobs["publish-manifest"]["needs"]
    source = "\n".join(step.get("run", "") for step in consumer["steps"])
    assert "scripts/check_prepared_selfhost_consumer.py" in source
    assert "prepared/prepared-selfhost-bundle.zip" in source
    assert "--source-checkout \"$GITHUB_WORKSPACE\"" in source
    assert 'DOCKER_CONFIG="$RUNNER_TEMP/selfhost-anonymous-docker-config"' in source
    assert "scripts/check_selfhost_locked_image_platform.py" in source
    assert "--image-lock prepared/prepared-selfhost-images.json" in source
    assert "--output \"$RUNNER_TEMP/selfhost-image-platform-preflight.json\"" in source
    assert "docker compose --profile '*'" in source
    assert '--install-root "$RUNNER_TEMP/selfhost-consumer/selfhost-prepared"' in source
    assert '--state-root "$SELFHOST_STATE_DIR"' in source
    assert '--secret-root "$SELFHOST_SECRET_DIR"' in source
    assert 'export SELFHOST_STATE_DIR="$RUNNER_TEMP/selfhost-consumer-state"' in source
    assert 'export SELFHOST_SECRET_DIR="$RUNNER_TEMP/selfhost-consumer-secrets"' in source
    assert "scripts/release_transaction.py validate" in source
    assert '--stack-lock release/stack-lock.json' in source
    assert '--source-sha "$GITHUB_SHA"' in source
    assert '.gates | length == 4' in source
    assert "docker compose up" not in source


def test_rust_only_release_rejects_retired_issuance_image_inputs() -> None:
    value = workflow()
    assert "infrastructure images" in value.get("on", value.get(True))[
        "workflow_dispatch"
    ]["inputs"]["selfhost_external_images_json"]["description"]
    steps = value["jobs"]["validate-stack"]["steps"]
    retired = next(step for step in steps if step.get("name") ==
                   "Reject retired Credentials image from the Rust-only stack")
    assert '.name == "marty-credentials-issuance"' in retired["run"]
    assert '.type == "oci"' in retired["run"]
    assert retired["run"].count("length == 0") == 2

    for job_name in ("build-selfhost-lock-roles", "prepare-selfhost-image-lock"):
        preflight = next(step for step in value["jobs"][job_name]["steps"]
                         if "EXTERNAL_IMAGES_JSON" in step.get("env", {}))
        source = preflight["run"]
        assert '(has("issuance") | not)' in source
        assert '(has("issuance-migrations") | not)' in source
        assert 'export MARTY_ISSUANCE_IMAGE=' not in source
        assert 'one locked issuance image required' not in source


def test_wrapper_base_images_are_index_digest_pinned() -> None:
    source = (ROOT / "docker/cloudflared-wrapper.Dockerfile").read_text(encoding="utf-8")
    lines = [line for line in source.splitlines() if line.startswith("FROM ")]
    assert len(lines) == 2
    assert all("@sha256:" in line for line in lines)
