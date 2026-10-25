"""Require unqualified installer inputs before stack publication, without granting acceptance."""

from pathlib import Path

import yaml
import pytest

ROOT = Path(__file__).parents[1]
WORKFLOW = ROOT / ".github/workflows/cd.yml"


def workflow() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def test_official_dispatch_requires_selfhost_inputs_without_optional_bypass() -> None:
    value = workflow()
    dispatch = value.get("on", value.get(True))["workflow_dispatch"]["inputs"]
    assert "prepare_selfhost_lock" not in dispatch
    assert dispatch["selfhost_public_profile"]["type"] == "choice"
    assert dispatch["selfhost_public_profile"]["default"] == "tester"
    assert dispatch["selfhost_public_profile"]["options"] == ["tester", "full"]
    assert dispatch["selfhost_external_images_json"]["required"] is True
    jobs = value["jobs"]
    for job_name in ("build-selfhost-lock-roles", "prepare-selfhost-image-lock"):
        assert "if" not in jobs[job_name]
        assert jobs[job_name]["runs-on"] == "ubuntu-latest"
    assert "qualify-release" in jobs["build-selfhost-lock-roles"]["needs"]
    assert "qualify-release" in jobs["prepare-selfhost-image-lock"]["needs"]
    assert jobs["publish-manifest"]["needs"] == [
        "resolve-transaction", "validate-stack", "build-ui",
        "build-services", "build-openbao-didcomm", "build-keycloak",
        "qualify-release", "build-operator-catalog", "prepare-official-candidate", "prepare-installer-inputs",
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
    assert "SELFHOST_PUBLIC_PROFILE=${{ inputs.selfhost_public_profile }}" in ui["with"]["build-args"]
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
    assert "if" not in steps[preflight]
    assert "PyYAML==6.0.3" in steps[preflight]["run"]
    assert "scripts/check_selfhost_external_images.py" in steps[preflight]["run"]
    assert "docker compose --profile '*'" in steps[preflight]["run"]
    assert "--base-compose docker-compose.selfhost.prod.yml" in steps[preflight]["run"]
    assert "--override-compose docker-compose.selfhost.bundle.override.yml" in steps[preflight]["run"]
    for job_name in ("build-ui", "build-services", "build-openbao-didcomm",
                     "build-selfhost-lock-roles"):
        assert "validate-stack" in jobs[job_name]["needs"] or (
            job_name == "build-selfhost-lock-roles" and "qualify-release" in jobs[job_name]["needs"]
        )


def test_lock_staging_checks_exact_source_provenance_and_full_profile_closure() -> None:
    jobs = workflow()["jobs"]
    preparation = jobs["prepare-selfhost-image-lock"]
    source = "\n".join(step.get("run", "") for step in preparation["steps"])
    assert "git rev-parse 'HEAD^{commit}'" in source
    assert "refs/remotes/origin/main" in source
    assert "scripts/release_transaction.py validate" in source
    assert ".gates | length == 5" in source
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
    assert "if" not in consumer
    assert consumer["needs"] == ["prepare-selfhost-image-lock"]
    assert "preflight-selfhost-prepared-consumer" in jobs["prepare-installer-inputs"]["needs"]
    assert "prepare-installer-inputs" in jobs["publish-manifest"]["needs"]
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
    assert '.gates | length == 5' in source
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


def test_installer_inputs_are_a_mandatory_unqualified_build_dependency() -> None:
    jobs = workflow()["jobs"]
    preparation = jobs["prepare-installer-inputs"]
    assert "if" not in preparation
    assert set(preparation["needs"]) == {
        "resolve-transaction", "validate-stack", "qualify-release",
        "build-operator-catalog", "prepare-selfhost-image-lock",
        "preflight-selfhost-prepared-consumer", "verifier-differential",
    }
    assert "prepare-installer-inputs" in jobs["publish-manifest"]["needs"]
    assert preparation["permissions"] == {"contents": "read", "actions": "read"}
    steps = preparation["steps"]
    assert all("if" not in step for step in steps)
    assert "continue-on-error" not in preparation
    assert all("continue-on-error" not in step for step in steps)
    source = "\n".join(step.get("run", "") for step in steps)
    for required in (
        "scripts/release_transaction.py validate", ".tag == $tag",
        "scripts/check_prepared_selfhost_consumer.py", "--verify-archive-only",
        '"$SOURCE_SHA:$TAG"', "readelf -h", "readelf -l",
        "scripts/installer_release.py inventory", "docker compose --profile '*'",
        '--build-run-attempt "$GITHUB_RUN_ATTEMPT"',
        '--output "$output/installer-inventory.json"',
    ):
        assert required in source
    stage = next(step["run"] for step in steps if step.get("name") ==
                 "Produce exact unqualified installer input inventory")
    staged_copies = [line for line in stage.splitlines()
                    if line.startswith("cp ") and not line.startswith('cp "$inputs/')]
    assert len(staged_copies) == 4
    for asset in ("install.sh", "marty-deploy-linux-amd64",
                  "prepared-selfhost-bundle.zip", "prepared-selfhost-images.json"):
        assert any(asset in line for line in staged_copies)
    assert 'cp "$inputs/"* "$output/"' in stage
    uploaded = steps[-1]["with"]
    assert uploaded["name"] == "installer-inputs-unqualified-${{ github.run_id }}-${{ github.run_attempt }}"
    assert uploaded["if-no-files-found"] == "error"
    assert "installer-inputs-unqualified" not in str(jobs["publish-manifest"]["steps"])
    assert all(token not in source for token in (
        "gh release create", "gh release upload", "gh workflow run",
        "installer-admission.json", "installer-channel.json",
    ))


def test_all_installer_subjects_bind_current_attempt_before_operator_execution(monkeypatch) -> None:
    from scripts import verify_installer_provenance
    jobs = workflow()["jobs"]
    steps = jobs["prepare-installer-inputs"]["steps"]
    verify = next(step["run"] for step in steps if step.get("name") ==
                  "Verify exact source, transaction, and current-attempt producer proofs")
    embedded = verify.split("python - <<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
    assert verify.index("verify_subject(subject") < verify.index('"$operator" --build-identity')
    verification_root = ROOT / ".synthetic-installer-verification"
    monkeypatch.setenv("RUNNER_TEMP", str(verification_root))
    monkeypatch.setenv("SOURCE_SHA", "a" * 40)
    monkeypatch.setenv("GITHUB_RUN_ID", "123")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "7")
    calls = []
    monkeypatch.setattr(verify_installer_provenance, "verify_subject",
                        lambda subject, bundle, **kwargs: calls.append((subject, bundle, kwargs)))
    exec(compile(embedded, "cd.yml installer verification", "exec"), {})
    assert {subject.name for subject, _, _ in calls} == {
        "marty-deploy-linux-amd64", "prepared-selfhost-bundle.zip",
        "prepared-selfhost-images.json", "prepared-selfhost-bundle.json",
        "prepared-selfhost-product-descriptor.json", "public-kms-jwk",
        "selfhost-public-kms-jwk.json",
    }
    assert len(calls) == 7
    for _, _, policy in calls:
        assert policy == dict(gh=verification_root / "installer-gh/gh_2.103.2_linux_amd64/bin/gh",
                              workflow=".github/workflows/cd.yml", source_sha="a" * 40,
                              run_id=123, run_attempt=7)
    assert calls[-1][1].name == "selfhost-public-kms-jwk.slsa-bundle.json"
    def refuse_old_attempt(subject, bundle, **policy):
        # The offline verifier rejects an old certificate invocation even when
        # the source and run ID match. The workflow must propagate that error.
        assert policy["run_attempt"] == 7
        raise ValueError("certificate run attempt differs")
    monkeypatch.setattr(verify_installer_provenance, "verify_subject", refuse_old_attempt)
    with pytest.raises(ValueError, match="run attempt differs"):
        exec(compile(embedded, "cd.yml stale producer rejection", "exec"), {})
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "invalid")
    with pytest.raises(ValueError):
        exec(compile(embedded, "cd.yml invalid attempt rejection", "exec"), {})
    pinned = next(step["run"] for step in steps if step.get("name") ==
                  "Prepare the installer-pinned provenance verifier")
    assert "--max-filesize 15031001" in pinned
    assert "62ccf747115ddc61237efffdde66a3c8f70ba249433dc64f70801089b59c59c8" in pinned
    assert "sha256sum --check --strict" in pinned
    assert pinned.index("sha256sum --check --strict") < pinned.index("tar -xzf")


def test_offline_producer_bundles_do_not_change_existing_asset_artifacts() -> None:
    jobs = workflow()["jobs"]
    prepared = jobs["prepare-selfhost-image-lock"]
    attestation = next(step for step in prepared["steps"]
                       if step.get("id") == "installer_prepared_provenance")
    assert set(attestation["with"]["subject-path"].splitlines()) == {
        "prepared-selfhost-bundle.zip", "prepared-selfhost-images.json",
        "prepared-selfhost-bundle.json", "prepared-selfhost-product-descriptor.json",
    }
    for job, existing, separate, bundle in (
        (prepared, "selfhost-lock-preparation-unqualified-", "installer-prepared-provenance-",
         "installer-prepared.provenance.jsonl"),
        (jobs["build-operator-catalog"], "operator-catalog-", "operator-installer-provenance-",
         "marty-deploy-linux-${{ matrix.arch }}.provenance.jsonl"),
    ):
        uploads = [step["with"] for step in job["steps"]
                   if step.get("uses", "").startswith("actions/upload-artifact@")]
        original = next(upload for upload in uploads if upload["name"].startswith(existing))
        proof = next(upload for upload in uploads if upload["name"].startswith(separate))
        assert ".provenance.jsonl" not in original["path"]
        assert proof["path"] == bundle
        assert proof["if-no-files-found"] == "error"
