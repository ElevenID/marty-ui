from __future__ import annotations

import hashlib
import json
from argparse import Namespace
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from scripts.check_canvas_oss_portability import (
    ALLOWED_BOOTSTRAP_COMMANDS,
    ContractError,
    finalize,
    validate_bootstrap_audit,
    validate_catalog,
    validate_contract_driver_manifest,
    validate_execution_assets,
    validate_image_manifest,
    validate_lock,
    validate_runtime_binding,
)


ROOT = Path(__file__).resolve().parents[1]


def load(relative: str) -> dict:
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


def write(path: Path, value: dict) -> Path:
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def runtime_context(release: str, source_id: str, *, gateway: str = "1", issuance: str = "2") -> dict:
    return {
        "schema_version": 1,
        "origin": "https://beta.elevenidllc.com",
        "release_version": release,
        "source_id": source_id,
        "deployment_release_marker": release,
        "service_image_digests": {
            "gateway": "sha256:" + gateway * 64,
            "issuance": "sha256:" + issuance * 64,
            "canvas-sync-worker": "sha256:" + issuance * 64,
        },
    }


def image_manifest() -> dict:
    lock = load("deploy-config/catalog/canvas-oss.lock.json")
    source = lock["source"]
    return {
        "schema_version": 1,
        "source_repository": "https://github.com/instructure/canvas-lms.git",
        "source_tag": source["tag"],
        "source_tag_object": source["tag_object"],
        "source_commit": source["commit"],
        "source_tree": source["tree"],
        "source_archive_sha256": "f" * 64,
        "release_train": source["release_train"],
        "source_modified": False,
        "dockerfile": "Dockerfile.production",
        "image_digest": "sha256:" + "a" * 64,
        "base_image": lock["image"]["base_image"],
        "base_source_policy": "docker/canvas-oss/source-policy.json",
        "base_source_policy_sha256": hashlib.sha256(
            (ROOT / "docker/canvas-oss/source-policy.json").read_bytes()
        ).hexdigest(),
        "oci_labels": lock["image"]["required_oci_labels"],
        "sbom": True,
        "provenance": True,
    }


def bootstrap_audit() -> dict:
    return {
        "schema_version": 1,
        "phase": "pre_start_only",
        "commands": [{"argv": command, "exit_code": 0} for command in ALLOWED_BOOTSTRAP_COMMANDS],
        "web_started_after_bootstrap": True,
        "forbidden_operation_counts": {
            "rails_runner": 0,
            "rails_console": 0,
            "post_bootstrap_database_access": 0,
            "custom_plugins": 0,
            "source_patches": 0,
            "custom_events": 0,
        },
    }


def contract_driver_manifest(source_sha: str = "d" * 40, image_id: str = "e" * 64) -> dict:
    lock = load("deploy-config/catalog/canvas-oss.lock.json")
    driver = lock["contract_driver"]
    return {
        "schema_version": 1,
        "execution_boundary": driver["execution_boundary"],
        "compose_project": "canvas-oss-portability",
        "compose_service": driver["compose_service"],
        "image_reference": f"elevenid-local/canvas-oss-contract:{source_sha}",
        "image_id": "sha256:" + image_id,
        "source_sha": source_sha,
        "source_repository": driver["source_repository"],
        "dockerfile": driver["dockerfile"],
        "package_manifest": driver["package_manifest"],
        "package_lock": driver["package_lock"],
        "audit_level": driver["audit_level"],
        "base_image": driver["base_image"],
        "secret_transport": driver["secret_transport"],
        "host_browser_processes": False,
        "unit_test_exit_code": 0,
        "contract_exit_code": 0,
        "labels": {
            "org.opencontainers.image.source": driver["source_repository"],
            "org.opencontainers.image.revision": source_sha,
            "io.elevenid.canvas-oss.execution-boundary": "docker-compose-one-shot",
        },
    }


def contract_execution(manifest: dict) -> dict:
    return {
        "boundary": manifest["execution_boundary"],
        "compose_service": manifest["compose_service"],
        "containerized": True,
        "host_browser_processes": False,
        "secret_transport": manifest["secret_transport"],
        "image_id": manifest["image_id"],
        "source_sha": manifest["source_sha"],
        "base_image": manifest["base_image"],
    }


def test_checked_in_canvas_oss_contract_is_strict() -> None:
    lock = load("deploy-config/catalog/canvas-oss.lock.json")
    Draft202012Validator(load("deploy-config/schemas/canvas-oss-lock.schema.json")).validate(lock)
    validate_lock(lock)
    validate_execution_assets(lock)
    validate_catalog(load("deploy-config/catalog/canvas-oss-portability.json"))


def test_image_manifest_rejects_modified_source() -> None:
    manifest = image_manifest()
    manifest["source_modified"] = True
    lock = load("deploy-config/catalog/canvas-oss.lock.json")
    lock["image"]["digest"] = manifest["image_digest"]
    lock["image"]["digest_state"] = "published"
    with pytest.raises(ContractError, match="modified Canvas source"):
        validate_image_manifest(manifest, lock)


def test_image_manifest_must_equal_reviewed_lock_digest() -> None:
    manifest = image_manifest()
    lock = load("deploy-config/catalog/canvas-oss.lock.json")
    lock["image"]["digest"] = "sha256:" + "b" * 64
    lock["image"]["digest_state"] = "published"
    with pytest.raises(ContractError, match="reviewed lock"):
        validate_image_manifest(manifest, lock)


def test_bootstrap_rejects_rails_runner() -> None:
    audit = bootstrap_audit()
    audit["commands"].append({"argv": ["bin/rails", "runner", "seed.rb"], "exit_code": 0})
    with pytest.raises(ContractError, match="outside the exact lifecycle allowlist"):
        validate_bootstrap_audit(audit)


def test_runtime_binding_requires_deployment_and_source_snapshot(tmp_path: Path) -> None:
    source_id = "c" * 40
    context = write(
        tmp_path / "runtime.json",
        runtime_context("mip-0.3.1-local-test", source_id),
    )
    write(
        tmp_path / "source-manifest.json",
        {
            "schema_version": 1,
            "source_kind": "local-worktree-snapshot",
            "release_version": "mip-0.3.1-local-test",
            "marty_ui_sha": source_id,
            "promotion_eligible": False,
            "release_ready": False,
        },
    )
    deployment = write(
        tmp_path / "local-deployment-manifest.json",
        {
            "schema_version": 1,
            "source_kind": "local-worktree-snapshot",
            "release_version": "mip-0.3.1-local-test",
            "marty_ui_sha": source_id,
            "beta_origin": "https://beta.elevenidllc.com",
            "source_manifest": "source-manifest.json",
            "services_marker": {
                "component": "services",
                "release_version": "mip-0.3.1-local-test",
                "marty_ui_sha": source_id,
                "deployment_release_marker": "mip-0.3.1-local-test",
                "image_digests": {
                    "gateway": "sha256:" + "1" * 64,
                    "issuance": "sha256:" + "2" * 64,
                    "canvas-sync-worker": "sha256:" + "2" * 64,
                },
            },
            "ui_marker": {
                "component": "ui",
                "release_version": "mip-0.3.1-local-test",
                "marty_ui_sha": source_id,
            },
            "images": [
                {
                    "container": container,
                    "configured_image": f"elevenid-local/{image_service}:mip-0.3.1-local-test",
                    "image_id": image_id,
                    "status": "running",
                }
                for container, image_service, image_id in (
                    ("marty-gateway", "gateway", "sha256:" + "1" * 64),
                    ("marty-issuance", "issuance", "sha256:" + "2" * 64),
                    ("marty-canvas-sync-worker", "issuance", "sha256:" + "2" * 64),
                )
            ],
        },
    )
    validate_runtime_binding(deployment, context, source_id)
    with pytest.raises(ContractError, match="explicitly reviewed"):
        validate_runtime_binding(deployment, context, "d" * 40)


def test_runtime_binding_rejects_current_ui_only_reused_backend_manifest(tmp_path: Path) -> None:
    source_id = "1" * 40
    source_digest = source_id + "2" * 24
    revision = "3" * 40
    release = "mip-0.3.1-local-current"
    context = write(
        tmp_path / "runtime.json",
        runtime_context(release, source_id),
    )
    write(
        tmp_path / "source-manifest.json",
        {
            "schema_version": 1,
            "release_version": release,
            "marty_ui_head": revision,
            "marty_ui_sha": source_id,
            "marty_ui_source_sha256": source_digest,
            "ui_image": f"elevenid-local/ui:{release}",
            "ui_image_id": "sha256:" + "4" * 64,
            "promotion_eligible": False,
            "release_ready": False,
        },
    )
    markers = {
        name: {"component": component, "release_version": release, "marty_ui_sha": source_id}
        for name, component in {
            "local_ui": "ui",
            "local_gateway": "services",
            "beta_ui": "ui",
            "beta_gateway": "services",
        }.items()
    }
    deployment = write(
        tmp_path / "local-deployment-manifest.json",
        {
            "release_version": release,
            "runtime_source": {"repository": "marty-ui", "revision": revision, "source_digest": source_digest, "release_source_id": source_id},
            "image": {"reference": f"elevenid-local/ui:{release}", "id": "sha256:" + "4" * 64},
            "markers": markers,
            "backend_images_reused": True,
        },
    )
    with pytest.raises(ContractError, match="UI-only/reused-backend"):
        validate_runtime_binding(deployment, context, source_id)


def test_runtime_binding_rejects_missing_canvas_worker_image(tmp_path: Path) -> None:
    source_id = "c" * 40
    release = "mip-0.3.1-local-test"
    context = write(
        tmp_path / "runtime.json",
        runtime_context(release, source_id),
    )
    write(
        tmp_path / "source-manifest.json",
        {
            "schema_version": 1,
            "source_kind": "local-worktree-snapshot",
            "release_version": release,
            "marty_ui_sha": source_id,
            "promotion_eligible": False,
            "release_ready": False,
        },
    )
    deployment = write(
        tmp_path / "local-deployment-manifest.json",
        {
            "schema_version": 1,
            "source_kind": "local-worktree-snapshot",
            "release_version": release,
            "marty_ui_sha": source_id,
            "beta_origin": "https://beta.elevenidllc.com",
            "source_manifest": "source-manifest.json",
            "services_marker": {
                "component": "services",
                "release_version": release,
                "marty_ui_sha": source_id,
                "deployment_release_marker": release,
                "image_digests": runtime_context(release, source_id)["service_image_digests"],
            },
            "ui_marker": {"component": "ui", "release_version": release, "marty_ui_sha": source_id},
            "images": [],
        },
    )
    with pytest.raises(ContractError, match="marty-gateway image evidence"):
        validate_runtime_binding(deployment, context, source_id)


def test_full_finalize_requires_all_oss_cases_and_hosted_classification(tmp_path: Path) -> None:
    catalog = load("deploy-config/catalog/canvas-oss-portability.json")
    lock = load("deploy-config/catalog/canvas-oss.lock.json")
    lock["image"]["digest"] = image_manifest()["image_digest"]
    lock["image"]["digest_state"] = "published"
    driver_manifest = contract_driver_manifest()
    observations = {
        "schema_version": 1,
        "started_at": "2026-07-15T08:00:00+00:00",
        "execution": contract_execution(driver_manifest),
        "cases": [
            {
                "id": case["id"],
                "status": {"oss_required": "passed", "hosted_required": "hosted_required", "outside_gate": "outside_gate"}[case["classification"]],
                "evidence": "Sanitized contract observation.",
            }
            for case in catalog["cases"]
        ],
    }
    args = Namespace(
        config=ROOT / "deploy-config/catalog/canvas-oss-portability.json",
        lock=write(tmp_path / "lock.json", lock),
        image_manifest=write(tmp_path / "image.json", image_manifest()),
        bootstrap_audit=write(tmp_path / "bootstrap.json", bootstrap_audit()),
        runtime_context=write(
            tmp_path / "runtime.json",
            runtime_context("mip-0.3.1-local-test", "b" * 40),
        ),
        observations=write(tmp_path / "observations.json", observations),
        driver_manifest=write(tmp_path / "driver.json", driver_manifest),
        output=tmp_path / "result.json",
        mode="full",
    )
    result = finalize(args)
    Draft202012Validator(load("deploy-config/schemas/canvas-oss-portability-result.schema.json")).validate(result)
    assert result["status"] == "passed"
    assert set(result["canvas"]["runtime_dependencies"]) == {"postgres", "redis", "mailpit", "edge"}
    assert result["attestation"]["rails_runner_calls"] == 0
    assert result["driver"]["status"] == "executed"
    assert result["driver"]["host_browser_processes"] is False
    assert next(case for case in result["cases"] if case["id"].startswith("new_quizzes"))["status"] == "hosted_required"


def test_full_finalize_does_not_accept_skipped_required_case(tmp_path: Path) -> None:
    catalog = load("deploy-config/catalog/canvas-oss-portability.json")
    lock = load("deploy-config/catalog/canvas-oss.lock.json")
    lock["image"]["digest"] = image_manifest()["image_digest"]
    lock["image"]["digest_state"] = "published"
    observations = {
        "schema_version": 1,
        "cases": [
            {
                "id": case["id"],
                "status": "not_run" if case["id"] == "learner_resource_launch" else {"oss_required": "passed", "hosted_required": "hosted_required", "outside_gate": "outside_gate"}[case["classification"]],
                "evidence": "Sanitized contract observation.",
            }
            for case in catalog["cases"]
        ],
    }
    args = Namespace(
        config=ROOT / "deploy-config/catalog/canvas-oss-portability.json",
        lock=write(tmp_path / "lock.json", lock),
        image_manifest=write(tmp_path / "image.json", image_manifest()),
        bootstrap_audit=write(tmp_path / "bootstrap.json", bootstrap_audit()),
        runtime_context=write(tmp_path / "runtime.json", runtime_context("test", "b" * 40)),
        observations=write(tmp_path / "observations.json", observations),
        output=tmp_path / "result.json",
        mode="full",
    )
    with pytest.raises(ContractError, match="learner_resource_launch"):
        finalize(args)


def test_contract_driver_manifest_rejects_native_or_environment_secret_execution() -> None:
    lock = load("deploy-config/catalog/canvas-oss.lock.json")
    manifest = contract_driver_manifest()
    observations = {"execution": contract_execution(manifest)}
    observations["execution"]["host_browser_processes"] = True
    with pytest.raises(ContractError, match="Compose driver manifest"):
        validate_contract_driver_manifest(manifest, lock, observations)

    observations["execution"] = contract_execution(manifest)
    manifest["secret_transport"] = "environment"
    with pytest.raises(ContractError, match="secret_transport"):
        validate_contract_driver_manifest(manifest, lock, observations)


def test_full_finalize_requires_contract_driver_manifest(tmp_path: Path) -> None:
    catalog = load("deploy-config/catalog/canvas-oss-portability.json")
    lock = load("deploy-config/catalog/canvas-oss.lock.json")
    lock["image"]["digest"] = image_manifest()["image_digest"]
    lock["image"]["digest_state"] = "published"
    manifest = contract_driver_manifest()
    observations = {
        "schema_version": 1,
        "execution": contract_execution(manifest),
        "cases": [
            {
                "id": case["id"],
                "status": {"oss_required": "passed", "hosted_required": "hosted_required", "outside_gate": "outside_gate"}[case["classification"]],
                "evidence": "Sanitized contract observation.",
            }
            for case in catalog["cases"]
        ],
    }
    args = Namespace(
        config=ROOT / "deploy-config/catalog/canvas-oss-portability.json",
        lock=write(tmp_path / "lock.json", lock),
        image_manifest=write(tmp_path / "image.json", image_manifest()),
        bootstrap_audit=write(tmp_path / "bootstrap.json", bootstrap_audit()),
        runtime_context=write(tmp_path / "runtime.json", runtime_context("test", "b" * 40)),
        observations=write(tmp_path / "observations.json", observations),
        output=tmp_path / "result.json",
        mode="full",
        driver_manifest=None,
    )
    with pytest.raises(ContractError, match="Compose contract driver manifest"):
        finalize(args)
