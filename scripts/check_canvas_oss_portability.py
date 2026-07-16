#!/usr/bin/env python3
"""Validate and finalize the unmodified Canvas OSS portability evidence bundle.

This checker deliberately consumes only fixed-schema, sanitized observations. It
does not make Canvas management calls and it cannot turn missing scenarios into
passes. The browser/API driver is responsible for producing observations from
standard Canvas UI, LTI Advantage, and documented REST operations.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


EXPECTED_MARTY_ORIGIN = "https://beta.elevenidllc.com"
EXPECTED_CANVAS_ORIGIN = "https://canvas-test.elevenidllc.com"
IMAGE_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SOURCE_ID_RE = re.compile(r"^[0-9a-f]{40}$")
ALLOWED_BOOTSTRAP_COMMANDS = [
    ["bin/rails", "db:create"],
    ["bin/rails", "db:migrate"],
    ["bin/rails", "db:initial_setup"],
    ["bin/rails", "brand_configs:generate_and_upload_all"],
]
REQUIRED_BETA_RUNTIME_IMAGES = {
    "gateway": ("marty-gateway", "gateway"),
    "issuance": ("marty-issuance", "issuance"),
    "canvas-sync-worker": ("marty-canvas-sync-worker", "issuance"),
}
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


class ContractError(RuntimeError):
    pass


def _load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"Cannot read JSON {path}: {exc}") from exc


def _write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def validate_lock(lock: dict[str, Any]) -> None:
    _require(lock.get("schema_version") == 1, "Canvas OSS lock schema_version must be 1")
    source = lock.get("source", {})
    _require(source.get("repository") == "https://github.com/instructure/canvas-lms.git", "Canvas source repository is not upstream")
    _require(source.get("tag") == "release/2026-05-06.409", "Canvas source tag is not the reviewed release")
    _require(source.get("tag_object") == "116bf6129f2658f0c292f6242f966b19c1117309", "Canvas annotated tag object changed")
    _require(bool(SOURCE_ID_RE.fullmatch(str(source.get("commit", "")))), "Canvas source commit must be a full lowercase SHA")
    _require(source.get("commit") == "b6932922d0d06cef2667820a4dd6560b667e2bef", "Canvas release tag peeled commit changed")
    _require(source.get("tree") == "63f3a4528a7daaccc057eb4e2acac93af89d3c92", "Canvas reviewed source tree changed")
    _require(source.get("release_train") == "stable/2026-05-06", "Canvas release train changed")
    _require(source.get("dockerfile") == "Dockerfile.production", "Canvas must use upstream Dockerfile.production")
    _require(source.get("source_modified") is False, "Canvas source_modified must be false")
    image = lock.get("image", {})
    _require(str(image.get("repository", "")).startswith("ghcr.io/"), "Canvas image repository must be GHCR")
    digest = image.get("digest")
    state = image.get("digest_state")
    if digest is None:
        _require(state == "pending_source_build", "A missing image digest must remain pending_source_build")
    else:
        _require(bool(IMAGE_DIGEST_RE.fullmatch(str(digest))), "Canvas lock image digest is invalid")
        _require(state == "published", "A pinned image digest must be published")
    base_image = image.get("base_image")
    _require(
        base_image
        == {
            "reference": "instructure/ruby-passenger:3.4-jammy",
            "index_digest": "sha256:80d3a0e22c6ae228494de406d67fca88d7ff2de89fece021423206087190fcbe",
            "linux_amd64_digest": "sha256:f928f286e0ea1cbef59025251dbfd121ae748dc4f94a54c85240e842d459e776",
        },
        "Canvas upstream base image provenance changed",
    )
    labels = image.get("required_oci_labels")
    _require(isinstance(labels, dict), "Canvas required OCI labels are missing")
    expected_labels = {
        "org.opencontainers.image.source": "https://github.com/instructure/canvas-lms",
        "org.opencontainers.image.revision": source["commit"],
        "org.opencontainers.image.version": source["tag"],
        "org.opencontainers.image.ref.name": source["tag"],
        "org.opencontainers.image.base.name": base_image["reference"],
        "org.opencontainers.image.base.digest": base_image["index_digest"],
        "io.elevenid.canvas-oss.base.linux-amd64.digest": base_image["linux_amd64_digest"],
    }
    _require(labels == expected_labels, "Canvas required OCI image labels changed")
    runtime_dependencies = lock.get("runtime_dependencies")
    _require(isinstance(runtime_dependencies, dict), "Canvas runtime dependency lock is missing")
    expected_dependency_prefixes = {
        "postgres": "postgres:14-alpine@sha256:",
        "redis": "redis:7-alpine@sha256:",
        "mailpit": "axllent/mailpit:v1.27@sha256:",
        "edge": "nginx:1.27-alpine@sha256:",
    }
    _require(set(runtime_dependencies) == set(expected_dependency_prefixes), "Canvas runtime dependency lock is incomplete")
    for name, prefix in expected_dependency_prefixes.items():
        reference = str(runtime_dependencies[name])
        _require(
            reference.startswith(prefix) and bool(IMAGE_DIGEST_RE.fullmatch(reference.rsplit("@", 1)[-1])),
            f"Canvas runtime dependency {name} is not immutable",
        )
    driver = lock.get("contract_driver")
    _require(isinstance(driver, dict), "Canvas contract driver lock is missing")
    expected_driver = {
        "source_repository": "https://github.com/ElevenID/marty-ui",
        "dockerfile": "tests/Dockerfile.canvas-oss-contract",
        "package_manifest": "tests/canvas-oss-contract/package.json",
        "package_lock": "tests/canvas-oss-contract/package-lock.json",
        "audit_level": "high",
        "compose_service": "canvas-contract",
        "monitor_service": "canvas-continuity-monitor",
        "execution_boundary": "docker_compose_one_shot",
        "secret_transport": "compose_secret_files",
        "host_browser_processes": False,
    }
    for field, expected in expected_driver.items():
        _require(driver.get(field) == expected, f"Canvas contract driver {field} changed")
    _require(
        bool(
            re.fullmatch(
                r"mcr\.microsoft\.com/playwright:v1\.56\.0-jammy@sha256:[0-9a-f]{64}",
                str(driver.get("base_image", "")),
            )
        ),
        "Canvas contract driver base image is not immutable",
    )
    bootstrap = lock.get("bootstrap", {})
    _require(bootstrap.get("phase") == "pre_start_only", "Canvas bootstrap must be pre-start only")
    _require(bootstrap.get("allowed_commands") == ALLOWED_BOOTSTRAP_COMMANDS, "Canvas bootstrap allowlist changed")
    forbidden = set(bootstrap.get("forbidden_after_start", []))
    _require(
        {"rails_runner", "rails_console", "direct_database_access", "custom_canvas_plugin", "canvas_source_patch", "custom_event_ingest"}.issubset(forbidden),
        "Canvas post-start forbidden-operation policy is incomplete",
    )
    topology = lock.get("acceptance_topology", {})
    _require(topology.get("marty_origin") == EXPECTED_MARTY_ORIGIN, "Marty acceptance origin changed")
    _require(topology.get("canvas_origin") == EXPECTED_CANVAS_ORIGIN, "Canvas acceptance origin changed")
    _require(topology.get("docker_network") == "marty-infra-network", "Canvas must attach to the existing beta tunnel network")
    _require(topology.get("tunnel_owner") == "existing_beta_stack", "Acceptance must not start a competing tunnel")
    _require(topology.get("contract_service") == "canvas-contract", "Browser contract must be a Compose service")
    _require(topology.get("continuity_monitor_service") == "canvas-continuity-monitor", "Continuity monitor must be a Compose service")
    _require(topology.get("driver_execution") == "docker_compose_one_shot", "Browser contract must use a Compose one-shot")
    _require(topology.get("host_runtime_processes") is False, "Acceptance must not start host runtime processes")


def validate_execution_assets(lock: dict[str, Any], root: Path = REPOSITORY_ROOT) -> None:
    driver = lock["contract_driver"]
    base_image = lock["image"]["base_image"]
    compose = (root / "docker-compose.canvas-oss-acceptance.yml").read_text(encoding="utf-8")
    dockerfile = (root / driver["dockerfile"]).read_text(encoding="utf-8")
    package_manifest = json.loads((root / driver["package_manifest"]).read_text(encoding="utf-8"))
    package_lock = json.loads((root / driver["package_lock"]).read_text(encoding="utf-8"))
    workflow = (root / ".github/workflows/canvas-oss-portability.yml").read_text(encoding="utf-8")
    image_workflow = (root / ".github/workflows/canvas-oss-image.yml").read_text(encoding="utf-8")
    source_policy = json.loads((root / "docker/canvas-oss/source-policy.json").read_text(encoding="utf-8"))
    database_config = (root / "scripts/canvas-oss/generate-runtime-config.mjs").read_text(encoding="utf-8")
    _require("\n  canvas-contract:\n" in compose, "Canvas contract Compose service is missing")
    _require("\n  canvas-continuity-monitor:\n" in compose, "Canvas continuity monitor Compose service is missing")
    _require(f"dockerfile: {driver['dockerfile']}" in compose, "Canvas contract Compose Dockerfile differs from the lock")
    _require("profiles: [contract]" in compose and "profiles: [monitor]" in compose, "Canvas runtime profiles are incomplete")
    _require("CANVAS_OSS_ADMIN_PASSWORD_FILE: /run/secrets/canvas_admin_password" in compose, "Canvas contract admin password is not a secret file")
    _require("CANVAS_OSS_MARTY_API_KEY_FILE: /run/secrets/canvas_marty_api_key" in compose, "Canvas contract API key is not a secret file")
    _require("CANVAS_OSS_ADMIN_PASSWORD: ${" not in compose, "Canvas admin password is exposed through container environment")
    _require("CANVAS_OSS_MARTY_API_KEY: ${" not in compose, "Canvas Marty API key is exposed through container environment")
    _require("POSTGRES_PASSWORD: ${" not in compose, "Canvas PostgreSQL password is exposed through container environment")
    _require("POSTGRES_PASSWORD_FILE: /run/secrets/canvas_postgres_password" in compose, "Canvas PostgreSQL secret file is missing")
    _require(compose.count("pull_policy: never") >= 2, "Contract and monitor services must refuse registry pulls")
    _require("File.read(ENV.fetch('POSTGRES_PASSWORD_FILE')).strip" in database_config, "Canvas database config does not read its secret file")
    _require("FROM ${CANVAS_OSS_PLAYWRIGHT_IMAGE}" in dockerfile, "Contract Dockerfile does not consume the locked Playwright image")
    _require("npm audit --audit-level=high" in dockerfile, "Contract image does not fail on high-severity npm advisories")
    _require(package_manifest.get("dependencies") == {"@playwright/test": "1.56.0"}, "Contract package manifest is not Playwright-only")
    _require("devDependencies" not in package_manifest, "Contract package manifest contains unrelated development dependencies")
    allowed_packages = {"", "node_modules/@playwright/test", "node_modules/fsevents", "node_modules/playwright", "node_modules/playwright-core"}
    _require(set(package_lock.get("packages", {})) == allowed_packages, "Contract package lock contains unrelated dependencies")
    _require("io.elevenid.canvas-oss.execution-boundary=\"docker-compose-one-shot\"" in dockerfile, "Contract image execution label is missing")
    _require(driver["base_image"] in workflow or ".contract_driver.base_image" in workflow, "Workflow does not resolve the locked Playwright image")
    _require("--profile contract run --rm --no-deps canvas-contract" in workflow, "Workflow does not run the browser contract through Compose")
    _require("--profile monitor up --detach --no-deps canvas-continuity-monitor" in workflow, "Workflow does not run continuity monitoring through Compose")
    _require("gh attestation verify \"oci://$image\"" in workflow, "Workflow does not cryptographically verify Canvas image provenance")
    _require("--signer-workflow github.com/ElevenID/marty-ui/.github/workflows/canvas-oss-image.yml" in workflow, "Canvas image signer workflow is not pinned")
    _require("--source-ref refs/heads/main" in workflow, "Canvas image provenance is not bound to the default branch")
    expected_base_identifier = f"docker-image://docker.io/{base_image['reference']}"
    _require(
        source_policy
        == {
            "rules": [
                {
                    "action": "CONVERT",
                    "selector": {"identifier": expected_base_identifier},
                    "updates": {
                        "identifier": f"{expected_base_identifier}@{base_image['linux_amd64_digest']}"
                    },
                }
            ]
        },
        "Canvas BuildKit source policy does not pin the upstream base tag to the reviewed amd64 digest",
    )
    _require(
        "EXPERIMENTAL_BUILDKIT_SOURCE_POLICY: ${{ github.workspace }}/docker/canvas-oss/source-policy.json"
        in image_workflow,
        "Canvas image workflow does not apply the reviewed BuildKit source policy",
    )
    _require(
        'test "$actual_contract_image_id" = "$CANVAS_OSS_CONTRACT_IMAGE_ID"' in workflow,
        "Workflow does not rebind the contract run to the recorded local image ID",
    )
    for forbidden in ("npx playwright install", 'node "$driver"', "canvas_oss_beta_lifecycle.py monitor", "beta-monitor.pid"):
        _require(forbidden not in workflow, f"Workflow starts a forbidden native runtime process: {forbidden}")


def validate_catalog(catalog: dict[str, Any]) -> None:
    _require(catalog.get("schema_version") == 1, "Canvas OSS catalog schema_version must be 1")
    _require(catalog.get("suite") == "canvas_oss_portability", "Unexpected Canvas OSS suite")
    target = catalog.get("target", {})
    _require(target.get("marty_origin") == EXPECTED_MARTY_ORIGIN, "Catalog Marty origin changed")
    _require(target.get("canvas_origin") == EXPECTED_CANVAS_ORIGIN, "Catalog Canvas origin changed")
    cases = catalog.get("cases")
    _require(isinstance(cases, list) and cases, "Canvas OSS catalog must contain cases")
    ids = [case.get("id") for case in cases]
    _require(len(ids) == len(set(ids)), "Canvas OSS case IDs must be unique")
    classifications = {case.get("classification") for case in cases}
    _require(classifications == {"oss_required", "hosted_required", "outside_gate"}, "Canvas OSS classifications are invalid")
    by_id = {case["id"]: case for case in cases}
    _require(by_id.get("new_quizzes_authoritative_submission", {}).get("classification") == "hosted_required", "New Quizzes must be hosted_required")
    _require(by_id.get("canvas_credentials_projection", {}).get("classification") == "outside_gate", "Canvas Credentials must remain outside the production gate")
    policy = catalog.get("artifact_policy", {})
    for forbidden in ("allow_har", "allow_browser_storage", "allow_cookies", "allow_raw_claims", "allow_tokens"):
        _require(policy.get(forbidden) is False, f"Artifact policy must disable {forbidden}")
    expected_attestation = {
        "canvas_source_modified": False,
        "canvas_custom_plugins": [],
        "rails_runner_calls": 0,
        "rails_console_calls": 0,
        "post_bootstrap_database_access": False,
        "legacy_event_ingest": False,
        "new_quizzes": "hosted_required",
        "canvas_credentials": "outside_gate",
    }
    _require(catalog.get("portable_attestation") == expected_attestation, "Portable attestation defaults changed")


def validate_image_manifest(manifest: dict[str, Any], lock: dict[str, Any]) -> None:
    _require(manifest.get("schema_version") == 1, "Canvas image manifest schema_version must be 1")
    _require(manifest.get("source_repository") == "https://github.com/instructure/canvas-lms.git", "Image manifest source repository is not upstream")
    _require(manifest.get("source_commit") == lock["source"]["commit"], "Image manifest source commit does not match the reviewed lock")
    _require(manifest.get("source_tag") == lock["source"]["tag"], "Image manifest source tag does not match the reviewed lock")
    _require(manifest.get("source_tag_object") == lock["source"]["tag_object"], "Image manifest tag object does not match the reviewed lock")
    _require(manifest.get("source_tree") == lock["source"]["tree"], "Image manifest source tree does not match the reviewed lock")
    _require(bool(re.fullmatch(r"[0-9a-f]{64}", str(manifest.get("source_archive_sha256", "")))), "Image manifest source archive checksum is invalid")
    _require(manifest.get("release_train") == lock["source"]["release_train"], "Image manifest release train does not match the reviewed lock")
    _require(manifest.get("source_modified") is False, "Image manifest reports modified Canvas source")
    _require(manifest.get("dockerfile") == "Dockerfile.production", "Image manifest did not use Dockerfile.production")
    _require(bool(IMAGE_DIGEST_RE.fullmatch(str(manifest.get("image_digest", "")))), "Image manifest digest is invalid")
    _require(lock["image"].get("digest_state") == "published", "Canvas image lock is not published")
    _require(manifest.get("image_digest") == lock["image"].get("digest"), "Image manifest digest does not match the reviewed lock")
    _require(manifest.get("base_image") == lock["image"]["base_image"], "Image manifest base image does not match the reviewed lock")
    source_policy_path = REPOSITORY_ROOT / "docker/canvas-oss/source-policy.json"
    source_policy_sha256 = hashlib.sha256(source_policy_path.read_bytes()).hexdigest()
    _require(
        manifest.get("base_source_policy") == "docker/canvas-oss/source-policy.json",
        "Image manifest does not identify the reviewed base source policy",
    )
    _require(
        manifest.get("base_source_policy_sha256") == source_policy_sha256,
        "Image manifest base source policy digest does not match the reviewed policy",
    )
    _require(manifest.get("oci_labels") == lock["image"]["required_oci_labels"], "Image manifest OCI labels do not match the reviewed lock")
    _require(manifest.get("sbom") is True, "Canvas image must publish an SBOM")
    _require(manifest.get("provenance") is True, "Canvas image must publish build provenance")


def validate_bootstrap_audit(audit: dict[str, Any]) -> None:
    _require(audit.get("schema_version") == 1, "Bootstrap audit schema_version must be 1")
    _require(audit.get("phase") == "pre_start_only", "Bootstrap audit phase is invalid")
    commands = audit.get("commands")
    _require(isinstance(commands, list), "Bootstrap audit commands must be an array")
    actual = [entry.get("argv") for entry in commands]
    _require(actual == ALLOWED_BOOTSTRAP_COMMANDS, "Bootstrap executed a command outside the exact lifecycle allowlist")
    _require(all(entry.get("exit_code") == 0 for entry in commands), "A Canvas lifecycle bootstrap command failed")
    _require(audit.get("web_started_after_bootstrap") is True, "Canvas web started before lifecycle bootstrap completed")
    counters = audit.get("forbidden_operation_counts", {})
    expected = {
        "rails_runner": 0,
        "rails_console": 0,
        "post_bootstrap_database_access": 0,
        "custom_plugins": 0,
        "source_patches": 0,
        "custom_events": 0,
    }
    _require(counters == expected, "Bootstrap audit contains forbidden operations")


def validate_contract_driver_manifest(
    manifest: dict[str, Any],
    lock: dict[str, Any],
    observations: dict[str, Any],
) -> dict[str, Any]:
    driver = lock["contract_driver"]
    _require(manifest.get("schema_version") == 1, "Contract driver manifest schema_version must be 1")
    exact = {
        "execution_boundary": driver["execution_boundary"],
        "compose_project": "canvas-oss-portability",
        "compose_service": driver["compose_service"],
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
    }
    for field, expected in exact.items():
        _require(manifest.get(field) == expected, f"Contract driver manifest {field} is invalid")
    image_id = str(manifest.get("image_id", ""))
    source_sha = str(manifest.get("source_sha", ""))
    _require(bool(IMAGE_DIGEST_RE.fullmatch(image_id)), "Contract driver image ID is invalid")
    _require(bool(SOURCE_ID_RE.fullmatch(source_sha)), "Contract driver source SHA is invalid")
    _require(
        manifest.get("image_reference") == f"elevenid-local/canvas-oss-contract:{source_sha}",
        "Contract driver image reference is not source-bound",
    )
    labels = manifest.get("labels")
    _require(isinstance(labels, dict), "Contract driver OCI labels are missing")
    _require(labels.get("org.opencontainers.image.source") == driver["source_repository"], "Contract driver source label is invalid")
    _require(labels.get("org.opencontainers.image.revision") == source_sha, "Contract driver revision label is invalid")
    _require(
        labels.get("io.elevenid.canvas-oss.execution-boundary") == "docker-compose-one-shot",
        "Contract driver execution label is invalid",
    )
    execution = observations.get("execution")
    _require(isinstance(execution, dict), "Full observations are missing container execution evidence")
    expected_execution = {
        "boundary": driver["execution_boundary"],
        "compose_service": driver["compose_service"],
        "containerized": True,
        "host_browser_processes": False,
        "secret_transport": driver["secret_transport"],
        "image_id": image_id,
        "source_sha": source_sha,
        "base_image": driver["base_image"],
    }
    _require(execution == expected_execution, "Browser observations do not match the Compose driver manifest")
    return {
        "status": "executed",
        "execution_boundary": driver["execution_boundary"],
        "compose_service": driver["compose_service"],
        "image_id": image_id,
        "source_sha": source_sha,
        "base_image": driver["base_image"],
        "secret_transport": driver["secret_transport"],
        "host_browser_processes": False,
    }


def _public_json(url: str) -> dict[str, Any]:
    request = urllib.request.Request(url, headers={"Cache-Control": "no-cache", "User-Agent": "canvas-oss-portability/1"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:  # noqa: S310 - fixed public origins only
            _require(response.status == 200, f"Unexpected status from {url}")
            payload = json.loads(response.read().decode("utf-8"))
    except Exception as exc:  # urllib exposes several transport-specific errors
        raise ContractError(f"Cannot read release marker {url}: {exc}") from exc
    _require(isinstance(payload, dict), f"Release marker {url} is not an object")
    return payload


def capture_runtime_context(output: Path) -> dict[str, Any]:
    services = _public_json(f"{EXPECTED_MARTY_ORIGIN}/.well-known/marty-release")
    ui = _public_json(f"{EXPECTED_MARTY_ORIGIN}/marty-ui-release.json")
    _require(services.get("component") == "services", "Services release marker component is invalid")
    _require(ui.get("component") == "ui", "UI release marker component is invalid")
    _require(services.get("release_version") == ui.get("release_version"), "Beta services and UI release versions differ")
    _require(services.get("marty_ui_sha") == ui.get("marty_ui_sha"), "Beta services and UI source IDs differ")
    _require(bool(SOURCE_ID_RE.fullmatch(str(services.get("marty_ui_sha", "")))), "Beta source ID must be 40 lowercase hex characters")
    _require(
        services.get("deployment_release_marker") == services.get("release_version"),
        "Beta services marker is not from a coordinated full release",
    )
    image_digests = services.get("image_digests")
    _require(isinstance(image_digests, dict), "Beta services marker has no coordinated image inventory")
    for service in REQUIRED_BETA_RUNTIME_IMAGES:
        _require(
            bool(IMAGE_DIGEST_RE.fullmatch(str(image_digests.get(service, "")))),
            f"Beta services marker is missing the coordinated {service} image",
        )
    context = {
        "schema_version": 1,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "origin": EXPECTED_MARTY_ORIGIN,
        "release_version": services["release_version"],
        "source_id": services["marty_ui_sha"],
        "deployment_release_marker": services["deployment_release_marker"],
        "service_image_digests": image_digests,
    }
    _write(output, context)
    return context


def _validate_context(context: dict[str, Any]) -> None:
    _require(context.get("schema_version") == 1, "Runtime context schema_version must be 1")
    _require(context.get("origin") == EXPECTED_MARTY_ORIGIN, "Runtime context Marty origin changed")
    _require(bool(context.get("release_version")), "Runtime context release_version is missing")
    _require(bool(SOURCE_ID_RE.fullmatch(str(context.get("source_id", "")))), "Runtime context source_id is invalid")
    _require(
        context.get("deployment_release_marker") == context.get("release_version"),
        "Runtime context was not captured from a coordinated full beta release",
    )
    image_digests = context.get("service_image_digests")
    _require(isinstance(image_digests, dict), "Runtime context service image inventory is missing")
    for service in REQUIRED_BETA_RUNTIME_IMAGES:
        _require(
            bool(IMAGE_DIGEST_RE.fullmatch(str(image_digests.get(service, "")))),
            f"Runtime context {service} image is missing",
        )


def validate_runtime_binding(manifest_path: Path, context_path: Path, expected_source_id: str) -> None:
    manifest = _load(manifest_path)
    context = _load(context_path)
    _validate_context(context)
    _require(manifest.get("release_version") == context.get("release_version"), "Runtime release does not match deployment manifest")
    _require(context.get("source_id") == expected_source_id, "Runtime source does not match the explicitly reviewed source ID")
    _require(
        not isinstance(manifest.get("runtime_source"), dict) and manifest.get("backend_images_reused") is not True,
        "UI-only/reused-backend beta manifests cannot qualify for Canvas portability acceptance",
    )

    # Only the coordinated full local release runner proves that the gateway,
    # issuance API, and durable Canvas worker were built from and deployed with
    # the same reviewed worktree snapshot.
    _require(manifest.get("schema_version") == 1, "Beta deployment manifest schema_version must be 1")
    _require(manifest.get("beta_origin") == EXPECTED_MARTY_ORIGIN, "Beta deployment manifest origin changed")
    _require(manifest.get("marty_ui_sha") == context.get("source_id"), "Runtime source does not match deployment manifest")
    _require(manifest.get("source_kind") == "local-worktree-snapshot", "Unsupported beta deployment source kind")
    _require(manifest.get("source_manifest") == "source-manifest.json", "Local deployment source_manifest is invalid")
    source_manifest = _load(manifest_path.parent / "source-manifest.json")
    _require(source_manifest.get("release_version") == context.get("release_version"), "Source snapshot release does not match runtime")
    _require(source_manifest.get("marty_ui_sha") == context.get("source_id"), "Source snapshot ID does not match runtime")
    _require(source_manifest.get("promotion_eligible") is False, "Local snapshot cannot be promotion eligible")
    _require(source_manifest.get("release_ready") is False, "Local snapshot cannot be release ready")
    _require(source_manifest.get("source_kind") == "local-worktree-snapshot", "Source snapshot kind is invalid")

    services_marker = manifest.get("services_marker")
    ui_marker = manifest.get("ui_marker")
    _require(isinstance(services_marker, dict), "Coordinated services release marker is missing")
    _require(isinstance(ui_marker, dict), "Coordinated UI release marker is missing")
    for name, marker, component in (
        ("services", services_marker, "services"),
        ("ui", ui_marker, "ui"),
    ):
        _require(marker.get("component") == component, f"Coordinated {name} marker component is invalid")
        _require(marker.get("release_version") == context.get("release_version"), f"Coordinated {name} marker release differs")
        _require(marker.get("marty_ui_sha") == context.get("source_id"), f"Coordinated {name} marker source differs")
    _require(
        services_marker.get("deployment_release_marker") == context.get("release_version"),
        "Services deployment release marker differs from the reviewed release",
    )

    marker_images = services_marker.get("image_digests")
    _require(isinstance(marker_images, dict), "Services marker image digest inventory is missing")
    _require(
        marker_images == context.get("service_image_digests"),
        "Public beta image inventory differs from the coordinated deployment manifest",
    )
    records = manifest.get("images")
    _require(isinstance(records, list), "Coordinated deployment container image evidence is missing")
    by_container = {
        str(record.get("container")): record
        for record in records
        if isinstance(record, dict) and record.get("container")
    }
    release = str(context["release_version"])
    for service, (container, image_service) in REQUIRED_BETA_RUNTIME_IMAGES.items():
        record = by_container.get(container)
        _require(record is not None, f"Coordinated deployment is missing {container} image evidence")
        expected_reference = f"elevenid-local/{image_service}:{release}"
        _require(record.get("configured_image") == expected_reference, f"{container} is not configured from the coordinated release image")
        image_id = str(record.get("image_id", ""))
        _require(bool(IMAGE_DIGEST_RE.fullmatch(image_id)), f"{container} image ID is invalid")
        _require(marker_images.get(service) == image_id, f"{container} image does not match the services release marker")
        _require(record.get("status") == "running", f"{container} was not running when deployment evidence was captured")
    _require(
        marker_images.get("issuance") == marker_images.get("canvas-sync-worker"),
        "Canvas sync worker must reuse the coordinated issuance image",
    )


def _validate_observations(catalog: dict[str, Any], observations: dict[str, Any], mode: str) -> list[dict[str, str]]:
    _require(observations.get("schema_version") == 1, "Observations schema_version must be 1")
    entries = observations.get("cases")
    _require(isinstance(entries, list), "Observations cases must be an array")
    observed = {entry.get("id"): entry for entry in entries}
    _require(len(observed) == len(entries), "Observation case IDs must be unique")
    result: list[dict[str, str]] = []
    for definition in catalog["cases"]:
        case_id = definition["id"]
        classification = definition["classification"]
        entry = observed.get(case_id, {"status": "not_run", "evidence": "No sanitized observation was produced."})
        status = entry.get("status")
        evidence = entry.get("evidence", "")
        _require(isinstance(evidence, str) and len(evidence) <= 240, f"{case_id} evidence must be a short sanitized string")
        if classification == "hosted_required":
            _require(status == "hosted_required", f"{case_id} must be hosted_required, never passed or skipped")
        elif classification == "outside_gate":
            _require(status == "outside_gate", f"{case_id} must remain outside_gate")
        else:
            _require(status in {"passed", "failed", "not_run"}, f"{case_id} has an invalid status")
            if mode == "full":
                _require(status == "passed", f"Required OSS case did not pass: {case_id}")
        result.append({"id": case_id, "classification": classification, "status": status, "evidence": evidence})
    extra = set(observed) - {case["id"] for case in catalog["cases"]}
    _require(not extra, f"Unknown observation cases: {', '.join(sorted(extra))}")
    return result


def finalize(args: argparse.Namespace) -> dict[str, Any]:
    lock = _load(args.lock)
    validate_lock(lock)
    validate_execution_assets(lock)
    catalog = _load(args.config)
    validate_catalog(catalog)
    image = _load(args.image_manifest)
    validate_image_manifest(image, lock)
    audit = _load(args.bootstrap_audit)
    validate_bootstrap_audit(audit)
    context = _load(args.runtime_context)
    _validate_context(context)
    observations = _load(args.observations)
    cases = _validate_observations(catalog, observations, args.mode)
    driver_manifest_path = getattr(args, "driver_manifest", None)
    if args.mode == "full":
        _require(driver_manifest_path is not None, "Full finalization requires the Compose contract driver manifest")
        driver_result = validate_contract_driver_manifest(_load(driver_manifest_path), lock, observations)
    else:
        driver = lock["contract_driver"]
        driver_result = {
            "status": "not_run",
            "execution_boundary": driver["execution_boundary"],
            "compose_service": driver["compose_service"],
            "image_id": None,
            "source_sha": None,
            "base_image": driver["base_image"],
            "secret_transport": driver["secret_transport"],
            "host_browser_processes": False,
        }
    status = "readiness_only" if args.mode == "readiness_only" else "passed"
    result = {
        "schema_version": 1,
        "suite": "canvas_oss_portability",
        "status": status,
        "run": {
            "started_at": observations.get("started_at", datetime.now(timezone.utc).isoformat()),
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "mode": args.mode,
        },
        "canvas": {
            "source_tag": image["source_tag"],
            "source_tag_object": image["source_tag_object"],
            "source_commit": image["source_commit"],
            "source_tree": image["source_tree"],
            "release_train": image["release_train"],
            "image_digest": image["image_digest"],
            "base_image": image["base_image"],
            "origin": EXPECTED_CANVAS_ORIGIN,
            "runtime_dependencies": lock["runtime_dependencies"],
        },
        "marty": {
            "origin": EXPECTED_MARTY_ORIGIN,
            "release_version": context["release_version"],
            "source_id": context["source_id"],
        },
        "driver": driver_result,
        "attestation": catalog["portable_attestation"],
        "cases": cases,
    }
    _write(args.output, result)
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=Path("deploy-config/catalog/canvas-oss-portability.json"))
    parser.add_argument("--lock", type=Path, default=Path("deploy-config/catalog/canvas-oss.lock.json"))
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--validate-config", action="store_true")
    action.add_argument("--capture-runtime-context", type=Path)
    action.add_argument("--validate-runtime-binding", type=Path)
    action.add_argument("--finalize", action="store_true")
    parser.add_argument("--image-manifest", type=Path)
    parser.add_argument("--bootstrap-audit", type=Path)
    parser.add_argument("--runtime-context", type=Path)
    parser.add_argument("--observations", type=Path)
    parser.add_argument("--driver-manifest", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--mode", choices=("full", "readiness_only"), default="full")
    parser.add_argument("--expected-source-id")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        lock = _load(args.lock)
        validate_lock(lock)
        validate_execution_assets(lock)
        validate_catalog(_load(args.config))
        if args.capture_runtime_context:
            capture_runtime_context(args.capture_runtime_context)
        elif args.validate_runtime_binding:
            _require(args.runtime_context is not None, "Runtime binding validation requires --runtime-context")
            _require(bool(args.expected_source_id), "Runtime binding validation requires --expected-source-id")
            validate_runtime_binding(args.validate_runtime_binding, args.runtime_context, args.expected_source_id)
        elif args.finalize:
            missing = [name for name in ("image_manifest", "bootstrap_audit", "runtime_context", "observations", "output") if getattr(args, name) is None]
            _require(not missing, f"Finalization requires: {', '.join(missing)}")
            finalize(args)
    except ContractError as exc:
        print(f"Canvas OSS portability contract failed: {exc}", file=sys.stderr)
        return 1
    print("Canvas OSS portability contract validated.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
