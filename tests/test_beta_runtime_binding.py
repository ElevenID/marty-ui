from __future__ import annotations

import json
from pathlib import Path
import pytest
from scripts.beta_runtime_binding import ContractError, validate_runtime_binding



def write(path: Path, value: dict) -> Path:
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def runtime_context(
    release: str, source_id: str, *, gateway: str = "1", issuance: str = "2"
) -> dict:
    return {
        "schema_version": 1,
        "origin": "https://beta.elevenidllc.com",
        "release_version": release,
        "source_id": source_id,
        "deployment_release_marker": release,
        "service_image_digests": {
            "gateway": "sha256:" + gateway * 64,
            "issuance": "sha256:" + issuance * 64,
                    },
    }


def runtime_binding_fixture(tmp_path: Path) -> tuple[Path, Path, str]:
    source_id = "c" * 40
    context = write(
        tmp_path / "runtime.json",
        runtime_context("mip-0.5.0-local-test", source_id),
    )
    write(
        tmp_path / "source-manifest.json",
        {
            "schema_version": 1,
            "source_kind": "local-worktree-snapshot",
            "release_version": "mip-0.5.0-local-test",
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
            "release_version": "mip-0.5.0-local-test",
            "marty_ui_sha": source_id,
            "beta_origin": "https://beta.elevenidllc.com",
            "source_manifest": "source-manifest.json",
            "services_marker": {
                "component": "services",
                "release_version": "mip-0.5.0-local-test",
                "marty_ui_sha": source_id,
                "deployment_release_marker": "mip-0.5.0-local-test",
                "image_digests": {
                    "gateway": "sha256:" + "1" * 64,
                    "issuance": "sha256:" + "2" * 64,
                                    },
            },
            "ui_marker": {
                "component": "ui",
                "release_version": "mip-0.5.0-local-test",
                "marty_ui_sha": source_id,
            },
            "images": [
                {
                    "container": container,
                    "configured_image": f"elevenid-local/{image_service}:mip-0.5.0-local-test",
                    "image_id": image_id,
                    "status": "running",
                }
                for container, image_service, image_id in (
                    ("marty-gateway", "gateway", "sha256:" + "1" * 64),
                    ("marty-issuance", "issuance", "sha256:" + "2" * 64),
                )
            ],
        },
    )
    return deployment, context, source_id


@pytest.mark.parametrize("worker_mismatch", [None, "image_id", "configured_image"])
def test_runtime_binding_requires_deployment_and_source_snapshot(
    tmp_path: Path, worker_mismatch: str | None,
) -> None:
    deployment, context, source_id = runtime_binding_fixture(tmp_path)
    validate_runtime_binding(deployment, context, source_id)
    with pytest.raises(ContractError, match="explicitly reviewed"):
        validate_runtime_binding(deployment, context, "d" * 40)
    if worker_mismatch is not None:
        changed = json.loads(deployment.read_text(encoding="utf-8"))
        worker = next(
            item
            for item in changed["images"]
            if item["container"] == "marty-issuance"
        )
        worker[worker_mismatch] = (
            "sha256:" + "9" * 64
            if worker_mismatch == "image_id"
            else "elevenid-local/gateway:mip-0.5.0-local-test"
        )
        write(deployment, changed)
        with pytest.raises(ContractError):
            validate_runtime_binding(deployment, context, source_id)


@pytest.mark.parametrize("changed", [
    None, "project", "role", "duplicate", "image", "tag", "source", "release",
    "running", "container_id", "missing_project",
])
def test_runtime_binding_compose_owned_immutable_shared_image(tmp_path: Path, changed: str | None) -> None:
    deployment, context_path, source_id = runtime_binding_fixture(tmp_path)
    manifest = json.loads(deployment.read_text())
    context = json.loads(context_path.read_text())
    shared = "sha256:" + "4" * 64
    manifest["compose_project"] = "elevenid-beta"
    for index, record in enumerate(manifest["images"]):
        role = record["container"].removeprefix("marty-")
        record.update(container=f"elevenid-beta-{role}-1", container_id=str(index + 1) * 64,
                      service=role, compose_project="elevenid-beta", compose_service=role,
                      configured_image=shared, image_id=shared, running=True,
                      runtime_marker_environment={"MARTY_UI_SHA": source_id,
                                                  "MARTY_RELEASE_VERSION": context["release_version"]})
        context["service_image_digests"][role] = shared
    manifest["services_marker"]["image_digests"] = context["service_image_digests"]
    worker = manifest["images"][-1]
    if changed == "project":
        worker["compose_project"] = "self-host-production"
    elif changed == "role":
        worker["compose_service"] = "gateway"
    elif changed == "duplicate":
        manifest["images"].append(dict(worker))
    elif changed == "image":
        worker["image_id"] = "sha256:" + "5" * 64
        worker["configured_image"] = worker["image_id"]
    elif changed == "tag":
        worker["configured_image"] = "elevenid-local/services:latest"
    elif changed == "source":
        worker["runtime_marker_environment"]["MARTY_UI_SHA"] = "d" * 40
    elif changed == "release":
        worker["runtime_marker_environment"]["MARTY_RELEASE_VERSION"] = "old-release"
    elif changed == "running":
        worker["running"] = False
    elif changed == "container_id":
        del worker["container_id"]
    elif changed == "missing_project":
        del manifest["compose_project"]
    write(deployment, manifest)
    write(context_path, context)
    if changed is None:
        validate_runtime_binding(deployment, context_path, source_id)
    else:
        with pytest.raises(ContractError):
            validate_runtime_binding(deployment, context_path, source_id)


def test_runtime_binding_rejects_current_ui_only_reused_backend_manifest(
    tmp_path: Path,
) -> None:
    source_id = "1" * 40
    source_digest = source_id + "2" * 24
    revision = "3" * 40
    release = "mip-0.5.0-local-current"
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
        name: {
            "component": component,
            "release_version": release,
            "marty_ui_sha": source_id,
        }
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
            "runtime_source": {
                "repository": "marty-ui",
                "revision": revision,
                "source_digest": source_digest,
                "release_source_id": source_id,
            },
            "image": {
                "reference": f"elevenid-local/ui:{release}",
                "id": "sha256:" + "4" * 64,
            },
            "markers": markers,
            "backend_images_reused": True,
        },
    )
    with pytest.raises(ContractError, match="UI-only/reused-backend"):
        validate_runtime_binding(deployment, context, source_id)


def test_runtime_binding_rejects_missing_required_runtime_image(tmp_path: Path) -> None:
    source_id = "c" * 40
    release = "mip-0.5.0-local-test"
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
                "image_digests": runtime_context(release, source_id)[
                    "service_image_digests"
                ],
            },
            "ui_marker": {
                "component": "ui",
                "release_version": release,
                "marty_ui_sha": source_id,
            },
            "images": [],
        },
    )
    with pytest.raises(ContractError, match="marty-gateway image evidence"):
        validate_runtime_binding(deployment, context, source_id)
