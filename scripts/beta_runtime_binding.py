"""Validate coordinated platform release image and source evidence."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

BETA_PROJECT = 'elevenid-beta'

EXPECTED_MARTY_ORIGIN = "https://beta.elevenidllc.com"


IMAGE_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


SOURCE_ID_RE = re.compile(r"^[0-9a-f]{40}$")


REQUIRED_BETA_RUNTIME_IMAGES = {
    "gateway": ("marty-gateway", "gateway"),
    "issuance": ("marty-issuance", "issuance"),
}


class ContractError(RuntimeError):
    pass


def _load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"Cannot read JSON {path}: {exc}") from exc


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


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
        "UI-only/reused-backend beta manifests cannot qualify for platform runtime acceptance",
    )

    # Only the coordinated full local release runner proves that the gateway,
    # issuance API were built from and deployed with
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
    _require(all(isinstance(record, dict) for record in records), "Invalid deployment image record")
    compose_owned = "compose_project" in manifest
    if compose_owned:
        _require(manifest["compose_project"] == BETA_PROJECT, "Deployment Compose project is not beta")
    else:
        _require(
            not any("compose_project" in record or "compose_service" in record for record in records),
            "Compose image evidence requires its deployment project",
        )
    release = str(context["release_version"])
    for service, (container, image_service) in REQUIRED_BETA_RUNTIME_IMAGES.items():
        matches = [record for record in records if (
            record.get("service") == service or record.get("compose_service") == service
        )] if compose_owned else [record for record in records if record.get("container") == container]
        _require(matches, f"Coordinated deployment is missing {container} image evidence")
        _require(len(matches) == 1, f"Coordinated deployment requires exactly one {container} image record")
        record = matches[0]
        image_id = str(record.get("image_id", ""))
        _require(bool(IMAGE_DIGEST_RE.fullmatch(image_id)), f"{container} image ID is invalid")
        expected_reference = f"elevenid-local/{image_service}:{release}"
        if compose_owned:
            _require(
                record.get("compose_project") == BETA_PROJECT
                and record.get("compose_service") == service and record.get("service") == service,
                f"{container} Compose ownership or service role differs",
            )
            _require(
                bool(re.fullmatch(r"[0-9a-f]{64}", str(record.get("container_id", ""))))
                and record.get("running") is True,
                f"{container} running container identity is missing",
            )
            environment = record.get("runtime_marker_environment", {})
            _require(
                isinstance(environment, dict)
                and environment.get("MARTY_UI_SHA") == context["source_id"]
                and environment.get("MARTY_RELEASE_VERSION") == release,
                f"{container} runtime source or release differs",
            )
            # Prepared shared Rust runtimes are configured by immutable image ID;
            # historical split images retain the coordinated release tag contract.
            if IMAGE_DIGEST_RE.fullmatch(str(record.get("configured_image", ""))):
                expected_reference = image_id
        _require(record.get("configured_image") == expected_reference, f"{container} is not configured from the coordinated release image")
        _require(marker_images.get(service) == image_id, f"{container} image does not match the services release marker")
        _require(record.get("status") == "running", f"{container} was not running when deployment evidence was captured")
