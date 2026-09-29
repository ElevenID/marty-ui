#!/usr/bin/env python3
"""Bind passport acceptance to one signed aggregate beta deployment generation."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Callable

try:
    from .check_passport_beta_fence_authority import (
        manifest_source, verify_issuance_attestation,
    )
    from .collect_passport_beta_acceptance import (
        BETA_ORIGIN, REQUIRED_PROBES, SERVICES, EvidenceError, digest_file,
        docker_inspect, get_capabilities, production_attachment_commitment,
        production_snapshot_commitment,
        read_json, require,
    )
    from .prepare_passport_beta_aggregate_compose import SIGNED_APPLICATIONS, INGRESS
    from .probe_passport_beta_host import ids
except ImportError:
    from check_passport_beta_fence_authority import (
        manifest_source, verify_issuance_attestation,
    )
    from collect_passport_beta_acceptance import (
        BETA_ORIGIN, REQUIRED_PROBES, SERVICES, EvidenceError, digest_file,
        docker_inspect, get_capabilities, production_attachment_commitment,
        production_snapshot_commitment,
        read_json, require,
    )
    from prepare_passport_beta_aggregate_compose import SIGNED_APPLICATIONS, INGRESS
    from probe_passport_beta_host import ids


SHA = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
CONTAINER = re.compile(r"[0-9a-f]{64}\Z")
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
RUNTIME_KEYS = {"container_id", "image_id", "configured_image", "started_at",
                "config_hash", "networks"}


def _runtime_image(
    service: str, expected: dict[str, Any], project: str,
    inspect: Callable[[str], dict[str, Any]],
) -> dict[str, str]:
    require(isinstance(expected, dict) and set(expected) == RUNTIME_KEYS,
            "Aggregate beta runtime identity is incomplete")
    container_id = expected["container_id"]
    require(isinstance(container_id, str) and CONTAINER.fullmatch(container_id) is not None
            and isinstance(expected["image_id"], str)
            and IMAGE_ID.fullmatch(expected["image_id"]) is not None
            and isinstance(expected["configured_image"], str)
            and bool(expected["configured_image"])
            and isinstance(expected["started_at"], str)
            and bool(expected["started_at"])
            and (expected["config_hash"] is None or
                 isinstance(expected["config_hash"], str))
            and isinstance(expected["networks"], list)
            and bool(expected["networks"])
            and all(isinstance(name, str) and bool(name)
                    for name in expected["networks"])
            and expected["networks"] == sorted(set(expected["networks"])),
            "Aggregate beta runtime identity is invalid")
    live = inspect(container_id)
    config = live.get("Config")
    state = live.get("State")
    labels = config.get("Labels") if isinstance(config, dict) else None
    networks = live.get("NetworkSettings", {}).get("Networks")
    require(isinstance(labels, dict) and isinstance(state, dict)
            and isinstance(networks, dict)
            and live.get("Id") == container_id
            and live.get("Image") == expected["image_id"]
            and config.get("Image") == expected["configured_image"]
            and labels.get("com.docker.compose.project") == project
            and labels.get("com.docker.compose.service") == service
            and labels.get("com.docker.compose.config-hash") == expected["config_hash"]
            and state.get("Running") is True and state.get("Status") == "running"
            and state.get("StartedAt") == expected["started_at"]
            and sorted(networks) == expected["networks"],
            "Aggregate beta runtime differs from deployment receipt")
    health = state.get("Health")
    require(health is None or (isinstance(health, dict)
                              and health.get("Status") == "healthy"),
            "Aggregate beta runtime is unhealthy")
    return {"container_id": container_id, "image_id": expected["image_id"],
            "oci_reference": expected["configured_image"]}


def collect_aggregate(
    artifact_dir: Path, *, api_key: str | None = None,
    inspect: Callable[[str], dict[str, Any]] = docker_inspect,
    probe: Callable[[str | None], tuple[int, dict[str, Any] | None]] = get_capabilities,
    attest: Callable[[Path, dict[str, str], str], bool] | None = None,
    attest_issuance: Callable[[str, str, str], bool] = verify_issuance_attestation,
    list_ids: Callable[[str], list[str]] = ids,
) -> dict[str, Any]:
    receipt_path = artifact_dir / "aggregate-deployment.json"
    plan_path = artifact_dir / "aggregate-deployment.json.plan.json"
    manifest_path = artifact_dir / "stack-manifest.json"
    receipt = read_json(receipt_path)
    plan = read_json(plan_path)
    source = receipt.get("source_commit")
    require(receipt.get("schema") == "marty.passport-beta-aggregate-deployment/v1"
            and receipt.get("beta_origin") == BETA_ORIGIN
            and receipt.get("acceptance_pending") is True
            and isinstance(source, str) and SHA.fullmatch(source) is not None
            and plan.get("schema") == "marty.passport-beta-aggregate-compose-plan/v1"
            and plan.get("source_commit") == source
            and plan.get("beta_origin") == BETA_ORIGIN
            and receipt.get("plan_sha256") == digest_file(plan_path).removeprefix("sha256:")
            and plan.get("stack_manifest_sha256")
                == digest_file(manifest_path).removeprefix("sha256:")
            and receipt.get("native_receipt_sha256") == plan.get("native_receipt_sha256")
            and receipt.get("production_snapshot_sha256")
                == plan.get("production_snapshot_sha256")
            and isinstance(plan.get("production_attachments_sha256"), str)
            and SHA256.fullmatch(plan["production_attachments_sha256"]) is not None,
            "Aggregate beta receipt, plan or source differs")
    require(attest is not None,
            "Aggregate beta acceptance requires signed release attestations")
    require(isinstance(api_key, str) and len(api_key) >= 32,
            "Aggregate beta acceptance requires a governed organization key")
    try:
        signed = manifest_source(manifest_path, source, attest, attest_issuance)
    except (OSError, ValueError) as exc:
        raise EvidenceError("Aggregate signed release did not verify") from exc
    require(signed["manifest_sha256"] == plan["stack_manifest_sha256"]
            and signed["services_image"] == plan.get("services_image")
            and signed["issuance_image"] == plan.get("issuance_image")
            and signed["oci_digests"].get("ghcr.io/elevenid/marty-ui-oss/ui")
                == str(plan.get("ui_image", "")).partition("@")[2],
            "Aggregate beta plan differs from signed stack images")
    runtime = receipt.get("beta_runtime")
    names = receipt.get("beta_services")
    targets = plan.get("target_services")
    expected_networks = plan.get("expected_networks_by_service")
    require(isinstance(runtime, dict) and isinstance(names, list)
            and isinstance(targets, list) and isinstance(expected_networks, dict)
            and set(runtime) == set(names) == set(targets) | {"postgres"}
            and len(names) == len(runtime)
            and set(expected_networks) == set(runtime)
            and set(SERVICES).issubset(runtime)
            and "passport-provider-ingress" not in runtime,
            "Aggregate beta simulator service inventory is invalid")
    expected_ids = {identity.get("container_id") for identity in runtime.values()
                    if isinstance(identity, dict)}
    require(len(expected_ids) == len(runtime),
            "Aggregate beta runtime has duplicate container IDs")
    for project, expected in (("elevenid-beta", expected_ids),
                              ("elevenid-beta-ui", {receipt.get("ui_container_id")})):
        listed = list_ids(project)
        require(isinstance(listed, list) and len(listed) == len(set(listed)),
                "Aggregate beta live project inventory is ambiguous")
        live_ids = set()
        for short_id in listed:
            record = inspect(short_id)
            config = record.get("Config")
            labels = config.get("Labels") if isinstance(config, dict) else None
            require(isinstance(labels, dict)
                    and labels.get("com.docker.compose.project") == project
                    and isinstance(record.get("Id"), str)
                    and CONTAINER.fullmatch(record["Id"]) is not None,
                    "Aggregate beta live project inventory is invalid")
            live_ids.add(record["Id"])
        require(len(live_ids) == len(listed) and live_ids == expected,
                "Aggregate beta live project inventory differs from deployment receipt")
    observed = {}
    for name in sorted(runtime):
        observed[name] = _runtime_image(name, runtime[name], "elevenid-beta", inspect)
        require(runtime[name]["networks"] == expected_networks[name],
                "Aggregate beta service network differs from signed plan")
    applications = plan.get("recreate_applications")
    ingress = plan.get("recreate_ingress_last")
    required = set(SIGNED_APPLICATIONS) | {"issuance"}
    require(isinstance(applications, list) and isinstance(ingress, list)
            and len(applications) == len(set(applications))
            and len(ingress) == len(set(ingress))
            and set(applications) == required - INGRESS
            and set(ingress) == required & INGRESS,
            "Aggregate beta signed application set is incomplete")
    recreate = required
    hashes = plan.get("service_config_hashes")
    require(isinstance(hashes, dict) and recreate.issubset(runtime),
            "Aggregate beta signed application set is incomplete")
    for name in recreate:
        image = plan["issuance_image"] if name == "issuance" else plan["services_image"]
        require(observed[name]["oci_reference"] == image
                and isinstance(hashes.get(name), str)
                and SHA256.fullmatch(hashes[name]) is not None
                and runtime[name]["config_hash"] == hashes[name],
                "Aggregate beta signed application image or config differs")
    ui = _runtime_image("ui-prod", receipt.get("ui_runtime"),
                        "elevenid-beta-ui", inspect)
    require(receipt.get("ui_container_id") == ui["container_id"]
            and ui["oci_reference"] == plan["ui_image"]
            and receipt["ui_runtime"]["config_hash"] == plan.get("ui_config_hash")
            and receipt["ui_runtime"]["networks"] == ["elevenid-beta-network"],
            "Aggregate beta UI differs from signed plan")
    service_ref = plan["services_image"]
    service_digest = service_ref.partition("@")[2]
    require(service_digest == signed["oci_digests"]["ghcr.io/elevenid/marty-ui-oss/services"],
            "Aggregate beta passport image is not signed")
    runtime_images = {}
    for name in SERVICES:
        require(observed[name]["oci_reference"] == service_ref,
                "Aggregate beta passport service is not the signed Rust image")
        runtime_images[name] = {**observed[name], "oci_digest": service_digest}
    unauth_status, _ = probe(None)
    require(unauth_status in (401, 403),
            "Unauthenticated passport capability request was not denied")
    authenticated = {"verified": False, "evidence": None}
    if api_key:
        status, body = probe(api_key)
        require(status == 200 and isinstance(body, dict)
                and body.get("supported") is True
                and body.get("encrypted_artifact_store") is True
                and body.get("bureau_configured") is True
                and body.get("blockers") == []
                and isinstance(body.get("signer"), dict)
                and body["signer"].get("configured") is True
                and body["signer"].get("mode") == "MANAGED_ISSUER_PROFILE"
                and body["signer"].get("blockers") == [],
                "Native passport capability is not ready")
        authenticated = {"verified": True, "evidence": {
            "http_status": 200, "supported": True,
            "signer_mode": "MANAGED_ISSUER_PROFILE"}}
    probes = {name: {"verified": False, "evidence": None}
              for name in REQUIRED_PROBES}
    probes["physical_claim_boundary"] = {"verified": True, "evidence": {
        "physical_claim": "not_claimed", "booklet_verified": False}}
    probes["capabilities_http"] = authenticated
    probes["unauthenticated_denial"] = {"verified": True, "evidence": {
        "http_status": unauth_status}}
    return {
        "schema": "marty.passport-beta-acceptance/v1", "status": "blocked",
        "beta_origin": BETA_ORIGIN, "physical_claim": "not_claimed",
        "release": {"source_commit": source,
                    "stack_manifest_sha256": signed["manifest_sha256"],
                    "oci_digests": signed["oci_digests"],
                    "signed_manifest_verified": True},
        "deployment": {"aggregate_deployment_receipt_sha256":
                       digest_file(receipt_path).removeprefix("sha256:"),
                       "aggregate_plan_sha256": receipt["plan_sha256"],
                       "release_version": signed["release"].removeprefix("marty-ui@"),
                       "provider_mode": "simulator",
                       "production_snapshot_commitment":
                       production_snapshot_commitment(
                           api_key, receipt["production_snapshot_sha256"]),
                       "production_attachment_commitment":
                       production_attachment_commitment(
                           api_key, plan["production_attachments_sha256"])},
        "runtime_images": runtime_images, "probes": probes,
    }
