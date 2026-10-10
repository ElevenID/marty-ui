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
    from .prepare_passport_beta_aggregate_handoff import verify_fence
    from .probe_passport_beta_host import beta_psql, ids, run as host_run
    from .qualify_selfhost_migrations import PRIVATE_KEY_SCHEMA_QUERY
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
    from prepare_passport_beta_aggregate_handoff import verify_fence
    from probe_passport_beta_host import beta_psql, ids, run as host_run
    from qualify_selfhost_migrations import PRIVATE_KEY_SCHEMA_QUERY


SHA = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
CONTAINER = re.compile(r"[0-9a-f]{64}\Z")
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
RUNTIME_KEYS = {"container_id", "image_id", "configured_image", "started_at",
                "config_hash", "networks"}
ISSUANCE_MIGRATION_VERSIONS = sorted((
    "issuance_service_baseline_v1",
    "0001_oid4vci_public_protocol",
    "0002_physical_document_jobs", "0003_passport_bureau_provider_binding",
    "0004_passport_submission_intent", "0005_passport_submission_provenance",
    "0006_passport_beta_batch_identity", "0007_passport_beta_batch_provenance",
    "0008_passport_beta_batch_wire_evidence",
))


def _probe_native_marker(plan: dict[str, Any], intent: dict[str, Any]) -> None:
    sql = (
        "SELECT (SELECT fence_epoch::text || '|' || source_commit || '|' || "
        "migration_set_sha256 FROM passport_cutover.native_migration_receipt "
        "WHERE singleton=true) || '|' || "
        "(SELECT rolcanlogin::text FROM pg_roles WHERE rolname='marty') || '|' || "
        "(SELECT rolcanlogin::text FROM pg_roles "
        "WHERE rolname='marty_beta_migrator')"
    )
    expected = (f"{plan['fence_epoch']}|{plan['source_commit']}|"
                f"{plan['migration_set_sha256']}|true|false")
    require(beta_psql(sql, host_run, plan["postgres_container_id"]) == expected,
            "Aggregate beta native migration marker or role state differs")
    ledger = beta_psql(
        "SELECT string_agg(version, ',' ORDER BY version) "
        "FROM issuance_service.rust_schema_migrations",
        host_run, plan["postgres_container_id"],
    )
    require(ledger == ",".join(ISSUANCE_MIGRATION_VERSIONS),
            "Aggregate beta Rust issuance migration ledger differs")
    require(not beta_psql(PRIVATE_KEY_SCHEMA_QUERY, host_run,
                          plan["postgres_container_id"]),
            "Aggregate beta database contains private-key storage")
    verify_fence(intent, host_run)


def _verify_native_lineage(
    artifact_dir: Path, plan: dict[str, Any], receipt: dict[str, Any],
    probe_native: Callable[[dict[str, Any], dict[str, Any]], None],
) -> None:
    prefix = artifact_dir / "aggregate-deployment.json"
    fence_path = Path(str(prefix) + ".fence-receipt.json")
    maintenance_path = Path(str(prefix) + ".maintenance-receipt.json")
    intent_path = Path(str(prefix) + ".maintenance-intent.json")
    native_path = Path(str(prefix) + ".native-receipt.json")
    fence = read_json(fence_path)
    maintenance = read_json(maintenance_path)
    intent = read_json(intent_path)
    native = read_json(native_path)
    require(fence.get("schema") == "marty.passport-beta-fence-installation/v1"
            and maintenance.get("schema") == "marty.passport-beta-db-maintenance-start/v1"
            and intent.get("schema") == "marty.passport-beta-db-maintenance-plan/v1"
            and native.get("schema") == "marty.passport-beta-native-db-gates/v1"
            and digest_file(fence_path).removeprefix("sha256:")
                == plan.get("fence_receipt_sha256")
            and digest_file(maintenance_path).removeprefix("sha256:")
                == plan.get("maintenance_receipt_sha256")
                == native.get("maintenance_receipt_sha256")
            and digest_file(intent_path).removeprefix("sha256:")
                == maintenance.get("intent_sha256")
            and digest_file(native_path).removeprefix("sha256:")
                == plan.get("native_receipt_sha256")
                == receipt.get("native_receipt_sha256")
            and all(item.get("source_commit") == plan["source_commit"]
                    for item in (fence, maintenance, intent, native))
            and all(str(item.get("fence_epoch")) == str(plan.get("fence_epoch"))
                    for item in (maintenance, intent, native))
            and all(item.get("postgres_container_id") == plan.get("postgres_container_id")
                    for item in (fence, maintenance, intent, native))
            and fence.get("postgres_system_identifier")
                == plan.get("postgres_system_identifier")
            and fence.get("database_oid") == plan.get("database_oid")
            and fence.get("production_snapshot_sha256")
                == plan.get("production_snapshot_sha256")
            and fence.get("production_attachments_sha256")
                == plan.get("production_attachments_sha256")
            and intent.get("fence_receipt_sha256")
                == plan.get("fence_receipt_sha256")
            and intent.get("production_snapshot_sha256")
                == plan.get("production_snapshot_sha256")
            and intent.get("production_attachments_sha256")
                == plan.get("production_attachments_sha256")
            and native.get("migration_set_sha256") == plan.get("migration_set_sha256")
            and native.get("app_login_enabled") is False
            and native.get("stopped_container_ids") == maintenance.get("stopped_container_ids")
                == intent.get("stop_container_ids")
            and maintenance.get("production_snapshot_sha256")
                == native.get("production_snapshot_sha256")
                == plan.get("production_snapshot_sha256")
            and maintenance.get("production_attachments_sha256")
                == plan.get("production_attachments_sha256")
            and native.get("postgres_system_identifier")
                == maintenance.get("postgres_system_identifier")
                == intent.get("postgres_system_identifier")
                == plan.get("postgres_system_identifier")
            and native.get("database_oid") == maintenance.get("database_oid")
                == intent.get("database_oid") == plan.get("database_oid")
            and isinstance(plan.get("migration_set_sha256"), str)
            and SHA256.fullmatch(plan["migration_set_sha256"]) is not None
            and isinstance(plan.get("postgres_container_id"), str)
            and CONTAINER.fullmatch(plan["postgres_container_id"]) is not None
            and str(plan.get("fence_epoch", "")).isdigit(),
            "Aggregate beta native migration lineage is invalid")
    probe_native(plan, intent)


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
    probe_native: Callable[[dict[str, Any], dict[str, Any]], None] = _probe_native_marker,
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
    migration_path = artifact_dir / "aggregate-deployment.json.issuance-migration.json"
    migration = read_json(migration_path)
    require(receipt.get("issuance_migration_receipt_sha256")
                == digest_file(migration_path).removeprefix("sha256:")
            and migration.get("schema") == "marty.passport-beta-issuance-migration/v1"
            and migration.get("source_commit") == source
            and migration.get("services_image") == plan.get("services_image")
            and migration.get("postgres_container_id")
                == plan.get("postgres_container_id")
            and migration.get("versions") == ISSUANCE_MIGRATION_VERSIONS,
            "Aggregate beta Rust issuance migration receipt differs")
    dependency_path = artifact_dir / "aggregate-deployment.json.issuance-dependency.json"
    dependency = read_json(dependency_path)
    recorded_runtime = receipt.get("beta_runtime")
    recorded_issuance = (recorded_runtime.get("issuance")
                         if isinstance(recorded_runtime, dict) else None)
    require(receipt.get("issuance_dependency_receipt_sha256")
                == digest_file(dependency_path).removeprefix("sha256:")
            and dependency.get("schema") == "marty.passport-beta-issuance-dependency/v1"
            and dependency.get("verified") is True
            and dependency.get("source_commit") == source
            and dependency.get("services_image") == plan.get("services_image")
            and dependency.get("postgres_container_id")
                == plan.get("postgres_container_id")
            and dependency.get("issuance_container_id")
                == (recorded_issuance.get("container_id")
                    if isinstance(recorded_issuance, dict) else None),
            "Aggregate beta Rust issuance dependency receipt differs")
    require(attest is not None,
            "Aggregate beta acceptance requires signed release attestations")
    require(isinstance(api_key, str) and len(api_key) >= 32,
            "Aggregate beta acceptance requires a governed organization key")
    ceremony_path = artifact_dir / "aggregate-deployment.json.issuer-ceremony.json"
    ceremony = read_json(ceremony_path)
    ceremony_intent_path = artifact_dir / "aggregate-deployment.json.issuer-ceremony-intent.json"
    ceremony_intent = read_json(ceremony_intent_path)
    runtime = receipt.get("beta_runtime")
    gateway = runtime.get("gateway") if isinstance(runtime, dict) else None
    require(receipt.get("issuer_ceremony_receipt_sha256")
                == digest_file(ceremony_path).removeprefix("sha256:")
            and receipt.get("issuer_ceremony") == ceremony
            and ceremony.get("schema") == "marty.passport-beta-aggregate-ceremony/v1"
            and ceremony.get("verified") is True
            and ceremony.get("source_commit") == source
            and ceremony.get("gateway_container_id")
                == (gateway.get("container_id") if isinstance(gateway, dict) else None)
            and ceremony.get("intent_file_sha256")
                == digest_file(ceremony_intent_path).removeprefix("sha256:")
            and ceremony_intent.get("schema")
                == "marty.passport-beta-aggregate-ceremony-intent/v1"
            and all(ceremony_intent.get(key) == ceremony.get(key)
                    for key in ("source_commit", "gateway_container_id",
                                "application_file_sha256", "issuer_chain_file_sha256",
                                "ceremony_file_sha256"))
            and ceremony.get("gateway_request_traces_verified") is True
            and ceremony.get("profile_creation_verified") is True
            and ceremony.get("certificate_chain_verified") is True
            and all(isinstance(ceremony.get(name), str)
                    and SHA256.fullmatch(ceremony[name]) is not None
                    for name in ("application_file_sha256", "issuer_chain_file_sha256",
                                 "ceremony_file_sha256", "csca_certificate_sha256",
                                 "dsc_certificate_sha256")),
            "Aggregate beta governed issuer ceremony differs from deployment")
    kms_path = artifact_dir / "aggregate-deployment.json.kms-pretransition.json"
    kms = read_json(kms_path)
    key_versions = kms.get("key_versions")
    signing_keys = runtime.get("signing-keys") if isinstance(runtime, dict) else None
    require(receipt.get("kms_pretransition_receipt_sha256")
                == digest_file(kms_path).removeprefix("sha256:")
            and receipt.get("kms_pretransition") == kms
            and kms.get("schema") == "marty.passport-beta-aggregate-kms-pretransition/v1"
            and kms.get("verified") is True
            and kms.get("source_commit") == source
            and kms.get("signing_keys_container_id")
                == (signing_keys.get("container_id") if isinstance(signing_keys, dict) else None)
            and kms.get("openbao_container_id")
                == plan.get("old_container_ids_by_service", {}).get("openbao")
            and kms.get("managed_kms_custody_verified") is True
            and kms.get("chain_verified") is True
            and kms.get("private_key_exported") is False
            and all(kms.get(name) == ceremony.get(name)
                    for name in ("application_file_sha256", "issuer_chain_file_sha256",
                                 "csca_certificate_sha256", "dsc_certificate_sha256"))
            and all(isinstance(kms.get(name), str)
                    and SHA256.fullmatch(kms[name]) is not None
                    for name in ("application_file_sha256", "issuer_chain_file_sha256",
                                 "csca_certificate_sha256", "dsc_certificate_sha256"))
            and isinstance(key_versions, dict) and set(key_versions) == {"csca", "dsc"}
            and all(type(version) is int and version > 0
                    for version in key_versions.values()),
            "Aggregate beta managed issuer proof differs from deployment")
    try:
        signed = manifest_source(manifest_path, source, attest, attest_issuance,
                                 rust_only=True)
    except (OSError, ValueError) as exc:
        raise EvidenceError("Aggregate signed release did not verify") from exc
    require(signed["manifest_sha256"] == plan["stack_manifest_sha256"]
            and signed["services_image"] == plan.get("services_image")
            and signed["issuance_image"] == plan.get("issuance_image")
            and signed["oci_digests"].get("ghcr.io/elevenid/marty-ui-oss/ui")
                == str(plan.get("ui_image", "")).partition("@")[2],
            "Aggregate beta plan differs from signed stack images")
    _verify_native_lineage(artifact_dir, plan, receipt, probe_native)
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
            and isinstance(runtime.get("postgres"), dict)
            and runtime["postgres"].get("container_id")
                == plan.get("postgres_container_id")
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
        image = plan["services_image"]
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
