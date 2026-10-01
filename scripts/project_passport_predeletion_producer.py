#!/usr/bin/env python3
"""Project an attested disposable Rust producer into predeletion probe evidence.

The result remains blocked. The protected acceptance workflow must bind a fresh
beta drain, production isolation, and the exact signed release before accepting.
"""

from __future__ import annotations

import copy
import re
from typing import Any


SHA = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
SERVICES = {
    "gateway", "flow", "issuance-native", "signing-keys",
    "passport-callback-signer", "passport-beta-bureau",
}


class ProjectionError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ProjectionError(message)


def bound(value: dict[str, Any], identity: dict[str, Any]) -> dict[str, Any]:
    return {**copy.deepcopy(value),
            "owner_uid": identity["owner_uid"],
            "owner_labels": copy.deepcopy(identity["owner_labels"]),
            "target": identity["project_id"]}


def probe(value: dict[str, Any], identity: dict[str, Any]) -> dict[str, Any]:
    return {"verified": True, "evidence": bound(value, identity)}


def project(record: dict[str, Any], release: dict[str, Any]) -> dict[str, Any]:
    """Require verified blocked inputs, then retain their exact job bindings."""
    require(isinstance(record, dict)
            and record.get("status") == "verified_blocked_receipt"
            and isinstance(record.get("plan"), dict)
            and isinstance(record.get("receipt"), dict)
            and isinstance(release, dict),
            "Attested producer, plan, or signed release is unavailable")
    plan, receipt = record["plan"], record["receipt"]
    source = record.get("source_commit")
    project_id = plan.get("project")
    services_reference = plan.get("services_reference")
    digest = (services_reference.partition("@")[-1]
              if isinstance(services_reference, str) else None)
    require(isinstance(source, str) and SHA.fullmatch(source) is not None
            and plan.get("source_commit") == receipt.get("source_commit") == source
            and plan.get("surface") == receipt.get("surface") == "base"
            and isinstance(project_id, str) and project_id
            and receipt.get("project") == project_id
            and receipt.get("status") == "blocked"
            and receipt.get("live_ownership_verified") is True
            and receipt.get("rust_routes_verified") is True
            and receipt.get("flow_execution_verified") is True
            and receipt.get("rust_restart_resume_verified") is True
            and receipt.get("physical_claim") == "not_claimed"
            and isinstance(services_reference, str)
            and services_reference.startswith("ghcr.io/elevenid/marty-ui-oss/services@")
            and isinstance(digest, str) and DIGEST.fullmatch(digest) is not None
            and release.get("source_commit") == source
            and release.get("stack_manifest_sha256")
                == plan.get("stack_manifest_sha256")
            and release.get("signed_manifest_verified") is True
            and isinstance(release.get("oci_digests"), dict)
            and release["oci_digests"].get(
                "ghcr.io/elevenid/marty-ui-oss/services") == digest,
            "Disposable producer and signed release identity differ")
    # Normalize the verified Compose project and plan labels to the acceptance
    # contract's owner shape. These are report bindings, not Docker label names.
    identity = {
        "kind": "compose", "project_id": project_id, "owner_uid": project_id,
        "owner_labels": {"source_commit": source, "surface": "base",
                         "owner_uid": project_id},
        "production_resources_excluded": True, "source_commit": source,
    }
    runtime = receipt.get("runtime_images")
    require(isinstance(runtime, dict) and set(runtime) == SERVICES,
            "Disposable six-service runtime is missing")
    images = {}
    for service, item in runtime.items():
        require(isinstance(item, dict)
                and item.get("oci_reference") == services_reference,
                "Disposable runtime differs from signed services image")
        images[service] = bound({**item, "oci_digest": digest}, identity)
    prior = receipt.get("pre_restart_native_runtime")
    require(isinstance(prior, dict)
            and prior.get("oci_reference") == services_reference,
            "Disposable pre-restart runtime is missing")
    prior = bound(prior, identity)

    route_proof = receipt.get("route")
    flow = receipt.get("flow_execution")
    signer = receipt.get("current_managed_signer")
    require(isinstance(route_proof, dict) and route_proof.get("verified") is True
            and isinstance(route_proof.get("evidence"), dict)
            and isinstance(flow, dict)
            and isinstance(flow.get("execution"), dict)
            and isinstance(flow.get("batch"), dict)
            and isinstance(signer, dict),
            "Disposable route, Flow, batch, or signer proof is missing")
    route = route_proof["evidence"]
    execution = flow["execution"]
    batch_proof = flow["batch"].get("batch")
    batch = batch_proof.get("evidence") if isinstance(batch_proof, dict) else None
    material = batch.get("selected_material_receipt") if isinstance(batch, dict) else None
    organization_id = route.get("organization_id")
    require(isinstance(batch, dict) and batch_proof.get("verified") is True
            and isinstance(material, dict)
            and isinstance(organization_id, str) and organization_id
            and signer.get("organization_id") == organization_id
            and signer.get("mode") == "managed_kms"
            and signer.get("issuer_profile_type") == "ICAO_EMRTD"
            and signer.get("managed_kms_custody_verified") is True
            and signer.get("chain_verified") is True
            and signer.get("private_key_exported") is False
            and signer.get("signing_keys_container_id")
                == images["signing-keys"]["container_id"]
            and signer.get("services_oci_reference") == services_reference
            and route.get("signed_gateway_callback_verified") is True
            and route.get("sod_signature_verified") is True
            and route.get("cross_tenant_status") == 404
            and route.get("tenant_capability_status") == 200
            and execution.get("restart_resume_verified") is True
            and execution.get("nine_steps_verified") is True
            and execution.get("six_native_effects_verified") is True
            and execution.get("durable_history_verified") is True
            and execution.get("restart_before_native_status") == "SOD_SIGNED"
            and execution.get("restart_after_native_status") in (
                "SUBMITTED", "IN_PRODUCTION", "QUALITY_CHECK", "READY_FOR_ACTIVATION")
            and execution.get("callback_bureau_status") in ("QUALITY_CHECK", "SHIPPED")
            and batch.get("selected_source_job_commitment")
                == material.get("source_job_id_commitment")
            and batch.get("selected_bureau_job_commitment")
                == material.get("bureau_job_id_commitment")
            and batch.get("companion_bureau_status") == "SHIPPED"
            and batch.get("companion_simulator_marker_verified") is True
            and batch.get("companion_native_completed") is True
            and batch.get("first_accepted_material_verified") is True
            and batch.get("native_binding_verified") is True
            and material.get("tenant_and_job_binding") is True
            and material.get("first_accepted_sod_der_matches_native") is True
            and material.get("first_accepted_dsc_der_matches_selected_chain") is True
            and material.get("first_accepted_dsc_pem_wire_matches_selected_chain") is True,
            "Selected managed signer or simulator job bindings differ")
    csca, dsc = signer.get("csca"), signer.get("dsc")
    require(isinstance(csca, dict) and isinstance(dsc, dict)
            and csca.get("status") == dsc.get("status") == "active"
            and isinstance(execution.get("sod_sha256"), str)
            and re.fullmatch(r"[0-9a-f]{64}", execution["sod_sha256"]) is not None,
            "Selected SOD or managed chain is incomplete")
    # The direct Gateway lifecycle and selected Flow are different synthetic
    # applications. Their SOD digests may differ; the selected Flow binds the
    # native batch and first accepted material below.
    selected_commitment = batch["selected_source_job_commitment"]
    selected_bureau = batch["selected_bureau_job_commitment"]
    companion_commitment = batch["companion_source_job_commitment"]
    companion_bureau = batch["companion_bureau_job_commitment"]
    callback_receipts = [execution["signed_callback_receipt_sha256"],
                         batch["companion_callback_receipt_sha256"]]
    returned = [
        {"source_job_commitment": selected_commitment,
         "bureau_job_commitment": selected_bureau,
         "status": execution["callback_bureau_status"]},
        {"source_job_commitment": companion_commitment,
         "bureau_job_commitment": companion_bureau,
         "status": batch["companion_bureau_status"]},
    ]
    batch_evidence = {
        "provider_kind": "simulator", "physical_claim": "not_claimed",
        "organization_id": organization_id, "commitment_scheme": "HMAC-SHA256",
        "simulator_marker_verified": batch["companion_simulator_marker_verified"],
        "source_commit": source,
        "stack_manifest_sha256": release["stack_manifest_sha256"],
        "services_oci_reference": services_reference,
        "request_commitment": batch["request_commitment"],
        "response_commitment": batch["response_commitment"],
        "http_status": batch["http_status"],
        "batch_status": batch["batch_status"],
        "submitted_job_commitments": batch["submitted_job_commitments"],
        "returned_jobs": returned,
        "native_binding_verified": batch["native_binding_verified"],
        "native_completed_jobs": 2,
        "callback_receipt_sha256": callback_receipts[0],
        "callback_receipts_sha256": callback_receipts,
    }
    callback_jobs = [
        {"source_job_commitment": source_job,
         "bureau_job_commitment": bureau_job,
         "receipt_sha256": callback_receipts[index],
         "native_completed": True, "organization_id": organization_id,
         "native_container_id": images["issuance-native"]["container_id"]}
        for index, (source_job, bureau_job) in enumerate((
            (selected_commitment, selected_bureau),
            (companion_commitment, companion_bureau),
        ))
    ]
    callback = {
        "provider_kind": "simulator", "signature_verified": True,
        "organization_bound": True, "organization_id": organization_id,
        "flow_execution_verified": True, "physical_claim": "not_claimed",
        "receipt_sha256": callback_receipts[0],
        "callback_receipts_sha256": callback_receipts,
        "source_job_commitments": batch["submitted_job_commitments"],
        "native_completed_jobs": 2,
        "native_container_id": images["issuance-native"]["container_id"],
        "jobs": callback_jobs,
    }
    sod = {
        "signature_verified": True, "chain_verified": signer["chain_verified"],
        "native_generate_sod_verified": True,
        "organization_id": organization_id,
        "dsc_issuer_profile_commitment": dsc["issuer_profile_commitment"],
        "csca_certificate_sha256": csca["certificate_sha256"],
        "dsc_certificate_sha256": dsc["certificate_sha256"],
        "sod_sha256": execution["sod_sha256"],
        "source_job_commitment": selected_commitment,
    }
    before = {
        "owner": "rust", "issuance_native_container_id": prior["container_id"],
        "oci_reference": services_reference, "image_id": prior["image_id"],
        "job_commitment": selected_commitment,
        "organization_id": organization_id,
        "dsc_issuer_profile_commitment": dsc["issuer_profile_commitment"],
        "status": execution["restart_before_native_status"],
    }
    after = {
        **before,
        "issuance_native_container_id": images["issuance-native"]["container_id"],
        "image_id": images["issuance-native"]["image_id"],
        "status": execution["restart_after_native_status"],
    }
    resume = {
        "before": bound(before, identity), "after": bound(after, identity),
        "job_resumed": True, "durable_record_verified":
            execution["durable_history_verified"],
        # The selected job keeps its KMS-signed SOD across the native restart.
        # The producer verifies the Signing Keys container stays unchanged;
        # this does not claim a second SOD signing after the restart.
        "kms_signing_continuity_verified": (
            signer["managed_kms_custody_verified"]
            and signer["signing_keys_container_id"]
                == images["signing-keys"]["container_id"]
            and execution["restart_resume_verified"]
            and execution["durable_history_verified"]),
        "preserved_signed_sod_sha256": execution["sod_sha256"],
        "unchanged_signing_keys_container_id": signer[
            "signing_keys_container_id"],
        "gateway_owner": "rust", "flow_owner": "rust",
        "source_commit": source, "services_oci_reference": services_reference,
    }
    material_evidence = {
        **material, "sod_sha256": execution["sod_sha256"],
        "dsc_certificate_sha256": dsc["certificate_sha256"],
    }
    routes = {**route, "gateway_owner": "rust", "flow_owner": "rust"}
    packaged = {
        "source_commit": source,
        "stack_manifest_sha256": release["stack_manifest_sha256"],
        "services_oci_reference": services_reference,
        "runtime_container_id": images["passport-beta-bureau"]["container_id"],
    }
    submission = {key: batch_evidence[key] for key in (
        "provider_kind", "physical_claim", "source_commit",
        "stack_manifest_sha256", "services_oci_reference", "http_status",
        "batch_status", "request_commitment", "response_commitment",
        "submitted_job_commitments", "returned_jobs")}
    probes = {
        "managed_csca_dsc_chain": probe(signer, identity),
        "sod_signature": probe(sod, identity),
        "nine_route_gateway_flow": probe(routes, identity),
        "packaged_image": probe(packaged, identity),
        "physical_bureau_submission": probe(submission, identity),
        "physical_bureau_batch": probe(batch_evidence, identity),
        "simulator_material_receipt": probe(material_evidence, identity),
        "signed_bureau_callback": probe(callback, identity),
        "rust_restart_resume": probe(resume, identity),
        "physical_claim_boundary": probe(
            {"physical_claim": "not_claimed", "booklet_verified": False}, identity),
    }
    return {
        "schema": "marty.passport-rust-predeletion-producer-projection/v1",
        "status": "blocked", "source_commit": source,
        "producer_run_id": record["producer_run_id"],
        "record_run_id": record["record_run_id"],
        "record_completed_at_utc": record["record_completed_at_utc"],
        "producer_receipt_sha256": record["receipt_file_sha256"],
        "producer_attestation_sha256": record["receipt_attestation_sha256"],
        "plan_sha256": record["plan_file_sha256"],
        "release": copy.deepcopy(release), "deployment": identity,
        "runtime_images": images, "pre_restart_native_runtime": prior,
        "probes": probes,
    }
