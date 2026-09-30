#!/usr/bin/env python3
"""Verify a protected plan and blocked Rust producer receipt before attestation."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
from typing import Callable

if __package__:
    from .check_passport_supported_rust_model import PROJECT
    from .collect_passport_supported_acceptance import COMPOSE_FLAGS, COMPOSE_SERVICES, DIGEST
    from .passport_supported_certificate_rehearsal import validate_certificate_setup
    from .passport_supported_protected_producer import _application
    from .passport_supported_provisioning_producer import ProducerError
    from .probe_passport_supported_routes import _frozen_routes
    from .passport_supported_provisioning_plan import (
        COMMIT, PLAN_WORKFLOW, RUN_ID, _attest,
    )
else:
    from check_passport_supported_rust_model import PROJECT
    from collect_passport_supported_acceptance import COMPOSE_FLAGS, COMPOSE_SERVICES, DIGEST
    from passport_supported_certificate_rehearsal import validate_certificate_setup
    from passport_supported_protected_producer import _application
    from passport_supported_provisioning_producer import ProducerError
    from probe_passport_supported_routes import _frozen_routes
    from passport_supported_provisioning_plan import (
        COMMIT, PLAN_WORKFLOW, RUN_ID, _attest,
    )


class HandoffError(ValueError):
    pass


HASH = re.compile(r"[0-9a-f]{64}\Z")
BLOCKER = "Live protected beta acceptance remains unproven"
RECEIPT_FIELDS = frozenset({
    "schema", "status", "project", "surface", "source_commit", "gateway_port",
    "physical_claim", "plan_run_id", "producer_run_id",
    "certificate_setup_passed", "live_ownership_verified", "rust_routes_verified",
    "signed_gateway_callback_verified", "flow_execution_verified",
    "flow_start_verified", "rust_restart_resume_verified", "certificate",
    "current_managed_signer", "native_batch_preflight",
    "route", "flow_execution", "runtime_images", "pre_restart_native_runtime",
    "runtime_edge", "blocker",
})
ROUTE_EVIDENCE_FIELDS = frozenset({
    "application_input_sha256", "job_id_sha256", "application_id_sha256",
    "bureau_job_id_sha256", "sod_sha256", "sod_signature_verified", "routes",
    "callback_receipt_sha256", "callback_bureau_job_id_sha256",
    "callback_private_status", "unsigned_webhook_http_status",
    "signed_callback_path", "signed_gateway_callback_verified", "physical_claim",
    "organization_id", "unauthenticated_status", "cross_tenant_status",
    "tenant_capability_unauthenticated_status", "tenant_capability_status",
})
CONTAINER_ID = re.compile(r"[0-9a-f]{64}\Z")


def _runtime_evidence(receipt: dict, plan: dict) -> None:
    runtime = receipt["runtime_images"]
    edge = receipt["runtime_edge"]
    reference = plan.get("services_reference")
    infra_images = plan.get("infra_images")
    if (not isinstance(runtime, dict) or set(runtime) != set(COMPOSE_SERVICES)
        or not isinstance(reference, str)
        or not isinstance(infra_images, dict)
        or not isinstance(edge, dict)
        or set(edge) != {"container_id", "oci_reference", "loopback_port"}
        or type(edge["loopback_port"]) is not int
        or edge["loopback_port"] != receipt["gateway_port"]
        or edge["oci_reference"] != infra_images.get("edge")
        or not isinstance(edge["container_id"], str)
        or CONTAINER_ID.fullmatch(edge["container_id"]) is None):
        raise HandoffError("Protected Rust runtime inventory is invalid")
    ids = {edge["container_id"]}
    for service in COMPOSE_SERVICES:
        item = runtime[service]
        flags = item.get("selectors") if isinstance(item, dict) else None
        if (not isinstance(item, dict)
            or set(item) != {"container_id", "image_id", "oci_reference", "selectors"}
            or not isinstance(item["container_id"], str)
            or CONTAINER_ID.fullmatch(item["container_id"]) is None
            or not isinstance(item["image_id"], str)
            or DIGEST.fullmatch(item["image_id"]) is None
            or item["oci_reference"] != reference
            or not isinstance(flags, dict)
            or set(flags) != set(COMPOSE_FLAGS[service])
            or any(value is not True for value in flags.values())):
            raise HandoffError("Protected Rust runtime inventory is invalid")
        ids.add(item["container_id"])
    if len(ids) != len(COMPOSE_SERVICES) + 1:
        raise HandoffError("Protected Rust runtime identities are not distinct")
    prior = receipt["pre_restart_native_runtime"]
    native = runtime["issuance-native"]
    if (not isinstance(prior, dict)
        or set(prior) != {"container_id", "image_id", "oci_reference",
                          "selectors", "inspection_receipt_sha256"}
        or not isinstance(prior["container_id"], str)
        or CONTAINER_ID.fullmatch(prior["container_id"]) is None
        or prior["container_id"] in ids
        or prior["image_id"] != native["image_id"]
        or prior["oci_reference"] != reference
        or prior["selectors"] != native["selectors"]
        or not isinstance(prior["inspection_receipt_sha256"], str)
        or HASH.fullmatch(prior["inspection_receipt_sha256"]) is None):
        raise HandoffError("Protected native restart baseline is invalid")


def _flow_execution_evidence(value: object, receipt: dict) -> None:
    if not isinstance(value, dict) or set(value) != {"references", "flow", "execution", "batch"}:
        raise HandoffError("Protected Rust Flow execution proof is invalid")
    references = value["references"]
    flow = value["flow"]
    execution = value["execution"]
    if (not isinstance(references, dict)
        or set(references) != {"credential_template_id_sha256",
                                   "application_template_id_sha256",
                                   "delivery_destination_profile_id_sha256"}
        or not isinstance(flow, dict)
        or set(flow) != {"flow_definition_id_sha256", "flow_instance_id_sha256",
                         "native_job_id_sha256", "application_id_sha256"}):
        raise HandoffError("Protected Rust Flow execution proof is invalid")
    values = list(references.values()) + list(flow.values())
    if any(type(item) is not str or HASH.fullmatch(item) is None for item in values):
        raise HandoffError("Protected Rust Flow execution proof is invalid")
    if len(set(values)) != len(values):
        raise HandoffError("Protected Rust Flow IDs are not distinct")
    if (not isinstance(execution, dict)
        or set(execution) != {"nine_steps_verified", "six_native_effects_verified",
                              "durable_history_verified", "restart_resume_verified",
                              "bureau_job_id_sha256",
                              "signed_callback_receipt_sha256", "sod_sha256"}
        or execution.get("nine_steps_verified") is not True
        or execution.get("six_native_effects_verified") is not True
        or execution.get("durable_history_verified") is not True
        or execution.get("restart_resume_verified") is not True
        or any(type(execution.get(name)) is not str
               or HASH.fullmatch(execution[name]) is None for name in (
                   "bureau_job_id_sha256", "signed_callback_receipt_sha256",
                   "sod_sha256"))
        or execution["bureau_job_id_sha256"] == flow["native_job_id_sha256"]):
        raise HandoffError("Protected Rust Flow execution proof is invalid")
    batch = value["batch"]
    proof = batch.get("batch") if isinstance(batch, dict) else None
    evidence = proof.get("evidence") if isinstance(proof, dict) else None
    fields = {
        "provider_kind", "physical_claim", "http_status", "batch_status",
        "selected_flow_in_two_job_batch", "native_binding_verified",
        "first_accepted_material_verified", "companion_native_completed",
        "selected_material_receipt",
        "companion_callback_receipt_sha256", "selected_source_job_commitment",
        "selected_bureau_job_commitment", "companion_source_job_commitment",
        "companion_bureau_job_commitment", "submitted_job_commitments",
        "returned_jobs", "request_commitment", "response_commitment",
    }
    if (not isinstance(batch, dict)
        or set(batch) != {"final_native_preflight", "batch",
                          "selected_source_job_sha256", "selected_bureau_job_sha256",
                          "dsc_der_sha256"}
        or batch["final_native_preflight"] != {
            "native_container_id": receipt["runtime_images"]["issuance-native"]["container_id"],
            "native_batch_preflight_verified": True}
        or batch["selected_source_job_sha256"] != flow["native_job_id_sha256"]
        or batch["selected_bureau_job_sha256"] != execution["bureau_job_id_sha256"]
        or batch["dsc_der_sha256"] != receipt["certificate"]["evidence"]["dsc_certificate_sha256"]
        or not isinstance(proof, dict) or set(proof) != {"verified", "evidence"}
        or proof["verified"] is not True
        or not isinstance(evidence, dict) or set(evidence) != fields
        or evidence["provider_kind"] != "simulator"
        or evidence["physical_claim"] != "not_claimed"
        or type(evidence["http_status"]) is not int or evidence["http_status"] != 202
        or evidence["batch_status"] != "QUEUED"
        or any(evidence[name] is not True for name in (
            "selected_flow_in_two_job_batch", "native_binding_verified",
            "first_accepted_material_verified", "companion_native_completed"))):
        raise HandoffError("Protected native batch proof is invalid")
    digest_fields = (
        "companion_callback_receipt_sha256", "selected_source_job_commitment",
        "selected_bureau_job_commitment", "companion_source_job_commitment",
        "companion_bureau_job_commitment", "request_commitment", "response_commitment",
    )
    if (any(type(evidence[name]) is not str or HASH.fullmatch(evidence[name]) is None
            for name in digest_fields)
        or len({evidence[name] for name in digest_fields}) != len(digest_fields)
        or evidence["submitted_job_commitments"] != [
            evidence["selected_source_job_commitment"],
            evidence["companion_source_job_commitment"]]
        or evidence["returned_jobs"] != [
            {"source_job_commitment": evidence["selected_source_job_commitment"],
             "bureau_job_commitment": evidence["selected_bureau_job_commitment"]},
            {"source_job_commitment": evidence["companion_source_job_commitment"],
             "bureau_job_commitment": evidence["companion_bureau_job_commitment"]}]):
        raise HandoffError("Protected native batch commitments are invalid")
    material = evidence["selected_material_receipt"]
    if (not isinstance(material, dict)
        or set(material) != {
            "source_job_id_commitment", "bureau_job_id_commitment",
            "tenant_and_job_binding", "first_accepted_sod_der_matches_native",
            "first_accepted_dsc_der_matches_selected_chain",
            "first_accepted_dsc_pem_wire_matches_selected_chain", "source"}
        or material["source_job_id_commitment"]
            != evidence["selected_source_job_commitment"]
        or material["bureau_job_id_commitment"]
            != evidence["selected_bureau_job_commitment"]
        or material["source"] != "private disposable PostgreSQL"
        or any(material[name] is not True for name in (
            "tenant_and_job_binding", "first_accepted_sod_der_matches_native",
            "first_accepted_dsc_der_matches_selected_chain",
            "first_accepted_dsc_pem_wire_matches_selected_chain"))):
        raise HandoffError("Protected selected material receipt is invalid")


def _route_evidence(route: object, gateway_port: int) -> None:
    evidence = route.get("evidence") if isinstance(route, dict) else None
    if (not isinstance(route, dict) or set(route) != {
            "verified", "evidence", "flow_execution_verified"}
        or route.get("verified") is not True
        or route.get("flow_execution_verified") is not False
        or not isinstance(evidence, dict)
        or set(evidence) != ROUTE_EVIDENCE_FIELDS
        or evidence.get("sod_signature_verified") is not True
        or evidence.get("signed_gateway_callback_verified") is not True
        or evidence.get("signed_callback_path") != "simulator-to-gateway-to-native"
        or evidence.get("physical_claim") != "not_claimed"
        or evidence.get("organization_id") != _application(gateway_port)["organization_id"]
        or evidence.get("unauthenticated_status") not in (401, 403)
        or evidence.get("cross_tenant_status") != 404
        or evidence.get("tenant_capability_unauthenticated_status") not in (401, 403)
        or evidence.get("tenant_capability_status") != 200
        or evidence.get("unsigned_webhook_http_status") != 422
        or evidence.get("callback_private_status") not in {"QUALITY_CHECK", "SHIPPED"}
        or not isinstance(evidence.get("routes"), list)
        or len(evidence["routes"]) < 9):
        raise HandoffError("Protected Rust route proof is invalid")
    hashes = (
        "application_input_sha256", "job_id_sha256", "application_id_sha256",
        "bureau_job_id_sha256", "sod_sha256", "callback_receipt_sha256",
        "callback_bureau_job_id_sha256",
    )
    expected_application = hashlib.sha256(json.dumps(
        _application(gateway_port), sort_keys=True, separators=(",", ":"),
    ).encode()).hexdigest()
    if (any(type(evidence.get(name)) is not str
            or HASH.fullmatch(evidence[name]) is None for name in hashes)
        or evidence["application_input_sha256"] != expected_application
        or evidence["callback_bureau_job_id_sha256"] != evidence["bureau_job_id_sha256"]):
        raise HandoffError("Protected Rust job or callback hash is invalid")
    routes = evidence["routes"]
    if (not all(isinstance(item, dict)
                and isinstance(item.get("method"), str)
                and isinstance(item.get("route"), str)
                and type(item.get("http_status")) is int
                and (item["http_status"] == 422
                     if item.get("route") == "/v1/passport/webhooks/personalization"
                     else item["http_status"] == 201
                     if item.get("route") == "/v1/passport/applications"
                     else item["http_status"] == 200)
                for item in routes)
        or {(item["method"], item["route"]) for item in routes} != _frozen_routes()):
        raise HandoffError("Protected Rust route status proof is invalid")
    capability_path = "/v1/passport/capabilities"
    webhook_path = "/v1/passport/webhooks/personalization"
    production_path = "/v1/passport/applications/{application_id}/production-status"
    for path in {item["route"] for item in routes}:
        found = [item for item in routes if item["route"] == path]
        if len(found) != 1 and path != production_path:
            raise HandoffError("Protected Rust route count is invalid")
        expected_fields = {"method", "route", "http_status"}
        if path == webhook_path:
            expected_fields |= {"positive_gateway_path_verified",
                                "signed_callback_observed_by"}
        elif path != capability_path:
            expected_fields.add("job_status")
        if any(set(item) != expected_fields
               or ("job_status" in expected_fields
                   and (not isinstance(item["job_status"], str)
                        or not 1 <= len(item["job_status"]) <= 64))
               for item in found):
            raise HandoffError("Protected Rust route entry is invalid")
    statuses = {
        "/v1/passport/applications": "DRAFT",
        "/v1/passport/applications/{application_id}/generate-data-groups": "DATA_GENERATED",
        "/v1/passport/applications/{application_id}/generate-sod": "SOD_SIGNED",
        "/v1/passport/applications/{application_id}/quality-verify": "READY_FOR_ACTIVATION",
        "/v1/passport/applications/{application_id}/activate": "ACTIVE",
    }
    if (any(not any(item.get("route") == path
                    and item.get("job_status") == status for item in routes)
            for path, status in statuses.items())
        or not any(item.get("route") ==
                   "/v1/passport/applications/{application_id}/production-status"
                   and item.get("job_status") in {"QUALITY_CHECK", "READY_FOR_ACTIVATION"}
                   for item in routes)
        or not any(item.get("route") == webhook_path
                   and item.get("positive_gateway_path_verified") is True
                   and item.get("signed_callback_observed_by") ==
                   "authenticated-private-bureau-receipt" for item in routes)):
        raise HandoffError("Protected Rust lifecycle or callback boundary is invalid")


def verify_handoff(
    plan_path: Path, receipt_path: Path, source_commit: str,
    producer_run_id: str, *,
    attest: Callable[[str, str, str, str, str], bool] = _attest,
) -> dict:
    if (COMMIT.fullmatch(source_commit) is None
        or RUN_ID.fullmatch(producer_run_id) is None):
        raise HandoffError("Protected handoff source/run is invalid")
    try:
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise HandoffError("Protected handoff artifact is invalid") from error
    if (not isinstance(plan, dict) or not isinstance(receipt, dict)
        or plan.get("schema") != "marty.passport-supported-provisioning-plan/v1"
        or plan.get("status") != "blocked"
        or plan.get("source_commit") != source_commit
        or not isinstance(plan.get("run_id"), str)
        or RUN_ID.fullmatch(plan["run_id"]) is None
        or not isinstance(plan.get("project"), str)
        or (match := PROJECT.fullmatch(plan["project"])) is None
        or match.group(1) != plan.get("surface")
        or receipt.get("schema") != "marty.passport-supported-rust-producer/v1"
        or set(receipt) != RECEIPT_FIELDS
        or receipt.get("status") != "blocked"
        or receipt.get("source_commit") != source_commit
        or receipt.get("producer_run_id") != producer_run_id
        or receipt.get("plan_run_id") != plan.get("run_id")
        or receipt.get("project") != plan.get("project")
        or receipt.get("surface") != plan.get("surface")
        or type(receipt.get("gateway_port")) is not int
        or not 1024 <= receipt["gateway_port"] <= 65535
        or receipt.get("physical_claim") != "not_claimed"
        or receipt.get("blocker") != BLOCKER
        or receipt.get("certificate_setup_passed") is not True
        or receipt.get("live_ownership_verified") is not True
        or receipt.get("rust_routes_verified") is not True
        or receipt.get("signed_gateway_callback_verified") is not True
        or receipt.get("flow_start_verified") is not True
        or receipt.get("flow_execution_verified") is not True
        or receipt.get("rust_restart_resume_verified") is not True):
        raise HandoffError("Protected Rust producer receipt differs from plan")
    certificate = receipt["certificate"]
    if (not isinstance(certificate, dict)
        or set(certificate) != {"schema", "status", "gateway_operator_authorization_verified",
                                "project", "source_commit", "evidence"}
        or not isinstance(certificate.get("evidence"), dict)
        or set(certificate["evidence"]) != {
            "csca_certificate_id", "csca_certificate_sha256", "dsc_certificate_sha256",
            "csca_issuer_did_sha256", "dsc_issuer_did_sha256",
            "csca_http_status", "dsc_http_status", "chain_verified_by",
            "managed_kms_custody_verified", "chain_verified",
            "csca_issuer_profile_commitment", "dsc_issuer_profile_commitment"}):
        raise HandoffError("Protected managed certificate evidence is invalid")
    try:
        validate_certificate_setup(certificate, plan, receipt["gateway_port"])
    except (ProducerError, KeyError, TypeError, ValueError) as error:
        raise HandoffError("Protected managed certificate evidence is invalid") from error
    _route_evidence(receipt["route"], receipt["gateway_port"])
    _runtime_evidence(receipt, plan)
    _flow_execution_evidence(receipt["flow_execution"], receipt)
    native_preflight = receipt["native_batch_preflight"]
    if (not isinstance(native_preflight, dict)
        or native_preflight != {
            "native_container_id": receipt["pre_restart_native_runtime"]["container_id"],
            "native_batch_preflight_verified": True,
        }):
        raise HandoffError("Native batch preflight differs from the released runtime")
    current_signer = receipt["current_managed_signer"]
    if (not isinstance(current_signer, dict)
        or set(current_signer) != {
            "signing_keys_container_id", "managed_kms_custody_verified",
            "chain_verified", "csca_issuer_profile_commitment",
            "dsc_issuer_profile_commitment", "mode", "issuer_profile_type",
            "organization_id", "private_key_exported", "services_oci_reference",
            "csca", "dsc"}
        or current_signer.get("signing_keys_container_id")
        != receipt["runtime_images"]["signing-keys"]["container_id"]
        or current_signer.get("services_oci_reference")
        != receipt["runtime_images"]["signing-keys"]["oci_reference"]
        or current_signer.get("mode") != "managed_kms"
        or current_signer.get("issuer_profile_type") != "ICAO_EMRTD"
        or current_signer.get("organization_id")
        != _application(receipt["gateway_port"])["organization_id"]
        or current_signer.get("private_key_exported") is not False
        or current_signer.get("managed_kms_custody_verified") is not True
        or current_signer.get("chain_verified") is not True
        or any(current_signer.get(field) != certificate["evidence"][field]
               for field in ("csca_issuer_profile_commitment",
                             "dsc_issuer_profile_commitment"))
        or any(not isinstance(current_signer.get(role), dict)
               or current_signer[role] != {
                   "status": "active",
                   "organization_id": current_signer["organization_id"],
                   "issuer_profile_commitment": current_signer[
                       f"{role}_issuer_profile_commitment"],
                   "certificate_sha256": certificate["evidence"][
                       f"{role}_certificate_sha256"],
               }
               for role in ("csca", "dsc"))):
        raise HandoffError("Current managed signer does not match the released runtime")
    try:
        verified = attest(str(plan_path), "ElevenID/marty-ui", PLAN_WORKFLOW,
                          source_commit, "refs/heads/main")
    except (OSError, ValueError) as error:
        raise HandoffError("Protected plan attestation failed") from error
    if verified is not True:
        raise HandoffError("Protected plan attestation failed")
    return {"schema": "marty.passport-supported-rust-producer-handoff/v1",
            "status": "blocked", "producer_run_id": producer_run_id,
            "project": plan["project"], "source_commit": source_commit}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--producer-run-id", required=True)
    args = parser.parse_args()
    try:
        result = verify_handoff(args.plan, args.receipt, args.source_commit,
                                args.producer_run_id)
    except HandoffError as error:
        parser.exit(1, f"Protected producer handoff blocked: {error}\n")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
