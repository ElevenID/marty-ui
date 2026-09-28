#!/usr/bin/env python3
"""Execute source-bound beta probes and preserve unproven acceptance gates."""

from __future__ import annotations

import argparse
import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

if __package__:
    from .collect_passport_beta_acceptance import (
        EvidenceError,
        collect,
        read_json,
        require,
        verify_attestations,
    )
    from .probe_passport_beta_batch import BatchProbeError
    from .probe_passport_beta_batch import exercise as exercise_batch
    from .probe_passport_beta_chain import (
        ChainProbeError,
        validate_plan,
        validate_sessions,
    )
    from .probe_passport_beta_chain import (
        exercise as exercise_chain,
    )
    from .probe_passport_beta_flow import PHYSICAL_STEPS, FlowProbeError
    from .probe_passport_beta_flow import exercise as exercise_flow
    from .probe_passport_beta_gateway import SHA256, ProbeError, exercise
    from .probe_passport_beta_host import (
        HostProbeError,
        assert_production_unchanged,
        beta_legacy_drain,
        beta_material_receipt,
        beta_native_route_ownership,
        production_snapshot,
    )
    from .probe_passport_beta_native_batch import (
        NativeBatchProbeError,
        clear_private_state,
        ensure_private_state_available,
        exercise as exercise_native_batch,
        request_private_preflight,
    )
    from .probe_passport_beta_physical_flow import (
        PhysicalFlowProbeError,
        require_source_checkout,
    )
    from .probe_passport_beta_physical_flow import (
        validate_plan as validate_physical_flow_plan,
    )
    from .probe_passport_beta_selected_flow import (
        SelectedFlowError,
    )
    from .probe_passport_beta_selected_flow import (
        exercise as exercise_selected_flow,
    )
    from .probe_passport_beta_selected_flow import (
        validate_inputs as validate_selected_flow_inputs,
    )
else:
    from collect_passport_beta_acceptance import (
        EvidenceError,
        collect,
        read_json,
        require,
        verify_attestations,
    )
    from probe_passport_beta_batch import BatchProbeError
    from probe_passport_beta_batch import exercise as exercise_batch
    from probe_passport_beta_chain import (
        ChainProbeError,
        validate_plan,
        validate_sessions,
    )
    from probe_passport_beta_chain import (
        exercise as exercise_chain,
    )
    from probe_passport_beta_flow import PHYSICAL_STEPS, FlowProbeError
    from probe_passport_beta_flow import exercise as exercise_flow
    from probe_passport_beta_gateway import SHA256, ProbeError, exercise
    from probe_passport_beta_host import (
        HostProbeError,
        assert_production_unchanged,
        beta_legacy_drain,
        beta_material_receipt,
        beta_native_route_ownership,
        production_snapshot,
    )
    from probe_passport_beta_native_batch import (
        NativeBatchProbeError,
        clear_private_state,
        ensure_private_state_available,
        exercise as exercise_native_batch,
        request_private_preflight,
    )
    from probe_passport_beta_physical_flow import (
        PhysicalFlowProbeError,
        require_source_checkout,
    )
    from probe_passport_beta_physical_flow import (
        validate_plan as validate_physical_flow_plan,
    )
    from probe_passport_beta_selected_flow import (
        SelectedFlowError,
    )
    from probe_passport_beta_selected_flow import (
        exercise as exercise_selected_flow,
    )
    from probe_passport_beta_selected_flow import (
        validate_inputs as validate_selected_flow_inputs,
    )


def run(
    artifact_dir: Path,
    application: dict[str, Any],
    api_key: str,
    *,
    collector: Callable[..., dict[str, Any]] = collect,
    attestor: Callable[..., bool] = verify_attestations,
    snapshot: Callable[[], dict[str, Any]] = production_snapshot,
    drain: Callable[[], dict[str, Any]] = beta_legacy_drain,
    lifecycle: Callable[..., dict[str, Any]] = exercise,
    certificate_plan: dict[str, Any] | None = None,
    csca_session: str | None = None,
    dsc_session: str | None = None,
    chain: Callable[..., dict[str, Any]] = exercise_chain,
    routing: Callable[[dict[str, dict[str, Any]], dict[str, Any] | None], dict[str, Any]] = beta_native_route_ownership,
    flow: Callable[[str], dict[str, Any]] = exercise_flow,
    material_receipt: Callable[..., dict[str, Any]] = beta_material_receipt,
    selected_flow_plan: dict[str, Any] | None = None,
    flow_operator_cookie: str | None = None,
    selected_flow: Callable[..., dict[str, Any]] = exercise_selected_flow,
    native_batch: Callable[..., tuple[str, dict[str, Any]]] = exercise_native_batch,
    native_preflight: Callable[..., None] = request_private_preflight,
    native_service_token: str | None = None,
    native_operator_token: str | None = None,
    private_state_path: Path | None = None,
    batch: Callable[..., dict[str, Any]] = exercise_batch,
    checkout_checker: Callable[[str], None] = require_source_checkout,
) -> dict[str, Any]:
    report = collector(artifact_dir, api_key=api_key, attest=attestor)
    require(report.get("status") == "blocked" and report.get("release", {}).get("signed_manifest_verified") is True, "Official beta release is not authenticated")
    require(report.get("probes", {}).get("capabilities_http", {}).get("verified") is True, "Managed issuer capability is not ready")
    require(report.get("deployment", {}).get("provider_mode") == "simulator"
            and report.get("provider_ingress_runtime_image") is None,
            "Beta passport acceptance requires Marty's isolated simulator")
    boundary = report.get("probes", {}).get("physical_claim_boundary", {})
    require(report.get("physical_claim") == "not_claimed"
            and boundary.get("verified") is True
            and boundary.get("evidence") == {
                "physical_claim": "not_claimed", "booklet_verified": False},
            "Beta passport report must not claim physical issuance")
    require(isinstance(certificate_plan, dict) and bool(csca_session) and bool(dsc_session),
            "Governed CSCA and DSC ceremony inputs are incomplete")
    validate_sessions(csca_session, dsc_session)
    validate_plan(certificate_plan)
    require(certificate_plan["organization_id"] == application.get("organization_id")
            and certificate_plan["dsc"]["dsc_issuer_did"] == application.get("issuer_did"),
            "Certificate plan does not match the passport application")
    bureau = report["runtime_images"].get("passport-beta-bureau")
    require(isinstance(bureau, dict)
            and all(isinstance(bureau.get(key), str)
                    for key in ("container_id", "oci_reference")),
            "Inspected beta simulator is missing")
    native_image = report["runtime_images"].get("issuance-native")
    if selected_flow_plan is not None:
        require(isinstance(selected_flow_plan, dict)
                and set(selected_flow_plan) == {"source_commit", "stack_manifest_sha256",
                    "organization_id", "issuer_did", "flow_definition_id", "references",
                    "physical_document"}
                and selected_flow_plan["source_commit"] == report["release"].get("source_commit")
                and selected_flow_plan["stack_manifest_sha256"] == report["release"].get("stack_manifest_sha256")
                and selected_flow_plan["organization_id"] == application.get("organization_id")
                and selected_flow_plan["issuer_did"] == application.get("issuer_did")
                and isinstance(selected_flow_plan.get("flow_definition_id"), str)
                and bool(selected_flow_plan["flow_definition_id"])
                and isinstance(selected_flow_plan.get("references"), dict)
                and isinstance(selected_flow_plan.get("physical_document"), dict)
                and isinstance(flow_operator_cookie, str) and bool(flow_operator_cookie),
                "Governed selected Flow inputs are incomplete")
        validate_selected_flow_inputs(
            selected_flow_plan["flow_definition_id"], application["organization_id"],
            application["issuer_did"], selected_flow_plan["references"],
            selected_flow_plan["physical_document"], flow_operator_cookie, api_key,
            bureau["container_id"],
        )
        validate_physical_flow_plan({
            key: selected_flow_plan[key] for key in (
                "source_commit", "stack_manifest_sha256", "organization_id",
                "issuer_did", "flow_definition_id", "physical_document"
            )
        }, report["release"], report["deployment"])
        checkout_checker(selected_flow_plan["source_commit"])
    for name in ("application_template_id", "credential_template_id",
                 "delivery_destination_profile_id"):
        require(isinstance(application.get(name), str) and bool(application[name]),
                "Managed passport application profile is incomplete")
        if selected_flow_plan is not None:
            require(selected_flow_plan["references"][name] == application[name],
                    "Selected Flow references differ from the managed application")
    if selected_flow_plan is not None:
        require(isinstance(native_image, dict)
                and isinstance(native_image.get("container_id"), str)
                and isinstance(native_service_token, str)
                and len(native_service_token) >= 32
                and isinstance(native_operator_token, str)
                and len(native_operator_token) >= 32
                and native_service_token != native_operator_token
                and all(character not in native_operator_token for character in "\r\n\0"),
                "Protected native batch operator credential or image is unavailable")
        require(isinstance(private_state_path, Path),
                "Protected native batch state path is unavailable")
        ensure_private_state_available(private_state_path)
        native_preflight(native_image["container_id"], application["organization_id"],
                         native_service_token, native_operator_token)
    route_ownership = routing(report["runtime_images"], report.get("provider_ingress_runtime_image"))
    route_evidence = route_ownership.get("evidence")
    webhook_owner = route_evidence.get("webhook_owner") if isinstance(route_evidence, dict) else None
    require(route_ownership.get("verified") is True
            and webhook_owner == "issuance-native",
            "Beta native route ownership did not verify")
    before_production = snapshot()
    before_drain = drain()
    selected_dsc: dict[str, str] = {}
    receipt_result: dict[str, Any] | None = None
    selected_result: dict[str, Any] | None = None
    batch_result: dict[str, Any] | None = None
    native_batch_result: dict[str, Any] | None = None

    def capture_dsc(der_sha256: str, pem_wire_sha256: str) -> None:
        selected_dsc.update(der_sha256=der_sha256, pem_wire_sha256=pem_wire_sha256)

    def compare_submission(org: str, source_job: str, bureau_job: str, sod_sha256: str) -> dict[str, Any]:
        nonlocal receipt_result
        require(org == application["organization_id"] and len(selected_dsc) == 2,
                "Selected DSC material is unavailable for the simulator receipt")
        receipt_result = material_receipt(org, source_job, bureau_job, sod_sha256,
                                          selected_dsc["der_sha256"], selected_dsc["pem_wire_sha256"],
                                          api_key.encode("utf-8"))
        require(receipt_result.get("verified") is True, "Simulator first accepted material receipt did not verify")
        return receipt_result

    try:
        chain_result = chain(certificate_plan, csca_session, dsc_session, on_dsc_material=capture_dsc)
        require(chain_result.get("verified") is True and isinstance(chain_result.get("evidence"), dict),
                "Managed CSCA and DSC chain did not verify")
        require(selected_dsc.get("der_sha256") == chain_result["evidence"].get("dsc_certificate_sha256"),
                "Selected DSC material differs from the verified chain")
        flow_result = flow(webhook_owner)
        flow_evidence = flow_result.get("evidence")
        require(flow_result.get("verified") is True and isinstance(flow_evidence, dict)
                and flow_evidence.get("unsigned_webhook_owner") == webhook_owner
                and flow_evidence.get("signature_denial_verified") is True,
                "Beta Flow and webhook probe did not verify")
        lifecycle_result = lifecycle(application, api_key, on_submission=compare_submission)
        if selected_flow_plan is not None:
            direct_receipt = receipt_result
            require(isinstance(direct_receipt, dict)
                    and isinstance(direct_receipt.get("evidence"), dict)
                    and isinstance(direct_receipt["evidence"].get("source_job_id_commitment"), str),
                    "Direct passport job commitment is unavailable")
            def bind_native_batch(
                instance_id: str, application_id: str, source_job_id: str,
                sod_sha256: str, issuer_profile_id: str,
            ) -> str:
                nonlocal native_batch_result
                require(len(selected_dsc) == 2,
                        "Selected DSC material is unavailable for the native batch")
                selected_bureau_id, native_batch_result = native_batch(
                    application, selected_flow_plan["physical_document"], api_key,
                    native_service_token, native_operator_token,
                    native_image["container_id"], bureau["container_id"],
                    instance_id, application_id, source_job_id, sod_sha256,
                    issuer_profile_id, selected_dsc["der_sha256"],
                    selected_dsc["pem_wire_sha256"], material_receipt,
                    private_state_path,
                )
                return selected_bureau_id

            selected_result = selected_flow(
                selected_flow_plan["flow_definition_id"], application["organization_id"],
                application["issuer_did"], selected_flow_plan["references"],
                selected_flow_plan["physical_document"], flow_operator_cookie, api_key,
                simulator_container_id=bureau["container_id"], on_submission=compare_submission,
                on_signed_sod=bind_native_batch,
            )
            selected_evidence = selected_result.get("evidence") if isinstance(selected_result, dict) else None
            require(isinstance(selected_result, dict) and selected_result.get("verified") is True
                    and isinstance(selected_evidence, dict)
                    and isinstance(selected_evidence.get("job_id"), str)
                    and bool(selected_evidence["job_id"])
                    and isinstance(selected_evidence.get("sod_sha256"), str)
                    and SHA256.fullmatch(selected_evidence["sod_sha256"]) is not None
                    and selected_evidence.get("ordered_steps") == list(PHYSICAL_STEPS)
                    and selected_evidence.get("completed_steps") == len(PHYSICAL_STEPS)
                    and selected_evidence.get("physical_claim") == "not_claimed"
                    and selected_evidence.get("signed_simulator_callback_verified") is True
                    and selected_evidence.get("terminal_native_status") == "ACTIVE"
                    and isinstance(selected_evidence.get("callback_receipt_sha256"), str)
                    and SHA256.fullmatch(selected_evidence["callback_receipt_sha256"]) is not None
                    and isinstance(receipt_result, dict) and isinstance(receipt_result.get("evidence"), dict)
                    and selected_evidence.get("source_job_commitment") == receipt_result["evidence"].get("source_job_id_commitment")
                    and selected_evidence.get("bureau_job_commitment") == receipt_result["evidence"].get("bureau_job_id_commitment")
                    and selected_evidence.get("source_job_commitment") != direct_receipt["evidence"]["source_job_id_commitment"],
                    "Selected Flow did not produce a distinct receipt-bound passport job")
            native_evidence = native_batch_result.get("evidence") if isinstance(native_batch_result, dict) else None
            require(isinstance(native_batch_result, dict)
                    and native_batch_result.get("verified") is True
                    and isinstance(native_evidence, dict)
                    and native_evidence.get("provider_kind") == "simulator"
                    and native_evidence.get("physical_claim") == "not_claimed"
                    and native_evidence.get("http_status") == 202
                    and native_evidence.get("batch_status") == "QUEUED"
                    and native_evidence.get("selected_flow_in_two_job_batch") is True
                    and native_evidence.get("native_binding_verified") is True
                    and native_evidence.get("first_accepted_material_verified") is True
                    and native_evidence.get("companion_native_completed") is True
                    and native_evidence.get("selected_source_job_commitment") == selected_evidence["source_job_commitment"]
                    and native_evidence.get("selected_bureau_job_commitment") == selected_evidence["bureau_job_commitment"]
                    and isinstance(native_evidence.get("companion_source_job_commitment"), str)
                    and SHA256.fullmatch(native_evidence["companion_source_job_commitment"])
                    and native_evidence["companion_source_job_commitment"] != native_evidence["selected_source_job_commitment"]
                    and isinstance(native_evidence.get("companion_bureau_job_commitment"), str)
                    and SHA256.fullmatch(native_evidence["companion_bureau_job_commitment"])
                    and native_evidence["companion_bureau_job_commitment"] != native_evidence["selected_bureau_job_commitment"]
                    and native_evidence.get("submitted_job_commitments") == [
                        native_evidence["selected_source_job_commitment"],
                        native_evidence["companion_source_job_commitment"]]
                    and native_evidence.get("returned_jobs") == [
                        {"source_job_commitment": native_evidence["selected_source_job_commitment"],
                         "bureau_job_commitment": native_evidence["selected_bureau_job_commitment"]},
                        {"source_job_commitment": native_evidence["companion_source_job_commitment"],
                         "bureau_job_commitment": native_evidence["companion_bureau_job_commitment"]}]
                    and all(isinstance(native_evidence.get(field), str)
                            and SHA256.fullmatch(native_evidence[field])
                            for field in ("request_commitment", "response_commitment",
                                          "companion_callback_receipt_sha256")),
                    "Selected Flow native batch proof did not verify")
        else:
            batch_result = batch(
                application, api_key, bureau["container_id"],
                report["release"]["source_commit"], report["release"]["stack_manifest_sha256"],
                bureau["oci_reference"],
            )
        if batch_result is not None:
            batch_evidence = batch_result.get("evidence") if isinstance(batch_result, dict) else None
            require(isinstance(batch_result, dict) and batch_result.get("verified") is True
                    and isinstance(batch_evidence, dict)
                    and batch_evidence.get("provider_kind") == "simulator"
                    and batch_evidence.get("physical_claim") == "not_claimed"
                    and batch_evidence.get("simulator_marker_verified") is True
                    and batch_evidence.get("native_binding_verified") is True
                    and batch_evidence.get("native_completed_jobs") == 2
                    and batch_evidence.get("source_commit") == report["release"]["source_commit"]
                    and batch_evidence.get("stack_manifest_sha256") == report["release"]["stack_manifest_sha256"]
                    and batch_evidence.get("services_oci_reference") == bureau["oci_reference"]
                    and batch_evidence.get("commitment_scheme") == "HMAC-SHA256"
                    and batch_evidence.get("http_status") == 202
                    and batch_evidence.get("batch_status") == "QUEUED"
                    and isinstance(batch_evidence.get("request_commitment"), str)
                    and SHA256.fullmatch(batch_evidence["request_commitment"])
                    and isinstance(batch_evidence.get("response_commitment"), str)
                    and SHA256.fullmatch(batch_evidence["response_commitment"])
                    and isinstance(batch_evidence.get("submitted_job_commitments"), list)
                    and len(batch_evidence["submitted_job_commitments"]) == 2
                    and len(set(batch_evidence["submitted_job_commitments"])) == 2
                    and all(isinstance(value, str) and SHA256.fullmatch(value)
                            for value in batch_evidence["submitted_job_commitments"])
                    and isinstance(batch_evidence.get("returned_jobs"), list)
                    and len(batch_evidence["returned_jobs"]) == 2
                    and {item.get("source_job_commitment") for item in batch_evidence["returned_jobs"]
                         if isinstance(item, dict)} == set(batch_evidence["submitted_job_commitments"])
                    and all(isinstance(item, dict)
                            and isinstance(item.get("bureau_job_commitment"), str)
                            and SHA256.fullmatch(item["bureau_job_commitment"])
                            and item.get("status") == "SHIPPED"
                            for item in batch_evidence["returned_jobs"])
                    and isinstance(batch_evidence.get("callback_receipts_sha256"), list)
                    and len(batch_evidence["callback_receipts_sha256"]) == 2
                    and all(isinstance(value, str) and SHA256.fullmatch(value)
                            for value in batch_evidence["callback_receipts_sha256"])
                    and batch_evidence.get("callback_receipt_sha256") == batch_evidence["callback_receipts_sha256"][0],
                    "Live beta simulator batch and signed callback receipt did not verify")
    finally:
        after_production = snapshot()
        production_window = assert_production_unchanged(before_production, after_production)
    after_drain = drain()
    after = collector(artifact_dir, api_key=api_key, attest=attestor)
    require(all(report[key] == after[key] for key in ("release", "deployment", "runtime_images")), "Beta release or runtime drifted during passport acceptance")
    require(report.get("provider_ingress_runtime_image") == after.get("provider_ingress_runtime_image"),
            "Beta provider ingress drifted during passport acceptance")
    require(route_ownership == routing(after["runtime_images"], after.get("provider_ingress_runtime_image")),
            "Beta native route selectors drifted during passport acceptance")
    require(receipt_result is not None and receipt_result.get("verified") is True,
            "Simulator first accepted material receipt is unavailable")
    report["probes"]["simulator_material_receipt"] = receipt_result
    # The retained simulator diagnostic sends synthetic material outside the
    # selected Flow. Keep its evidence, but do not qualify release probes from
    # a pair that the native batch route did not dispatch and bind.
    report["probes"]["simulator_batch_diagnostic"] = (
        batch_result if batch_result is not None else
        {"verified": False, "evidence": {"missing": ["diagnostic_not_run"]}}
    )
    if native_batch_result is not None:
        native_evidence = native_batch_result["evidence"]
        report["probes"]["physical_bureau_batch"] = {"verified": True, "evidence": {
            **native_evidence,
            "source_commit": report["release"]["source_commit"],
            "stack_manifest_sha256": report["release"]["stack_manifest_sha256"],
            "services_oci_reference": bureau["oci_reference"],
            "native_completed_jobs": 2,
            "selected_flow_callback_verified": True,
            "selected_callback_receipt_sha256": selected_result["evidence"]["callback_receipt_sha256"],
        }}
        report["probes"]["physical_bureau_submission"] = {"verified": False, "evidence": {
            "selected_flow_in_two_job_batch": True,
            "missing": ["protected_recorder_identity_correlation"],
        }}
    else:
        report["probes"]["physical_bureau_batch"] = {"verified": False, "evidence": {
            "missing": ["selected_flow_in_native_batch", "exact_native_batch_wire_proof"],
        }}
        report["probes"]["physical_bureau_submission"] = {"verified": False, "evidence": {
            "missing": ["selected_flow_batch_binding"],
        }}
    report["probes"]["packaged_image"] = {"verified": True, "evidence": {
        "source_commit": report["release"]["source_commit"],
        "stack_manifest_sha256": report["release"]["stack_manifest_sha256"],
        "services_oci_reference": bureau["oci_reference"],
        "runtime_container_id": bureau["container_id"],
    }}
    report["probes"]["signed_bureau_callback"] = {"verified": False, "evidence": {
        "selected_flow_batch_callback": native_batch_result is not None,
        "missing": ["same_job_negative_callback_denials"] if native_batch_result is not None
                   else ["selected_flow_batch_callback", "same_job_negative_callback_denials"],
    }}
    if selected_result is not None:
        selected_evidence = selected_result["evidence"]
        report["probes"]["selected_physical_flow"] = {"verified": True, "evidence": {
            "sod_sha256": selected_evidence["sod_sha256"],
            "ordered_steps": selected_evidence["ordered_steps"],
            "completed_steps": selected_evidence["completed_steps"],
            "source_job_commitment": selected_evidence["source_job_commitment"],
            "bureau_job_commitment": selected_evidence["bureau_job_commitment"],
            "callback_receipt_sha256": selected_evidence["callback_receipt_sha256"],
            "terminal_native_status": selected_evidence["terminal_native_status"],
            "physical_claim": selected_evidence["physical_claim"],
        }}
    lifecycle_evidence = lifecycle_result.get("evidence")
    require(lifecycle_result.get("verified") is True and isinstance(lifecycle_evidence, dict)
            and lifecycle_evidence.get("sod_signature_verified") is True
            and isinstance(lifecycle_evidence.get("sod_sha256"), str)
            and SHA256.fullmatch(lifecycle_evidence["sod_sha256"]) is not None,
            "Native SOD signature evidence is unavailable")
    safe_lifecycle_evidence = {
        "sod_sha256": lifecycle_evidence["sod_sha256"],
        "sod_signature_verified": True,
    }
    route_statuses = {
        ("POST", "/v1/passport/applications", 201),
        ("POST", "/v1/passport/applications/{application_id}/generate-data-groups", 200),
        ("POST", "/v1/passport/applications/{application_id}/generate-sod", 200),
        ("POST", "/v1/passport/applications/{application_id}/submit-personalization", 200),
        ("GET", "/v1/passport/applications/{application_id}/production-status", 200),
        ("POST", "/v1/passport/applications/{application_id}/quality-verify", 200),
        ("POST", "/v1/passport/applications/{application_id}/activate", 200),
    }
    routes = lifecycle_evidence.get("routes")
    if selected_result is not None:
        require(isinstance(routes, list) and len(routes) >= len(route_statuses)
                and all(isinstance(item, dict)
                        and set(item) == {"method", "route", "http_status", "job_status"}
                        and (item["method"], item["route"], item["http_status"]) in route_statuses
                        and item["job_status"] in {
                            "DRAFT", "DATA_GENERATED", "SOD_SIGNED", "SUBMITTED",
                            "IN_PRODUCTION", "QUALITY_CHECK", "READY_FOR_ACTIVATION", "ACTIVE"}
                        for item in routes)
                and {(item["method"], item["route"], item["http_status"])
                     for item in routes} == route_statuses,
                "Direct passport route evidence is incomplete")
        safe_lifecycle_evidence["routes"] = routes
    if selected_result is not None:
        safe_lifecycle_evidence["source_job_commitment"] = direct_receipt["evidence"]["source_job_id_commitment"]
    report["probes"]["gateway_application_lifecycle"] = {
        "verified": True, "evidence": safe_lifecycle_evidence}
    selected_evidence = selected_result["evidence"] if selected_result is not None else None
    report["probes"]["sod_signature"] = {"verified": True, "evidence": {
        "sod_sha256": (selected_evidence["sod_sha256"] if selected_evidence is not None
                       else lifecycle_evidence["sod_sha256"]),
        "native_generate_sod_verified": True,
        **({"dsc_certificate_sha256": chain_result["evidence"]["dsc_certificate_sha256"],
            "source_job_commitment": selected_evidence["source_job_commitment"]}
           if selected_evidence is not None else {}),
    }}
    report["probes"]["beta_native_route_ownership"] = route_ownership
    report["probes"]["flow_capability_and_webhook_denial"] = flow_result
    report["probes"]["nine_route_gateway_flow"] = {"verified": False, "evidence": {
        "capabilities_http": report["probes"]["capabilities_http"].get("evidence"),
        "application_lifecycle": safe_lifecycle_evidence,
        "flow_and_webhook_denial": flow_result.get("evidence"),
        "native_route_ownership": route_ownership.get("evidence"),
        "missing": (["same_job_gateway_route_trace"] if native_batch_result is not None
                    else ["executed_simulator_flow", "selected_flow_in_two_job_batch"]),
    }}
    chain_evidence = chain_result["evidence"]
    report["probes"]["managed_csca_dsc_chain"] = {"verified": True, "evidence": {
        key: chain_evidence[key] for key in (
            "csca_certificate_sha256", "dsc_certificate_sha256",
            "csca_http_status", "dsc_http_status", "chain_verified_by")
        if key in chain_evidence
    }}
    report["probes"]["legacy_drain"] = {
        "verified": before_drain.get("verified") is True and after_drain.get("verified") is True,
        "evidence": {"before": before_drain.get("evidence"), "after": after_drain.get("evidence")},
    }
    report["probes"]["production_continuity_during_probe"] = production_window
    # The required production-isolation gate spans deployment and rollback,
    # which this workflow does not control. Preserve it as unverified.
    report["status"] = "blocked"
    if native_batch_result is not None:
        clear_private_state(private_state_path)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--application-file", type=Path, required=True)
    parser.add_argument("--certificate-plan-file", type=Path)
    parser.add_argument("--selected-flow-plan-file", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        api_key = os.environ.get("PASSPORT_ACCEPTANCE_API_KEY")
        require(isinstance(api_key, str) and len(api_key) >= 32, "Passport beta API key is unavailable")
        require(args.certificate_plan_file is not None
                and all(os.environ.get(name, "").strip() for name in (
                    "PASSPORT_ACCEPTANCE_CSCA_OPERATOR_COOKIE",
                    "PASSPORT_ACCEPTANCE_DSC_OPERATOR_COOKIE",
                )), "Protected acceptance requires the managed CSCA and DSC ceremony")
        require(args.selected_flow_plan_file is not None
                and os.environ.get("PASSPORT_ACCEPTANCE_FLOW_OPERATOR_COOKIE", "").strip(),
                "Protected acceptance requires the selected physical Flow probe")
        application = read_json(args.application_file)
        certificate_plan = read_json(args.certificate_plan_file) if args.certificate_plan_file else None
        selected_flow_plan = read_json(args.selected_flow_plan_file) if args.selected_flow_plan_file else None
        report = run(
            args.artifact_dir, application, api_key, certificate_plan=certificate_plan,
            csca_session=os.environ.get("PASSPORT_ACCEPTANCE_CSCA_OPERATOR_COOKIE"),
            dsc_session=os.environ.get("PASSPORT_ACCEPTANCE_DSC_OPERATOR_COOKIE"),
            selected_flow_plan=selected_flow_plan,
            flow_operator_cookie=os.environ.get("PASSPORT_ACCEPTANCE_FLOW_OPERATOR_COOKIE"),
            native_service_token=os.environ.get("PASSPORT_ACCEPTANCE_INTERNAL_SERVICE_TOKEN"),
            native_operator_token=os.environ.get("PASSPORT_ACCEPTANCE_RECONCILIATION_OPERATOR_TOKEN"),
            private_state_path=Path.home() / ".local" / "state" / "marty" / "passport-beta-native-pending.json",
        )
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (EvidenceError, ProbeError, ChainProbeError, FlowProbeError, SelectedFlowError,
            BatchProbeError, NativeBatchProbeError, PhysicalFlowProbeError,
            HostProbeError, OSError) as exc:
        args.output.write_text(json.dumps({"schema": "marty.passport-beta-acceptance/v1", "status": "blocked", "blocker": str(exc)}, indent=2) + "\n", encoding="utf-8")
        parser.exit(1, f"Passport beta acceptance blocked: {exc}\n")
    print(f"Wrote blocked passport beta acceptance evidence: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
