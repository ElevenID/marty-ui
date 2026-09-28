#!/usr/bin/env python3
"""Execute source-bound beta probes and preserve unproven acceptance gates."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any, Callable

if __package__:
    from .collect_passport_beta_acceptance import (
        EvidenceError, collect, read_json, require, verify_attestations,
    )
    from .probe_passport_beta_gateway import ProbeError, SHA256, exercise
    from .probe_passport_beta_chain import (
        ChainProbeError, exercise as exercise_chain, validate_plan, validate_sessions,
    )
    from .probe_passport_beta_flow import PHYSICAL_STEPS, FlowProbeError, exercise as exercise_flow
    from .probe_passport_beta_batch import BatchProbeError, exercise as exercise_batch
    from .probe_passport_beta_physical_flow import (
        PhysicalFlowProbeError, exercise as exercise_physical_flow, require_source_checkout,
        validate_operator_session, validate_plan as validate_physical_flow_plan,
    )
    from .probe_passport_beta_host import (
        HostProbeError, assert_production_unchanged, beta_legacy_drain, beta_native_route_ownership,
        production_snapshot,
    )
else:
    from collect_passport_beta_acceptance import (
        EvidenceError, collect, read_json, require, verify_attestations,
    )
    from probe_passport_beta_gateway import ProbeError, SHA256, exercise
    from probe_passport_beta_chain import (
        ChainProbeError, exercise as exercise_chain, validate_plan, validate_sessions,
    )
    from probe_passport_beta_flow import PHYSICAL_STEPS, FlowProbeError, exercise as exercise_flow
    from probe_passport_beta_batch import BatchProbeError, exercise as exercise_batch
    from probe_passport_beta_physical_flow import (
        PhysicalFlowProbeError, exercise as exercise_physical_flow, require_source_checkout,
        validate_operator_session, validate_plan as validate_physical_flow_plan,
    )
    from probe_passport_beta_host import (
        HostProbeError, assert_production_unchanged, beta_legacy_drain, beta_native_route_ownership,
        production_snapshot,
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
    batch: Callable[..., dict[str, Any]] = exercise_batch,
    physical_flow_plan: dict[str, Any] | None = None,
    flow_session: str | None = None,
    physical_flow: Callable[..., dict[str, Any]] = exercise_physical_flow,
    checkout_checker: Callable[[str], None] = require_source_checkout,
) -> dict[str, Any]:
    report = collector(artifact_dir, api_key=api_key, attest=attestor)
    require(report.get("status") == "blocked" and report.get("release", {}).get("signed_manifest_verified") is True, "Official beta release is not authenticated")
    require(report.get("probes", {}).get("capabilities_http", {}).get("verified") is True, "Managed issuer capability is not ready")
    require(report.get("deployment", {}).get("provider_mode") == "simulator",
            "Beta software-route acceptance requires the Marty simulator")
    if physical_flow_plan is not None or flow_session is not None:
        require(isinstance(physical_flow_plan, dict) and bool(flow_session),
                "Physical Flow probe inputs are incomplete")
        validate_operator_session(flow_session)
        validate_physical_flow_plan(physical_flow_plan, report["release"], report["deployment"])
        require(physical_flow_plan["organization_id"] == application.get("organization_id")
                and physical_flow_plan["issuer_did"] == application.get("issuer_did"),
                "Physical Flow plan and managed application identity differ")
        checkout_checker(physical_flow_plan["source_commit"])
    chain_requested = any(value is not None for value in (certificate_plan, csca_session, dsc_session))
    if chain_requested:
        require(isinstance(certificate_plan, dict) and bool(csca_session) and bool(dsc_session),
                "Governed CSCA and DSC ceremony inputs are incomplete")
        validate_sessions(csca_session, dsc_session)
        validate_plan(certificate_plan)
        require(certificate_plan["organization_id"] == application.get("organization_id")
                and certificate_plan["dsc"]["dsc_issuer_did"] == application.get("issuer_did"),
                "Certificate plan does not match the passport application")
    require(isinstance(application.get("organization_id"), str)
            and bool(application["organization_id"]),
            "Beta acceptance application has no organization identity")
    route_ownership = routing(report["runtime_images"], report.get("provider_ingress_runtime_image"))
    route_evidence = route_ownership.get("evidence")
    webhook_owner = route_evidence.get("webhook_owner") if isinstance(route_evidence, dict) else None
    require(route_ownership.get("verified") is True
            and webhook_owner in ("issuance-native", "passport-provider-ingress"),
            "Beta native route ownership did not verify")
    before_production = snapshot()
    before_drain = drain()
    try:
        flow_result = flow(webhook_owner)
        flow_evidence = flow_result.get("evidence")
        require(flow_result.get("verified") is True and isinstance(flow_evidence, dict)
                and flow_evidence.get("unsigned_webhook_owner") == webhook_owner
                and flow_evidence.get("signature_denial_verified") is True,
                "Beta Flow and webhook probe did not verify")
        lifecycle_result = lifecycle(application, api_key)
        bureau = report["runtime_images"].get("passport-beta-bureau")
        require(isinstance(bureau, dict)
                and all(isinstance(bureau.get(key), str)
                        for key in ("container_id", "oci_reference")),
                "Inspected beta simulator is missing")
        batch_result = batch(
            application, api_key, bureau["container_id"],
            report["release"]["source_commit"], report["release"]["stack_manifest_sha256"],
            bureau["oci_reference"],
        )
        batch_evidence = batch_result.get("evidence") if isinstance(batch_result, dict) else None
        require(isinstance(batch_result, dict) and batch_result.get("verified") is True
                and isinstance(batch_evidence, dict)
                and batch_evidence.get("provider_kind") == "simulator"
                and batch_evidence.get("physical_claim") == "not_claimed"
                and batch_evidence.get("simulator_marker_verified") is True
                and batch_evidence.get("native_binding_verified") is True
                and batch_evidence.get("native_completed_jobs") == 2
                and isinstance(batch_evidence.get("callback_receipts_sha256"), list)
                and len(batch_evidence["callback_receipts_sha256"]) >= 2
                and all(isinstance(value, str) and SHA256.fullmatch(value) is not None
                        for value in batch_evidence["callback_receipts_sha256"])
                and batch_evidence.get("callback_receipt_sha256")
                == batch_evidence["callback_receipts_sha256"][0],
                "Live beta simulator batch and signed callback receipt did not verify")
        require(batch_evidence.get("source_commit") == report["release"]["source_commit"]
                and batch_evidence.get("stack_manifest_sha256") == report["release"]["stack_manifest_sha256"]
                and batch_evidence.get("services_oci_reference") == bureau["oci_reference"]
                and batch_evidence.get("commitment_scheme") == "HMAC-SHA256"
                and batch_evidence.get("http_status") == 202
                and batch_evidence.get("batch_status") == "QUEUED"
                and isinstance(batch_evidence.get("request_commitment"), str)
                and SHA256.fullmatch(batch_evidence["request_commitment"]) is not None
                and isinstance(batch_evidence.get("response_commitment"), str)
                and SHA256.fullmatch(batch_evidence["response_commitment"]) is not None
                and isinstance(batch_evidence.get("submitted_job_commitments"), list)
                and len(batch_evidence["submitted_job_commitments"]) == 2
                and all(isinstance(value, str) and SHA256.fullmatch(value) is not None
                        for value in batch_evidence["submitted_job_commitments"])
                and len(set(batch_evidence["submitted_job_commitments"])) == 2
                and isinstance(batch_evidence.get("returned_jobs"), list)
                and len(batch_evidence["returned_jobs"]) == 2
                and {job.get("source_job_commitment") for job in batch_evidence["returned_jobs"]
                     if isinstance(job, dict)} == set(batch_evidence["submitted_job_commitments"]),
                "Beta simulator submission is not bound to the signed release and both jobs")
        physical_result = None
        if physical_flow_plan is not None:
            physical_result = physical_flow(
                physical_flow_plan, report["release"], report["deployment"],
                bureau["container_id"], flow_session, api_key,
            )
            physical_evidence = physical_result.get("evidence") if isinstance(physical_result, dict) else None
            direct_evidence = lifecycle_result.get("evidence")
            require(isinstance(physical_result, dict) and physical_result.get("verified") is True
                    and isinstance(physical_evidence, dict)
                    and physical_evidence.get("source_commit") == report["release"]["source_commit"]
                    and physical_evidence.get("stack_manifest_sha256") == report["release"]["stack_manifest_sha256"]
                    and physical_evidence.get("steps") == list(PHYSICAL_STEPS)
                    and physical_evidence.get("provider_kind") == "simulator"
                    and physical_evidence.get("physical_claim") == "not_claimed"
                    and physical_evidence.get("sod_signature_verified") is True
                    and isinstance(physical_evidence.get("sod_sha256"), str)
                    and SHA256.fullmatch(physical_evidence["sod_sha256"]) is not None
                    and physical_evidence.get("signed_simulator_callback_verified") is True
                    and isinstance(physical_evidence.get("callback_receipt_sha256"), str)
                    and SHA256.fullmatch(physical_evidence["callback_receipt_sha256"]) is not None
                    and physical_evidence.get("terminal_native_status") == "ACTIVE"
                    and isinstance(direct_evidence, dict)
                    and all(isinstance(physical_evidence.get(key), str)
                            and SHA256.fullmatch(physical_evidence[key]) is not None
                            and isinstance(direct_evidence.get(key), str)
                            and SHA256.fullmatch(direct_evidence[key]) is not None
                            and physical_evidence[key] != direct_evidence[key]
                            for key in ("application_id_sha256", "job_id_sha256", "bureau_job_id_sha256")),
                    "One Flow job did not bind its SOD, simulator receipt, and terminal state")
        chain_result = None
        if chain_requested:
            chain_result = chain(certificate_plan, csca_session, dsc_session)
            require(chain_result.get("verified") is True and chain_result.get("evidence") is not None,
                    "Managed CSCA and DSC chain did not verify")
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
    report["probes"]["gateway_application_lifecycle"] = lifecycle_result
    lifecycle_evidence = lifecycle_result.get("evidence")
    require(lifecycle_result.get("verified") is True and isinstance(lifecycle_evidence, dict)
            and lifecycle_evidence.get("sod_signature_verified") is True
            and isinstance(lifecycle_evidence.get("sod_sha256"), str)
            and SHA256.fullmatch(lifecycle_evidence["sod_sha256"]) is not None,
            "Native SOD signature evidence is unavailable")
    report["probes"]["sod_signature"] = {"verified": True, "evidence": {
        "sod_sha256": lifecycle_evidence["sod_sha256"],
        "native_generate_sod_verified": True,
    }}
    report["probes"]["beta_native_route_ownership"] = route_ownership
    report["probes"]["flow_capability_and_webhook_denial"] = flow_result
    report["probes"]["physical_bureau_batch"] = batch_result
    report["probes"]["packaged_image"] = {"verified": True, "evidence": {
        "source_commit": report["release"]["source_commit"],
        "stack_manifest_sha256": report["release"]["stack_manifest_sha256"],
        "services_oci_reference": bureau["oci_reference"],
        "runtime_container_id": bureau["container_id"],
    }}
    report["probes"]["physical_bureau_submission"] = {"verified": True, "evidence": {
        "provider_kind": "simulator", "physical_claim": "not_claimed",
        "source_commit": batch_evidence["source_commit"],
        "stack_manifest_sha256": batch_evidence["stack_manifest_sha256"],
        "services_oci_reference": batch_evidence["services_oci_reference"],
        "http_status": batch_evidence["http_status"],
        "batch_status": batch_evidence["batch_status"],
        "request_commitment": batch_evidence["request_commitment"],
        "response_commitment": batch_evidence["response_commitment"],
        "submitted_job_commitments": batch_evidence["submitted_job_commitments"],
        "returned_jobs": batch_evidence["returned_jobs"],
    }}
    report["physical_claim"] = "not_claimed"
    report["probes"]["physical_claim_boundary"] = {"verified": True, "evidence": {
        "physical_claim": "not_claimed", "booklet_verified": False,
        "provider_kind": "simulator",
    }}
    report["probes"]["signed_bureau_callback"] = {"verified": True, "evidence": {
        "provider_kind": "simulator", "physical_claim": "not_claimed",
        "unsigned_signature_denied": True,
        "callback_receipts_sha256": batch_evidence["callback_receipts_sha256"],
        "accepted_by_native_callback": True,
        "flow_callback_receipt_sha256": (physical_result["evidence"]["callback_receipt_sha256"]
                                         if physical_result is not None else None),
    }}
    if physical_result is not None:
        report["probes"]["executed_physical_document_flow"] = physical_result
    report["probes"]["nine_route_gateway_flow"] = {"verified": physical_result is not None, "evidence": {
        "capabilities_http": report["probes"]["capabilities_http"].get("evidence"),
        "application_lifecycle": lifecycle_result.get("evidence"),
        "flow_and_webhook_denial": flow_result.get("evidence"),
        "native_route_ownership": route_ownership.get("evidence"),
        "signed_simulator_callback": report["probes"]["signed_bureau_callback"]["evidence"],
        "physical_flow": physical_result.get("evidence") if physical_result is not None else None,
        "execution_relationship": ("flow_job_end_to_end_with_separate_direct_lifecycle"
                                   if physical_result is not None else "physical_flow_absent"),
        "missing": [] if physical_result is not None else ["executed_physical_document_flow"],
    }}
    if chain_result is not None:
        report["probes"]["managed_csca_dsc_chain"] = chain_result
    report["probes"]["legacy_drain"] = {
        "verified": before_drain.get("verified") is True and after_drain.get("verified") is True,
        "evidence": {"before": before_drain.get("evidence"), "after": after_drain.get("evidence")},
    }
    report["probes"]["production_continuity_during_probe"] = production_window
    # The required production-isolation gate spans deployment and rollback,
    # which this workflow does not control. Preserve it as unverified.
    report["status"] = "blocked"
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--application-file", type=Path, required=True)
    parser.add_argument("--certificate-plan-file", type=Path)
    parser.add_argument("--physical-flow-plan-file", type=Path)
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
        require(args.physical_flow_plan_file is not None
                and os.environ.get("PASSPORT_ACCEPTANCE_FLOW_OPERATOR_COOKIE", "").strip(),
                "Protected acceptance requires the simulator-backed physical Flow probe")
        application = read_json(args.application_file)
        certificate_plan = read_json(args.certificate_plan_file)
        physical_flow_plan = read_json(args.physical_flow_plan_file)
        report = run(
            args.artifact_dir, application, api_key, certificate_plan=certificate_plan,
            csca_session=os.environ.get("PASSPORT_ACCEPTANCE_CSCA_OPERATOR_COOKIE"),
            dsc_session=os.environ.get("PASSPORT_ACCEPTANCE_DSC_OPERATOR_COOKIE"),
            physical_flow_plan=physical_flow_plan,
            flow_session=os.environ.get("PASSPORT_ACCEPTANCE_FLOW_OPERATOR_COOKIE"),
        )
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (EvidenceError, ProbeError, ChainProbeError, FlowProbeError, BatchProbeError,
            PhysicalFlowProbeError, HostProbeError, OSError) as exc:
        args.output.write_text(json.dumps({"schema": "marty.passport-beta-acceptance/v1", "status": "blocked", "blocker": str(exc)}, indent=2) + "\n", encoding="utf-8")
        parser.exit(1, f"Passport beta acceptance blocked: {exc}\n")
    print(f"Wrote blocked passport beta acceptance evidence: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
