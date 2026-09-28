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
    if selected_flow_plan is not None:
        require(isinstance(selected_flow_plan, dict)
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
        )
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
            selected_result = selected_flow(
                selected_flow_plan["flow_definition_id"], application["organization_id"],
                application["issuer_did"], selected_flow_plan["references"],
                selected_flow_plan["physical_document"], flow_operator_cookie, api_key,
                on_submission=compare_submission,
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
                    and isinstance(receipt_result, dict) and isinstance(receipt_result.get("evidence"), dict)
                    and selected_evidence.get("source_job_commitment") == receipt_result["evidence"].get("source_job_id_commitment")
                    and selected_evidence.get("bureau_job_commitment") == receipt_result["evidence"].get("bureau_job_id_commitment")
                    and selected_evidence.get("source_job_commitment") != direct_receipt["evidence"]["source_job_id_commitment"],
                    "Selected Flow did not produce a distinct receipt-bound passport job")
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
    require(receipt_result is not None and receipt_result.get("verified") is True,
            "Simulator first accepted material receipt is unavailable")
    report["probes"]["simulator_material_receipt"] = receipt_result
    if selected_result is not None:
        selected_evidence = selected_result["evidence"]
        report["probes"]["selected_physical_flow"] = {"verified": True, "evidence": {
            "sod_sha256": selected_evidence["sod_sha256"],
            "ordered_steps": selected_evidence["ordered_steps"],
            "completed_steps": selected_evidence["completed_steps"],
            "source_job_commitment": selected_evidence["source_job_commitment"],
            "bureau_job_commitment": selected_evidence["bureau_job_commitment"],
            "physical_claim": selected_evidence["physical_claim"],
        }}
    lifecycle_evidence = lifecycle_result.get("evidence")
    require(lifecycle_result.get("verified") is True and isinstance(lifecycle_evidence, dict)
            and lifecycle_evidence.get("sod_signature_verified") is True
            and isinstance(lifecycle_evidence.get("sod_sha256"), str)
            and SHA256.fullmatch(lifecycle_evidence["sod_sha256"]) is not None,
            "Native SOD signature evidence is unavailable")
    if selected_result is not None:
        report["probes"]["gateway_application_lifecycle"] = {"verified": True, "evidence": {
            **lifecycle_evidence,
            "source_job_commitment": direct_receipt["evidence"]["source_job_id_commitment"],
        }}
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
        "application_lifecycle": lifecycle_result.get("evidence"),
        "flow_and_webhook_denial": flow_result.get("evidence"),
        "native_route_ownership": route_ownership.get("evidence"),
        "missing": (["signed_simulator_webhook", "same_job_gateway_route_trace"]
                    if selected_result is not None else ["signed_simulator_webhook", "executed_simulator_flow"]),
    }}
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
    parser.add_argument("--selected-flow-plan-file", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        api_key = os.environ.get("PASSPORT_ACCEPTANCE_API_KEY")
        require(isinstance(api_key, str) and len(api_key) >= 32, "Passport beta API key is unavailable")
        application = read_json(args.application_file)
        certificate_plan = read_json(args.certificate_plan_file) if args.certificate_plan_file else None
        selected_flow_plan = read_json(args.selected_flow_plan_file) if args.selected_flow_plan_file else None
        report = run(
            args.artifact_dir, application, api_key, certificate_plan=certificate_plan,
            csca_session=os.environ.get("PASSPORT_ACCEPTANCE_CSCA_OPERATOR_COOKIE"),
            dsc_session=os.environ.get("PASSPORT_ACCEPTANCE_DSC_OPERATOR_COOKIE"),
            selected_flow_plan=selected_flow_plan,
            flow_operator_cookie=os.environ.get("PASSPORT_ACCEPTANCE_FLOW_OPERATOR_COOKIE"),
        )
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (EvidenceError, ProbeError, ChainProbeError, FlowProbeError, SelectedFlowError, HostProbeError, OSError) as exc:
        args.output.write_text(json.dumps({"schema": "marty.passport-beta-acceptance/v1", "status": "blocked", "blocker": str(exc)}, indent=2) + "\n", encoding="utf-8")
        parser.exit(1, f"Passport beta acceptance blocked: {exc}\n")
    print(f"Wrote blocked passport beta acceptance evidence: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
