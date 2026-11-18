#!/usr/bin/env python3
"""Join protected beta passport evidence before a D-12 recording receipt.

The acceptance runner remains blocked. Its selected job evidence and the two
uncut negative callback recordings are independently verified before this
producer can qualify a preliminary receipt.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import math
import os
import re
import tempfile
from pathlib import Path
from typing import Any
from uuid import UUID

try:
    from .collect_passport_beta_acceptance import production_snapshot_commitment
    from .probe_passport_beta_flow import PHYSICAL_STEPS
    from .probe_passport_beta_selected_flow import PASSPORT_FLOW_ROUTES, selected_plan_commitment
except ImportError:
    from collect_passport_beta_acceptance import production_snapshot_commitment
    from probe_passport_beta_flow import PHYSICAL_STEPS
    from probe_passport_beta_selected_flow import PASSPORT_FLOW_ROUTES, selected_plan_commitment


SHA256 = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
IDENTIFIER = re.compile(r"[A-Za-z0-9._:-]{1,255}\Z")
SERVICES_IMAGE = re.compile(r"ghcr\.io/elevenid/marty-ui-oss/services@sha256:[0-9a-f]{64}\Z")
MEDIA_FILES = {
    "unsigned": ("unsigned-callback-uncut.webm", "unsigned-callback-privacy-scan.json"),
    "foreign": ("foreign-callback-uncut.webm", "foreign-callback-privacy-scan.json"),
}
CASE_FIELDS = {
    "http_status", "webhook_owner", "request_kind", "response_projection",
    "organization_commitment", "source_job_commitment", "bureau_job_commitment",
    "job_state_before_commitment", "job_state_after_commitment",
    "video_sha256", "privacy_scan_report_sha256",
}
ROUTES = (
    ("GET", "/v1/passport/capabilities"), *PASSPORT_FLOW_ROUTES,
    ("POST", "/v1/passport/webhooks/personalization"),
)
PRIVATE_LABELS = {
    "organization_commitment": ("organization", "organization_id"),
    "flow_definition_commitment": ("flow-definition", "flow_definition_id"),
    "flow_instance_commitment": ("flow-instance", "flow_instance_id"),
    "application_commitment": ("application", "application_id"),
    "source_job_commitment": ("source-job", "source_job_id"),
    "bureau_job_commitment": ("bureau-job", "bureau_job_id"),
}
BATCH_PUBLIC_FIELDS = (
    "provider_kind", "physical_claim", "http_status", "batch_status",
    "selected_flow_in_two_job_batch", "native_binding_verified",
    "first_accepted_material_verified", "companion_native_completed",
    "companion_callback_receipt_sha256", "selected_source_job_commitment",
    "selected_bureau_job_commitment", "companion_source_job_commitment",
    "companion_bureau_job_commitment", "submitted_job_commitments",
    "returned_jobs", "request_commitment", "response_commitment",
    "source_commit", "stack_manifest_sha256", "services_oci_reference",
    "native_completed_jobs", "selected_flow_callback_verified",
    "selected_callback_receipt_sha256",
)


class PreliminaryEvidenceError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PreliminaryEvidenceError(message)


def _digest(path: Path, limit: int) -> str:
    require(path.is_file() and not path.is_symlink()
            and 0 < path.stat().st_size <= limit,
            "Negative callback media is missing or oversized")
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def _read_json(path: Path, limit: int) -> dict[str, Any]:
    _digest(path, limit)
    try:
        value = json.loads(path.read_text(encoding="utf-8"),
                           parse_constant=lambda _: require(False, "Nonfinite JSON number is invalid"))
    except (OSError, ValueError) as exc:
        raise PreliminaryEvidenceError("Negative callback evidence is invalid") from exc
    require(isinstance(value, dict), "Negative callback evidence is invalid")
    return value


def verify_negative_media(
    media_dir: Path,
    *,
    release: dict[str, Any],
    deployment: dict[str, Any],
    selected: dict[str, str],
) -> dict[str, Any]:
    """Return only bounded, same-job denial evidence for the preliminary report."""
    require(media_dir.is_dir() and not media_dir.is_symlink(),
            "Negative callback media directory is unavailable")
    require(all(isinstance(selected.get(key), str)
                and SHA256.fullmatch(selected[key]) is not None
                for key in ("organization_commitment", "source_job_commitment",
                            "bureau_job_commitment")),
            "Selected passport job commitments are unavailable")
    require(isinstance(release.get("source_commit"), str)
            and COMMIT.fullmatch(release["source_commit"]) is not None
            and isinstance(release.get("stack_manifest_sha256"), str)
            and SHA256.fullmatch(release["stack_manifest_sha256"]) is not None
            and all(isinstance(deployment.get(key), str)
                    and SHA256.fullmatch(deployment[key]) is not None
                    for key in ("aggregate_deployment_receipt_sha256",
                                "aggregate_plan_sha256")),
            "Selected signed beta release or deployment lineage is unavailable")
    media = _read_json(media_dir / "negative-callback-media.json", 1024 * 1024)
    require(set(media) == {"schema", "verified", "physical_claim", "release",
                           "deployment", "negative_runs"}
            and media.get("schema") == "marty.passport-beta-negative-media/v1"
            and media.get("verified") is True
            and media.get("physical_claim") == "not_claimed"
            and isinstance(media.get("release"), dict)
            and set(media["release"]) == {"source_commit", "stack_manifest_sha256"}
            and all(media["release"].get(field) == release.get(field)
                    for field in ("source_commit", "stack_manifest_sha256"))
            and isinstance(media.get("deployment"), dict)
            and set(media["deployment"]) == {"aggregate_deployment_receipt_sha256",
                                            "aggregate_plan_sha256"}
            and all(media["deployment"].get(field) == deployment.get(field)
                    for field in ("aggregate_deployment_receipt_sha256",
                                  "aggregate_plan_sha256"))
            and isinstance(media.get("negative_runs"), dict)
            and set(media["negative_runs"]) == set(MEDIA_FILES),
            "Negative callback media differs from the selected beta deployment")
    runs = media["negative_runs"]
    for name, (video_name, scan_name) in MEDIA_FILES.items():
        run = runs[name]
        expected_fields = CASE_FIELDS | ({"signature_valid", "foreign_organization"}
                                         if name == "foreign" else set())
        require(isinstance(run, dict) and set(run) == expected_fields
                and run.get("webhook_owner") == "issuance-native"
                and run.get("request_kind") == ("missing_signature_header" if name == "unsigned"
                                                else "signed_foreign_organization")
                and run.get("http_status") == (422 if name == "unsigned" else 404)
                and run.get("response_projection") == ({"missing_signature_header": True}
                                                       if name == "unsigned" else
                                                       {"webhook_job_not_found": True})
                and run.get("source_job_commitment") == selected["source_job_commitment"]
                and run.get("bureau_job_commitment") == selected["bureau_job_commitment"]
                and all(isinstance(run.get(key), str) and SHA256.fullmatch(run[key]) is not None
                        for key in ("organization_commitment", "job_state_before_commitment",
                                    "job_state_after_commitment", "video_sha256",
                                    "privacy_scan_report_sha256"))
                and run["job_state_before_commitment"] == run["job_state_after_commitment"],
                f"{name} callback denial is incomplete or differs from selected job")
        if name == "unsigned":
            require(run["organization_commitment"] == selected["organization_commitment"],
                    "Unsigned callback organization differs from selected job")
        else:
            require(run["organization_commitment"] != selected["organization_commitment"]
                    and run.get("signature_valid") is True
                    and run.get("foreign_organization") is True,
                    "Foreign callback organization or signature is unproven")
        video_digest = _digest(media_dir / video_name, 128 * 1024 * 1024)
        scan_path = media_dir / scan_name
        scan_digest = _digest(scan_path, 1024 * 1024)
        require(video_digest == run["video_sha256"]
                and scan_digest == run["privacy_scan_report_sha256"],
                f"{name} callback media digest differs from receipt")
        scan = _read_json(scan_path, 1024 * 1024)
        require(set(scan) == {"schemaVersion", "passed", "findings", "videoSha256",
                              "frameSamplingFps"}
                and type(scan.get("schemaVersion")) is int and scan["schemaVersion"] == 1
                and scan.get("passed") is True
                and scan.get("findings") == []
                and scan.get("videoSha256") == video_digest
                and isinstance(scan.get("frameSamplingFps"), (int, float))
                and not isinstance(scan["frameSamplingFps"], bool)
                and math.isfinite(scan["frameSamplingFps"])
                and scan["frameSamplingFps"] >= 2,
                f"{name} callback privacy scan is incomplete")
    unsigned, foreign = runs["unsigned"], runs["foreign"]
    require(unsigned["video_sha256"] != foreign["video_sha256"]
            and unsigned["job_state_before_commitment"]
            == foreign["job_state_before_commitment"],
            "Negative callback clips do not prove one unchanged selected job")
    return {
        "negative_runs": {name: dict(runs[name]) for name in MEDIA_FILES},
        "probe": {"verified": True, "evidence": {
            "unsigned_denied": True, "foreign_organization_denied": True,
            "job_unchanged": True,
            "source_job_commitment": selected["source_job_commitment"],
            "bureau_job_commitment": selected["bureau_job_commitment"],
            "unsigned_uncut_video_sha256": unsigned["video_sha256"],
            "foreign_uncut_video_sha256": foreign["video_sha256"],
        }},
    }


def _probe(report: dict[str, Any], name: str) -> dict[str, Any]:
    probes = report.get("probes")
    require(isinstance(probes, dict), "Selected beta passport probes are unavailable")
    item = probes.get(name)
    require(isinstance(item, dict) and item.get("verified") is True
            and isinstance(item.get("evidence"), dict),
            f"Selected beta passport probe is incomplete: {name}")
    return item["evidence"]


def _commitment(api_key: str, label: str, value: str) -> str:
    return hmac.new(api_key.encode("utf-8"), f"{label}:{value}".encode("utf-8"),
                    hashlib.sha256).hexdigest()


def verify_positive_job(report: dict[str, Any], private_plan: dict[str, Any],
                        api_key: str) -> dict[str, Any]:
    """Correlate selected Rust Flow, KMS chain, native batch, and callback."""
    require(isinstance(report, dict)
            and report.get("schema") == "marty.passport-beta-acceptance/v1"
            and report.get("status") == "blocked"
            and report.get("beta_origin") == "https://beta.elevenidllc.com"
            and report.get("physical_claim") == "not_claimed"
            and isinstance(report.get("release"), dict)
            and report["release"].get("signed_manifest_verified") is True
            and isinstance(report.get("deployment"), dict)
            and report["deployment"].get("provider_mode") == "simulator"
            and isinstance(api_key, str) and len(api_key) >= 32
            and not any(character in api_key for character in "\r\n\0"),
            "Signed simulator acceptance report is unavailable")
    release, deployment = report["release"], report["deployment"]
    require(isinstance(release.get("source_commit"), str)
            and COMMIT.fullmatch(release["source_commit"]) is not None
            and isinstance(release.get("stack_manifest_sha256"), str)
            and SHA256.fullmatch(release["stack_manifest_sha256"]) is not None
            and all(isinstance(deployment.get(key), str)
                    and SHA256.fullmatch(deployment[key]) is not None
                    for key in ("aggregate_deployment_receipt_sha256", "aggregate_plan_sha256")),
            "Aggregate beta release lineage is incomplete")
    require(isinstance(private_plan, dict)
            and set(private_plan) == {"schema", "source_commit", "stack_manifest_sha256",
                                      *[field for _, field in PRIVATE_LABELS.values()]}
            and private_plan.get("schema") == "marty.passport-beta-demo-private/v1"
            and private_plan.get("source_commit") == release["source_commit"]
            and private_plan.get("stack_manifest_sha256") == release["stack_manifest_sha256"]
            and all(isinstance(private_plan.get(field), str)
                    and IDENTIFIER.fullmatch(private_plan[field]) is not None
                    for _, field in PRIVATE_LABELS.values()),
            "Protected selected-job handoff differs from signed release")
    try:
        require(str(UUID(private_plan["bureau_job_id"])) == private_plan["bureau_job_id"],
                "Selected bureau job ID is not canonical")
    except ValueError as exc:
        raise PreliminaryEvidenceError("Selected bureau job ID is not canonical") from exc
    selected = {field: _commitment(api_key, label, private_plan[private_field])
                for field, (label, private_field) in PRIVATE_LABELS.items()}
    flow = _probe(report, "selected_physical_flow")
    gateway_trace = _probe(report, "nine_route_gateway_flow")
    route_owner = _probe(report, "beta_native_route_ownership")
    capability = _probe(report, "capabilities_http")
    webhook = _probe(report, "flow_capability_and_webhook_denial")
    require(flow.get("ordered_steps") == list(PHYSICAL_STEPS)
            and flow.get("completed_steps") == len(PHYSICAL_STEPS) == 9
            and flow.get("flow_routes") == [
                {"method": method, "path": path} for method, path in PASSPORT_FLOW_ROUTES]
            and all(flow.get(field) == commitment for field, commitment in selected.items())
            and flow.get("terminal_native_status") == "ACTIVE"
            and flow.get("physical_claim") == "not_claimed"
            and isinstance(flow.get("selected_flow_plan_commitment"), str)
            and SHA256.fullmatch(flow["selected_flow_plan_commitment"]) is not None
            and all(gateway_trace.get(field) == commitment
                    for field, commitment in selected.items())
            and gateway_trace.get("routes") == [
                {"method": method, "path": path} for method, path in ROUTES]
            and gateway_trace.get("ordered_steps") == list(PHYSICAL_STEPS)
            and gateway_trace.get("completed_steps") == len(PHYSICAL_STEPS)
            and gateway_trace.get("gateway_owner") == "rust"
            and gateway_trace.get("flow_owner") == "rust"
            and route_owner.get("native_selectors") is True
            and route_owner.get("flow_native_target") is True
            and route_owner.get("webhook_owner") == "issuance-native"
            and route_owner.get("simulator_callback_gateway_target") is True
            and capability == {"http_status": 200, "supported": True,
                               "signer_mode": "MANAGED_ISSUER_PROFILE"}
            and webhook.get("unsigned_webhook_owner") == "issuance-native"
            and webhook.get("signature_denial_verified") is True,
            "Selected nine-step Rust Flow and Gateway routes are unproven")
    chain = _probe(report, "managed_csca_dsc_chain")
    sod = _probe(report, "sod_signature")
    material = _probe(report, "simulator_material_receipt")
    batch = _probe(report, "physical_bureau_batch")
    require(chain.get("managed_kms_custody_verified") is True
            and chain.get("chain_verified") is True
            and chain.get("sod_dsc_binding_verified") is True
            and all(chain.get(field) == selected[field]
                    for field in ("organization_commitment", "application_commitment",
                                  "source_job_commitment"))
            and all(isinstance(chain.get(field), str)
                    and SHA256.fullmatch(chain[field]) is not None
                    for field in ("csca_issuer_profile_commitment",
                                  "dsc_issuer_profile_commitment", "sod_dsc_certificate_sha256"))
            and chain["csca_issuer_profile_commitment"] != chain["dsc_issuer_profile_commitment"]
            and sod.get("source_job_commitment") == selected["source_job_commitment"]
            and sod.get("dsc_certificate_sha256") == chain["sod_dsc_certificate_sha256"]
            and isinstance(sod.get("sod_sha256"), str)
            and SHA256.fullmatch(sod["sod_sha256"]) is not None
            and flow.get("sod_sha256") == sod["sod_sha256"]
            and material.get("tenant_and_job_binding") is True
            and material.get("first_accepted_sod_der_matches_native") is True
            and material.get("first_accepted_dsc_der_matches_selected_chain") is True
            and material.get("first_accepted_dsc_pem_wire_matches_selected_chain") is True
            and material.get("source_job_id_commitment") == selected["source_job_commitment"]
            and material.get("bureau_job_id_commitment") == selected["bureau_job_commitment"],
            "Managed certificate, selected SOD, or first accepted material differs")
    selected_jobs = batch.get("returned_jobs")
    require(batch.get("provider_kind") == "simulator"
            and batch.get("physical_claim") == "not_claimed"
            and batch.get("selected_flow_in_two_job_batch") is True
            and batch.get("native_binding_verified") is True
            and batch.get("first_accepted_material_verified") is True
            and batch.get("companion_native_completed") is True
            and batch.get("selected_flow_callback_verified") is True
            and batch.get("native_completed_jobs") == 2
            and batch.get("http_status") == 202 and batch.get("batch_status") == "QUEUED"
            and batch.get("selected_source_job_commitment") == selected["source_job_commitment"]
            and batch.get("selected_bureau_job_commitment") == selected["bureau_job_commitment"]
            and batch.get("selected_callback_receipt_sha256") == flow.get("callback_receipt_sha256")
            and isinstance(batch.get("selected_callback_receipt_sha256"), str)
            and SHA256.fullmatch(batch["selected_callback_receipt_sha256"]) is not None
            and batch.get("source_commit") == release["source_commit"]
            and batch.get("stack_manifest_sha256") == release["stack_manifest_sha256"]
            and isinstance(batch.get("services_oci_reference"), str)
            and SERVICES_IMAGE.fullmatch(batch["services_oci_reference"]) is not None
            and all(isinstance(batch.get(field), str)
                    and SHA256.fullmatch(batch[field]) is not None
                    for field in ("request_commitment", "response_commitment",
                                  "companion_callback_receipt_sha256",
                                  "companion_source_job_commitment",
                                  "companion_bureau_job_commitment"))
            and isinstance(batch.get("submitted_job_commitments"), list)
            and len(batch["submitted_job_commitments"]) == 2
            and all(isinstance(item, str) and SHA256.fullmatch(item) is not None
                    for item in batch["submitted_job_commitments"])
            and len(set(batch["submitted_job_commitments"])) == 2
            and selected["source_job_commitment"] in batch["submitted_job_commitments"]
            and isinstance(selected_jobs, list) and len(selected_jobs) == 2
            and all(isinstance(item, dict)
                    and set(item) == {"source_job_commitment", "bureau_job_commitment"}
                    and all(isinstance(item.get(field), str)
                            and SHA256.fullmatch(item[field]) is not None
                            for field in ("source_job_commitment", "bureau_job_commitment"))
                    and item["source_job_commitment"] in batch["submitted_job_commitments"]
                    for item in selected_jobs)
            and len({item["source_job_commitment"] for item in selected_jobs}) == 2
            and len({item["bureau_job_commitment"] for item in selected_jobs}) == 2
            and sum(isinstance(item, dict)
                    and item.get("source_job_commitment") == selected["source_job_commitment"]
                    and item.get("bureau_job_commitment") == selected["bureau_job_commitment"]
                    for item in selected_jobs) == 1,
            "Selected job is absent from native two-job simulator batch")
    boundary = _probe(report, "physical_claim_boundary")
    require(boundary == {"physical_claim": "not_claimed", "booklet_verified": False},
            "Passport evidence claims a physical booklet")
    return {
        "selected": selected,
        "probes": {
            "managed_csca_dsc_chain": {"verified": True, "evidence": {
                field: chain[field] for field in (
                    "csca_issuer_profile_commitment", "dsc_issuer_profile_commitment",
                    "managed_kms_custody_verified", "chain_verified", "sod_dsc_binding_verified",
                    "sod_dsc_certificate_sha256", "organization_commitment",
                    "application_commitment", "source_job_commitment")}},
            "sod_signature": {"verified": True, "evidence": {
                "sod_sha256": sod["sod_sha256"],
                "dsc_certificate_sha256": sod["dsc_certificate_sha256"],
                "source_job_commitment": sod["source_job_commitment"]}},
            "simulator_material_receipt": {"verified": True, "evidence": {
                field: material[field] for field in (
                    "tenant_and_job_binding", "first_accepted_sod_der_matches_native",
                    "first_accepted_dsc_der_matches_selected_chain",
                    "first_accepted_dsc_pem_wire_matches_selected_chain",
                    "source_job_id_commitment", "bureau_job_id_commitment")}},
            "nine_route_gateway_flow": {"verified": True, "evidence": {
                "routes": gateway_trace["routes"],
                "gateway_owner": gateway_trace["gateway_owner"],
                "flow_owner": gateway_trace["flow_owner"],
                "ordered_steps": gateway_trace["ordered_steps"],
                "completed_steps": gateway_trace["completed_steps"],
                **selected}},
            "physical_bureau_batch": {"verified": True, "evidence": {
                field: batch[field] for field in BATCH_PUBLIC_FIELDS if field in batch}},
            "physical_bureau_submission": {"verified": True, "evidence": {
                "provider_kind": "simulator", "physical_claim": "not_claimed",
                "selected_source_job_commitment": selected["source_job_commitment"],
                "selected_bureau_job_commitment": selected["bureau_job_commitment"],
                "organization_commitment": selected["organization_commitment"],
                "application_commitment": selected["application_commitment"],
                "flow_instance_commitment": selected["flow_instance_commitment"]}},
            "signed_bureau_callback": {"verified": True, "evidence": {
                "provider_kind": "simulator", "physical_claim": "not_claimed",
                "signature_verified": True, "organization_bound": True,
                "source_job_commitment": selected["source_job_commitment"],
                "bureau_job_commitment": selected["bureau_job_commitment"],
                "organization_commitment": selected["organization_commitment"],
                "application_commitment": selected["application_commitment"],
                "flow_instance_commitment": selected["flow_instance_commitment"],
                "callback_receipt_sha256": batch["selected_callback_receipt_sha256"]}},
            "physical_claim_boundary": {"verified": True, "evidence": boundary},
        },
    }


def qualify_preliminary(
    report: dict[str, Any],
    private_plan: dict[str, Any],
    selected_flow_plan: dict[str, Any],
    artifact_dir: Path,
    media_dir: Path,
    api_key: str,
) -> dict[str, Any]:
    """Build only the public D-12 receipt from one protected beta execution."""
    positive = verify_positive_job(report, private_plan, api_key)
    release, deployment = report["release"], report["deployment"]
    require(artifact_dir.is_dir() and not artifact_dir.is_symlink(),
            "Aggregate beta artifact directory is unavailable")
    stack_path = artifact_dir / "stack-manifest.json"
    deployed_path = artifact_dir / "aggregate-deployment.json"
    deployment_plan_path = artifact_dir / "aggregate-deployment.json.plan.json"
    stack_digest = _digest(stack_path, 8 * 1024 * 1024)
    deployed_digest = _digest(deployed_path, 8 * 1024 * 1024)
    plan_digest = _digest(deployment_plan_path, 8 * 1024 * 1024)
    require(stack_digest == release["stack_manifest_sha256"]
            and deployed_digest == deployment["aggregate_deployment_receipt_sha256"]
            and plan_digest == deployment["aggregate_plan_sha256"],
            "Aggregate beta files differ from protected acceptance report")
    deployed = _read_json(deployed_path, 8 * 1024 * 1024)
    plan = _read_json(deployment_plan_path, 8 * 1024 * 1024)
    require(deployed.get("schema") == "marty.passport-beta-aggregate-deployment/v1"
            and deployed.get("beta_origin") == report["beta_origin"]
            and deployed.get("source_commit") == release["source_commit"]
            and deployed.get("plan_sha256") == plan_digest
            and deployed.get("acceptance_pending") is True
            and isinstance(deployed.get("beta_services"), list)
            and "passport-beta-bureau" in deployed["beta_services"]
            and "passport-provider-ingress" not in deployed["beta_services"]
            and plan.get("schema") == "marty.passport-beta-aggregate-compose-plan/v1"
            and plan.get("source_commit") == release["source_commit"]
            and plan.get("stack_manifest_sha256") == stack_digest
            and plan.get("beta_origin") == report["beta_origin"],
            "Aggregate simulator deployment or plan does not match selected release")
    fixture = _read_json(Path(__file__).resolve().parents[1] / "contracts"
                         / "passport-beta-synthetic-document.json", 16 * 1024)
    require(isinstance(selected_flow_plan, dict)
            and set(selected_flow_plan) == {"source_commit", "stack_manifest_sha256",
                                            "organization_id", "issuer_did",
                                            "flow_definition_id", "references",
                                            "physical_document"}
            and selected_flow_plan.get("source_commit") == release["source_commit"]
            and selected_flow_plan.get("stack_manifest_sha256") == stack_digest
            and selected_flow_plan.get("organization_id") == private_plan["organization_id"]
            and selected_flow_plan.get("flow_definition_id") == private_plan["flow_definition_id"]
            and selected_flow_plan.get("physical_document") == fixture,
            "Protected selected Flow did not use the fixed synthetic identity fixture")
    require(report["probes"]["selected_physical_flow"]["evidence"].get(
                "selected_flow_plan_commitment")
            == selected_plan_commitment(selected_flow_plan, api_key),
            "Synthetic fixture is not bound to the executed selected Flow")
    continuity = _probe(report, "production_continuity_during_probe")
    legacy = _probe(report, "legacy_drain")
    baseline = deployment.get("production_snapshot_commitment")
    attachments = deployment.get("production_attachment_commitment")
    require(isinstance(continuity.get("before_sha256"), str)
            and SHA256.fullmatch(continuity["before_sha256"]) is not None
            and continuity.get("after_sha256") == continuity["before_sha256"]
            and continuity.get("scope") == "acceptance-run-window-only"
            and isinstance(continuity.get("container_counts"), dict)
            and isinstance(baseline, str) and SHA256.fullmatch(baseline) is not None
            and baseline == production_snapshot_commitment(
                api_key, continuity["before_sha256"])
            and isinstance(attachments, str) and SHA256.fullmatch(attachments) is not None
            and isinstance(legacy.get("before"), dict)
            and isinstance(legacy.get("after"), dict)
            and all(legacy[phase] == {
                "in_flight_jobs": 0, "legacy_or_unknown_artifacts": 0,
                "active_physical_document_flows": 0,
                "database": "beta", "source": "live PostgreSQL",
            } for phase in ("before", "after")),
            "Production continuity or beta passport drain is unproven")
    negative = verify_negative_media(media_dir, release=release,
                                     deployment=deployment, selected=positive["selected"])
    return {
        "schema": "marty.passport-beta-preliminary/v1",
        "status": "qualified_for_recording",
        "beta_origin": report["beta_origin"],
        "physical_claim": "not_claimed",
        "release": {
            "source_commit": release["source_commit"],
            "stack_manifest_sha256": stack_digest,
            "signed_manifest_verified": True,
        },
        "deployment": {
            "provider_mode": "simulator",
            "aggregate_deployment_receipt_sha256": deployed_digest,
            "aggregate_plan_sha256": plan_digest,
        },
        "probes": positive["probes"] | {
            "unsigned_or_foreign_callback_denied": negative["probe"]},
        "negative_runs": negative["negative_runs"],
        "synthetic_identities_only": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--acceptance-report-file", type=Path, required=True)
    parser.add_argument("--private-demo-handoff-file", type=Path, required=True)
    parser.add_argument("--selected-flow-plan-file", type=Path, required=True)
    parser.add_argument("--negative-media-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        key = os.environ.get("PASSPORT_ACCEPTANCE_API_KEY")
        require(isinstance(key, str) and len(key) >= 32,
                "Protected passport API key is unavailable")
        require(args.output.parent.is_dir() and not args.output.parent.is_symlink()
                and not args.output.is_symlink(),
                "Preliminary output directory is invalid")
        output_path = args.output.resolve()
        protected_inputs = (
            args.acceptance_report_file,
            args.private_demo_handoff_file,
            args.selected_flow_plan_file,
            Path(__file__).resolve().parents[1] / "contracts"
            / "passport-beta-synthetic-document.json",
        )
        require(all(output_path != source.resolve() for source in protected_inputs)
                and not output_path.is_relative_to(args.artifact_dir.resolve())
                and not output_path.is_relative_to(args.negative_media_dir.resolve()),
                "Preliminary output overlaps protected evidence")
        if args.output.exists():
            require(args.output.is_file(), "Preliminary output path is invalid")
            args.output.unlink()
        report = qualify_preliminary(
            _read_json(args.acceptance_report_file, 8 * 1024 * 1024),
            _read_json(args.private_demo_handoff_file, 16 * 1024),
            _read_json(args.selected_flow_plan_file, 1024 * 1024),
            args.artifact_dir, args.negative_media_dir, key,
        )
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8",
                                         dir=args.output.parent, prefix=".passport-preliminary-",
                                         suffix=".tmp", delete=False) as target:
            temporary = Path(target.name)
            json.dump(report, target, indent=2, sort_keys=True, allow_nan=False)
            target.write("\n")
        try:
            temporary.replace(args.output)
        finally:
            temporary.unlink(missing_ok=True)
    except (PreliminaryEvidenceError, OSError) as exc:
        parser.exit(1, f"Passport preliminary qualification blocked: {exc}\n")
    print(f"Wrote qualified passport preliminary evidence: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
