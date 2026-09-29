"""Preliminary negative media must describe two real clips of one beta job."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.probe_passport_beta_flow import PHYSICAL_STEPS
from scripts.probe_passport_beta_selected_flow import PASSPORT_FLOW_ROUTES
from scripts.probe_passport_beta_selected_flow import selected_plan_commitment
from scripts.collect_passport_beta_acceptance import production_snapshot_commitment
from scripts.produce_passport_beta_preliminary import (
    ROUTES, PreliminaryEvidenceError, qualify_preliminary, verify_negative_media,
    verify_positive_job,
)


RELEASE = {"source_commit": "a" * 40, "stack_manifest_sha256": "b" * 64}
DEPLOYMENT = {"aggregate_deployment_receipt_sha256": "c" * 64,
              "aggregate_plan_sha256": "d" * 64}
SELECTED = {"organization_commitment": "1" * 64,
            "source_job_commitment": "2" * 64,
            "bureau_job_commitment": "3" * 64}


def digest(contents: bytes) -> str:
    return hashlib.sha256(contents).hexdigest()


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def media_fixture(directory: Path, *, selected: dict = SELECTED,
                  release: dict = RELEASE, deployment: dict = DEPLOYMENT) -> dict:
    runs = {}
    for name, status, organization, projection in (
        ("unsigned", 422, selected["organization_commitment"],
         {"missing_signature_header": True}),
        ("foreign", 404, "4" * 64, {"webhook_job_not_found": True}),
    ):
        video = b"\x1aE\xdf\xa3" + name.encode() + b" uncut browser callback"
        video_name = f"{name}-callback-uncut.webm"
        (directory / video_name).write_bytes(video)
        scan = {"schemaVersion": 1, "passed": True, "findings": [],
                "videoSha256": digest(video), "frameSamplingFps": 2}
        scan_name = f"{name}-callback-privacy-scan.json"
        write_json(directory / scan_name, scan)
        runs[name] = {
            "http_status": status, "webhook_owner": "issuance-native",
            "request_kind": ("missing_signature_header" if name == "unsigned"
                             else "signed_foreign_organization"),
            "response_projection": projection,
            "organization_commitment": organization,
            "source_job_commitment": selected["source_job_commitment"],
            "bureau_job_commitment": selected["bureau_job_commitment"],
            "job_state_before_commitment": "5" * 64,
            "job_state_after_commitment": "5" * 64,
            "video_sha256": digest(video),
            "privacy_scan_report_sha256": digest((directory / scan_name).read_bytes()),
        }
    runs["foreign"].update(signature_valid=True, foreign_organization=True)
    report = {"schema": "marty.passport-beta-negative-media/v1", "verified": True,
              "physical_claim": "not_claimed", "release": {
                  field: release[field] for field in RELEASE},
              "deployment": {
                  field: deployment[field] for field in DEPLOYMENT},
              "negative_runs": runs}
    write_json(directory / "negative-callback-media.json", report)
    return report


def test_qualifies_two_scanned_denials_of_selected_job(tmp_path: Path) -> None:
    media_fixture(tmp_path)
    result = verify_negative_media(tmp_path, release=RELEASE, deployment=DEPLOYMENT,
                                   selected=SELECTED)
    assert result["probe"]["verified"] is True
    assert result["probe"]["evidence"]["source_job_commitment"] == SELECTED["source_job_commitment"]
    assert result["negative_runs"]["unsigned"]["http_status"] == 422
    assert result["negative_runs"]["foreign"]["http_status"] == 404


@pytest.mark.parametrize("change", [
    lambda media: media["release"].update(source_commit="f" * 40),
    lambda media: media["deployment"].update(aggregate_plan_sha256="f" * 64),
    lambda media: media["negative_runs"]["foreign"].update(source_job_commitment="f" * 64),
    lambda media: media["negative_runs"]["foreign"].update(
        organization_commitment=SELECTED["organization_commitment"]),
    lambda media: media["negative_runs"]["foreign"].update(signature_valid=False),
    lambda media: media["negative_runs"]["unsigned"].update(http_status=200),
    lambda media: media["negative_runs"]["foreign"].update(job_state_after_commitment="f" * 64),
    lambda media: media["negative_runs"]["foreign"].update(job_state_before_commitment="f" * 64,
                                                              job_state_after_commitment="f" * 64),
])
def test_rejects_cross_deployment_or_cross_job_negative_media(tmp_path: Path, change) -> None:
    media = media_fixture(tmp_path)
    change(media)
    write_json(tmp_path / "negative-callback-media.json", media)
    with pytest.raises(PreliminaryEvidenceError):
        verify_negative_media(tmp_path, release=RELEASE, deployment=DEPLOYMENT,
                              selected=SELECTED)


def test_rejects_changed_video_or_scan(tmp_path: Path) -> None:
    media_fixture(tmp_path)
    video = tmp_path / "unsigned-callback-uncut.webm"
    video.write_bytes(video.read_bytes() + b"changed")
    with pytest.raises(PreliminaryEvidenceError, match="digest"):
        verify_negative_media(tmp_path, release=RELEASE, deployment=DEPLOYMENT,
                              selected=SELECTED)


@pytest.mark.parametrize("field,value", [
    ("schemaVersion", True),
    ("frameSamplingFps", float("inf")),
])
def test_rejects_scan_json_recorder_would_reject(tmp_path: Path, field: str, value: object) -> None:
    media = media_fixture(tmp_path)
    scan_path = tmp_path / "unsigned-callback-privacy-scan.json"
    scan = json.loads(scan_path.read_text(encoding="utf-8"))
    scan[field] = value
    write_json(scan_path, scan)
    media["negative_runs"]["unsigned"]["privacy_scan_report_sha256"] = digest(scan_path.read_bytes())
    write_json(tmp_path / "negative-callback-media.json", media)
    with pytest.raises(PreliminaryEvidenceError):
        verify_negative_media(tmp_path, release=RELEASE, deployment=DEPLOYMENT,
                              selected=SELECTED)


def test_rejects_symlink_media(tmp_path: Path) -> None:
    media_fixture(tmp_path)
    video = tmp_path / "unsigned-callback-uncut.webm"
    data = tmp_path / "other.webm"
    video.rename(data)
    try:
        video.symlink_to(data)
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(PreliminaryEvidenceError, match="missing or oversized"):
        verify_negative_media(tmp_path, release=RELEASE, deployment=DEPLOYMENT,
                              selected=SELECTED)


def positive_fixture() -> tuple[dict, dict]:
    from scripts.produce_passport_beta_preliminary import _commitment

    private = {"schema": "marty.passport-beta-demo-private/v1", **RELEASE,
               "organization_id": "org-a", "flow_definition_id": "flow-a",
               "flow_instance_id": "instance-a", "application_id": "app-a",
               "source_job_id": "source-a",
               "bureau_job_id": "76a7baef-368a-4722-95a4-df70ea1dfefa"}
    pairs = {"organization_commitment": ("organization", "organization_id"),
             "flow_definition_commitment": ("flow-definition", "flow_definition_id"),
             "flow_instance_commitment": ("flow-instance", "flow_instance_id"),
             "application_commitment": ("application", "application_id"),
             "source_job_commitment": ("source-job", "source_job_id"),
             "bureau_job_commitment": ("bureau-job", "bureau_job_id")}
    selected = {field: _commitment("k" * 32, label, private[private_field])
                for field, (label, private_field) in pairs.items()}
    callback = "6" * 64
    chain = {"csca_issuer_profile_commitment": "7" * 64,
             "dsc_issuer_profile_commitment": "8" * 64,
             "managed_kms_custody_verified": True, "chain_verified": True,
             "sod_dsc_binding_verified": True, "sod_dsc_certificate_sha256": "9" * 64,
             "organization_commitment": selected["organization_commitment"],
             "application_commitment": selected["application_commitment"],
             "source_job_commitment": selected["source_job_commitment"]}
    material = {"tenant_and_job_binding": True,
                "first_accepted_sod_der_matches_native": True,
                "first_accepted_dsc_der_matches_selected_chain": True,
                "first_accepted_dsc_pem_wire_matches_selected_chain": True,
                "source_job_id_commitment": selected["source_job_commitment"],
                "bureau_job_id_commitment": selected["bureau_job_commitment"]}
    batch = {"provider_kind": "simulator", "physical_claim": "not_claimed",
             "source_commit": RELEASE["source_commit"],
             "stack_manifest_sha256": RELEASE["stack_manifest_sha256"],
             "services_oci_reference": "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "f" * 64,
             "selected_flow_in_two_job_batch": True, "native_binding_verified": True,
             "first_accepted_material_verified": True, "selected_flow_callback_verified": True,
             "companion_native_completed": True,
             "native_completed_jobs": 2, "http_status": 202, "batch_status": "QUEUED",
             "companion_callback_receipt_sha256": "a" * 64,
             "companion_source_job_commitment": "a" * 64,
             "companion_bureau_job_commitment": "b" * 64,
             "selected_source_job_commitment": selected["source_job_commitment"],
             "selected_bureau_job_commitment": selected["bureau_job_commitment"],
             "selected_callback_receipt_sha256": callback,
             "submitted_job_commitments": [selected["source_job_commitment"], "a" * 64],
             "returned_jobs": [
                 {"source_job_commitment": selected["source_job_commitment"],
                  "bureau_job_commitment": selected["bureau_job_commitment"]},
                 {"source_job_commitment": "a" * 64, "bureau_job_commitment": "b" * 64}],
             "request_commitment": "c" * 64, "response_commitment": "d" * 64}
    def probe(evidence):
        return {"verified": True, "evidence": evidence}
    report = {"schema": "marty.passport-beta-acceptance/v1", "status": "blocked",
              "beta_origin": "https://beta.elevenidllc.com", "physical_claim": "not_claimed",
              "release": {**RELEASE, "signed_manifest_verified": True},
              "deployment": {**DEPLOYMENT, "provider_mode": "simulator"},
              "probes": {
                  "selected_physical_flow": probe({
                      **selected, "ordered_steps": list(PHYSICAL_STEPS), "completed_steps": 9,
                      "flow_routes": [{"method": method, "path": path}
                                      for method, path in PASSPORT_FLOW_ROUTES],
                      "terminal_native_status": "ACTIVE", "physical_claim": "not_claimed",
                      "sod_sha256": "e" * 64, "callback_receipt_sha256": callback,
                      "selected_flow_plan_commitment": "0" * 64}),
                  "nine_route_gateway_flow": probe({
                      **selected,
                      "routes": [{"method": method, "path": path} for method, path in ROUTES],
                      "gateway_owner": "rust", "flow_owner": "rust",
                      "ordered_steps": list(PHYSICAL_STEPS), "completed_steps": 9}),
                  "beta_native_route_ownership": probe({
                      "native_selectors": True, "flow_native_target": True,
                      "webhook_owner": "issuance-native",
                      "simulator_callback_gateway_target": True}),
                  "capabilities_http": probe({"http_status": 200, "supported": True,
                                              "signer_mode": "MANAGED_ISSUER_PROFILE"}),
                  "flow_capability_and_webhook_denial": probe({
                      "unsigned_webhook_owner": "issuance-native",
                      "signature_denial_verified": True}),
                  "managed_csca_dsc_chain": probe(chain),
                  "sod_signature": probe({"source_job_commitment": selected["source_job_commitment"],
                                          "dsc_certificate_sha256": "9" * 64,
                                          "sod_sha256": "e" * 64}),
                  "simulator_material_receipt": probe(material),
                  "physical_bureau_batch": probe(batch),
                  "physical_claim_boundary": probe({"physical_claim": "not_claimed",
                                                    "booklet_verified": False}),
              }}
    return report, private


def test_positive_join_proves_one_selected_rust_passport_job() -> None:
    report, private = positive_fixture()
    result = verify_positive_job(report, private, "k" * 32)
    assert result["probes"]["nine_route_gateway_flow"]["verified"] is True
    assert len(result["probes"]["nine_route_gateway_flow"]["evidence"]["routes"]) == 9
    assert result["probes"]["signed_bureau_callback"]["evidence"]["signature_verified"] is True
    assert "source-a" not in str(result)
    assert "76a7baef" not in str(result)


def test_positive_join_rejects_runner_route_inventory_without_same_job_trace() -> None:
    report, private = positive_fixture()
    report["probes"]["nine_route_gateway_flow"] = {
        "verified": False, "evidence": {"missing": ["same_job_gateway_route_trace"]}}
    with pytest.raises(PreliminaryEvidenceError, match="nine_route_gateway_flow"):
        verify_positive_job(report, private, "k" * 32)


@pytest.mark.parametrize("probe,field,value", [
    ("selected_physical_flow", "completed_steps", 8),
    ("selected_physical_flow", "source_job_commitment", "f" * 64),
    ("nine_route_gateway_flow", "source_job_commitment", "f" * 64),
    ("nine_route_gateway_flow", "organization_commitment", "f" * 64),
    ("nine_route_gateway_flow", "flow_definition_commitment", "f" * 64),
    ("nine_route_gateway_flow", "bureau_job_commitment", "f" * 64),
    ("nine_route_gateway_flow", "routes", []),
    ("beta_native_route_ownership", "webhook_owner", "passport-provider-ingress"),
    ("managed_csca_dsc_chain", "managed_kms_custody_verified", False),
    ("managed_csca_dsc_chain", "sod_dsc_certificate_sha256", "f" * 64),
    ("sod_signature", "sod_sha256", "f" * 64),
    ("simulator_material_receipt", "first_accepted_dsc_der_matches_selected_chain", False),
    ("physical_bureau_batch", "selected_bureau_job_commitment", "f" * 64),
    ("physical_bureau_batch", "selected_callback_receipt_sha256", "f" * 64),
    ("physical_bureau_batch", "companion_native_completed", False),
    ("physical_bureau_batch", "services_oci_reference", "unverified"),
])
def test_positive_join_rejects_broken_same_job_evidence(probe, field, value) -> None:
    report, private = positive_fixture()
    report["probes"][probe]["evidence"][field] = value
    with pytest.raises(PreliminaryEvidenceError):
        verify_positive_job(report, private, "k" * 32)


def qualification_fixture(tmp_path: Path) -> tuple[dict, dict, dict, Path, Path]:
    report, private = positive_fixture()
    artifacts = tmp_path / "artifacts"
    media = tmp_path / "media"
    artifacts.mkdir()
    media.mkdir()
    stack_path = artifacts / "stack-manifest.json"
    write_json(stack_path, {"schema": "marty.stack/v1"})
    stack_sha = digest(stack_path.read_bytes())
    report["release"]["stack_manifest_sha256"] = stack_sha
    private["stack_manifest_sha256"] = stack_sha
    report["probes"]["physical_bureau_batch"]["evidence"]["stack_manifest_sha256"] = stack_sha
    plan_path = artifacts / "aggregate-deployment.json.plan.json"
    write_json(plan_path, {
        "schema": "marty.passport-beta-aggregate-compose-plan/v1",
        "source_commit": RELEASE["source_commit"],
        "stack_manifest_sha256": stack_sha,
        "beta_origin": "https://beta.elevenidllc.com",
        "target_services": ["gateway", "flow", "issuance-native", "signing-keys",
                            "passport-callback-signer", "passport-beta-bureau"],
    })
    plan_sha = digest(plan_path.read_bytes())
    deployed_path = artifacts / "aggregate-deployment.json"
    write_json(deployed_path, {
        "schema": "marty.passport-beta-aggregate-deployment/v1",
        "source_commit": RELEASE["source_commit"],
        "beta_origin": "https://beta.elevenidllc.com",
        "plan_sha256": plan_sha,
        "acceptance_pending": True,
        "beta_services": ["gateway", "flow", "issuance-native", "signing-keys",
                          "passport-callback-signer", "passport-beta-bureau", "postgres"],
        "beta_runtime": {name: {} for name in (
            "gateway", "flow", "issuance-native", "signing-keys",
            "passport-callback-signer", "passport-beta-bureau", "postgres")},
    })
    report["deployment"]["aggregate_deployment_receipt_sha256"] = digest(
        deployed_path.read_bytes())
    report["deployment"]["aggregate_plan_sha256"] = plan_sha
    selected = verify_positive_job(report, private, "k" * 32)["selected"]
    media_fixture(media, selected=selected, release=report["release"],
                  deployment=report["deployment"])
    fixture_path = (Path(__file__).resolve().parents[1] / "contracts"
                    / "passport-beta-synthetic-document.json")
    selected_plan = {
        "source_commit": RELEASE["source_commit"],
        "stack_manifest_sha256": stack_sha,
        "organization_id": private["organization_id"],
        "issuer_did": "did:web:beta.example:issuer",
        "flow_definition_id": private["flow_definition_id"],
        "references": {"application_template_id": "app-template"},
        "physical_document": json.loads(fixture_path.read_text(encoding="utf-8")),
    }
    report["probes"]["selected_physical_flow"]["evidence"][
        "selected_flow_plan_commitment"] = selected_plan_commitment(selected_plan, "k" * 32)
    report["deployment"]["production_snapshot_commitment"] = (
        production_snapshot_commitment("k" * 32, "f" * 64))
    report["deployment"]["production_attachment_commitment"] = "a" * 64
    report["probes"]["production_continuity_during_probe"] = {
        "verified": True, "evidence": {
            "before_sha256": "f" * 64, "after_sha256": "f" * 64,
            "container_counts": {"marty-selfhost-prod": 24},
            "scope": "acceptance-run-window-only",
        }}
    empty_drain = {"in_flight_jobs": 0, "legacy_or_unknown_artifacts": 0,
                   "active_physical_document_flows": 0,
                   "database": "beta", "source": "live PostgreSQL"}
    report["probes"]["legacy_drain"] = {
        "verified": True, "evidence": {"before": empty_drain, "after": empty_drain}}
    return report, private, selected_plan, artifacts, media


def test_qualified_receipt_joins_signed_deployment_synthetic_job_and_media(tmp_path: Path) -> None:
    arguments = qualification_fixture(tmp_path)
    result = qualify_preliminary(*arguments, "k" * 32)
    assert result["status"] == "qualified_for_recording"
    assert result["synthetic_identities_only"] is True
    assert all(result["probes"][name]["verified"] is True for name in (
        "nine_route_gateway_flow", "managed_csca_dsc_chain",
        "physical_bureau_batch", "signed_bureau_callback",
        "unsigned_or_foreign_callback_denied"))
    assert "org-a" not in str(result)
    assert "76a7baef" not in str(result)
    assert "SYNTHETIC" not in str(result)


@pytest.mark.skipif(shutil.which("node") is None, reason="Node unavailable")
def test_qualified_receipt_matches_d12_decoder(tmp_path: Path) -> None:
    arguments = qualification_fixture(tmp_path)
    result = qualify_preliminary(*arguments, "k" * 32)
    report_path = tmp_path / "preliminary.json"
    private_path = tmp_path / "private.json"
    write_json(report_path, result)
    write_json(private_path, arguments[1])
    root = Path(__file__).resolve().parents[1]
    code = """const fs=require('node:fs');
const {validatePreliminary}=require('./tests/scripts/audit-beta-physical-passport-flow.js');
const [report, deployed, artifacts, privatePlan]=process.argv.slice(1);
validatePreliminary(JSON.parse(fs.readFileSync(report)),
  JSON.parse(fs.readFileSync(deployed)), artifacts,
  JSON.parse(fs.readFileSync(privatePlan)), 'k'.repeat(32));"""
    completed = subprocess.run([
        "node", "-e", code, str(report_path),
        str(arguments[3] / "aggregate-deployment.json"), str(arguments[3]),
        str(private_path),
    ], cwd=root, capture_output=True, text=True, check=False)
    assert completed.returncode == 0, completed.stderr


def test_qualified_cli_writes_only_after_complete_join(tmp_path: Path) -> None:
    report, private, selected_plan, artifacts, media = qualification_fixture(tmp_path)
    report_path = tmp_path / "acceptance.json"
    private_path = tmp_path / "private.json"
    selected_path = tmp_path / "selected.json"
    output_path = tmp_path / "preliminary.json"
    for path, value in ((report_path, report), (private_path, private),
                        (selected_path, selected_plan)):
        write_json(path, value)
    command = [
        sys.executable, "scripts/produce_passport_beta_preliminary.py",
        "--artifact-dir", str(artifacts),
        "--acceptance-report-file", str(report_path),
        "--private-demo-handoff-file", str(private_path),
        "--selected-flow-plan-file", str(selected_path),
        "--negative-media-dir", str(media),
        "--output", str(output_path),
    ]
    environment = os.environ | {"PASSPORT_ACCEPTANCE_API_KEY": "k" * 32}
    root = Path(__file__).resolve().parents[1]
    success = subprocess.run(command, cwd=root, env=environment,
                             capture_output=True, text=True, check=False)
    assert success.returncode == 0, success.stderr
    assert json.loads(output_path.read_text(encoding="utf-8"))["status"] == (
        "qualified_for_recording")
    report["probes"]["nine_route_gateway_flow"]["verified"] = False
    write_json(report_path, report)
    blocked = subprocess.run(command, cwd=root, env=environment,
                             capture_output=True, text=True, check=False)
    assert blocked.returncode != 0
    assert not output_path.exists()


@pytest.mark.parametrize("change", [
    lambda args: args[2]["physical_document"]["applicant"].update(given_name="REAL"),
    lambda args: args[3].joinpath("stack-manifest.json").write_text("{}"),
    lambda args: args[0]["probes"]["nine_route_gateway_flow"].update(verified=False),
    lambda args: args[0]["probes"]["production_continuity_during_probe"].update(verified=False),
    lambda args: args[0]["probes"]["legacy_drain"].update(verified=False),
    lambda args: args[0]["probes"]["selected_physical_flow"]["evidence"].update(
        selected_flow_plan_commitment="f" * 64),
    lambda args: args[4].joinpath("foreign-callback-uncut.webm").write_bytes(b"changed"),
])
def test_qualified_receipt_rejects_missing_contract_part(tmp_path: Path, change) -> None:
    arguments = list(qualification_fixture(tmp_path))
    change(arguments)
    with pytest.raises(PreliminaryEvidenceError):
        qualify_preliminary(*arguments, "k" * 32)
