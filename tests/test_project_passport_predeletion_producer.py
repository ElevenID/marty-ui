"""A blocked projection must preserve selected job and release provenance."""

from __future__ import annotations

from copy import deepcopy

import pytest

from scripts.project_passport_predeletion_producer import (
    ProjectionError, SERVICES, project,
)


SOURCE = "a" * 40
STACK = "b" * 64
SERVICE_DIGEST = "sha256:" + "c" * 64
REFERENCE = "ghcr.io/elevenid/marty-ui-oss/services@" + SERVICE_DIGEST
ORGANIZATION = "00000000-0000-0000-0000-000000000001"
PROJECT = "marty-passport-acceptance-base-123456abcdef"


def inputs() -> tuple[dict, dict]:
    runtime = {
        service: {"container_id": f"{index:064x}",
                  "image_id": "sha256:" + "d" * 64,
                  "oci_reference": REFERENCE, "selectors": {}}
        for index, service in enumerate(sorted(SERVICES), 1)
    }
    signer = {
        "mode": "managed_kms", "issuer_profile_type": "ICAO_EMRTD",
        "organization_id": ORGANIZATION, "managed_kms_custody_verified": True,
        "chain_verified": True, "private_key_exported": False,
        "signing_keys_container_id": runtime["signing-keys"]["container_id"],
        "services_oci_reference": REFERENCE,
        "csca": {"status": "active", "issuer_profile_commitment": "1" * 64,
                 "certificate_sha256": "2" * 64},
        "dsc": {"status": "active", "issuer_profile_commitment": "3" * 64,
                "certificate_sha256": "4" * 64},
    }
    selected = "5" * 64
    selected_bureau = "6" * 64
    companion = "7" * 64
    companion_bureau = "8" * 64
    batch = {
        "provider_kind": "simulator", "physical_claim": "not_claimed",
        "http_status": 202, "batch_status": "QUEUED",
        "selected_flow_in_two_job_batch": True,
        "native_binding_verified": True,
        "first_accepted_material_verified": True,
        "companion_native_completed": True,
        "companion_bureau_status": "SHIPPED",
        "companion_simulator_marker_verified": True,
        "selected_material_receipt": {
            "source_job_id_commitment": selected,
            "bureau_job_id_commitment": selected_bureau,
            "tenant_and_job_binding": True,
            "first_accepted_sod_der_matches_native": True,
            "first_accepted_dsc_der_matches_selected_chain": True,
            "first_accepted_dsc_pem_wire_matches_selected_chain": True,
            "source": "private disposable PostgreSQL",
        },
        "selected_source_job_commitment": selected,
        "selected_bureau_job_commitment": selected_bureau,
        "companion_source_job_commitment": companion,
        "companion_bureau_job_commitment": companion_bureau,
        "companion_callback_receipt_sha256": "9" * 64,
        "submitted_job_commitments": [selected, companion],
        "returned_jobs": [
            {"source_job_commitment": selected,
             "bureau_job_commitment": selected_bureau},
            {"source_job_commitment": companion,
             "bureau_job_commitment": companion_bureau},
        ],
        "request_commitment": "a" * 64,
        "response_commitment": "b" * 64,
    }
    receipt = {
        "source_commit": SOURCE, "surface": "base", "project": PROJECT,
        "status": "blocked", "live_ownership_verified": True,
        "rust_routes_verified": True, "flow_execution_verified": True,
        "rust_restart_resume_verified": True, "physical_claim": "not_claimed",
        "runtime_images": runtime,
        "pre_restart_native_runtime": {
            **runtime["issuance-native"], "container_id": "f" * 64,
            "inspection_receipt_sha256": "e" * 64,
        },
        "route": {"verified": True, "evidence": {
            "organization_id": ORGANIZATION,
            "signed_gateway_callback_verified": True,
            "sod_signature_verified": True, "sod_sha256": "0" * 64,
            "cross_tenant_status": 404, "tenant_capability_status": 200,
            "routes": [],
        }},
        "flow_execution": {
            "execution": {
                "nine_steps_verified": True, "six_native_effects_verified": True,
                "durable_history_verified": True, "restart_resume_verified": True,
                "restart_before_native_status": "SOD_SIGNED",
                "restart_after_native_status": "SUBMITTED",
                "callback_bureau_status": "QUALITY_CHECK",
                "signed_callback_receipt_sha256": "c" * 64,
                "sod_sha256": "d" * 64,
            },
            "batch": {"batch": {"verified": True, "evidence": batch}},
        },
        "current_managed_signer": signer,
    }
    record = {
        "status": "verified_blocked_receipt", "source_commit": SOURCE,
        "producer_run_id": 101, "record_run_id": 102,
        "plan_run_id": "100",
        "record_completed_at_utc": "2026-09-30T12:00:00Z",
        "receipt_file_sha256": "e" * 64,
        "receipt_attestation_sha256": "f" * 64,
        "plan_file_sha256": "0" * 64,
        "plan": {"source_commit": SOURCE, "surface": "base",
                 "project": PROJECT, "services_reference": REFERENCE,
                 "stack_manifest_sha256": STACK},
        "receipt": receipt,
    }
    release = {"source_commit": SOURCE, "stack_manifest_sha256": STACK,
               "signed_manifest_verified": True,
               "oci_digests": {
                   "ghcr.io/elevenid/marty-ui-oss/services": SERVICE_DIGEST}}
    return record, release


def test_projection_preserves_same_job_material_callback_and_restart() -> None:
    record, release = inputs()
    result = project(record, release)
    assert result["status"] == "blocked"
    assert result["record_run_id"] == record["record_run_id"]
    assert result["record_completed_at_utc"] == record[
        "record_completed_at_utc"]
    assert len(result["probes"]) == 10
    assert result["probes"]["sod_signature"]["evidence"][
        "sod_sha256"] == "d" * 64
    assert result["probes"]["nine_route_gateway_flow"]["evidence"][
        "sod_sha256"] == "0" * 64
    batch = result["probes"]["physical_bureau_batch"]["evidence"]
    assert [job["status"] for job in batch["returned_jobs"]] == [
        "QUALITY_CHECK", "SHIPPED"]
    assert batch["callback_receipts_sha256"] == ["c" * 64, "9" * 64]
    material = result["probes"]["simulator_material_receipt"]["evidence"]
    assert material["source_job_id_commitment"] == batch[
        "submitted_job_commitments"][0]
    resume = result["probes"]["rust_restart_resume"]["evidence"]
    assert resume["before"]["status"] == "SOD_SIGNED"
    assert resume["after"]["status"] == "SUBMITTED"
    assert resume["before"]["issuance_native_container_id"] != resume[
        "after"]["issuance_native_container_id"]


@pytest.mark.parametrize("mutation", [
    lambda record, release: release.update(source_commit="b" * 40),
    lambda record, release: record["receipt"]["current_managed_signer"].update(
        private_key_exported=True),
    lambda record, release: record["receipt"]["flow_execution"]["batch"][
        "batch"]["evidence"]["selected_material_receipt"].update(
            source_job_id_commitment="0" * 64),
    lambda record, release: record["receipt"]["flow_execution"]["execution"].update(
        restart_after_native_status="SOD_SIGNED"),
    lambda record, release: record["receipt"]["flow_execution"]["batch"][
        "batch"]["evidence"].update(companion_simulator_marker_verified=False),
])
def test_projection_rejects_unbound_evidence(mutation) -> None:
    record, release = inputs()
    mutation(record, release)
    with pytest.raises(ProjectionError):
        project(record, release)


def test_projection_cannot_mutate_verified_source() -> None:
    record, release = inputs()
    original = deepcopy(record)
    projected = project(record, release)
    projected["probes"]["managed_csca_dsc_chain"]["evidence"][
        "csca"]["status"] = "tampered"
    assert record == original
