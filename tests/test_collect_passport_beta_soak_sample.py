from datetime import datetime, timezone

import pytest

from scripts.collect_passport_beta_acceptance import (
    EvidenceError, production_attachment_commitment,
    production_snapshot_commitment,
)
from scripts.collect_passport_beta_soak_sample import sample


KEY = "k" * 40
SNAPSHOT = "a" * 64
ATTACHMENTS = "b" * 64


def report():
    return {
        "schema": "marty.passport-beta-acceptance/v1",
        "status": "blocked", "beta_origin": "https://beta.elevenidllc.com",
        "physical_claim": "not_claimed",
        "release": {"signed_manifest_verified": True,
                    "source_commit": "c" * 40,
                    "stack_manifest_sha256": "d" * 64},
        "deployment": {
            "provider_mode": "simulator",
            "aggregate_deployment_receipt_sha256": "e" * 64,
            "aggregate_plan_sha256": "f" * 64,
            "production_snapshot_commitment": production_snapshot_commitment(KEY, SNAPSHOT),
            "production_attachment_commitment": production_attachment_commitment(KEY, ATTACHMENTS),
        },
        "probes": {
            "capabilities_http": {"verified": True},
            "unauthenticated_denial": {"verified": True},
            "physical_claim_boundary": {"verified": True, "evidence": {
                "physical_claim": "not_claimed", "booklet_verified": False}},
        },
        "runtime_images": {"passport-beta-bureau": {
            "container_id": "1" * 64, "oci_digest": "sha256:" + "2" * 64}},
    }


def collect(tmp_path, *, source=None, attachment=ATTACHMENTS, routes=True,
            drained=True, job_status="ACTIVE", bureau_job="test-bureau",
            public_site=True):
    (tmp_path / "aggregate-deployment.json").write_text("{}")
    selected = {"schema": "marty.passport-beta-demo-private/v1",
                "source_commit": "c" * 40,
                "stack_manifest_sha256": "d" * 64,
                "organization_id": "test-org", "application_id": "test-app",
                "source_job_id": "test-job", "bureau_job_id": "test-bureau"}
    return sample(
        tmp_path, KEY, selected,
        {"run_id": "123", "workflow_commit": "c" * 40},
        collector=lambda *_args, **_kwargs: source or report(),
        snapshot=lambda: {"sha256": SNAPSHOT},
        attachments=lambda: attachment,
        public_site=lambda: public_site,
        native_routes=lambda *_args: {"verified": routes},
        status_request=lambda *_args: (200, {
            "id": "test-job", "application_id": "test-app",
            "bureau_job_id": bureau_job,
            "organization_id": "test-org", "status": job_status}),
        drain=lambda: {"verified": drained, "evidence": {
            "in_flight_jobs": 0, "legacy_or_unknown_artifacts": 0,
            "active_physical_document_flows": 0,
            "database": "beta", "source": "live PostgreSQL"}},
        clock=lambda: datetime(2026, 10, 1, 12, tzinfo=timezone.utc),
    )


def test_sample_binds_live_runtime_drain_and_production_baseline(tmp_path):
    result = collect(tmp_path)
    assert result["status"] == "observed"
    assert result["release"]["source_commit"] == "c" * 40
    assert result["checks"]["production_attachments_unchanged"] is True
    assert result["checks"]["production_public_site_reachable"] is True
    assert result["checks"]["native_gateway_flow_and_callback_route"] is True
    assert result["checks"]["selected_passport_job_active"] is True
    assert result["physical_claim"] == "not_claimed"


def test_sample_fails_on_changed_production_attachment(tmp_path):
    with pytest.raises(EvidenceError, match="Production differs"):
        collect(tmp_path, attachment="9" * 64)


def test_sample_fails_if_production_public_site_is_unavailable(tmp_path):
    with pytest.raises(EvidenceError, match="Production public site"):
        collect(tmp_path, public_site=False)


def test_sample_fails_on_missing_native_route_or_nonzero_drain(tmp_path):
    with pytest.raises(EvidenceError, match="Native passport route"):
        collect(tmp_path, routes=False)
    with pytest.raises(EvidenceError, match="Native passport route"):
        collect(tmp_path, drained=False)


def test_sample_fails_on_unsigned_or_physically_claimed_release(tmp_path):
    unsigned = report()
    unsigned["release"]["signed_manifest_verified"] = False
    with pytest.raises(EvidenceError, match="not ready"):
        collect(tmp_path, source=unsigned)
    claimed = report()
    claimed["physical_claim"] = "claimed"
    with pytest.raises(EvidenceError, match="not ready"):
        collect(tmp_path, source=claimed)


def test_sample_fails_if_selected_job_regresses(tmp_path):
    with pytest.raises(EvidenceError, match="no longer active"):
        collect(tmp_path, job_status="FAILED")
    with pytest.raises(EvidenceError, match="no longer active"):
        collect(tmp_path, bureau_job="different-bureau")
