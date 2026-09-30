"""Protected final producer binds the same old writer after predeletion."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json

import pytest

from scripts import collect_passport_python_deletion_cutover as producer
from scripts.probe_passport_beta_cutover_snapshot import digest


HEAD = "a" * 40
DELETION = "b" * 40
WRITER = "c" * 64


def fixture():
    first = {"observation_watermark": 100, "receipt_sha256": "1" * 64,
             "observed_at_utc": "2026-09-29T01:00:00.000Z"}
    prior = {"observation_watermark": 150, "receipt_sha256": "2" * 64,
             "observed_at_utc": "2026-09-29T02:00:00.000Z"}
    final = {"observation_watermark": 190, "receipt_sha256": "3" * 64,
             "observed_at_utc": "2026-09-29T03:00:00.000Z"}
    installation = {
        "schema": "marty.passport-beta-fence-installation/v1",
        "source_commit": HEAD, "credentials_deletion_head": DELETION,
        "direct_database_probe": first,
        "fence_installed_at_utc": "2026-09-29T00:59:00.000Z",
        "production_snapshot_sha256": "4" * 64,
        "production_attachments_sha256": "5" * 64,
    }
    snapshot = {
        "schema": "marty.passport-beta-cutover-snapshot/v1",
        "status": "observed", "installation_provenance": "local_host_continuity_only",
        "installation_receipt_sha256": digest(installation),
        "fence_first_probe": first, "direct_database_probe": final,
        "database_uid": "postgresql:123:456",
        "beta_cluster_uid": "docker:daemon",
        "beta_inventory_attestation_sha256": "6" * 64,
        "writer_deployment_uid": f"elevenid-beta:issuance:{WRITER}",
        "writer_container_id": WRITER,
        "writer_image_digest": "sha256:" + "7" * 64,
        "writer_started_at": "2026-09-29T00:00:00Z",
        "writer_generation": 0,
        "fence_epoch": 9,
        "fence_installed_at_utc": installation["fence_installed_at_utc"],
        "fence_verification_sha256": "8" * 64,
        "observation_watermark": 200,
        "observed_at_utc": "2026-09-29T03:05:00.000Z",
        "production_snapshot_sha256": "4" * 64,
        "production_attachments_sha256": "5" * 64,
        "counts": {
            "total_job_count": 0, "nonterminal_job_count": 0,
            "legacy_or_unknown_artifact_count": 0,
            "unreadable_artifact_count": 0,
            "active_passport_flow_count": 0,
        },
    }
    snapshot["snapshot_sha256"] = digest(snapshot)
    legacy = {
        "database_uid": snapshot["database_uid"],
        "beta_cluster_uid": snapshot["beta_cluster_uid"],
        "beta_inventory_attestation_sha256":
            snapshot["beta_inventory_attestation_sha256"],
        "writer_deployment_uid": snapshot["writer_deployment_uid"],
        "writer_container_id": WRITER,
        "writer_image_digest": snapshot["writer_image_digest"],
        "writer_generation_at_drain": 0,
        "writer_database_role": "marty",
        "fence_watermark": 9,
        "fence_enabled_at_utc": installation["fence_installed_at_utc"],
        "drain_watermark": 150,
        "drain_snapshot_attestation_sha256": "a" * 64,
        "drain_checked_at_utc": "2026-09-29T02:10:00Z",
    }
    fence = {
        "scope": "physical_document_jobs_and_physical_flows",
        "enabled": True,
        "database_uid": snapshot["database_uid"],
        "writer_deployment_uid": snapshot["writer_deployment_uid"],
        "writer_container_id": WRITER, "writer_generation": 0,
        "fence_epoch": 9,
        "verification_sha256": snapshot["fence_verification_sha256"],
        "unrelated_issuance_continues": True,
        "direct_database_probe": prior,
    }
    predeletion = {
        "schema": "marty.passport-rust-predeletion-acceptance/v1",
        "status": "accepted", "release": {"source_commit": HEAD},
        "fence_installation_receipt_sha256": hashlib.sha256(
            (json.dumps(installation, sort_keys=True) + "\n").encode()).hexdigest(),
        "probes": {"legacy_drain": {"evidence": {
            "legacy_source": legacy, "passport_write_fence": fence,
        }}},
    }
    supported = {
        "schema": "marty.passport-supported-consumer-acceptance/v1",
        "status": "accepted", "source_commit": HEAD,
        "legacy_source_binding": {
            "database_uid": snapshot["database_uid"],
            "writer_deployment_uid": snapshot["writer_deployment_uid"],
        },
    }
    return supported, predeletion, snapshot, installation


def run(supported, predeletion, snapshot, installation):
    return producer.collect(
        source_commit=HEAD, run_id=42, deletion_head=DELETION,
        supported_run_id=10, predeletion_run_id=11,
        supported=supported, predeletion=predeletion,
        snapshot=snapshot, snapshot_file_sha256="9" * 64,
        installation=installation,
        installation_file_sha256=hashlib.sha256(
            (json.dumps(installation, sort_keys=True) + "\n").encode()).hexdigest(),
        checked_at=datetime(2026, 9, 29, 3, 30, tzinfo=timezone.utc),
    )


def test_final_report_matches_predeletion_writer_and_zero_counts():
    supported, predeletion, snapshot, installation = fixture()
    report = run(supported, predeletion, snapshot, installation)
    assert report["status"] == "accepted"
    assert report["legacy_source"]["writer_container_id"] == WRITER
    assert report["legacy_source"]["final_watermark"] == 190
    assert report["write_fence"]["direct_database_probe"] == (
        snapshot["direct_database_probe"])


def test_changed_writer_or_stale_probe_is_rejected():
    supported, predeletion, snapshot, installation = fixture()
    snapshot["writer_generation"] = 1
    snapshot["snapshot_sha256"] = digest({
        key: value for key, value in snapshot.items() if key != "snapshot_sha256"
    })
    with pytest.raises(producer.HostProbeError, match="predeletion acceptance"):
        run(supported, predeletion, snapshot, installation)
    snapshot["writer_generation"] = 0
    snapshot["direct_database_probe"] = (
        predeletion["probes"]["legacy_drain"]["evidence"]
        ["passport_write_fence"]["direct_database_probe"])
    with pytest.raises(producer.HostProbeError, match="stale"):
        run(supported, predeletion, snapshot, installation)


def test_changed_snapshot_or_fence_is_rejected():
    supported, predeletion, snapshot, installation = fixture()
    snapshot["counts"]["total_job_count"] = 1
    with pytest.raises(producer.HostProbeError, match="stale"):
        run(supported, predeletion, snapshot, installation)
    supported, predeletion, snapshot, installation = fixture()
    predeletion["probes"]["legacy_drain"]["evidence"]["passport_write_fence"][
        "fence_epoch"] += 1
    with pytest.raises(producer.HostProbeError, match="predeletion acceptance"):
        run(supported, predeletion, snapshot, installation)


def test_same_drain_snapshot_attestation_is_rejected():
    supported, predeletion, snapshot, installation = fixture()
    predeletion["probes"]["legacy_drain"]["evidence"]["legacy_source"][
        "drain_snapshot_attestation_sha256"] = "9" * 64
    with pytest.raises(producer.HostProbeError, match="predeletion acceptance"):
        run(supported, predeletion, snapshot, installation)


def test_unbound_fence_installation_is_rejected():
    supported, predeletion, snapshot, installation = fixture()
    predeletion["fence_installation_receipt_sha256"] = "f" * 64
    with pytest.raises(producer.HostProbeError, match="attested predeletion installation"):
        run(supported, predeletion, snapshot, installation)


def test_predeletion_drain_watermark_must_be_the_direct_probe_watermark():
    supported, predeletion, snapshot, installation = fixture()
    predeletion["probes"]["legacy_drain"]["evidence"]["legacy_source"][
        "drain_watermark"] += 1
    with pytest.raises(producer.HostProbeError, match="stale"):
        run(supported, predeletion, snapshot, installation)


def test_predeletion_fence_time_must_be_database_installed_time():
    supported, predeletion, snapshot, installation = fixture()
    predeletion["probes"]["legacy_drain"]["evidence"]["legacy_source"][
        "fence_enabled_at_utc"] = "2026-09-29T00:58:00.000Z"
    with pytest.raises(producer.HostProbeError, match="stale"):
        run(supported, predeletion, snapshot, installation)


def test_predeletion_drain_must_follow_its_write_probe():
    supported, predeletion, snapshot, installation = fixture()
    predeletion["probes"]["legacy_drain"]["evidence"]["legacy_source"][
        "drain_checked_at_utc"] = "2026-09-29T01:59:00Z"
    with pytest.raises(producer.HostProbeError, match="stale"):
        run(supported, predeletion, snapshot, installation)
