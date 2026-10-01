"""Predeletion acceptance requires a later, unchanged beta observation."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json

import pytest

from scripts.compose_passport_predeletion_acceptance import (
    AcceptanceError, compose, signed_release,
)
from scripts.project_passport_predeletion_producer import project
from scripts.probe_passport_beta_cutover_snapshot import digest
from tests.test_project_passport_predeletion_producer import inputs


SOURCE = "a" * 40


def installation_file_sha(installation: dict) -> str:
    contents = json.dumps(installation, sort_keys=True, indent=2) + "\n"
    return hashlib.sha256(contents.encode()).hexdigest()


def test_signed_release_requires_actual_v_tag_and_same_source() -> None:
    released = {
        "release": "marty-ui@1.1.218", "source_commit": SOURCE,
        "manifest_sha256": "b" * 64, "signed_manifest_verified": True,
        "oci_digests": {"ghcr.io/elevenid/marty-ui-oss/services":
                        "sha256:" + "c" * 64},
    }
    assert signed_release(SOURCE, "v1.1.218", released)[
        "stack_manifest_sha256"] == "b" * 64
    with pytest.raises(AcceptanceError):
        signed_release(SOURCE, "1.1.218", released)
    with pytest.raises(AcceptanceError):
        signed_release("f" * 40, "v1.1.218", released)


def evidence() -> tuple[dict, dict, dict]:
    producer, release = inputs()
    projection = project(producer, release)
    observed = {
        "schema": "marty.passport-beta-cutover-snapshot/v1",
        "status": "observed", "observed_at_utc": "2026-09-30T12:02:00Z",
        "snapshot_sha256": "1" * 64,
        "installation_receipt_sha256": "2" * 64,
        "database_uid": "postgresql:123:456",
        "beta_cluster_uid": "docker:beta",
        "beta_inventory_attestation_sha256": "3" * 64,
        "writer_deployment_uid": "elevenid-beta:issuance:abc",
        "writer_container_id": "a" * 64,
        "writer_image_digest": "sha256:" + "4" * 64,
        "writer_started_at": "2026-09-30T11:00:00Z",
        "writer_generation": 1, "fence_epoch": 2,
        "fence_installed_at_utc": "2026-09-30T12:00:30Z",
        "fence_verification_sha256": "5" * 64,
        "production_snapshot_sha256": "6" * 64,
        "production_attachments_sha256": "7" * 64,
        "direct_database_probe": {"observation_watermark": 3},
        "counts": {
            "total_job_count": 0, "nonterminal_job_count": 0,
            "legacy_or_unknown_artifact_count": 0,
            "unreadable_artifact_count": 0,
            "active_passport_flow_count": 0,
        },
    }
    observation = {
        "schema": "marty.passport-rust-predeletion-drain/v1",
        "status": "verified_observation", "source_commit": SOURCE,
        "installation": {"source_commit": SOURCE},
        "snapshot": observed,
        "observation_run_id": 103,
        "observation_completed_at_utc": "2026-09-30T12:03:00Z",
        "attestation_sha256": {
            "installation": "8" * 64, "snapshot": "9" * 64,
            "drain": "a" * 64,
        },
        "probe": {"verified": True, "evidence": {
            "source_commit": SOURCE,
            "python_passport_writes_fenced": True,
            "count_source_database_uid": observed["database_uid"],
            "legacy_source": {
                "drain_checked_at_utc": observed["observed_at_utc"],
                "writer_deployment_uid": observed["writer_deployment_uid"],
            },
        }},
    }
    observation["fence_installation_receipt_sha256"] = installation_file_sha(
        observation["installation"])
    observed["installation_receipt_sha256"] = digest(
        observation["installation"])
    fresh = deepcopy(observed)
    fresh["observed_at_utc"] = "2026-09-30T12:05:00Z"
    fresh["snapshot_sha256"] = "b" * 64
    fresh["direct_database_probe"]["observation_watermark"] = 4
    return projection, observation, fresh


def accept(projection: dict, observation: dict, fresh: dict) -> dict:
    return compose(
        projection, observation, fresh, run_id=104,
        installation_file_sha256=installation_file_sha(
            observation["installation"]),
        workflow_started_at_utc="2026-09-30T12:04:00Z",
        accepted_at_utc="2026-09-30T12:06:00Z",
    )


def test_accepts_twelve_bound_probes_after_fresh_beta_isolation() -> None:
    projection, observation, fresh = evidence()
    result = accept(projection, observation, fresh)
    assert result["status"] == "accepted"
    assert result["fence_installation_receipt_sha256"] == observation[
        "fence_installation_receipt_sha256"]
    assert len(result["probes"]) == 12
    assert result["producer_provenance"]["record_run_id"] == 102
    assert result["drain_provenance"]["observation_run_id"] == 103
    assert result["deployment"]["database_uid"] != fresh["database_uid"]
    assert result["probes"]["production_isolation"]["evidence"][
        "fresh_beta_snapshot_sha256"] == fresh["snapshot_sha256"]


@pytest.mark.parametrize("mutation", [
    lambda projection, observation, fresh: fresh.update(
        production_snapshot_sha256="f" * 64),
    lambda projection, observation, fresh: fresh.update(
        writer_generation=2),
    lambda projection, observation, fresh: fresh["counts"].update(
        active_passport_flow_count=1),
    lambda projection, observation, fresh: fresh["direct_database_probe"].update(
        observation_watermark=3),
    lambda projection, observation, fresh: observation.update(
        observation_completed_at_utc="2026-09-30T12:07:00Z"),
    lambda projection, observation, fresh: projection.update(
        source_commit="f" * 40),
    lambda projection, observation, fresh: observation.update(
        fence_installation_receipt_sha256="f" * 64),
    lambda projection, observation, fresh: fresh.update(
        installation_receipt_sha256="f" * 64),
])
def test_rejects_changed_or_stale_live_evidence(mutation) -> None:
    projection, observation, fresh = evidence()
    mutation(projection, observation, fresh)
    with pytest.raises(AcceptanceError):
        accept(projection, observation, fresh)
