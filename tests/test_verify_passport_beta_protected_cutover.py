"""Maintenance accepts only an exact protected final cutover artifact."""

from __future__ import annotations

import json

import pytest

from scripts import verify_passport_beta_protected_cutover as cutover


HEAD = "a" * 40
DELETION = "b" * 40
FILE_HASH = "c" * 64


def fixture(tmp_path):
    snapshot = {
        "snapshot_sha256": "d" * 64,
        "database_uid": "postgresql:123:456",
        "beta_cluster_uid": "docker:daemon",
        "beta_inventory_attestation_sha256": "e" * 64,
        "writer_deployment_uid": "elevenid-beta:issuance:" + "f" * 64,
        "writer_image_digest": "sha256:" + "1" * 64,
        "writer_container_id": "f" * 64,
        "writer_started_at": "2026-09-29T00:00:00Z",
        "writer_generation": 0,
        "observation_watermark": 200,
        "fence_epoch": 7,
        "fence_verification_sha256": "2" * 64,
        "direct_database_probe": {"observation_watermark": 199},
        "production_snapshot_sha256": "3" * 64,
    }
    report = {
        "schema": "marty.passport-python-deletion-cutover/v1",
        "status": "accepted", "run_id": 42,
        "rust_source_commit": HEAD, "deletion_head": DELETION,
        "cutover_snapshot_file_sha256": FILE_HASH,
        "cutover_snapshot_sha256": snapshot["snapshot_sha256"],
        "supported_acceptance_run_id": 10,
        "predeletion_acceptance_run_id": 11,
        "legacy_source": {
            "environment": "beta", "database_uid": snapshot["database_uid"],
            "beta_cluster_uid": snapshot["beta_cluster_uid"],
            "beta_inventory_attestation_sha256":
                snapshot["beta_inventory_attestation_sha256"],
            "writer_deployment_uid": snapshot["writer_deployment_uid"],
            "writer_image_digest": snapshot["writer_image_digest"],
            "writer_container_id": snapshot["writer_container_id"],
            "writer_started_at": snapshot["writer_started_at"],
            "writer_generation": 0, "writer_running": True,
            "final_watermark": snapshot["observation_watermark"],
        },
        "write_fence": {
            "enabled": True, "database_uid": snapshot["database_uid"],
            "writer_deployment_uid": snapshot["writer_deployment_uid"],
            "writer_container_id": snapshot["writer_container_id"],
            "writer_generation": 0, "fence_epoch": 7,
            "verification_sha256": snapshot["fence_verification_sha256"],
            "direct_database_probe": snapshot["direct_database_probe"],
        },
        "counts": {
            "source_database_uid": snapshot["database_uid"],
            "nonterminal_job_count": 0,
            "legacy_or_unknown_artifact_count": 0,
            "unreadable_artifact_count": 0,
            "active_passport_flow_count": 0,
        },
        "production_snapshot_sha256": snapshot["production_snapshot_sha256"],
        "production_unchanged": True,
        "other_beta_resources_unchanged": True,
    }
    path = tmp_path / "passport-python-deletion-cutover-42.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    run = {
        "id": 42, "status": "completed", "conclusion": "success",
        "event": "workflow_dispatch", "path": cutover.WORKFLOW,
        "head_branch": "main", "head_sha": HEAD,
        "repository": {"full_name": cutover.REPOSITORY},
        "head_repository": {"full_name": cutover.REPOSITORY},
    }
    return path, snapshot, report, run


def execute_for(run, calls):
    def execute(args):
        calls.append(args)
        return json.dumps(run) if args[:2] == ["gh", "api"] else "verified"
    return execute


def verify(path, snapshot, run, execute):
    return cutover.verify(
        path, source_commit=HEAD, deletion_head=DELETION,
        snapshot=snapshot, snapshot_file_sha256=FILE_HASH,
        receipt={"credentials_deletion_head": DELETION}, execute=execute,
    )


def test_exact_protected_report_binds_snapshot_and_source(tmp_path):
    path, snapshot, _report, run = fixture(tmp_path)
    calls = []
    result = verify(path, snapshot, run, execute_for(run, calls))
    assert result["cutover_report_run_id"] == 42
    assert result["cutover_report_file_sha256"] == cutover.file_sha256(path)
    assert calls[1] == [
        "gh", "attestation", "verify", str(path), "--repo", cutover.REPOSITORY,
        "--signer-workflow", f"{cutover.REPOSITORY}/{cutover.WORKFLOW}",
        "--source-digest", HEAD, "--source-ref", "refs/heads/main",
    ]


def test_wrong_workflow_or_writer_fails_closed(tmp_path):
    path, snapshot, report, run = fixture(tmp_path)
    run["path"] = ".github/workflows/other.yml"
    with pytest.raises(cutover.HostProbeError, match="protected main"):
        verify(path, snapshot, run, execute_for(run, []))
    run["path"] = cutover.WORKFLOW
    report["legacy_source"]["writer_generation"] = 1
    path.write_text(json.dumps(report), encoding="utf-8")
    with pytest.raises(cutover.HostProbeError, match="live cutover snapshot"):
        verify(path, snapshot, run, execute_for(run, []))


def test_missing_attestation_fails_closed(tmp_path):
    path, snapshot, _report, run = fixture(tmp_path)
    def execute(args):
        if args[:2] == ["gh", "api"]:
            return json.dumps(run)
        raise cutover.HostProbeError("Protected passport report verification failed")
    with pytest.raises(cutover.HostProbeError, match="verification failed"):
        verify(path, snapshot, run, execute)
