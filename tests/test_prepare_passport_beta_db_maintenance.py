"""Maintenance planning must cover the whole fenced beta generation."""

from __future__ import annotations

import json
import hashlib

import pytest

from scripts import prepare_passport_beta_db_maintenance as maintenance
from scripts.probe_passport_beta_host import HostProbeError


def record(service: str, number: int, *, running: bool = True) -> dict:
    return {
        "Id": f"{number:x}" + "0" * 63, "Image": "sha256:" + "a" * 64,
        "Config": {"Image": "issuance@sha256:" + "b" * 64, "Labels": {
            "com.docker.compose.project": "elevenid-beta",
            "com.docker.compose.service": service,
        }},
        "State": {"Running": running, "Status": "running" if running else "exited",
                  "StartedAt": "2026-09-29T00:00:00Z"},
        "RestartCount": 0,
    }


def snapshot(path, receipt, writer, *, inventory="e" * 64):
    value = {
        "schema": "marty.passport-beta-cutover-snapshot/v1",
        "status": "observed", "installation_provenance": "local_host_continuity_only",
        "installation_receipt_sha256": hashlib.sha256(json.dumps(
            receipt, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        "database_uid": "postgresql:123:456", "fence_epoch": 789,
        "beta_cluster_uid": "docker:daemon",
        "writer_deployment_uid": f"elevenid-beta:issuance:{writer['container_id']}",
        "fence_verification_sha256": hashlib.sha256(json.dumps(
            receipt["fence"], sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        "fence_first_probe": receipt["direct_database_probe"],
        "direct_database_probe": {"observation_watermark": 2},
        "observation_watermark": 3,
        "counts": {
            "total_job_count": 0, "nonterminal_job_count": 0,
            "legacy_or_unknown_artifact_count": 0,
            "unreadable_artifact_count": 0,
            "active_passport_flow_count": 0,
        },
        "beta_inventory_attestation_sha256": inventory,
        "production_snapshot_sha256": "f" * 64,
        "production_attachments_sha256": "0" * 64,
        "writer_container_id": writer["container_id"],
        "writer_image_digest": "sha256:" + "b" * 64,
        "writer_started_at": writer["started_at"],
        "writer_generation": 0,
    }
    value["snapshot_sha256"] = hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    path.write_text(json.dumps(value), encoding="utf-8")
    return value


def test_full_generation_includes_unexpected_service_and_refuses_stopped_one(monkeypatch):
    services = (*maintenance.REQUIRED_SERVICES, "openbao", "unreviewed-db-client")
    records = {record(service, index)["Id"]: record(service, index)
               for index, service in enumerate(services, 1)}
    monkeypatch.setattr(maintenance, "ids", lambda _project, _runner: list(records))
    monkeypatch.setattr(maintenance, "inspect", lambda key, _runner: records[key])
    postgres_id = next(key for key, item in records.items()
                       if item["Config"]["Labels"]["com.docker.compose.service"]
                       == "postgres")
    generation = maintenance.running_beta_generation(postgres_id)
    assert {item["service"] for item in generation} == set(services)
    assert "unreviewed-db-client" in {item["service"] for item in generation}
    records[next(key for key, item in records.items()
                 if item["Config"]["Labels"]["com.docker.compose.service"]
                 == "unreviewed-db-client")]["State"]["Running"] = False
    with pytest.raises(HostProbeError, match="ambiguous or stopped"):
        maintenance.running_beta_generation(postgres_id)


def test_plan_binds_current_fence_source_and_production(monkeypatch, tmp_path):
    head = "b" * 40
    postgres_id = "c" * 64
    service_id = "d" * 64
    openbao_id = "1" * 64
    receipt = {
        "post_install_observation_sha256": "e" * 64,
        "credentials_deletion_head": "c" * 40,
        "production_snapshot_sha256": "f" * 64,
        "production_attachments_sha256": "0" * 64,
        "fence": {"epoch": 789}, "direct_database_probe": {"watermark": 1},
    }
    receipt_path = tmp_path / "fence.json"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    monkeypatch.setattr(maintenance, "protected_source", lambda _runner: head)
    checked = []
    monkeypatch.setattr(maintenance, "protected_file",
                        lambda relative, _runner: checked.append(relative))
    monkeypatch.setattr(maintenance, "manifest_source", lambda _manifest, _head: {
        "release": "marty-ui@1.2.3", "manifest_sha256": "a" * 64,
    })
    monkeypatch.setattr(maintenance, "checked_receipt", lambda _path, _head: {
        "container_id": postgres_id, "system_id": "123", "database_oid": "456",
        "fence_epoch": "789",
    })
    generation = [
        {"service": "postgres", "container_id": postgres_id,
         "image_id": "sha256:" + "a" * 64, "started_at": "today"},
        {"service": "auth", "container_id": service_id,
         "image_id": "sha256:" + "b" * 64, "started_at": "today"},
        {"service": "issuance", "container_id": "2" * 64,
         "image_id": "sha256:" + "b" * 64, "started_at": "today"},
        {"service": "openbao", "container_id": openbao_id,
         "image_id": "sha256:" + "c" * 64, "started_at": "today"},
    ]
    monkeypatch.setattr(maintenance, "running_beta_generation",
                        lambda _id, _runner: generation)
    monkeypatch.setattr(maintenance, "production_attachment_sha256",
                        lambda _runner: "0" * 64)
    observed = {
        "schema": "marty.passport-beta-fence-postinstall-target/v1",
        "observation_sha256": "e" * 64,
        "production_attachments_sha256": "0" * 64,
        "docker": {"context": "approved", "daemon_id": "daemon"},
        "production": {"sha256": "f" * 64},
        "beta": {
            "postgres_system_identifier": "123", "database_oid": "456",
            "services": {**{item["service"]: item for item in generation},
                         "issuance": {**generation[2], "restart_count": 0,
                                      "configured_image": "issuance@sha256:" + "b" * 64}},
        },
    }
    snapshot_path = tmp_path / "snapshot.json"
    snapshot(snapshot_path, receipt, observed["beta"]["services"]["issuance"])
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps({"deletion_head": "a" * 40}), encoding="utf-8")
    verified_heads = []
    def verify_report(*_args, **kwargs):
        verified_heads.append(kwargs["deletion_head"])
        return {"cutover_report_file_sha256": "8" * 64,
                "cutover_report_run_id": 42}
    monkeypatch.setattr(maintenance, "verify_cutover_report", verify_report)
    checked_probes = []
    monkeypatch.setattr(maintenance, "validate_direct_probe",
                        lambda probe, **kwargs: checked_probes.append((probe, kwargs)))
    monkeypatch.setattr(maintenance, "inspect", lambda _id, _runner: {
        "Id": "2" * 64, "Image": "sha256:" + "b" * 64,
        "Config": {"Image": "issuance@sha256:" + "b" * 64,
                   "Labels": {"com.docker.compose.project": "elevenid-beta",
                              "com.docker.compose.service": "issuance"}},
        "State": {"Running": True, "Status": "running", "StartedAt": "today"},
        "RestartCount": 0,
    })
    monkeypatch.setattr(maintenance, "beta_psql",
                        lambda *_args: "0|4|2026-09-29T00:00:00.000Z")
    def runner(command):
        return "approved" if command[1] == "context" else "daemon"
    plan = maintenance.prepare(tmp_path / "stack.json", receipt_path,
                               snapshot_path, report_path,
                               runner, lambda _runner: observed)
    assert checked == list(maintenance.PROTECTED_FILES)
    assert plan["stop_container_ids"] == [service_id, "2" * 64]
    assert plan["production_snapshot_sha256"] == "f" * 64
    assert plan["production_attachments_sha256"] == "0" * 64
    assert plan["legacy_writer_container_id"] == "2" * 64
    assert verified_heads == ["a" * 40]
    assert len(checked_probes) == 2
    observed["beta"]["services"]["issuance"]["restart_count"] = 1
    with pytest.raises(HostProbeError, match="live fenced Python writer"):
        maintenance.prepare(tmp_path / "stack.json", receipt_path,
                            snapshot_path, report_path,
                            runner, lambda _runner: observed)
    observed["beta"]["services"]["issuance"]["restart_count"] = 0
    receipt["production_snapshot_sha256"] = "0" * 64
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    with pytest.raises(HostProbeError, match="production differs"):
        maintenance.prepare(tmp_path / "stack.json", receipt_path,
                            snapshot_path, report_path,
                            runner, lambda _runner: observed)


def test_resume_verifies_full_ids_and_requires_every_service_stopped(monkeypatch, tmp_path):
    postgres = record("postgres", 1)
    auth = record("auth", 2)
    openbao = record("openbao", 3)
    issuance = record("issuance", 4)
    records = {item["Id"]: item for item in (postgres, auth, openbao, issuance)}
    receipt_path = tmp_path / "fence.json"
    receipt_raw = {
        "production_snapshot_sha256": "f" * 64,
        "credentials_deletion_head": "c" * 40,
        "production_attachments_sha256": "0" * 64,
        "post_install_observation_sha256": "e" * 64,
        "fence": {"epoch": 789}, "direct_database_probe": {"watermark": 1},
    }
    receipt_path.write_text(json.dumps(receipt_raw), encoding="utf-8")
    snapshot_path = tmp_path / "snapshot.json"
    snap = snapshot(snapshot_path, receipt_raw, {
        "container_id": issuance["Id"],
        "started_at": issuance["State"]["StartedAt"],
    })
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps({"deletion_head": "a" * 40}), encoding="utf-8")
    verified_heads = []
    def verify_report(*_args, **kwargs):
        verified_heads.append(kwargs["deletion_head"])
        return {"cutover_report_file_sha256": "8" * 64,
                "cutover_report_run_id": 42}
    monkeypatch.setattr(maintenance, "verify_cutover_report", verify_report)
    monkeypatch.setattr(maintenance, "validate_direct_probe",
                        lambda *_args, **_kwargs: None)
    head = "b" * 40
    monkeypatch.setattr(maintenance, "protected_source", lambda _runner: head)
    monkeypatch.setattr(maintenance, "protected_file", lambda _relative, _runner: None)
    monkeypatch.setattr(maintenance, "manifest_source", lambda _path, _head: {
        "release": "marty-ui@1.2.3", "manifest_sha256": "a" * 64,
    })
    monkeypatch.setattr(maintenance, "checked_receipt", lambda _path, _head: {
        "container_id": postgres["Id"], "system_id": "123",
        "database_oid": "456", "fence_epoch": "789",
    })
    monkeypatch.setattr(maintenance, "file_sha256", lambda path: (
        "c" * 64 if path == receipt_path else "d" * 64
    ))
    monkeypatch.setattr(maintenance, "production_snapshot",
                        lambda _runner: {"sha256": "f" * 64})
    monkeypatch.setattr(maintenance, "production_attachment_sha256",
                        lambda _runner: "0" * 64)
    monkeypatch.setattr(maintenance, "ids", lambda _project, _runner: [
        item[:12] for item in records
    ])
    monkeypatch.setattr(maintenance, "inspect", lambda key, _runner: (
        records[next(full for full in records if full.startswith(key))]
    ))
    monkeypatch.setattr(maintenance, "beta_psql", lambda *_args: "123|456")

    def runner(command):
        return "approved" if command[1] == "context" else "daemon"

    generation = [
        {"service": item["Config"]["Labels"]["com.docker.compose.service"],
         "container_id": item["Id"], "image_id": item["Image"],
         "started_at": item["State"]["StartedAt"]}
        for item in (postgres, auth, openbao, issuance)
    ]
    plan = {
        "schema": "marty.passport-beta-db-maintenance-plan/v1",
        "source_commit": head, "release": "marty-ui@1.2.3",
        "stack_manifest_sha256": "a" * 64,
        "fence_receipt_sha256": "c" * 64,
        "start_sql_sha256": "d" * 64,
        "verify_sql_sha256": "d" * 64,
        "postgres_container_id": postgres["Id"],
        "postgres_system_identifier": "123", "database_oid": "456",
        "fence_epoch": "789", "docker": {"context": "approved", "daemon_id": "daemon"},
        "production_snapshot_sha256": "f" * 64,
        "production_attachments_sha256": "0" * 64,
        "post_install_observation_sha256": "e" * 64,
        "cutover_snapshot_path": str(snapshot_path.resolve()),
        "cutover_snapshot_file_sha256": hashlib.sha256(
            snapshot_path.read_bytes()).hexdigest(),
        "cutover_snapshot_sha256": snap["snapshot_sha256"],
        "cutover_report_path": str(report_path.resolve()),
        "cutover_report_file_sha256": "8" * 64,
        "cutover_report_run_id": 42,
        "legacy_writer_container_id": issuance["Id"],
        "legacy_writer_image_digest": snap["writer_image_digest"],
        "legacy_writer_started_at": snap["writer_started_at"],
        "legacy_writer_generation": 0,
        "beta_generation": generation,
        "stop_container_ids": [auth["Id"], issuance["Id"]],
    }
    assert maintenance.verify_plan(plan, tmp_path / "stack.json", receipt_path,
                                   snapshot_path, report_path,
                                   require_stopped=False, runner=runner)["verified"]
    assert verified_heads == ["a" * 40]
    with pytest.raises(HostProbeError, match="allowed maintenance state"):
        maintenance.verify_plan(plan, tmp_path / "stack.json", receipt_path,
                                snapshot_path, report_path,
                                require_stopped=True, runner=runner)
    auth["State"].update({"Running": False, "Status": "exited"})
    issuance["State"].update({"Running": False, "Status": "exited"})
    result = maintenance.verify_plan(plan, tmp_path / "stack.json", receipt_path,
                                     snapshot_path, report_path,
                                     require_stopped=True, runner=runner)
    assert result["stopped_container_ids"] == [auth["Id"], issuance["Id"]]
    openbao["State"].update({"Running": False, "Status": "exited"})
    with pytest.raises(HostProbeError, match="Preserved beta openbao"):
        maintenance.verify_plan(plan, tmp_path / "stack.json", receipt_path,
                                snapshot_path, report_path,
                                require_stopped=True, runner=runner)
    openbao["State"].update({"Running": True, "Status": "running"})
    records["f" * 64] = record("unexpected", 15)
    with pytest.raises(HostProbeError, match="generation changed"):
        maintenance.verify_plan(plan, tmp_path / "stack.json", receipt_path,
                                snapshot_path, report_path,
                                require_stopped=True, runner=runner)
    records.pop("f" * 64)
    issuance["RestartCount"] = 1
    with pytest.raises(HostProbeError, match="Old Python writer generation changed"):
        maintenance.verify_plan(plan, tmp_path / "stack.json", receipt_path,
                                snapshot_path, report_path, require_stopped=True, runner=runner)
    issuance["RestartCount"] = 0
    snap["writer_generation"] = 1
    snap.pop("snapshot_sha256")
    snap["snapshot_sha256"] = hashlib.sha256(json.dumps(
        snap, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    snapshot_path.write_text(json.dumps(snap), encoding="utf-8")
    with pytest.raises(HostProbeError, match="Cutover snapshot differs"):
        maintenance.verify_plan(plan, tmp_path / "stack.json", receipt_path,
                                snapshot_path, report_path, require_stopped=True, runner=runner)
