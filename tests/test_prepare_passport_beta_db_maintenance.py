"""Maintenance planning must cover the whole fenced beta generation."""

from __future__ import annotations

import json

import pytest

from scripts import prepare_passport_beta_db_maintenance as maintenance
from scripts.probe_passport_beta_host import HostProbeError


def record(service: str, number: int, *, running: bool = True) -> dict:
    return {
        "Id": f"{number:x}" + "0" * 63, "Image": "sha256:" + "a" * 64,
        "Config": {"Labels": {
            "com.docker.compose.project": "elevenid-beta",
            "com.docker.compose.service": service,
        }},
        "State": {"Running": running, "Status": "running" if running else "exited",
                  "StartedAt": "2026-09-29T00:00:00Z"},
    }


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
        "production_snapshot_sha256": "f" * 64,
        "production_attachments_sha256": "0" * 64,
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
            "services": {item["service"]: item for item in generation},
        },
    }
    def runner(command):
        return "approved" if command[1] == "context" else "daemon"
    plan = maintenance.prepare(tmp_path / "stack.json", receipt_path, runner,
                               lambda _runner: observed)
    assert checked == list(maintenance.PROTECTED_FILES)
    assert plan["stop_container_ids"] == [service_id]
    assert plan["production_snapshot_sha256"] == "f" * 64
    assert plan["production_attachments_sha256"] == "0" * 64
    receipt["production_snapshot_sha256"] = "0" * 64
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    with pytest.raises(HostProbeError, match="production differs"):
        maintenance.prepare(tmp_path / "stack.json", receipt_path, runner,
                            lambda _runner: observed)


def test_resume_verifies_full_ids_and_requires_every_service_stopped(monkeypatch, tmp_path):
    postgres = record("postgres", 1)
    auth = record("auth", 2)
    openbao = record("openbao", 3)
    records = {item["Id"]: item for item in (postgres, auth, openbao)}
    receipt_path = tmp_path / "fence.json"
    receipt_path.write_text(json.dumps({
        "production_snapshot_sha256": "f" * 64,
        "production_attachments_sha256": "0" * 64,
        "post_install_observation_sha256": "e" * 64,
    }), encoding="utf-8")
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
        for item in (postgres, auth, openbao)
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
        "beta_generation": generation,
        "stop_container_ids": [auth["Id"]],
    }
    assert maintenance.verify_plan(plan, tmp_path / "stack.json", receipt_path,
                                   require_stopped=False, runner=runner)["verified"]
    with pytest.raises(HostProbeError, match="allowed maintenance state"):
        maintenance.verify_plan(plan, tmp_path / "stack.json", receipt_path,
                                require_stopped=True, runner=runner)
    auth["State"].update({"Running": False, "Status": "exited"})
    result = maintenance.verify_plan(plan, tmp_path / "stack.json", receipt_path,
                                     require_stopped=True, runner=runner)
    assert result["stopped_container_ids"] == [auth["Id"]]
    openbao["State"].update({"Running": False, "Status": "exited"})
    with pytest.raises(HostProbeError, match="Preserved beta openbao"):
        maintenance.verify_plan(plan, tmp_path / "stack.json", receipt_path,
                                require_stopped=True, runner=runner)
    openbao["State"].update({"Running": True, "Status": "running"})
    records["f" * 64] = record("unexpected", 15)
    with pytest.raises(HostProbeError, match="generation changed"):
        maintenance.verify_plan(plan, tmp_path / "stack.json", receipt_path,
                                require_stopped=True, runner=runner)
