"""The aggregate handoff must bind signed source, stopped beta, and native SQL."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts import prepare_passport_beta_aggregate_handoff as handoff


HEAD = "a" * 40
CONTAINER = "b" * 64
DIGEST = "c" * 64
SNAPSHOT = "d" * 64
ATTACHMENTS = "9" * 64
STOPPED = ["e" * 64]


def write(path: Path, value: dict) -> Path:
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    manifest = write(tmp_path / "stack-manifest.json", {"schema": "marty.stack/v1"})
    fence = write(tmp_path / "fence.json", {"schema": "fence"})
    maintenance = tmp_path / "maintenance.json"
    intent = write(tmp_path / "maintenance.json.intent.json", {
        "schema": "marty.passport-beta-db-maintenance-plan/v1",
        "postgres_container_id": CONTAINER, "fence_epoch": "7",
        "postgres_system_identifier": "100", "database_oid": "200",
        "verify_sql_sha256": handoff.file_sha256(handoff.VERIFY),
        "stop_container_ids": STOPPED,
    })
    write(maintenance, {
        "schema": "marty.passport-beta-db-maintenance-start/v1",
        "intent_sha256": handoff.file_sha256(intent),
        "source_commit": HEAD, "postgres_container_id": CONTAINER,
        "fence_epoch": "7", "production_snapshot_sha256": SNAPSHOT,
        "production_attachments_sha256": ATTACHMENTS,
        "stopped_container_ids": STOPPED,
    })
    native = write(tmp_path / "native.json", {
        "schema": "marty.passport-beta-native-db-gates/v1",
        "source_commit": HEAD,
        "maintenance_receipt_sha256": handoff.file_sha256(maintenance),
        "postgres_container_id": CONTAINER,
        "postgres_system_identifier": "100", "database_oid": "200",
        "fence_epoch": "7", "migration_image": "image@sha256:" + "f" * 64,
        "migration_set_sha256": DIGEST, "native_sql_sha256": "1" * 64,
        "production_snapshot_sha256": SNAPSHOT,
        "stopped_container_ids": STOPPED, "app_login_enabled": False,
    })
    monkeypatch.setattr(handoff, "protected_source", lambda _runner: HEAD)
    monkeypatch.setattr(handoff, "PROTECTED_FILES", ())
    monkeypatch.setattr(handoff, "manifest_source", lambda *_: {
        "release": "marty-ui@1.2.3", "services_image": "services@sha256:" + "2" * 64,
        "issuance_image": "issuance@sha256:" + "3" * 64,
        "manifest_sha256": handoff.file_sha256(manifest),
        "oci_digests": {handoff.UI_REPOSITORY: "sha256:" + "5" * 64},
    })
    monkeypatch.setattr(handoff, "verify_plan", lambda *args, **kwargs: {
        "verified": True, "stopped_container_ids": STOPPED,
        "production_snapshot_sha256": SNAPSHOT,
        "production_attachments_sha256": ATTACHMENTS,
    })
    monkeypatch.setattr(handoff, "native_prepare", lambda *_: ({
        "source_commit": HEAD,
        "postgres_container_id": CONTAINER,
        "postgres_system_identifier": "100", "database_oid": "200",
        "fence_epoch": "7", "migration_image": "image@sha256:" + "f" * 64,
        "migration_set_sha256": DIGEST, "sql_sha256": "1" * 64,
        "enable_login_sql_sha256": "4" * 64,
    }, b"native SQL"))
    monkeypatch.setattr(handoff, "beta_psql", lambda *_: f"7|{HEAD}|{DIGEST}|false|false")
    def runner(command):
        if "-qAt" in command:
            return json.dumps({"schema": "marty.passport-beta-fence-verification/v1",
                               "phase": "fully_fenced", "epoch": 7})
        return ""
    return (manifest, fence, maintenance, native), runner


def test_handoff_requires_stopped_signed_native_state(tmp_path, monkeypatch):
    paths, runner = fixture(tmp_path, monkeypatch)
    plan = handoff.prepare(*paths, runner=runner)
    assert plan["schema"] == "marty.passport-beta-aggregate-handoff/v1"
    assert plan["source_commit"] == HEAD
    assert plan["stopped_container_ids"] == STOPPED
    assert plan["native_receipt_sha256"] == handoff.file_sha256(paths[-1])
    assert plan["services_image"].startswith("services@sha256:")
    assert plan["ui_image"] == handoff.UI_REPOSITORY + "@sha256:" + "5" * 64


def test_handoff_rejects_changed_native_receipt(tmp_path, monkeypatch):
    paths, runner = fixture(tmp_path, monkeypatch)
    receipt = json.loads(paths[-1].read_text(encoding="utf-8"))
    receipt["app_login_enabled"] = True
    write(paths[-1], receipt)
    with pytest.raises(handoff.HostProbeError, match="Native database receipt differs"):
        handoff.prepare(*paths, runner=runner)


def test_handoff_rejects_reopened_database_login(tmp_path, monkeypatch):
    paths, runner = fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(handoff, "beta_psql", lambda *_: f"7|{HEAD}|{DIGEST}|true|false")
    with pytest.raises(handoff.HostProbeError, match="closed app login differ"):
        handoff.prepare(*paths, runner=runner)


def test_handoff_rejects_changed_fence(tmp_path, monkeypatch):
    paths, _ = fixture(tmp_path, monkeypatch)
    def changed_fence(command):
        if "-qAt" in command:
            return json.dumps({"schema": "marty.passport-beta-fence-verification/v1",
                               "phase": "fully_fenced", "epoch": 8})
        return ""
    with pytest.raises(handoff.HostProbeError, match="fence changed"):
        handoff.prepare(*paths, runner=changed_fence)
