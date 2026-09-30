"""Acceptance must bind to the exact signed aggregate beta generation."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from scripts.collect_passport_beta_acceptance import (
    EvidenceError, SERVICES, collect, production_attachment_commitment,
    production_snapshot_commitment,
)
from scripts import collect_passport_beta_aggregate_acceptance as aggregate
from scripts.prepare_passport_beta_aggregate_compose import SIGNED_APPLICATIONS, INGRESS


COMMIT = "a" * 40
SERVICES_DIGEST = "sha256:" + "b" * 64
UI_DIGEST = "sha256:" + "c" * 64
SERVICES_IMAGE = "ghcr.io/elevenid/marty-ui-oss/services@" + SERVICES_DIGEST
UI_IMAGE = "ghcr.io/elevenid/marty-ui-oss/ui@" + UI_DIGEST
NETWORK = "elevenid-beta-network"
ALL_APPS = set(SIGNED_APPLICATIONS) | {"issuance"}


def listed(live, project):
    return [key for key, value in live.items() if value["Config"]["Labels"].get(
        "com.docker.compose.project") == project]


def write(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fixture(tmp_path: Path, monkeypatch):
    (tmp_path / "stack-manifest.json").write_text("{}\n", encoding="utf-8")
    (tmp_path / "SHA256SUMS").write_text("signed fixture\n", encoding="utf-8")
    signed = {
        "release": "marty-ui@1.1.999", "manifest_sha256": digest(tmp_path / "stack-manifest.json"),
        "services_image": SERVICES_IMAGE,
        "issuance_image": "ghcr.io/elevenid/marty-credentials/issuance@sha256:" + "d" * 64,
        "oci_digests": {"ghcr.io/elevenid/marty-ui-oss/ui": UI_DIGEST,
                        "ghcr.io/elevenid/marty-ui-oss/services": SERVICES_DIGEST},
    }
    seen = []
    def manifest_source(path, source, attest, attest_issuance):
        seen.append((path, source, attest("probe", {}, source)))
        return signed
    monkeypatch.setattr(aggregate, "manifest_source", manifest_source)
    postgres_id = format(len(ALL_APPS) + 1, "x").rjust(64, "0")
    prefix = tmp_path / "aggregate-deployment.json"
    fence_path = Path(str(prefix) + ".fence-receipt.json")
    maintenance_path = Path(str(prefix) + ".maintenance-receipt.json")
    intent_path = Path(str(prefix) + ".maintenance-intent.json")
    native_path = Path(str(prefix) + ".native-receipt.json")
    common = {"source_commit": COMMIT, "fence_epoch": "7",
              "postgres_container_id": postgres_id,
              "postgres_system_identifier": "11", "database_oid": "22"}
    write(fence_path, {"schema": "marty.passport-beta-fence-installation/v1",
                       **common, "production_snapshot_sha256": "f" * 64,
                       "production_attachments_sha256": "6" * 64})
    stopped = ["a" * 64]
    write(intent_path, {"schema": "marty.passport-beta-db-maintenance-plan/v1",
                        **common, "stop_container_ids": stopped,
                        "fence_receipt_sha256": digest(fence_path),
                        "production_snapshot_sha256": "f" * 64,
                        "production_attachments_sha256": "6" * 64})
    write(maintenance_path, {
        "schema": "marty.passport-beta-db-maintenance-start/v1", **common,
        "stopped_container_ids": stopped, "intent_sha256": digest(intent_path),
        "production_snapshot_sha256": "f" * 64,
        "production_attachments_sha256": "6" * 64,
    })
    write(native_path, {
        "schema": "marty.passport-beta-native-db-gates/v1", **common,
        "maintenance_receipt_sha256": digest(maintenance_path),
        "stopped_container_ids": stopped, "migration_set_sha256": "5" * 64,
        "production_snapshot_sha256": "f" * 64, "app_login_enabled": False,
    })
    plan = {
        "schema": "marty.passport-beta-aggregate-compose-plan/v1",
        "source_commit": COMMIT, "beta_origin": "https://beta.elevenidllc.com",
        "stack_manifest_sha256": signed["manifest_sha256"],
        "native_receipt_sha256": "e" * 64,
        "fence_receipt_sha256": digest(fence_path),
        "maintenance_receipt_sha256": digest(maintenance_path),
        "postgres_container_id": postgres_id,
        "postgres_system_identifier": "11", "database_oid": "22",
        "fence_epoch": "7", "migration_set_sha256": "5" * 64,
        "production_snapshot_sha256": "f" * 64,
        "production_attachments_sha256": "6" * 64,
        "target_services": sorted(ALL_APPS),
        "expected_networks_by_service": {
            name: [NETWORK] for name in (*sorted(ALL_APPS), "postgres")},
        "recreate_applications": sorted(ALL_APPS - INGRESS),
        "recreate_ingress_last": sorted(ALL_APPS & INGRESS),
        "service_config_hashes": {name: "1" * 64 for name in ALL_APPS},
        "services_image": SERVICES_IMAGE,
        "issuance_image": signed["issuance_image"],
        "ui_image": UI_IMAGE, "ui_config_hash": "2" * 64,
    }
    plan_path = tmp_path / "aggregate-deployment.json.plan.json"
    plan["native_receipt_sha256"] = digest(native_path)
    write(plan_path, plan)
    identities = {}
    live = {}
    for index, name in enumerate((*sorted(ALL_APPS), "postgres"), 1):
        container_id = format(index, "x").rjust(64, "0")
        image = ("postgres:15" if name == "postgres" else
                 signed["issuance_image"] if name == "issuance" else SERVICES_IMAGE)
        identity = {"container_id": container_id,
                    "image_id": "sha256:" + "3" * 64,
                    "configured_image": image,
                    "started_at": "2026-09-29T00:00:00Z",
                    "config_hash": "1" * 64 if name != "postgres" else None,
                    "networks": [NETWORK]}
        identities[name] = identity
        live[container_id] = {
            "Id": container_id, "Image": identity["image_id"],
            "Config": {"Image": image, "Labels": {
                "com.docker.compose.project": "elevenid-beta",
                "com.docker.compose.service": name,
                "com.docker.compose.config-hash": identity["config_hash"],
            }, "Env": ["SECRET_TOKEN=protected"]},
            "State": {"Running": True, "Status": "running",
                      "StartedAt": identity["started_at"]},
            "NetworkSettings": {"Networks": {NETWORK: {}}},
        }
    ui_id = "9" * 64
    ui_identity = {"container_id": ui_id,
                   "image_id": "sha256:" + "4" * 64,
                   "configured_image": UI_IMAGE,
                   "started_at": "2026-09-29T00:00:00Z",
                   "config_hash": "2" * 64,
                   "networks": [NETWORK]}
    live[ui_id] = {
        "Id": ui_id, "Image": ui_identity["image_id"],
        "Config": {"Image": UI_IMAGE, "Labels": {
            "com.docker.compose.project": "elevenid-beta-ui",
            "com.docker.compose.service": "ui-prod",
            "com.docker.compose.config-hash": ui_identity["config_hash"],
        }},
        "State": {"Running": True, "Status": "running",
                  "StartedAt": ui_identity["started_at"]},
        "NetworkSettings": {"Networks": {NETWORK: {}}},
    }
    receipt = {
        "schema": "marty.passport-beta-aggregate-deployment/v1",
        "beta_origin": "https://beta.elevenidllc.com",
        "source_commit": COMMIT, "plan_sha256": digest(plan_path),
        "native_receipt_sha256": plan["native_receipt_sha256"],
        "production_snapshot_sha256": plan["production_snapshot_sha256"],
        "beta_services": sorted(identities), "beta_runtime": identities,
        "ui_container_id": ui_id, "ui_runtime": ui_identity,
        "acceptance_pending": True,
    }
    write(tmp_path / "aggregate-deployment.json", receipt)
    def probe(key):
        if key is None:
            return 401, None
        return 200, {"supported": True, "encrypted_artifact_store": True,
                     "bureau_configured": True, "blockers": [],
                     "signer": {"configured": True, "mode": "MANAGED_ISSUER_PROFILE",
                                "blockers": []}}
    return plan, receipt, identities, live, probe, seen


def test_collects_exact_aggregate_generation_without_old_manifests(tmp_path, monkeypatch):
    plan, receipt, identities, live, probe, seen = fixture(tmp_path, monkeypatch)
    report = collect(tmp_path, api_key="k" * 32, inspect=live.__getitem__,
                     probe=probe, attest=lambda *_: True,
                     list_ids=lambda project: listed(live, project),
                     probe_native=lambda *_: None)
    assert report["release"]["source_commit"] == COMMIT
    assert report["release"]["signed_manifest_verified"] is True
    assert report["deployment"]["aggregate_deployment_receipt_sha256"] == digest(
        tmp_path / "aggregate-deployment.json")
    assert report["deployment"]["aggregate_plan_sha256"] == receipt["plan_sha256"]
    assert report["deployment"]["provider_mode"] == "simulator"
    assert report["deployment"]["production_snapshot_commitment"] == (
        production_snapshot_commitment("k" * 32, "f" * 64))
    assert report["deployment"]["production_attachment_commitment"] == (
        production_attachment_commitment("k" * 32, "6" * 64))
    assert "production_snapshot_sha256" not in json.dumps(report)
    assert report["runtime_images"]["flow"]["container_id"] == identities["flow"]["container_id"]
    assert set(report["runtime_images"]) == set(SERVICES)
    assert "SECRET_TOKEN" not in json.dumps(report)
    assert seen == [(tmp_path / "stack-manifest.json", COMMIT, True)]


def test_rejects_recreated_service_after_aggregate_receipt(tmp_path, monkeypatch):
    _, _, identities, live, probe, _ = fixture(tmp_path, monkeypatch)
    live[identities["flow"]["container_id"]]["Id"] = "8" * 64
    with pytest.raises(EvidenceError, match="live project inventory differs"):
        collect(tmp_path, api_key="k" * 32, inspect=live.__getitem__,
                probe=probe, attest=lambda *_: True,
                list_ids=lambda project: listed(live, project),
                probe_native=lambda *_: None)


def test_rejects_receipt_or_plan_digest_drift(tmp_path, monkeypatch):
    plan, _, _, live, probe, _ = fixture(tmp_path, monkeypatch)
    plan["source_commit"] = "b" * 40
    write(tmp_path / "aggregate-deployment.json.plan.json", plan)
    with pytest.raises(EvidenceError, match="receipt, plan or source differs"):
        collect(tmp_path, api_key="k" * 32, inspect=live.__getitem__,
                probe=probe, attest=lambda *_: True,
                list_ids=lambda project: listed(live, project),
                probe_native=lambda *_: None)


def test_rejects_extra_live_beta_container(tmp_path, monkeypatch):
    _, _, _, live, probe, _ = fixture(tmp_path, monkeypatch)
    extra = next(iter(live.values())).copy()
    extra["Id"] = "8" * 64
    extra["Config"] = {"Labels": {"com.docker.compose.project": "elevenid-beta",
                                  "com.docker.compose.service": "passport-provider-ingress"}}
    live[extra["Id"]] = extra
    with pytest.raises(EvidenceError, match="live project inventory differs"):
        collect(tmp_path, api_key="k" * 32, inspect=live.__getitem__,
                probe=probe, attest=lambda *_: True,
                list_ids=lambda project: listed(live, project),
                probe_native=lambda *_: None)


def test_rejects_plan_that_omits_signed_applications(tmp_path, monkeypatch):
    plan, receipt, _, live, probe, _ = fixture(tmp_path, monkeypatch)
    plan["recreate_applications"].remove("auth")
    write(tmp_path / "aggregate-deployment.json.plan.json", plan)
    receipt["plan_sha256"] = digest(tmp_path / "aggregate-deployment.json.plan.json")
    write(tmp_path / "aggregate-deployment.json", receipt)
    with pytest.raises(EvidenceError, match="signed application set is incomplete"):
        collect(tmp_path, api_key="k" * 32, inspect=live.__getitem__,
                probe=probe, attest=lambda *_: True,
                list_ids=lambda project: listed(live, project),
                probe_native=lambda *_: None)


def test_rejects_missing_native_receipt_even_with_matching_plan(tmp_path, monkeypatch):
    _, _, _, live, probe, _ = fixture(tmp_path, monkeypatch)
    (tmp_path / "aggregate-deployment.json.native-receipt.json").unlink()
    with pytest.raises(EvidenceError, match="Invalid evidence file"):
        collect(tmp_path, api_key="k" * 32, inspect=live.__getitem__,
                probe=probe, attest=lambda *_: True,
                list_ids=lambda project: listed(live, project),
                probe_native=lambda *_: None)


def test_rejects_live_native_marker_drift(tmp_path, monkeypatch):
    _, _, _, live, probe, _ = fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(aggregate, "beta_psql", lambda *_: "wrong marker")
    with pytest.raises(EvidenceError, match="native migration marker"):
        aggregate.collect_aggregate(
            tmp_path, api_key="k" * 32, inspect=live.__getitem__,
            probe=probe, attest=lambda *_: True,
            list_ids=lambda project: listed(live, project))
