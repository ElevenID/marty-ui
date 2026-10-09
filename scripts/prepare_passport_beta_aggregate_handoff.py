#!/usr/bin/env python3
"""Read-only handoff from fenced native SQL to the Rust beta deployment."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
from typing import Any, Callable

try:
    from .check_passport_beta_fence_authority import (
        PROTECTED_FILES, file_sha256, manifest_source, protected_file, protected_source,
    )
    from .prepare_passport_beta_db_maintenance import verify_plan
    from .prepare_passport_beta_native_migrations import (
        NativeMigrationError, prepare as native_prepare,
    )
    from .probe_passport_beta_host import HostProbeError, beta_psql, inspect, run
except ImportError:
    from check_passport_beta_fence_authority import (
        PROTECTED_FILES, file_sha256, manifest_source, protected_file, protected_source,
    )
    from prepare_passport_beta_db_maintenance import verify_plan
    from prepare_passport_beta_native_migrations import (
        NativeMigrationError, prepare as native_prepare,
    )
    from probe_passport_beta_host import HostProbeError, beta_psql, inspect, run


SHA256 = re.compile(r"[0-9a-f]{64}\Z")
UI_REPOSITORY = "ghcr.io/elevenid/marty-ui-oss/ui"
ROOT = Path(__file__).resolve().parents[1]
VERIFY = ROOT / "scripts/sql/passport-beta-fence-verify.sql"
TRANSITION_SQL = ROOT / "scripts/sql/passport-beta-rust-owner-transition.sql"
RUST_OWNER_VERIFY_SQL = ROOT / "scripts/sql/passport-beta-rust-owner-verify.sql"
DRAIN_SQL = ROOT / "scripts/sql/passport-beta-fence-drain.sql"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise HostProbeError(message)


def read_object(path: Path, schema: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise HostProbeError("Beta handoff receipt is unreadable") from exc
    require(isinstance(value, dict) and value.get("schema") == schema,
            "Beta handoff receipt schema is invalid")
    return value


def verify_fence(
    intent: dict[str, Any], runner: Callable[[list[str]], str],
) -> None:
    require(file_sha256(VERIFY) == intent.get("verify_sql_sha256"),
            "Protected beta fence verifier changed")
    container = str(intent.get("postgres_container_id"))
    system_id = str(intent.get("postgres_system_identifier"))
    database_oid = str(intent.get("database_oid"))
    epoch = str(intent.get("fence_epoch"))
    require(re.fullmatch(r"[0-9a-f]{64}", container) is not None
            and all(re.fullmatch(r"[0-9]+", item) is not None
                    for item in (system_id, database_oid, epoch)),
            "Beta fence verifier target is invalid")
    sql = (
        "SET marty.passport_beta_verified_project = 'elevenid-beta';\n"
        f"SET marty.passport_beta_expected_system_identifier = '{system_id}';\n"
        f"SET marty.passport_beta_expected_database_oid = '{database_oid}';\n"
        + VERIFY.read_text(encoding="utf-8")
    )
    raw = runner(["docker", "exec", container, "psql", "-X", "-U", "postgres",
                  "-d", "marty", "-qAt", "-v", "ON_ERROR_STOP=1", "-c", sql])
    try:
        observed = json.loads(raw)
    except ValueError as exc:
        raise HostProbeError("Beta fence verifier returned ambiguous evidence") from exc
    require(isinstance(observed, dict)
            and observed.get("schema") == "marty.passport-beta-fence-verification/v1"
            and observed.get("phase") == "fully_fenced"
            and str(observed.get("epoch")) == epoch,
            "Beta fence changed after native database gates")


def prepare(
    stack_manifest: Path, fence_receipt: Path, maintenance_receipt: Path,
    native_receipt: Path, runner: Callable[[list[str]], str] = run,
) -> dict[str, Any]:
    """Recheck the stopped generation and committed SQL before app login opens."""
    source_commit = protected_source(runner)
    for relative in PROTECTED_FILES:
        protected_file(relative, runner)
    signed = manifest_source(stack_manifest, source_commit, rust_only=True)
    intent_path = Path(str(maintenance_receipt) + ".intent.json")
    intent = read_object(intent_path, "marty.passport-beta-db-maintenance-plan/v1")
    docs = [item for item in intent.get("beta_generation", [])
            if isinstance(item, dict) and item.get("service") == "docs"]
    require(len(docs) == 1 and re.fullmatch(r"[0-9a-f]{64}",
            str(docs[0].get("container_id"))) is not None,
            "Exact beta docs container is absent from maintenance")
    docs_record = inspect(docs[0]["container_id"], runner)
    docs_config = docs_record.get("Config")
    docs_labels = docs_config.get("Labels") if isinstance(docs_config, dict) else None
    docs_image = docs_config.get("Image") if isinstance(docs_config, dict) else None
    require(docs_record.get("Id") == docs[0]["container_id"]
            and docs_record.get("Image") == docs[0].get("image_id")
            and isinstance(docs_labels, dict)
            and docs_labels.get("com.docker.compose.project") == "elevenid-beta"
            and docs_labels.get("com.docker.compose.service") == "docs"
            and re.fullmatch(r"sha256:[0-9a-f]{64}", str(docs_image)) is not None,
            "Preserved beta docs image is not immutable")
    snapshot_path = intent.get("cutover_snapshot_path")
    report_path = intent.get("cutover_report_path")
    require(isinstance(snapshot_path, str) and Path(snapshot_path).is_absolute(),
            "Beta cutover snapshot path is absent from maintenance intent")
    require(isinstance(report_path, str) and Path(report_path).is_absolute(),
            "Protected cutover report path is absent from maintenance intent")
    stopped = verify_plan(intent, stack_manifest, fence_receipt,
                          Path(snapshot_path), Path(report_path),
                          require_stopped=True, runner=runner)
    require(stopped.get("verified") is True
            and stopped.get("stopped_container_ids") == intent.get("stop_container_ids"),
            "Beta generation is not fully stopped")
    maintenance = read_object(maintenance_receipt,
                              "marty.passport-beta-db-maintenance-start/v1")
    native = read_object(native_receipt, "marty.passport-beta-native-db-gates/v1")
    plan, _ = native_prepare(stack_manifest, fence_receipt)
    require(maintenance.get("intent_sha256") == file_sha256(intent_path)
            and maintenance.get("source_commit") == source_commit
            and maintenance.get("postgres_container_id") == intent.get("postgres_container_id")
            and str(maintenance.get("fence_epoch")) == str(intent.get("fence_epoch"))
            and maintenance.get("stopped_container_ids") == intent.get("stop_container_ids")
            and all(maintenance.get(field) == intent.get(field) for field in (
                "cutover_snapshot_file_sha256", "cutover_snapshot_sha256",
                "cutover_report_file_sha256", "cutover_report_run_id",
                "legacy_writer_container_id", "legacy_writer_image_digest",
                "legacy_writer_started_at", "legacy_writer_generation",
            ))
            and maintenance.get("production_snapshot_sha256")
                == stopped.get("production_snapshot_sha256")
            and maintenance.get("production_attachments_sha256")
                == stopped.get("production_attachments_sha256"),
            "Beta maintenance receipt differs from the stopped target")
    require(native.get("source_commit") == source_commit
            and plan.get("source_commit") == source_commit
            and native.get("maintenance_receipt_sha256") == file_sha256(maintenance_receipt)
            and native.get("postgres_container_id") == plan.get("postgres_container_id")
            and native.get("postgres_system_identifier") == plan.get("postgres_system_identifier")
            and native.get("database_oid") == plan.get("database_oid")
            and str(native.get("fence_epoch")) == str(plan.get("fence_epoch"))
            and native.get("migration_image") == plan.get("migration_image")
            and native.get("migration_set_sha256") == plan.get("migration_set_sha256")
            and native.get("native_sql_sha256") == plan.get("sql_sha256")
            and native.get("production_snapshot_sha256")
                == stopped.get("production_snapshot_sha256")
            and native.get("stopped_container_ids") == intent.get("stop_container_ids")
            and native.get("app_login_enabled") is False,
            "Native database receipt differs from signed source or stopped target")
    container = str(plan["postgres_container_id"])
    epoch = str(plan["fence_epoch"])
    digest = str(plan["migration_set_sha256"])
    require(SHA256.fullmatch(digest) is not None,
            "Native migration digest is invalid")
    sql = (
        "SELECT (SELECT fence_epoch::text || '|' || source_commit || '|' || "
        "migration_set_sha256 FROM passport_cutover.native_migration_receipt "
        "WHERE singleton=true) || '|' || "
        "(SELECT rolcanlogin::text FROM pg_roles WHERE rolname='marty') || '|' || "
        "(SELECT rolcanlogin::text FROM pg_roles "
        "WHERE rolname='marty_beta_migrator')"
    )
    require(beta_psql(sql, runner, container)
            == f"{epoch}|{source_commit}|{digest}|false|false",
            "Committed native migrations or closed app login differ")
    verify_fence(intent, runner)
    require(signed["manifest_sha256"] == file_sha256(stack_manifest),
            "Signed stack manifest changed during beta handoff")
    return {
        "schema": "marty.passport-beta-aggregate-handoff/v1",
        "source_commit": source_commit,
        "stack_manifest_sha256": file_sha256(stack_manifest),
        "fence_receipt_sha256": file_sha256(fence_receipt),
        "cutover_snapshot_file_sha256": intent["cutover_snapshot_file_sha256"],
        "cutover_snapshot_sha256": intent["cutover_snapshot_sha256"],
        "cutover_report_file_sha256": intent["cutover_report_file_sha256"],
        "cutover_report_run_id": intent["cutover_report_run_id"],
        "legacy_writer_container_id": intent["legacy_writer_container_id"],
        "legacy_writer_image_digest": intent["legacy_writer_image_digest"],
        "legacy_writer_started_at": intent["legacy_writer_started_at"],
        "legacy_writer_generation": intent["legacy_writer_generation"],
        "maintenance_receipt_sha256": file_sha256(maintenance_receipt),
        "native_receipt_sha256": file_sha256(native_receipt),
        "postgres_container_id": container,
        "fence_epoch": epoch,
        "migration_set_sha256": digest,
        "enable_login_sql_sha256": plan["enable_login_sql_sha256"],
        "transition_sql_sha256": file_sha256(TRANSITION_SQL),
        "rust_owner_verify_sql_sha256": file_sha256(RUST_OWNER_VERIFY_SQL),
        "fence_verify_sql_sha256": file_sha256(VERIFY),
        "drain_sql_sha256": file_sha256(DRAIN_SQL),
        "production_snapshot_sha256": stopped["production_snapshot_sha256"],
        "production_attachments_sha256": stopped["production_attachments_sha256"],
        "stopped_container_ids": stopped["stopped_container_ids"],
        "release": signed["release"],
        "ui_image": f"{UI_REPOSITORY}@{signed['oci_digests'][UI_REPOSITORY]}",
        "services_image": signed["services_image"],
        "build_only_artifacts": signed["build_only_artifacts"],
        "docs_image": docs_image,
        "issuance_image": signed["services_image"],
        "migration_image": plan["migration_image"],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stack-manifest", required=True, type=Path)
    parser.add_argument("--fence-receipt", required=True, type=Path)
    parser.add_argument("--maintenance-receipt", required=True, type=Path)
    parser.add_argument("--native-receipt", required=True, type=Path)
    args = parser.parse_args()
    try:
        plan = prepare(args.stack_manifest, args.fence_receipt,
                       args.maintenance_receipt, args.native_receipt)
    except (HostProbeError, NativeMigrationError, OSError, ValueError, KeyError) as exc:
        raise SystemExit(f"Protected beta aggregate handoff is unavailable: {exc}") from exc
    print(json.dumps(plan, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
