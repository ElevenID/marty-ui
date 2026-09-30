#!/usr/bin/env python3
"""Read-only protected-source plan for the fenced beta database window."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Callable

try:
    from .check_passport_beta_fence_authority import (
        PROTECTED_FILES, file_sha256, manifest_source, protected_file,
        protected_source,
    )
    from .prepare_passport_beta_native_migrations import (
        NativeMigrationError, checked_receipt,
    )
    from .probe_passport_beta_fence_target import REQUIRED_SERVICES, observe_fenced
    from .probe_passport_beta_cutover_snapshot import (
        ZERO_COUNT_WATERMARK_SQL, validate_direct_probe,
    )
    from .verify_passport_beta_protected_cutover import verify as verify_cutover_report
    from .probe_passport_beta_host import (
        BETA_PROJECT, HostProbeError, beta_psql, ids, inspect,
        production_attachment_sha256, production_snapshot, run,
    )
except ImportError:
    from check_passport_beta_fence_authority import (
        PROTECTED_FILES, file_sha256, manifest_source, protected_file,
        protected_source,
    )
    from prepare_passport_beta_native_migrations import (
        NativeMigrationError, checked_receipt,
    )
    from probe_passport_beta_fence_target import REQUIRED_SERVICES, observe_fenced
    from probe_passport_beta_cutover_snapshot import (
        ZERO_COUNT_WATERMARK_SQL, validate_direct_probe,
    )
    from verify_passport_beta_protected_cutover import verify as verify_cutover_report
    from probe_passport_beta_host import (
        BETA_PROJECT, HostProbeError, beta_psql, ids, inspect,
        production_attachment_sha256, production_snapshot, run,
    )


ROOT = Path(__file__).resolve().parents[1]
START = "scripts/sql/passport-beta-db-maintenance-start.sql"
VERIFY = "scripts/sql/passport-beta-fence-verify.sql"
DOCKER_ID = re.compile(r"[0-9a-f]{64}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
IMAGE_DIGEST = re.compile(r".+@(sha256:[0-9a-f]{64})\Z")
PRESERVED_SERVICES = frozenset({"postgres", "openbao"})


def require(condition: bool, message: str) -> None:
    if not condition:
        raise HostProbeError(message)


def checked_snapshot(path: Path, receipt: dict[str, Any]) -> tuple[dict[str, Any], str]:
    """Bind observed continuity bytes; a protected producer must attest them."""
    try:
        snapshot_bytes = path.read_bytes()
        raw = json.loads(snapshot_bytes)
    except (OSError, ValueError) as exc:
        raise HostProbeError("Beta cutover snapshot is unreadable") from exc
    require(isinstance(raw, dict)
            and raw.get("schema") == "marty.passport-beta-cutover-snapshot/v1"
            and raw.get("status") == "observed"
            and raw.get("installation_provenance") == "local_host_continuity_only"
            and SHA256.fullmatch(str(raw.get("snapshot_sha256"))) is not None
            and raw["snapshot_sha256"] == hashlib.sha256(json.dumps(
                {key: value for key, value in raw.items() if key != "snapshot_sha256"},
                sort_keys=True, separators=(",", ":"),
            ).encode()).hexdigest()
            and raw.get("installation_receipt_sha256") == hashlib.sha256(
                json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            and raw.get("counts") == {
                "total_job_count": 0, "nonterminal_job_count": 0,
                "legacy_or_unknown_artifact_count": 0,
                "unreadable_artifact_count": 0,
                "active_passport_flow_count": 0,
            }
            and type(raw.get("observation_watermark")) is int
            and isinstance(raw.get("direct_database_probe"), dict)
            and type(raw["direct_database_probe"].get("observation_watermark")) is int
            and raw["observation_watermark"]
                > raw["direct_database_probe"]["observation_watermark"],
            "Beta cutover snapshot or fence receipt differs")
    return raw, hashlib.sha256(snapshot_bytes).hexdigest()


def running_beta_generation(
    postgres_id: str, runner: Callable[[list[str]], str] = run,
) -> list[dict[str, str]]:
    """Include every running Compose service, not only passport or known DB users."""
    result = []
    seen_ids: set[str] = set()
    seen_services: set[str] = set()
    for container_id in ids(BETA_PROJECT, runner):
        record = inspect(container_id, runner)
        config = record.get("Config")
        state = record.get("State")
        labels = config.get("Labels") if isinstance(config, dict) else None
        service = labels.get("com.docker.compose.service") if isinstance(labels, dict) else None
        full_id = record.get("Id")
        if (not isinstance(labels, dict)
                or labels.get("com.docker.compose.project") != BETA_PROJECT
                or not isinstance(service, str) or not service
                or not isinstance(full_id, str) or DOCKER_ID.fullmatch(full_id) is None
                or not isinstance(state, dict)
                or state.get("Running") is not True or state.get("Status") != "running"
                or not isinstance(record.get("Image"), str)
                or not isinstance(state.get("StartedAt"), str)
                or full_id in seen_ids or service in seen_services):
            raise HostProbeError("Beta Compose service generation is ambiguous or stopped")
        seen_ids.add(full_id)
        seen_services.add(service)
        result.append({
            "service": service, "container_id": full_id,
            "image_id": record["Image"], "started_at": state["StartedAt"],
        })
    require(set(REQUIRED_SERVICES).issubset(seen_services),
            "Required fenced beta services are absent")
    require(sum(item["container_id"] == postgres_id and item["service"] == "postgres"
                for item in result) == 1,
            "Fenced PostgreSQL is not the sole beta database container")
    require("openbao" in seen_services,
            "Fenced beta OpenBao is absent from the preserved generation")
    return sorted(result, key=lambda item: item["service"])


def prepare(
    manifest_path: Path, receipt_path: Path, snapshot_path: Path,
    report_path: Path,
    runner: Callable[[list[str]], str] = run,
    observer: Callable[[Callable[[list[str]], str]], dict[str, Any]] = observe_fenced,
) -> dict[str, Any]:
    head = protected_source(runner)
    for relative in PROTECTED_FILES:
        protected_file(relative, runner)
    source = manifest_source(manifest_path, head)
    receipt_target = checked_receipt(receipt_path, head)
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise HostProbeError("Fenced beta receipt is unreadable") from exc
    require(isinstance(receipt, dict), "Fenced beta receipt is invalid")
    observed = observer(runner)
    beta = observed.get("beta")
    docker = observed.get("docker")
    production = observed.get("production")
    require(observed.get("schema") == "marty.passport-beta-fence-postinstall-target/v1"
            and isinstance(beta, dict) and isinstance(docker, dict)
            and isinstance(production, dict),
            "Fenced beta observation is invalid")
    services = beta.get("services")
    require(isinstance(services, dict), "Fenced beta service inventory is invalid")
    postgres = services.get("postgres")
    require(isinstance(postgres, dict)
            and postgres.get("container_id") == receipt_target["container_id"]
            and beta.get("postgres_system_identifier") == receipt_target["system_id"]
            and beta.get("database_oid") == receipt_target["database_oid"]
            and observed.get("observation_sha256")
                == receipt.get("post_install_observation_sha256")
            and production.get("sha256")
                == receipt.get("production_snapshot_sha256")
            and observed.get("production_attachments_sha256")
                == receipt.get("production_attachments_sha256")
            and production_attachment_sha256(runner)
                == receipt.get("production_attachments_sha256")
            and SHA256.fullmatch(str(production.get("sha256"))) is not None,
            "Fenced beta or production differs from installation receipt")
    generation = running_beta_generation(receipt_target["container_id"], runner)
    by_service = {item["service"]: item for item in generation}
    for service, expected in services.items():
        require(isinstance(expected, dict),
                "Fenced beta service inventory is invalid")
        require(service in by_service
                and by_service[service]["container_id"] == expected["container_id"]
                and by_service[service]["image_id"] == expected["image_id"]
                and by_service[service]["started_at"] == expected["started_at"],
                "Fenced beta service changed during full generation inventory")
    require(runner(["docker", "context", "show"]) == docker.get("context")
            and runner(["docker", "info", "--format", "{{.ID}}"])
                == docker.get("daemon_id"),
            "Docker context changed during maintenance planning")
    snapshot, snapshot_file_sha256 = checked_snapshot(snapshot_path, receipt)
    report = verify_cutover_report(
        report_path, source_commit=head,
        deletion_head=receipt.get("credentials_deletion_head", ""),
        snapshot=snapshot, snapshot_file_sha256=snapshot_file_sha256,
        receipt=receipt,
    )
    database_uid = f"postgresql:{receipt_target['system_id']}:{receipt_target['database_oid']}"
    validate_direct_probe(snapshot["fence_first_probe"],
                          postgres=receipt_target["container_id"],
                          database_uid=database_uid,
                          epoch=int(receipt_target["fence_epoch"]), docker=docker)
    validate_direct_probe(snapshot["direct_database_probe"],
                          postgres=receipt_target["container_id"],
                          database_uid=database_uid,
                          epoch=int(receipt_target["fence_epoch"]), docker=docker)
    writer = services.get("issuance")
    live_writer = inspect(writer["container_id"], runner) if isinstance(writer, dict) else {}
    live_config = live_writer.get("Config")
    live_state = live_writer.get("State")
    live_labels = live_config.get("Labels") if isinstance(live_config, dict) else None
    live_image = IMAGE_DIGEST.fullmatch(str(live_config.get("Image"))) \
        if isinstance(live_config, dict) else None
    require(isinstance(writer, dict)
            and snapshot.get("database_uid")
                == database_uid
            and snapshot.get("beta_cluster_uid") == f"docker:{docker['daemon_id']}"
            and snapshot.get("fence_epoch") == int(receipt_target["fence_epoch"])
            and snapshot.get("fence_verification_sha256")
                == hashlib.sha256(json.dumps(receipt.get("fence"), sort_keys=True,
                                             separators=(",", ":")).encode()).hexdigest()
            and snapshot.get("fence_first_probe")
                == receipt.get("direct_database_probe")
            and snapshot.get("beta_inventory_attestation_sha256")
                == observed["observation_sha256"]
            and snapshot.get("production_snapshot_sha256") == production["sha256"]
            and snapshot.get("production_attachments_sha256")
                == receipt["production_attachments_sha256"]
            and snapshot.get("writer_container_id") == writer.get("container_id")
            and snapshot.get("writer_deployment_uid")
                == f"elevenid-beta:issuance:{writer.get('container_id')}"
            and snapshot.get("writer_started_at") == writer.get("started_at")
            and snapshot.get("writer_generation") == writer.get("restart_count")
            and type(snapshot.get("writer_generation")) is int
            and IMAGE_DIGEST.fullmatch(str(writer.get("configured_image"))) is not None
            and snapshot.get("writer_image_digest")
                == IMAGE_DIGEST.fullmatch(writer["configured_image"]).group(1)
            and live_writer.get("Id") == writer["container_id"]
            and live_writer.get("Image") == writer.get("image_id")
            and isinstance(live_labels, dict)
            and live_labels.get("com.docker.compose.project") == BETA_PROJECT
            and live_labels.get("com.docker.compose.service") == "issuance"
            and isinstance(live_state, dict)
            and live_state.get("Running") is True
            and live_state.get("Status") == "running"
            and live_state.get("StartedAt") == writer["started_at"]
            and live_writer.get("RestartCount") == writer["restart_count"]
            and live_image is not None
            and live_image.group(1) == snapshot["writer_image_digest"]
            and any(item["service"] == "issuance"
                    and item["container_id"] == writer["container_id"]
                    and item["started_at"] == writer["started_at"]
                    for item in generation),
            "Cutover snapshot differs from the live fenced Python writer")
    count_watermark = beta_psql(
        ZERO_COUNT_WATERMARK_SQL, runner, receipt_target["container_id"],
    ).split("|", 2)
    require(len(count_watermark) == 3 and count_watermark[0] == "0"
            and count_watermark[1].isdecimal()
            and int(count_watermark[1]) > snapshot["observation_watermark"],
            "Passport jobs appeared or the protected cutover snapshot is stale")
    return {
        "schema": "marty.passport-beta-db-maintenance-plan/v1",
        "source_commit": head,
        "release": source["release"],
        "stack_manifest_sha256": source["manifest_sha256"],
        "fence_receipt_sha256": file_sha256(receipt_path),
        "start_sql_sha256": file_sha256(ROOT / START),
        "verify_sql_sha256": file_sha256(ROOT / VERIFY),
        "docker": docker,
        "postgres_container_id": receipt_target["container_id"],
        "postgres_system_identifier": receipt_target["system_id"],
        "database_oid": receipt_target["database_oid"],
        "fence_epoch": receipt_target["fence_epoch"],
        "production_snapshot_sha256": production["sha256"],
        "production_attachments_sha256": receipt["production_attachments_sha256"],
        "post_install_observation_sha256": observed["observation_sha256"],
        "cutover_snapshot_path": str(snapshot_path.resolve(strict=True)),
        "cutover_snapshot_file_sha256": snapshot_file_sha256,
        "cutover_snapshot_sha256": snapshot["snapshot_sha256"],
        "cutover_report_path": str(report_path.resolve(strict=True)),
        "cutover_report_file_sha256": report["cutover_report_file_sha256"],
        "cutover_report_run_id": report["cutover_report_run_id"],
        "legacy_writer_container_id": writer["container_id"],
        "legacy_writer_image_digest": snapshot["writer_image_digest"],
        "legacy_writer_started_at": writer["started_at"],
        "legacy_writer_generation": writer["restart_count"],
        "beta_generation": generation,
        "stop_container_ids": [item["container_id"] for item in generation
                               if item["service"] not in PRESERVED_SERVICES],
    }


def verify_plan(
    plan: dict[str, Any], manifest_path: Path, receipt_path: Path,
    snapshot_path: Path, report_path: Path,
    *, require_stopped: bool,
    runner: Callable[[list[str]], str] = run,
) -> dict[str, Any]:
    """Recheck durable intent after stopping services or a supervised retry."""
    require(isinstance(plan, dict)
            and plan.get("schema") == "marty.passport-beta-db-maintenance-plan/v1",
            "Maintenance intent is invalid")
    head = protected_source(runner)
    for relative in PROTECTED_FILES:
        protected_file(relative, runner)
    source = manifest_source(manifest_path, head)
    receipt = checked_receipt(receipt_path, head)
    receipt_raw = json.loads(receipt_path.read_text(encoding="utf-8"))
    require(plan.get("source_commit") == head
            and plan.get("release") == source["release"]
            and plan.get("stack_manifest_sha256") == source["manifest_sha256"]
            and plan.get("fence_receipt_sha256") == file_sha256(receipt_path)
            and plan.get("start_sql_sha256") == file_sha256(ROOT / START)
            and plan.get("verify_sql_sha256") == file_sha256(ROOT / VERIFY)
            and plan.get("postgres_container_id") == receipt["container_id"]
            and plan.get("postgres_system_identifier") == receipt["system_id"]
            and plan.get("database_oid") == receipt["database_oid"]
            and plan.get("fence_epoch") == receipt["fence_epoch"],
            "Maintenance intent differs from protected source or fence")
    require(isinstance(receipt_raw, dict)
            and plan.get("production_snapshot_sha256")
                == receipt_raw.get("production_snapshot_sha256")
            and plan.get("production_attachments_sha256")
                == receipt_raw.get("production_attachments_sha256")
            and plan.get("post_install_observation_sha256")
                == receipt_raw.get("post_install_observation_sha256"),
            "Maintenance intent differs from fence installation receipt")
    snapshot, snapshot_file_sha256 = checked_snapshot(snapshot_path, receipt_raw)
    report = verify_cutover_report(
        report_path, source_commit=head,
        deletion_head=receipt_raw.get("credentials_deletion_head", ""),
        snapshot=snapshot, snapshot_file_sha256=snapshot_file_sha256,
        receipt=receipt_raw,
    )
    docker = plan.get("docker")
    require(isinstance(docker, dict), "Maintenance Docker identity is invalid")
    database_uid = f"postgresql:{receipt['system_id']}:{receipt['database_oid']}"
    validate_direct_probe(snapshot["fence_first_probe"],
                          postgres=receipt["container_id"],
                          database_uid=database_uid,
                          epoch=int(receipt["fence_epoch"]), docker=docker)
    validate_direct_probe(snapshot["direct_database_probe"],
                          postgres=receipt["container_id"],
                          database_uid=database_uid,
                          epoch=int(receipt["fence_epoch"]), docker=docker)
    require(plan.get("cutover_snapshot_path") == str(snapshot_path.resolve(strict=True))
            and plan.get("cutover_snapshot_file_sha256") == snapshot_file_sha256
            and plan.get("cutover_snapshot_sha256") == snapshot["snapshot_sha256"]
            and plan.get("cutover_report_path") == str(report_path.resolve(strict=True))
            and plan.get("cutover_report_file_sha256")
                == report["cutover_report_file_sha256"]
            and plan.get("cutover_report_run_id") == report["cutover_report_run_id"]
            and plan.get("legacy_writer_container_id")
                == snapshot.get("writer_container_id")
            and plan.get("legacy_writer_image_digest")
                == snapshot.get("writer_image_digest")
            and plan.get("legacy_writer_started_at")
                == snapshot.get("writer_started_at")
            and plan.get("legacy_writer_generation")
                == snapshot.get("writer_generation")
            and snapshot.get("database_uid")
                == database_uid
            and snapshot.get("beta_cluster_uid") == f"docker:{docker['daemon_id']}"
            and snapshot.get("writer_deployment_uid")
                == f"elevenid-beta:issuance:{plan.get('legacy_writer_container_id')}"
            and snapshot.get("fence_epoch") == int(receipt["fence_epoch"])
            and snapshot.get("fence_verification_sha256")
                == hashlib.sha256(json.dumps(receipt_raw.get("fence"), sort_keys=True,
                                             separators=(",", ":")).encode()).hexdigest()
            and snapshot.get("fence_first_probe")
                == receipt_raw.get("direct_database_probe")
            and snapshot.get("beta_inventory_attestation_sha256")
                == plan.get("post_install_observation_sha256")
            and snapshot.get("production_snapshot_sha256")
                == plan.get("production_snapshot_sha256")
            and snapshot.get("production_attachments_sha256")
                == plan.get("production_attachments_sha256"),
            "Cutover snapshot differs from maintenance intent")
    docker = plan.get("docker")
    require(isinstance(docker, dict)
            and runner(["docker", "context", "show"]) == docker.get("context")
            and runner(["docker", "info", "--format", "{{.ID}}"])
                == docker.get("daemon_id"),
            "Maintenance Docker context changed")
    production = production_snapshot(runner)
    require(production.get("sha256") == plan.get("production_snapshot_sha256"),
            "Production changed during beta maintenance")
    require(production_attachment_sha256(runner)
            == plan.get("production_attachments_sha256"),
            "Production network or ports changed during beta maintenance")
    generation = plan.get("beta_generation")
    require(isinstance(generation, list) and generation,
            "Maintenance beta generation is invalid")
    planned: dict[str, dict[str, str]] = {}
    for item in generation:
        require(isinstance(item, dict)
                and isinstance(item.get("container_id"), str)
                and DOCKER_ID.fullmatch(item["container_id"]) is not None
                and isinstance(item.get("service"), str)
                and item["container_id"] not in planned,
                "Maintenance beta generation is invalid")
        planned[item["container_id"]] = item
    current_ids = [inspect(container_id, runner).get("Id")
                   for container_id in ids(BETA_PROJECT, runner)]
    require(set(current_ids) == set(planned)
            and len(current_ids) == len(planned)
            and len({item["service"] for item in generation}) == len(generation),
            "Beta Compose generation changed during maintenance")
    stopped = []
    for container_id, item in planned.items():
        record = inspect(container_id, runner)
        config = record.get("Config")
        state = record.get("State")
        labels = config.get("Labels") if isinstance(config, dict) else None
        require(record.get("Id") == container_id
                and record.get("Image") == item.get("image_id")
                and isinstance(labels, dict)
                and labels.get("com.docker.compose.project") == BETA_PROJECT
                and labels.get("com.docker.compose.service") == item.get("service")
                and isinstance(state, dict)
                and state.get("StartedAt") == item.get("started_at"),
                "Beta container identity changed during maintenance")
        if item["service"] == "issuance":
            config_image = config.get("Image") if isinstance(config, dict) else None
            image = IMAGE_DIGEST.fullmatch(str(config_image))
            require(container_id == plan["legacy_writer_container_id"]
                    and state.get("StartedAt") == plan["legacy_writer_started_at"]
                    and record.get("RestartCount")
                        == plan["legacy_writer_generation"]
                    and image is not None
                    and image.group(1) == plan["legacy_writer_image_digest"],
                    "Old Python writer generation changed during maintenance")
        if item["service"] in PRESERVED_SERVICES:
            if item["service"] == "postgres":
                require(container_id == receipt["container_id"],
                        "Fenced beta PostgreSQL stopped or changed")
            require(state.get("Running") is True
                    and state.get("Status") == "running",
                    f"Preserved beta {item['service']} stopped or changed")
        elif state.get("Running") is False and state.get("Status") == "exited":
            stopped.append(container_id)
        else:
            require(not require_stopped and state.get("Running") is True
                    and state.get("Status") == "running",
                    "Beta service is not in an allowed maintenance state")
    expected_stops = [item["container_id"] for item in generation
                      if item["service"] not in PRESERVED_SERVICES]
    require(plan.get("stop_container_ids") == expected_stops,
            "Maintenance stop inventory changed")
    identity = beta_psql(
        "SELECT system_identifier::text || '|' || "
        "(SELECT oid::text FROM pg_database WHERE datname=current_database()) "
        "FROM pg_control_system()", runner, receipt["container_id"],
    )
    require(identity == receipt["system_id"] + "|" + receipt["database_oid"],
            "Fenced beta PostgreSQL identity changed during maintenance")
    return {"schema": "marty.passport-beta-db-maintenance-state/v1",
            "verified": True, "stopped_container_ids": stopped,
            "postgres_container_id": receipt["container_id"],
            "production_snapshot_sha256": production["sha256"],
            "production_attachments_sha256": plan["production_attachments_sha256"]}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stack-manifest", type=Path, required=True)
    parser.add_argument("--fence-receipt", type=Path, required=True)
    parser.add_argument("--cutover-snapshot", type=Path, required=True)
    parser.add_argument("--cutover-report", type=Path, required=True)
    parser.add_argument("--verify-plan", type=Path)
    parser.add_argument("--require-stopped", action="store_true")
    args = parser.parse_args()
    try:
        if args.verify_plan:
            plan = json.loads(args.verify_plan.read_text(encoding="utf-8"))
            result = verify_plan(plan, args.stack_manifest, args.fence_receipt,
                                 args.cutover_snapshot, args.cutover_report,
                                 require_stopped=args.require_stopped)
        else:
            require(not args.require_stopped, "A maintenance plan is required")
            result = prepare(args.stack_manifest, args.fence_receipt,
                             args.cutover_snapshot, args.cutover_report)
        print(json.dumps(result,
                         sort_keys=True, separators=(",", ":")))
    except (HostProbeError, NativeMigrationError, OSError, ValueError, KeyError) as exc:
        raise SystemExit(f"Protected beta maintenance plan is unavailable: {exc}") from exc


if __name__ == "__main__":
    main()
