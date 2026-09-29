#!/usr/bin/env python3
"""Read-only protected-source plan for the fenced beta database window."""

from __future__ import annotations

import argparse
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
    from .probe_passport_beta_host import (
        BETA_PROJECT, HostProbeError, beta_psql, ids, inspect,
        production_snapshot, run,
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
    from probe_passport_beta_host import (
        BETA_PROJECT, HostProbeError, beta_psql, ids, inspect,
        production_snapshot, run,
    )


ROOT = Path(__file__).resolve().parents[1]
START = "scripts/sql/passport-beta-db-maintenance-start.sql"
VERIFY = "scripts/sql/passport-beta-fence-verify.sql"
DOCKER_ID = re.compile(r"[0-9a-f]{64}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise HostProbeError(message)


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
    return sorted(result, key=lambda item: item["service"])


def prepare(
    manifest_path: Path, receipt_path: Path,
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
        "post_install_observation_sha256": observed["observation_sha256"],
        "beta_generation": generation,
        "stop_container_ids": [item["container_id"] for item in generation
                               if item["service"] != "postgres"],
    }


def verify_plan(
    plan: dict[str, Any], manifest_path: Path, receipt_path: Path,
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
            and plan.get("post_install_observation_sha256")
                == receipt_raw.get("post_install_observation_sha256"),
            "Maintenance intent differs from fence installation receipt")
    docker = plan.get("docker")
    require(isinstance(docker, dict)
            and runner(["docker", "context", "show"]) == docker.get("context")
            and runner(["docker", "info", "--format", "{{.ID}}"])
                == docker.get("daemon_id"),
            "Maintenance Docker context changed")
    production = production_snapshot(runner)
    require(production.get("sha256") == plan.get("production_snapshot_sha256"),
            "Production changed during beta maintenance")
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
        if item["service"] == "postgres":
            require(container_id == receipt["container_id"]
                    and state.get("Running") is True
                    and state.get("Status") == "running",
                    "Fenced beta PostgreSQL stopped or changed")
        elif state.get("Running") is False and state.get("Status") == "exited":
            stopped.append(container_id)
        else:
            require(not require_stopped and state.get("Running") is True
                    and state.get("Status") == "running",
                    "Beta service is not in an allowed maintenance state")
    expected_stops = [item["container_id"] for item in generation
                      if item["service"] != "postgres"]
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
            "production_snapshot_sha256": production["sha256"]}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stack-manifest", type=Path, required=True)
    parser.add_argument("--fence-receipt", type=Path, required=True)
    parser.add_argument("--verify-plan", type=Path)
    parser.add_argument("--require-stopped", action="store_true")
    args = parser.parse_args()
    try:
        if args.verify_plan:
            plan = json.loads(args.verify_plan.read_text(encoding="utf-8"))
            result = verify_plan(plan, args.stack_manifest, args.fence_receipt,
                                 require_stopped=args.require_stopped)
        else:
            require(not args.require_stopped, "A maintenance plan is required")
            result = prepare(args.stack_manifest, args.fence_receipt)
        print(json.dumps(result,
                         sort_keys=True, separators=(",", ":")))
    except (HostProbeError, NativeMigrationError, OSError, ValueError, KeyError) as exc:
        raise SystemExit(f"Protected beta maintenance plan is unavailable: {exc}") from exc


if __name__ == "__main__":
    main()
