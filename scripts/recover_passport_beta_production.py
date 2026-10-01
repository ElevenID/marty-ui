#!/usr/bin/env python3
"""Restore only captured production containers stopped during a beta cutover.

The baseline is captured before beta mutation. Recovery never creates a container,
changes a network, or invokes Compose. A restart is a recorded continuity breach.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import time
from typing import Any, Callable

try:
    from .probe_passport_beta_host import (
        PRODUCTION_PROJECTS, REQUIRED_PRODUCTION_SERVICES, HostProbeError,
        ids, inspect, production_attachment_sha256, production_public_route,
        production_snapshot, run,
    )
except ImportError:
    from probe_passport_beta_host import (
        PRODUCTION_PROJECTS, REQUIRED_PRODUCTION_SERVICES, HostProbeError,
        ids, inspect, production_attachment_sha256, production_public_route,
        production_snapshot, run,
    )


SCHEMA = "marty.passport-beta-production-recovery-baseline/v1"
RESULT_SCHEMA = "marty.passport-beta-production-recovery/v1"
CONTAINER = re.compile(r"[0-9a-f]{64}\Z")
IMAGE = re.compile(r"sha256:[0-9a-f]{64}\Z")


class RecoveryError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RecoveryError(message)


def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True,
        separators=(",", ":")).encode()).hexdigest()


def docker_identity(runner: Callable[[list[str]], str]) -> dict[str, str]:
    context = runner(["docker", "context", "show"])
    daemon_id = runner(["docker", "info", "--format", "{{.ID}}"])
    require(bool(context) and bool(daemon_id), "docker_identity_unavailable")
    return {"context": context, "daemon_id": daemon_id}


def container_identity(record: dict[str, Any], project: str) -> dict[str, Any]:
    config = record.get("Config")
    state = record.get("State")
    networks = record.get("NetworkSettings")
    host = record.get("HostConfig")
    require(isinstance(config, dict) and isinstance(state, dict)
            and isinstance(networks, dict) and isinstance(host, dict),
            "production_container_incomplete")
    labels = config.get("Labels")
    service = labels.get("com.docker.compose.service") if isinstance(labels, dict) else None
    attachment = networks.get("Networks")
    mounts = record.get("Mounts")
    container_id = record.get("Id")
    image_id = record.get("Image")
    require(isinstance(container_id, str) and CONTAINER.fullmatch(container_id) is not None
            and isinstance(image_id, str) and IMAGE.fullmatch(image_id) is not None
            and isinstance(config.get("Image"), str) and bool(config["Image"])
            and isinstance(service, str) and bool(service)
            and labels.get("com.docker.compose.project") == project
            and isinstance(attachment, dict) and bool(attachment)
            and isinstance(mounts, list)
            and isinstance(host.get("PortBindings"), (dict, type(None))),
            "production_container_identity_invalid")
    stable_networks = []
    for name, network in sorted(attachment.items()):
        require(isinstance(name, str) and isinstance(network, dict)
                and isinstance(network.get("NetworkID"), str)
                and isinstance(network.get("Aliases"), (list, type(None))),
                "production_network_identity_invalid")
        stable_networks.append({"name": name, "id": network["NetworkID"],
                                "aliases": network.get("Aliases")})
    running = state.get("Running")
    status = state.get("Status")
    require(type(running) is bool and status in ("running", "exited")
            and running == (status == "running"), "production_state_invalid")
    return {
        "id": container_id, "project": project, "service": service,
        "image_id": image_id, "configured_image": config["Image"],
        "mounts_sha256": digest(sorted(mounts, key=lambda item: json.dumps(
            item, sort_keys=True, separators=(",", ":")))),
        "networks": stable_networks,
        "port_bindings_sha256": digest(host.get("PortBindings")),
        "was_running": running,
    }


def production_inventory(runner: Callable[[list[str]], str]) -> list[dict[str, Any]]:
    inventory = []
    for project in PRODUCTION_PROJECTS:
        project_ids = ids(project, runner)
        require(bool(project_ids), "production_project_missing")
        for short_id in project_ids:
            record = inspect(short_id, runner)
            require(isinstance(record.get("Id"), str)
                    and record["Id"].startswith(short_id),
                    "production_container_id_changed")
            inventory.append(container_identity(record, project))
    inventory.sort(key=lambda item: item["id"])
    require(len({item["id"] for item in inventory}) == len(inventory),
            "production_container_duplicate")
    for project, required in REQUIRED_PRODUCTION_SERVICES.items():
        running = {item["service"] for item in inventory
                   if item["project"] == project and item["was_running"]}
        require(required <= running, "required_production_service_missing")
    return inventory


def capture(
    runner: Callable[[list[str]], str] = run,
    public_probe: Callable[[], dict[str, Any]] = production_public_route,
) -> dict[str, Any]:
    docker = docker_identity(runner)
    inventory = production_inventory(runner)
    snapshot = production_snapshot(runner)
    attachments = production_attachment_sha256(runner)
    route = public_probe()
    require(route == {"origin": "https://elevenidllc.com/", "status": 200},
            "production_public_route_unavailable")
    return {"schema": SCHEMA, "captured_at_utc": datetime.now(timezone.utc).isoformat(),
            "docker": docker, "containers": inventory,
            "snapshot_sha256": snapshot["sha256"],
            "attachments_sha256": attachments}


def validate_baseline(baseline: dict[str, Any]) -> list[dict[str, Any]]:
    require(baseline.get("schema") == SCHEMA and isinstance(baseline.get("docker"), dict)
            and isinstance(baseline.get("containers"), list)
            and bool(baseline["containers"]), "baseline_invalid")
    require(all(isinstance(item, dict) and isinstance(item.get("id"), str)
                and CONTAINER.fullmatch(item["id"]) is not None
                and item.get("project") in PRODUCTION_PROJECTS
                and type(item.get("was_running")) is bool
                for item in baseline["containers"]), "baseline_invalid")
    require(all(isinstance(baseline.get(key), str)
                and re.fullmatch(r"[0-9a-f]{64}", baseline[key]) is not None
                for key in ("snapshot_sha256", "attachments_sha256")),
            "baseline_invalid")
    return baseline["containers"]


def same_container(before: dict[str, Any], current: dict[str, Any]) -> bool:
    if any(current.get(key) != before.get(key) for key in (
        "id", "project", "service", "image_id", "configured_image",
        "mounts_sha256", "port_bindings_sha256")):
        return False
    prior_networks = before.get("networks")
    live_networks = current.get("networks")
    if not isinstance(prior_networks, list) or not isinstance(live_networks, list) \
            or len(prior_networks) != len(live_networks):
        return False
    for prior, live in zip(prior_networks, live_networks):
        if prior.get("name") != live.get("name") \
                or prior.get("aliases") != live.get("aliases"):
            return False
        # Docker may clear NetworkID while a container is stopped. A nonempty
        # observed ID, and every ID after restart, must match the captured ID.
        if live.get("id") != prior.get("id") and not (
                not current["was_running"] and live.get("id") == ""):
            return False
    return True


def recover(
    baseline: dict[str, Any],
    runner: Callable[[list[str]], str] = run,
    public_probe: Callable[[], dict[str, Any]] = production_public_route,
    *,
    timeout_seconds: float = 180,
    now: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    restarted: list[str] = []
    result: dict[str, Any] = {"schema": RESULT_SCHEMA, "verified": False,
        "continuity_breached": False, "restarted_container_ids": restarted,
        "checked_at_utc": datetime.now(timezone.utc).isoformat()}
    try:
        expected = validate_baseline(baseline)
        require(docker_identity(runner) == baseline["docker"],
                "docker_identity_changed")
        observed = production_inventory_unchecked(runner)
        require([item["id"] for item in observed] == [item["id"] for item in expected],
                "production_container_set_changed")
        for before, current in zip(expected, observed):
            require(same_container(before, current),
                "production_container_identity_changed")
            if not before["was_running"]:
                require(not current["was_running"],
                        "historical_production_container_started")
        for before, current in zip(expected, observed):
            if before["was_running"] and not current["was_running"]:
                # Recheck immediately before mutation; a concurrent change fails closed.
                fresh = container_identity(inspect(before["id"], runner), before["project"])
                require(fresh == current and docker_identity(runner) == baseline["docker"],
                        "production_identity_changed_before_start")
                # A lost docker response can hide a successful start. Record the
                # attempted mutation before invoking it and never claim continuity.
                result["continuity_breached"] = True
                result.setdefault("restart_attempted_container_ids", []).append(before["id"])
                runner(["docker", "start", before["id"]])
                restarted.append(before["id"])
        deadline = now() + timeout_seconds
        while True:
            require(docker_identity(runner) == baseline["docker"],
                    "docker_identity_changed")
            final = production_inventory_unchecked(runner)
            require([item["id"] for item in final] == [item["id"] for item in expected]
                    and all(same_container(before, current)
                        for before, current in zip(expected, final)),
                    "production_container_identity_changed")
            require(all(not current["was_running"] for before, current in zip(expected, final)
                        if not before["was_running"]),
                    "historical_production_container_started")
            try:
                require(all(current["was_running"] for before, current in zip(expected, final)
                            if before["was_running"]), "production_container_not_running")
                snapshot = production_snapshot(runner)
                route = public_probe()
                require(route == {"origin": "https://elevenidllc.com/", "status": 200},
                        "production_public_route_unavailable")
                if not restarted:
                    require(snapshot["sha256"] == baseline["snapshot_sha256"]
                            and production_attachment_sha256(runner)
                                == baseline["attachments_sha256"],
                            "production_baseline_changed")
                result.update(verified=True, status="restored" if restarted else "unchanged",
                              checked_at_utc=datetime.now(timezone.utc).isoformat())
                return result
            except (RecoveryError, HostProbeError, OSError, ValueError):
                if now() >= deadline:
                    raise RecoveryError("production_health_or_public_route_unavailable")
                sleep(2)
    except (RecoveryError, HostProbeError, OSError, ValueError) as exc:
        reason = str(exc) if isinstance(exc, RecoveryError) else "production_probe_failed"
        result.update(status="blocked", reason_code=reason,
                      checked_at_utc=datetime.now(timezone.utc).isoformat())
        return result


def production_inventory_unchecked(
    runner: Callable[[list[str]], str],
) -> list[dict[str, Any]]:
    """Inspect all project members without assuming the required services run."""
    inventory = []
    for project in PRODUCTION_PROJECTS:
        for short_id in ids(project, runner):
            record = inspect(short_id, runner)
            require(isinstance(record.get("Id"), str)
                    and record["Id"].startswith(short_id),
                    "production_container_id_changed")
            inventory.append(container_identity(record, project))
    inventory.sort(key=lambda item: item["id"])
    require(len({item["id"] for item in inventory}) == len(inventory),
            "production_container_duplicate")
    return inventory


def write_private(path: Path, value: dict[str, Any]) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        json.dump(value, output, sort_keys=True, indent=2)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())


def restore_from_path(path: Path) -> dict[str, Any]:
    try:
        if not path.is_absolute() or not path.is_file():
            raise RecoveryError("baseline_path_invalid")
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise RecoveryError("baseline_invalid")
    except (OSError, ValueError) as exc:
        reason = str(exc) if isinstance(exc, RecoveryError) else "baseline_unreadable"
        return {"schema": RESULT_SCHEMA, "verified": False,
                "continuity_breached": False, "restarted_container_ids": [],
                "status": "blocked", "reason_code": reason,
                "checked_at_utc": datetime.now(timezone.utc).isoformat()}
    return recover(value)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--capture", action="store_true")
    group.add_argument("--restore", action="store_true")
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.capture:
        require(args.output is not None and args.output.is_absolute()
                and args.output.parent.is_dir() and args.baseline is None,
                "output_path_invalid")
        value = capture()
        write_private(args.output, value)
    else:
        require(args.output is None and args.baseline is not None,
                "baseline_path_invalid")
        value = restore_from_path(args.baseline)
    print(json.dumps(value, sort_keys=True))
    if args.restore and not value["verified"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
