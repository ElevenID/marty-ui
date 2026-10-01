#!/usr/bin/env python3
"""Fail closed unless a one-job passport runner owns the current beta host."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import stat
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from check_canvas_oss_runner import (
    GIB,
    REQUIRED_TOOLS,
    check_runner_process_quiescence,
    docker,
)


RUNNER_PREFIX = "passport-beta-wsl2-"
BETA_NETWORK = "elevenid-beta-network"
BETA_TUNNELS = ("elevenid-beta-nginx-proxy-1", "elevenid-beta-cloudflared-1")
PRODUCTION_PREFIX = "marty-selfhost-prod-"
REQUIRED_PRODUCTION = {
    PRODUCTION_PREFIX + service + "-1" for service in (
        "applicant", "auth", "canvas-sync-worker", "cloudflared",
        "compliance-profile", "credential-template", "deployment-profile",
        "device-registration", "edge", "event-stream", "flow", "gateway",
        "issuance", "keycloak", "notification", "organization", "postgres",
        "presentation-policy", "redis", "revocation-profile", "signing-keys",
        "trust-profile", "ui", "verification",
    )
}
HISTORICAL_STOPPED_PRODUCTION = {
    # Completed or retired containers observed before passport runner setup.
    # Any newly stopped production service must still block admission.
    "marty-selfhost-prod-keycloak-configurator-1",
    "marty-selfhost-prod-issuance-migrations-1",
    "marty-selfhost-prod-db-migrate-1",
    "marty-selfhost-prod-revocation-profile-migrate-1",
    "marty-selfhost-prod-billing-1",
}
HISTORICAL_EXIT_CODES = {
    "marty-selfhost-prod-keycloak-configurator-1": "0",
    # This migration failed before runner setup; its container and exit state
    # are pinned in the registration baseline and cannot change during a job.
    "marty-selfhost-prod-issuance-migrations-1": "1",
    "marty-selfhost-prod-db-migrate-1": "0",
    "marty-selfhost-prod-revocation-profile-migrate-1": "0",
    # Retired from the current production Compose model.
    "marty-selfhost-prod-billing-1": "255",
}
NO_HEALTHCHECK_PRODUCTION = {
    "marty-selfhost-prod-cloudflared-1",
    "marty-selfhost-prod-canvas-sync-worker-1",
}
PASSPORT_DISPOSABLE_PREFIX = "marty-passport-"


def _docker_objects(runner, *args: str) -> list[dict[str, str]]:
    objects = []
    for line in runner(*args, "--format", "{{json .}}").splitlines():
        item = json.loads(line)
        if not isinstance(item, dict):
            raise RuntimeError("Docker host inventory is invalid")
        objects.append(item)
    return objects


def check_disposable_quarantine(runner=docker, temp_root: Path | None = None) -> None:
    """Reject leftover disposable objects before or after a protected job."""
    counts = {"containers": 0, "networks": 0, "volumes": 0, "staged_paths": 0}
    for kind, args, name_key in (
        ("containers", ("ps", "-a"), "Names"),
        ("networks", ("network", "ls"), "Name"),
        ("volumes", ("volume", "ls"), "Name"),
    ):
        for item in _docker_objects(runner, *args):
            name, labels = item.get(name_key), item.get("Labels")
            if not isinstance(name, str) or not isinstance(labels, str):
                raise RuntimeError("Docker passport inventory is incomplete")
            label_parts = labels.split(",")
            owned_label = any(
                part.startswith("com.marty.passport.")
                or part.startswith("com.docker.compose.project=" + PASSPORT_DISPOSABLE_PREFIX)
                for part in label_parts
            )
            if name.startswith(PASSPORT_DISPOSABLE_PREFIX) or owned_label:
                counts[kind] += 1
    root = temp_root or Path(tempfile.gettempdir())
    counts["staged_paths"] = sum(
        path.name.startswith(PASSPORT_DISPOSABLE_PREFIX) for path in root.iterdir()
    )
    if any(counts.values()):
        raise RuntimeError(
            "Passport disposable host is quarantined: "
            + ", ".join(f"{kind}={count}" for kind, count in counts.items())
        )


def production_inventory(runner=docker) -> dict[str, dict[str, str]]:
    inventory = {}
    for item in _docker_objects(runner, "ps", "-a", "--no-trunc"):
        name = item.get("Names")
        if not isinstance(name, str) or not name.startswith(PRODUCTION_PREFIX):
            continue
        if name in inventory or any(not isinstance(item.get(key), str) for key in
                                    ("ID", "State", "Status", "HealthStatus")):
            raise RuntimeError("Production container inventory is incomplete")
        status = item["Status"]
        exit_match = re.match(r"^Exited \((\d+)\) ", status)
        inventory[name] = {key: item[key] for key in ("ID", "State", "HealthStatus")}
        inventory[name]["ExitCode"] = exit_match.group(1) if exit_match else ""
    running_names = {name for name, item in inventory.items()
                     if item["State"] == "running"}
    if running_names != REQUIRED_PRODUCTION:
        raise RuntimeError("Required production runtime inventory changed")
    if set(inventory) != REQUIRED_PRODUCTION | HISTORICAL_STOPPED_PRODUCTION:
        raise RuntimeError("Production container inventory changed")
    ids = {item["ID"] for item in inventory.values()}
    if len(ids) != len(inventory) or not all(ids):
        raise RuntimeError("Production container IDs are incomplete")
    inspect_format = "{{.Id}}|{{.State.StartedAt}}|{{.RestartCount}}"
    inspected = {}
    for line in runner("inspect", "--format", inspect_format, *sorted(ids)).splitlines():
        parts = line.split("|")
        if len(parts) != 3 or parts[0] in inspected or not parts[1] or not parts[2].isdigit():
            raise RuntimeError("Production restart inventory is incomplete")
        inspected[parts[0]] = (parts[1], parts[2])
    if set(inspected) != ids:
        raise RuntimeError("Production restart inventory is incomplete")
    for name, item in inventory.items():
        item["StartedAt"], item["RestartCount"] = inspected[item["ID"]]
        if name in running_names:
            expected_health = ({"", "none"} if name in NO_HEALTHCHECK_PRODUCTION
                               else {"healthy"})
            if item["HealthStatus"] not in expected_health:
                raise RuntimeError("A production container is unhealthy")
        elif name not in HISTORICAL_STOPPED_PRODUCTION or item["State"] != "exited":
            raise RuntimeError("A production container is stopped on the shared Docker host")
        elif item["ExitCode"] != HISTORICAL_EXIT_CODES[name]:
            raise RuntimeError("A historical production container exit state changed")
    return dict(sorted(inventory.items()))


def check_production_baseline(inventory: dict[str, dict[str, str]], path: Path) -> None:
    baseline = json.loads(path.read_text(encoding="utf-8"))
    if baseline.get("schema") != "marty.passport-beta-runner-host/v1":
        raise RuntimeError("Production runner baseline schema is invalid")
    if baseline.get("production_identity") != inventory:
        raise RuntimeError("Production container identity or state changed since runner registration")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--host-setup", action="store_true")
    parser.add_argument("--baseline", type=Path)
    args = parser.parse_args()
    try:
        if sys.platform != "linux" or not os.environ.get("WSL_INTEROP"):
            raise RuntimeError("passport-beta-wsl2 runner must execute inside WSL2")
        os_release = Path("/etc/os-release").read_text(encoding="utf-8")
        if "ID=ubuntu" not in os_release or 'VERSION_ID="24.04"' not in os_release:
            raise RuntimeError("dedicated runner distribution must be Ubuntu 24.04 under WSL2")
        missing_tools = [name for name in REQUIRED_TOOLS if shutil.which(name) is None]
        if missing_tools:
            raise RuntimeError("dedicated runner is missing tools: " + ", ".join(missing_tools))
        socket_path = Path("/var/run/docker.sock")
        try:
            socket_is_unix = stat.S_ISSOCK(socket_path.stat().st_mode)
        except OSError:
            socket_is_unix = False
        if not socket_is_unix:
            raise RuntimeError("Docker Desktop WSL integration socket is unavailable")
        if args.host_setup:
            check_runner_process_quiescence()
        else:
            runner_name = os.environ.get("RUNNER_NAME", "")
            if not runner_name.startswith(RUNNER_PREFIX):
                raise RuntimeError("job is not on the dedicated passport beta runner")
            if os.environ.get("RUNNER_OS") != "Linux" or os.environ.get("RUNNER_ARCH") != "X64":
                raise RuntimeError("passport runner OS/architecture labels are invalid")
            if os.environ.get("PASSPORT_BETA_RUNNER_LABELS_VERIFIED") != runner_name:
                raise RuntimeError("passport runner labels were not verified before job startup")
        if docker("info", "--format", "{{.OSType}}") != "linux":
            raise RuntimeError("passport runner is not attached to a Linux Docker daemon")
        if not docker("compose", "version", "--short"):
            raise RuntimeError("Docker Compose v2 is unavailable")
        if int(docker("info", "--format", "{{.MemTotal}}")) < 12 * GIB:
            raise RuntimeError("shared Docker daemon exposes less than 12 GiB")
        if shutil.disk_usage(Path.cwd()).free < 80 * GIB:
            raise RuntimeError("passport runner workspace has less than 80 GiB free")
        docker("network", "inspect", BETA_NETWORK)
        for name in BETA_TUNNELS:
            if docker("inspect", name, "--format", "{{.State.Running}}") != "true":
                raise RuntimeError("existing beta tunnel is not running: " + name)
        production = production_inventory()
        baseline_path = args.baseline
        if not args.host_setup:
            baseline_path = Path(os.environ["PASSPORT_BETA_PRODUCTION_BASELINE"])
        if baseline_path is not None:
            check_production_baseline(production, baseline_path)
        check_disposable_quarantine()
        report = {
            "schema": "marty.passport-beta-runner-host/v1",
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "host_setup_only": args.host_setup,
            "runner_label": "passport-beta-wsl2",
            "docker_socket_available": True,
            "beta_network": BETA_NETWORK,
            "beta_tunnels": list(BETA_TUNNELS),
            "production_containers": sorted(REQUIRED_PRODUCTION),
            "production_identity": production,
            "production_mutation_allowed": False,
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except Exception as exc:
        print(f"Passport beta runner preflight failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
