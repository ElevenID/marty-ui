#!/usr/bin/env python3
"""Remove stale resources from only the Canvas OSS acceptance Compose project."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROJECT = "canvas-oss-portability"
EXTERNAL_TUNNEL_NETWORK = "marty-infra-network"
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILE = REPOSITORY_ROOT / "docker-compose.canvas-oss-acceptance.yml"
PROJECT_LABEL = "com.docker.compose.project"


class FreshStateError(RuntimeError):
    """Raised when cleanup escapes its scope or cannot prove an empty project."""


@dataclass(frozen=True)
class DockerSnapshot:
    project_containers: frozenset[str]
    project_volumes: frozenset[str]
    project_networks: frozenset[str]
    non_project_running_containers: frozenset[str]
    tunnel_network_id: str
    non_project_tunnel_members: frozenset[str]


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def cleanup_command(compose_file: Path = COMPOSE_FILE) -> list[str]:
    """Return the sole mutating command, pinned to the acceptance project."""

    return [
        "docker",
        "compose",
        "--project-name",
        PROJECT,
        "--file",
        str(compose_file.resolve()),
        "down",
        "--volumes",
        "--remove-orphans",
        "--timeout",
        "30",
    ]


def _docker_text(*args: str) -> str:
    try:
        result = subprocess.run(
            ["docker", *args],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        # Docker inspection output can contain the beta environment. Never
        # include captured output in the exception or artifact.
        raise FreshStateError("Docker inspection failed during Canvas fresh-state verification") from exc
    return result.stdout


def _docker_json(*args: str) -> Any:
    try:
        return json.loads(_docker_text(*args))
    except json.JSONDecodeError as exc:
        raise FreshStateError("Docker returned invalid inspection data") from exc


def _ids(resource: str, *extra: str) -> frozenset[str]:
    options = ["--quiet"]
    if resource == "container":
        # Network inspection keys use full container IDs. Keep both sides of
        # the tunnel-membership comparison in the same representation.
        options.append("--no-trunc")
    return frozenset(
        value.strip()
        for value in _docker_text(resource, "ls", *options, *extra).splitlines()
        if value.strip()
    )


def _project_ids(resource: str) -> frozenset[str]:
    options = ["--filter", f"label={PROJECT_LABEL}={PROJECT}"]
    if resource == "container":
        options.insert(0, "--all")
    return _ids(resource, *options)


def _container_records() -> list[dict[str, Any]]:
    ids = _ids("container", "--all")
    if not ids:
        return []
    payload = _docker_json("container", "inspect", *sorted(ids))
    if not isinstance(payload, list) or not all(isinstance(item, dict) for item in payload):
        raise FreshStateError("Docker container inspection was ambiguous")
    return payload


def capture_snapshot() -> DockerSnapshot:
    project_containers = _project_ids("container")
    records = _container_records()
    non_project_running: set[str] = set()
    for record in records:
        container_id = str(record.get("Id") or "")
        config = record.get("Config") if isinstance(record.get("Config"), dict) else {}
        labels = config.get("Labels") if isinstance(config.get("Labels"), dict) else {}
        state = record.get("State") if isinstance(record.get("State"), dict) else {}
        if container_id and labels.get(PROJECT_LABEL) != PROJECT and state.get("Running") is True:
            non_project_running.add(container_id)

    network_payload = _docker_json("network", "inspect", EXTERNAL_TUNNEL_NETWORK)
    if not isinstance(network_payload, list) or len(network_payload) != 1 or not isinstance(network_payload[0], dict):
        raise FreshStateError("The existing beta tunnel network is missing or ambiguous")
    network = network_payload[0]
    network_id = str(network.get("Id") or "")
    if not network_id:
        raise FreshStateError("The existing beta tunnel network has no immutable identity")
    members = network.get("Containers")
    if members is None:
        members = {}
    if not isinstance(members, dict):
        raise FreshStateError("The existing beta tunnel network membership is invalid")
    non_project_members = set(str(value) for value in members) - set(project_containers)

    return DockerSnapshot(
        project_containers=project_containers,
        project_volumes=_project_ids("volume"),
        project_networks=_project_ids("network"),
        non_project_running_containers=frozenset(non_project_running),
        tunnel_network_id=network_id,
        non_project_tunnel_members=frozenset(non_project_members),
    )


def validate_fresh_state(before: DockerSnapshot, after: DockerSnapshot) -> None:
    """Prove target resources are gone and everything outside scope survived."""

    remaining = (
        len(after.project_containers)
        + len(after.project_volumes)
        + len(after.project_networks)
    )
    if remaining:
        raise FreshStateError("Canvas acceptance project resources remain after cleanup")
    if before.tunnel_network_id != after.tunnel_network_id:
        raise FreshStateError("The existing beta tunnel network changed during cleanup")
    if not before.non_project_running_containers.issubset(after.non_project_running_containers):
        raise FreshStateError("A running container outside the Canvas acceptance project was affected")
    if not before.non_project_tunnel_members.issubset(after.non_project_tunnel_members):
        raise FreshStateError("A non-Canvas beta tunnel attachment was affected")


def write_audit(path: Path, before: DockerSnapshot, after: DockerSnapshot, started_at: str) -> None:
    report = {
        "schema_version": 1,
        "project": PROJECT,
        "compose_file": COMPOSE_FILE.name,
        "started_at": started_at,
        "finished_at": now(),
        "operation": "compose_down_volumes_remove_orphans",
        "preexisting_project_resources": {
            "containers": len(before.project_containers),
            "volumes": len(before.project_volumes),
            "networks": len(before.project_networks),
        },
        "remaining_project_resources": {
            "containers": len(after.project_containers),
            "volumes": len(after.project_volumes),
            "networks": len(after.project_networks),
        },
        "external_tunnel_network_preserved": True,
        "non_project_running_containers_preserved": True,
        "non_project_tunnel_members_preserved": True,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    started_at = now()
    try:
        if not COMPOSE_FILE.is_file():
            raise FreshStateError("Canvas acceptance Compose file is missing")
        before = capture_snapshot()
        subprocess.run(cleanup_command(), check=True)
        after = capture_snapshot()
        validate_fresh_state(before, after)
        write_audit(args.output, before, after, started_at)
    except (OSError, subprocess.CalledProcessError, FreshStateError) as exc:
        print(f"Canvas OSS fresh-state gate failed: {exc}", file=sys.stderr)
        return 1
    print("Canvas OSS Compose project is fresh; beta and external tunnel resources were preserved.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
