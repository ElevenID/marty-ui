#!/usr/bin/env python3
"""Operate a clean, project-scoped interoperability stack on any Docker engine."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PROJECT = re.compile(r"^marty-conformance-[a-z0-9](?:[a-z0-9-]{1,46}[a-z0-9])?$")
BASE_FILES = (
    "docker-compose.base.yml",
    "docker-compose.profile.ghcr.yml",
    "docker-compose.profile.oidf.yml",
)
W3C_FILE = "docker-compose.profile.w3c-vc.yml"
EUDI_FILE = "docker-compose.profile.eudi.yml"
ISOLATION_FILE = "docker-compose.profile.conformance.yml"
EUDI_ISOLATION_FILE = "docker-compose.profile.conformance-eudi.yml"
PUBLIC_PORT_SERVICES = {"oidf-tls-proxy", "eudi-wallet-tester-tls", "eudi-verifier-tls"}


def validate_project(project: str) -> str:
    if not PROJECT.fullmatch(project):
        raise ValueError(
            "project must match marty-conformance-<run-id> using lowercase letters, digits, and hyphens"
        )
    return project


def compose_command(project: str, *, include_eudi: bool, include_w3c: bool = False) -> list[str]:
    command = ["docker", "compose", "--project-name", validate_project(project)]
    files = [*BASE_FILES]
    if include_w3c:
        files.append(W3C_FILE)
    if include_eudi:
        files.append(EUDI_FILE)
    files.append(ISOLATION_FILE)
    if include_eudi:
        files.append(EUDI_ISOLATION_FILE)
    for compose_file in files:
        command.extend(["--file", os.fspath(ROOT / compose_file)])
    command.extend(["--profile", "oidf"])
    if include_eudi:
        command.extend(["--profile", "eudi"])
    return command


def rendered_config(project: str, *, include_eudi: bool, include_w3c: bool = False) -> dict[str, Any]:
    completed = subprocess.run(
        [
            *compose_command(project, include_eudi=include_eudi, include_w3c=include_w3c),
            "config",
            "--format",
            "json",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode:
        raise ValueError(f"Compose configuration failed:\n{completed.stderr.strip()}")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise ValueError("Compose returned invalid JSON configuration") from error


def validate_isolation(config: dict[str, Any], project: str) -> list[int]:
    """Reject any resource that could collide with or reuse another project."""
    services = config.get("services", {})
    fixed = [name for name, service in services.items() if service.get("container_name")]
    if fixed:
        raise ValueError(f"fixed container names defeat project isolation: {', '.join(sorted(fixed))}")

    published: list[int] = []
    for name, service in services.items():
        ports = service.get("ports", [])
        if ports and name not in PUBLIC_PORT_SERVICES:
            raise ValueError(f"service {name} unexpectedly publishes a host port")
        for port in ports:
            value = port.get("published")
            if value is None:
                raise ValueError(f"service {name} must publish an explicit host port")
            published.append(int(value))
    if len(published) != len(set(published)):
        raise ValueError("conformance services publish duplicate host ports")

    for kind in ("networks", "volumes"):
        for name, resource in config.get(kind, {}).items():
            actual = resource.get("name", "")
            if not actual.startswith(f"{project}_"):
                raise ValueError(f"{kind[:-1]} {name} is not scoped to project {project}: {actual}")
    return published


def project_container_ids(project: str) -> list[str]:
    completed = subprocess.run(
        [
            "docker",
            "ps",
            "--all",
            "--quiet",
            "--filter",
            f"label=com.docker.compose.project={project}",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return [line for line in completed.stdout.splitlines() if line]


def container_project(container_id: str) -> str:
    completed = subprocess.run(
        ["docker", "inspect", "--format", "{{ index .Config.Labels \"com.docker.compose.project\" }}", container_id],
        capture_output=True,
        text=True,
        check=True,
    )
    return completed.stdout.strip()


def assert_ports_available(ports: list[int], project: str, *, resume: bool = False) -> None:
    for port in ports:
        completed = subprocess.run(
            ["docker", "ps", "--quiet", "--filter", f"publish={port}"],
            capture_output=True,
            text=True,
            check=True,
        )
        owners = [line for line in completed.stdout.splitlines() if line]
        foreign = [container_id for container_id in owners if container_project(container_id) != project]
        if foreign:
            raise ValueError(f"host port {port} is already published; choose a different conformance port")
    if project_container_ids(project) and not resume:
        raise ValueError(
            f"project {project} already has containers; use the exact down command before starting a fresh run"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--project",
        default=os.environ.get("MARTY_CONFORMANCE_PROJECT", ""),
        help="unique marty-conformance-<run-id> project name",
    )
    parser.add_argument("--include-eudi", action="store_true")
    parser.add_argument("--include-w3c", action="store_true")
    parser.add_argument(
        "--resume",
        action="store_true",
        help="resume only the exact project after an interrupted up command",
    )
    parser.add_argument(
        "command",
        choices=("bootstrap-reviewer", "config", "up", "ps", "ports", "down"),
    )
    args = parser.parse_args()
    project = validate_project(args.project)
    command = compose_command(
        project,
        include_eudi=args.include_eudi,
        include_w3c=args.include_w3c,
    )

    if args.command == "down":
        # The validated project name and Compose labels precisely scope this
        # destructive operation; no container names, globs, or shared volumes
        # are used.
        return subprocess.run(
            [*command, "down", "--volumes", "--remove-orphans"], cwd=ROOT, check=False
        ).returncode

    config = rendered_config(
        project,
        include_eudi=args.include_eudi,
        include_w3c=args.include_w3c,
    )
    ports = validate_isolation(config, project)
    if args.command == "config":
        print(json.dumps(config, indent=2, sort_keys=True))
        return 0
    if args.command == "up":
        assert_ports_available(ports, project, resume=args.resume)
        return subprocess.run([*command, "up", "--detach", "--wait"], cwd=ROOT, check=False).returncode
    if args.command == "bootstrap-reviewer":
        if not project_container_ids(project):
            raise ValueError("bootstrap-reviewer requires an existing exact conformance project")
        return subprocess.run(
            [*command, "up", "--detach", "--force-recreate", "--no-deps", "keycloak-configurator"],
            cwd=ROOT,
            check=False,
        ).returncode
    if args.command == "ports":
        for service in sorted(PUBLIC_PORT_SERVICES & config.get("services", {}).keys()):
            subprocess.run([*command, "port", service, "443"], cwd=ROOT, check=True)
        return 0
    return subprocess.run([*command, "ps"], cwd=ROOT, check=False).returncode


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"Conformance stack error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
