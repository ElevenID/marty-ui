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
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
PROJECT = re.compile(r"^marty-conformance-[a-z0-9](?:[a-z0-9-]{1,46}[a-z0-9])?$")
BASE_FILES = (
    "docker-compose.base.yml",
    "docker-compose.profile.oidf.yml",
)
GHCR_FILE = "docker-compose.profile.ghcr.yml"
W3C_FILE = "docker-compose.profile.w3c-vc.yml"
ISOLATION_FILE = "docker-compose.profile.conformance.yml"
PUBLIC_PORT_SERVICES = {"oidf-tls-proxy"}
LOCAL_BUILD_ARGS = (
    "MARTY_RS_URI",
    "MARTY_RS_DIGEST",
    "MARTY_COMMON_URI",
    "MARTY_COMMON_DIGEST",
)


def validate_project(project: str) -> str:
    if not PROJECT.fullmatch(project):
        raise ValueError(
            "project must match marty-conformance-<run-id> using lowercase letters, digits, and hyphens"
        )
    return project


def compose_command(project: str, *, include_w3c: bool = False, use_ghcr: bool = True) -> list[str]:
    command = ["docker", "compose", "--project-name", validate_project(project)]
    files = [*BASE_FILES]
    if use_ghcr:
        files.insert(1, GHCR_FILE)
    if include_w3c:
        files.append(W3C_FILE)
    files.append(ISOLATION_FILE)
    for compose_file in files:
        command.extend(["--file", os.fspath(ROOT / compose_file)])
    command.extend(["--profile", "oidf"])
    return command


def rendered_config(project: str, *, include_w3c: bool = False, use_ghcr: bool = True) -> dict[str, Any]:
    completed = subprocess.run(
        [
            *compose_command(project, include_w3c=include_w3c, use_ghcr=use_ghcr),
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


def local_build_arguments() -> list[str]:
    """Return explicit immutable bootstrap build arguments for source runs."""
    missing = [name for name in LOCAL_BUILD_ARGS if not os.environ.get(name, "").strip()]
    if missing:
        raise ValueError(
            "--local-build requires published, digest-pinned bootstrap artifacts: "
            + ", ".join(missing)
        )
    values: list[str] = []
    for name in LOCAL_BUILD_ARGS:
        values.extend(["--build-arg", f"{name}={os.environ[name]}"])
    return values


def configure_oidf_internal_tls_port() -> None:
    """Keep the bridge listener identical to the published HTTPS origin.

    Docker port publishing applies only to host traffic. The separately
    composed official runner reaches the TLS proxy over its narrow bridge, so
    the proxy itself must listen on the URL's port. The helper derives that
    value once and rejects contradictory operator configuration.
    """
    value = os.environ.get("OIDF_PUBLIC_BASE_URL", "").strip()
    if not value:
        # Compose owns the required-variable diagnostic. Keeping this helper a
        # no-op until an OIDF origin is supplied lets non-rendering commands
        # retain their narrower project-safety validation.
        return
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("OIDF_PUBLIC_BASE_URL must be an absolute HTTPS URL")
    port = str(parsed.port or 443)
    configured = os.environ.get("OIDF_INTERNAL_TLS_PORT", "").strip()
    if configured and configured != port:
        raise ValueError("OIDF_INTERNAL_TLS_PORT must equal the port in OIDF_PUBLIC_BASE_URL")
    os.environ["OIDF_INTERNAL_TLS_PORT"] = port


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--project",
        default=os.environ.get("MARTY_CONFORMANCE_PROJECT", ""),
        help="unique marty-conformance-<run-id> project name",
    )
    parser.add_argument("--include-w3c", action="store_true")
    parser.add_argument("--local-build", action="store_true", help="build the checked-out source; never certification-grade evidence")
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
    configure_oidf_internal_tls_port()
    command = compose_command(
        project,
        include_w3c=args.include_w3c,
        use_ghcr=not args.local_build,
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
        include_w3c=args.include_w3c,
        use_ghcr=not args.local_build,
    )
    ports = validate_isolation(config, project)
    if args.command == "config":
        print(json.dumps(config, indent=2, sort_keys=True))
        return 0
    if args.command == "up":
        assert_ports_available(ports, project, resume=args.resume)
        if args.local_build:
            build_result = subprocess.run(
                [*command, "build", *local_build_arguments()], cwd=ROOT, check=False
            )
            if build_result.returncode:
                return build_result.returncode
            return subprocess.run(
                # Keycloak configuration is intentionally a one-shot service.
                # Compose's --wait treats its successful exit as an error even
                # after every long-running service becomes healthy.
                [*command, "up", "--detach", "--no-build"], cwd=ROOT, check=False
            ).returncode
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
