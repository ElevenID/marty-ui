#!/usr/bin/env python3
"""Fail closed unless the candidate builder uses the exact reviewed backend."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Callable, Sequence
from typing import NoReturn

EXPECTED_DOCKER = "29.7.2"
EXPECTED_BUILDX = "v0.36.1"
EXPECTED_BUILDKIT = "v0.32.2"
EXPECTED_DRIVER = "docker-container"
EXPECTED_DRIVER_OPTION = (
    "image=moby/buildkit@"
    "sha256:28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8"
)
EXPECTED_DRIVER_STATUS = [["driver-type", "io.containerd.snapshotter.v1"]]
MAX_NODES_JSON_BYTES = 65_536
COMMAND_TIMEOUT_SECONDS = 30


class BackendContractError(ValueError):
    """The live builder is outside the reviewed candidate contract."""


TextRunner = Callable[[Sequence[str]], str]
CheckRunner = Callable[[Sequence[str]], None]


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise BackendContractError(message)


def _run_text(command: Sequence[str]) -> str:
    return subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        timeout=COMMAND_TIMEOUT_SECONDS,
    ).stdout


def _run_check(command: Sequence[str]) -> None:
    subprocess.run(
        command,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=COMMAND_TIMEOUT_SECONDS,
    )


def _nodes(nodes_json: str) -> list[object]:
    _require(
        len(nodes_json.encode("utf-8")) <= MAX_NODES_JSON_BYTES,
        "Buildx node metadata is too large",
    )
    try:
        nodes = json.loads(nodes_json)
    except json.JSONDecodeError as error:
        raise BackendContractError("Buildx node metadata is invalid") from error
    _require(isinstance(nodes, list), "Buildx node metadata changed")
    return nodes


def require_exact_backend(
    nodes_json: str,
    driver: str,
    *,
    run_text: TextRunner = _run_text,
    run_check: CheckRunner = _run_check,
) -> None:
    _require(driver == EXPECTED_DRIVER, "Buildx driver changed")
    docker_version = run_text(
        ["docker", "version", "--format", "{{.Server.Version}}"]
    ).strip()
    _require(docker_version == EXPECTED_DOCKER, "Docker version changed")

    buildx_fields = run_text(["docker", "buildx", "version"]).split()
    _require(
        len(buildx_fields) >= 2 and buildx_fields[1] == EXPECTED_BUILDX,
        "Buildx version changed",
    )

    # This standalone checked command makes a nonzero or timed-out live
    # inspection fatal; structured version checks below cannot mask it.
    run_check(["docker", "buildx", "inspect", "--bootstrap"])

    nodes = _nodes(nodes_json)
    _require(len(nodes) == 1, "Buildx must expose exactly one node")
    node = nodes[0]
    _require(isinstance(node, dict), "Buildx node metadata changed")
    _require(node.get("status") == "running", "Buildx node is not running")
    _require(node.get("buildkit") == EXPECTED_BUILDKIT, "BuildKit version changed")
    _require(
        node.get("driver-opts") == [EXPECTED_DRIVER_OPTION],
        "BuildKit image selection changed",
    )
    platforms = node.get("platforms")
    _require(isinstance(platforms, str), "Buildx node platforms changed")
    _require(
        "linux/amd64" in {value.strip() for value in platforms.split(",")},
        "Buildx node does not support linux/amd64",
    )

    driver_status_raw = run_text(
        ["docker", "info", "--format", "{{json .DriverStatus}}"]
    )
    try:
        driver_status = json.loads(driver_status_raw)
    except json.JSONDecodeError as error:
        raise BackendContractError("Docker driver status is invalid") from error
    _require(
        driver_status == EXPECTED_DRIVER_STATUS,
        "Docker containerd image store changed",
    )


def _fail(message: str) -> NoReturn:
    print(f"verification candidate backend contract failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> int:
    try:
        require_exact_backend(
            os.environ.get("MARTY_BUILDX_NODES_JSON", ""),
            os.environ.get("MARTY_BUILDX_DRIVER", ""),
        )
    except (BackendContractError, subprocess.SubprocessError):
        _fail("unsupported or unavailable backend")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
