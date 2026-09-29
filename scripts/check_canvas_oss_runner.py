#!/usr/bin/env python3
"""Fail closed unless the local WSL runner is attached to the beta Docker daemon."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path


GIB = 1024**3
PASSPORT_PROJECT_PREFIX = "marty-passport-acceptance-"
PASSPORT_OWNER_LABEL = "com.marty.passport.acceptance.owner=supported-consumer"
PASSPORT_PROJECT_LABEL = "com.docker.compose.project=" + PASSPORT_PROJECT_PREFIX
REQUIRED_TOOLS = (
    "docker",
    "gh",
    "jq",
    "node",
    "python3",
    "curl",
    "openssl",
    "timeout",
)


def docker(*args: str) -> str:
    local_environment = os.environ.copy()
    local_environment["DOCKER_HOST"] = "unix:///var/run/docker.sock"
    for name in ("DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"):
        local_environment.pop(name, None)
    result = subprocess.run(["docker", *args], check=True, capture_output=True,
                            text=True, encoding="utf-8", timeout=30,
                            env=local_environment)
    return result.stdout.strip()


def check_passport_host_quarantine(
    runner=docker, temp_root: Path | None = None,
) -> None:
    """Refuse another one-job runner while disposable passport state remains."""
    root = temp_root or Path(tempfile.gettempdir())
    counts = {"containers": 0, "networks": 0, "volumes": 0, "staged_paths": 0}
    for kind, args, name_key in (
        ("containers", ("ps", "-a", "--format", "{{json .}}"), "Names"),
        ("networks", ("network", "ls", "--format", "{{json .}}"), "Name"),
        ("volumes", ("volume", "ls", "--format", "{{json .}}"), "Name"),
    ):
        for line in runner(*args).splitlines():
            item = json.loads(line)
            if not isinstance(item, dict):
                raise RuntimeError("Docker passport quarantine inventory is invalid")
            name, labels = item.get(name_key), item.get("Labels")
            if not isinstance(name, str) or not isinstance(labels, str):
                raise RuntimeError("Docker passport quarantine inventory is incomplete")
            if (name.startswith(PASSPORT_PROJECT_PREFIX)
                or re.search(r"(?:^|,)" + re.escape(PASSPORT_OWNER_LABEL)
                             + r"(?:,|$)", labels)
                or re.search(r"(?:^|,)" + re.escape(PASSPORT_PROJECT_LABEL), labels)):
                counts[kind] += 1
    counts["staged_paths"] = sum(
        path.name.startswith(PASSPORT_PROJECT_PREFIX) for path in root.iterdir()
    )
    if any(counts.values()):
        raise RuntimeError(
            "Disposable passport host is quarantined: "
            + ", ".join(f"{kind}={count}" for kind, count in counts.items())
        )


def runner_process_inventory() -> str:
    result = subprocess.run(["ps", "-eo", "comm=,args="], check=True,
                            capture_output=True, text=True, encoding="utf-8",
                            timeout=10)
    return result.stdout


def check_runner_process_quiescence(runner=runner_process_inventory) -> None:
    """Reject a surviving runner, rehearsal, or Docker startup client."""
    for line in runner().splitlines():
        fields = line.strip().split(maxsplit=1)
        if not fields:
            raise RuntimeError("Runner process inventory is incomplete")
        command = fields[0]
        arguments = fields[1] if len(fields) == 2 else ""
        active_runner = command in {"Runner.Listener", "Runner.Worker"}
        active_rehearsal = (
            command.startswith("python") or command in {"timeout", "bash", "sh"}
        ) and "passport_supported_infra_rehearsal.py" in arguments
        active_docker = (command in {"docker", "docker.exe"}
                         and PASSPORT_PROJECT_PREFIX in arguments)
        if active_runner or active_rehearsal or active_docker:
            raise RuntimeError("A prior passport runner or startup process is still active")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--host-setup",
        action="store_true",
        help="Validate the dedicated WSL host before ephemeral GitHub registration.",
    )
    args = parser.parse_args()
    try:
        if sys.platform != "linux" or not os.environ.get("WSL_INTEROP"):
            raise RuntimeError("canvas-oss-wsl2 runner must execute inside WSL2")
        os_release = Path("/etc/os-release").read_text(encoding="utf-8")
        if "ID=ubuntu" not in os_release or 'VERSION_ID="24.04"' not in os_release:
            raise RuntimeError("dedicated runner distribution must be Ubuntu 24.04 under WSL2")
        missing_tools = [name for name in REQUIRED_TOOLS if shutil.which(name) is None]
        if missing_tools:
            raise RuntimeError(f"dedicated runner is missing required tools: {', '.join(missing_tools)}")
        socket_path = Path("/var/run/docker.sock")
        try:
            socket_is_unix = stat.S_ISSOCK(socket_path.stat().st_mode)
        except OSError:
            socket_is_unix = False
        if not socket_is_unix:
            raise RuntimeError("Docker Desktop WSL integration socket /var/run/docker.sock is unavailable")
        if args.host_setup:
            check_runner_process_quiescence()
        if not args.host_setup:
            runner_name = os.environ.get("RUNNER_NAME", "")
            if not runner_name.startswith("canvas-oss-wsl2-"):
                raise RuntimeError("job is not executing on the dedicated Canvas OSS runner name")
            if os.environ.get("RUNNER_OS") != "Linux" or os.environ.get("RUNNER_ARCH") != "X64":
                raise RuntimeError("GitHub runner OS/architecture labels are not Linux/X64")
            if os.environ.get("CANVAS_OSS_RUNNER_LABELS_VERIFIED") != runner_name:
                raise RuntimeError("ephemeral runner labels were not verified before job startup")
        server_os = docker("info", "--format", "{{.OSType}}")
        compose_version = docker("compose", "version", "--short")
        if not compose_version:
            raise RuntimeError("Docker Compose v2 is unavailable on the orchestration runner")
        docker_memory = int(docker("info", "--format", "{{.MemTotal}}"))
        if server_os != "linux" or docker_memory < 12 * GIB:
            raise RuntimeError("Docker Desktop Linux daemon must expose at least 12 GiB")
        if shutil.disk_usage(Path.cwd()).free < 80 * GIB:
            raise RuntimeError("Canvas source image/runtime requires at least 80 GiB free")
        docker("network", "inspect", "marty-infra-network")
        required = {"tunnel-nginx-proxy", "cloudflared-tunnel"}
        states = {
            name: docker("inspect", name, "--format", "{{.State.Running}}")
            for name in required
        }
        if any(value != "true" for value in states.values()):
            raise RuntimeError("existing beta tunnel containers must remain running")
        check_passport_host_quarantine()
        report = {
            "schema_version": 1,
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "runner_class": "ephemeral_wsl2",
            "host_setup_only": args.host_setup,
            "ubuntu_version": "24.04",
            "required_tools_available": True,
            "docker_socket_available": True,
            "github_labels_verified": not args.host_setup,
            "docker_server_os": server_os,
            "docker_compose_version": compose_version,
            "docker_memory_gib": round(docker_memory / GIB, 1),
            "free_disk_gib": round(shutil.disk_usage(Path.cwd()).free / GIB, 1),
            "beta_network": "marty-infra-network",
            "beta_tunnel_running": True,
            "docker_desktop_shutdown_allowed": False,
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except Exception as exc:
        print(f"Canvas OSS runner preflight failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
