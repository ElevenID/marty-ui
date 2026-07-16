#!/usr/bin/env python3
"""Fail closed unless the local WSL runner is attached to the beta Docker daemon."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


GIB = 1024**3
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
    result = subprocess.run(["docker", *args], check=True, capture_output=True, text=True)
    return result.stdout.strip()


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
