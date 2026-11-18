"""Shared bounded Docker and runner quiescence checks; no provider runtime."""
from __future__ import annotations

import os
import subprocess
import json
import re
import tempfile
from pathlib import Path



GIB = 1024**3


PASSPORT_PROJECT_PREFIX = "marty-passport-acceptance-"


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
        ) and any(name in arguments for name in (
            "passport_supported_infra_rehearsal.py",
            "passport_supported_certificate_rehearsal.py",
        ))
        active_docker = (command in {"docker", "docker.exe"}
                         and PASSPORT_PROJECT_PREFIX in arguments)
        if active_runner or active_rehearsal or active_docker:
            raise RuntimeError("A prior passport runner or startup process is still active")


PASSPORT_OWNER_LABEL = "com.marty.passport.acceptance.owner=supported-consumer"


PASSPORT_PROJECT_LABEL = "com.docker.compose.project=" + PASSPORT_PROJECT_PREFIX


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
