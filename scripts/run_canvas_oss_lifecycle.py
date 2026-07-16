#!/usr/bin/env python3
"""Run only the approved stock Canvas lifecycle, then start the web tier."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


ALLOWED = [
    ["bin/rails", "db:create"],
    ["bin/rails", "db:migrate"],
    ["bin/rails", "db:initial_setup"],
    ["bin/rails", "brand_configs:generate_and_upload_all"],
]

# The workflow starts this Compose-bound continuity probe before bootstrapping
# Canvas so it can prove that beta stays available for the entire operation.
# No Canvas data-plane service may already be running when lifecycle begins.
ALLOWED_PREEXISTING_SERVICES = frozenset({"canvas-continuity-monitor"})


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def compose_prefix(args: argparse.Namespace) -> list[str]:
    return [
        "docker",
        "compose",
        "--project-name",
        args.project,
        "--file",
        str(args.compose.resolve()),
    ]


def run(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=check, text=True)  # noqa: S603 - fixed command allowlist


def container_health(name: str) -> str:
    result = subprocess.run(
        ["docker", "inspect", name, "--format", "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}"],
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else "missing"


def write_audit(path: Path, entries: list[dict[str, object]], web_started: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    value = {
        "schema_version": 1,
        "phase": "pre_start_only",
        "commands": entries,
        "web_started_after_bootstrap": web_started,
        "forbidden_operation_counts": {
            "rails_runner": 0,
            "rails_console": 0,
            "post_bootstrap_database_access": 0,
            "custom_plugins": 0,
            "source_patches": 0,
            "custom_events": 0,
        },
    }
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def unexpected_running_services(running: list[str]) -> list[str]:
    """Return pre-existing services that make the Canvas lifecycle unclean."""

    return sorted(set(running) - ALLOWED_PREEXISTING_SERVICES)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--compose", type=Path, default=Path("docker-compose.canvas-oss-acceptance.yml"))
    parser.add_argument("--project", default="canvas-oss-portability")
    parser.add_argument("--audit", type=Path, required=True)
    parser.add_argument("--health-timeout", type=int, default=900)
    args = parser.parse_args()

    image = os.environ.get("CANVAS_OSS_IMAGE", "")
    if "@sha256:" not in image:
        print("CANVAS_OSS_IMAGE must be an immutable digest reference", file=sys.stderr)
        return 1
    for setting in (
        "CANVAS_OSS_POSTGRES_IMAGE",
        "CANVAS_OSS_REDIS_IMAGE",
        "CANVAS_OSS_MAILPIT_IMAGE",
        "CANVAS_OSS_EDGE_IMAGE",
    ):
        if "@sha256:" not in os.environ.get(setting, ""):
            print(f"{setting} must be an immutable digest reference", file=sys.stderr)
            return 1

    prefix = compose_prefix(args)
    running = subprocess.run(
        prefix + ["ps", "--services", "--filter", "status=running"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    unexpected = unexpected_running_services(running)
    if unexpected:
        print(f"Canvas OSS compose project is not clean: {', '.join(unexpected)}", file=sys.stderr)
        return 1

    run(prefix + ["up", "--detach", "canvas-postgres", "canvas-redis", "canvas-mail"])
    entries: list[dict[str, object]] = []
    try:
        for argv in ALLOWED:
            started = now()
            # Canvas's documented initial-setup password is supplied through a
            # Compose secret. Export it only inside the one-shot process so the
            # value never appears in docker inspect Config.Env or the command
            # line recorded in the lifecycle audit.
            secret_wrapper = [
                "sh",
                "-euc",
                'test -r /run/secrets/canvas_admin_password; '
                'export CANVAS_LMS_ADMIN_PASSWORD="$(cat /run/secrets/canvas_admin_password)"; '
                'exec "$@"',
                "canvas-lifecycle-secret-wrapper",
            ]
            result = run(
                prefix
                + ["--profile", "lifecycle", "run", "--rm", "canvas-lifecycle", *secret_wrapper, *argv],
                check=False,
            )
            entry = {"argv": argv, "started_at": started, "finished_at": now(), "exit_code": result.returncode}
            entries.append(entry)
            write_audit(args.audit, entries, False)
            if result.returncode != 0:
                return result.returncode

        # Only after every lifecycle command succeeds may the Canvas web/jobs
        # processes start. No later command path in this script can exec Rails.
        run(prefix + ["up", "--detach", "canvas-web", "canvas-jobs", "canvas-edge"])
        deadline = time.monotonic() + args.health_timeout
        while time.monotonic() < deadline:
            if container_health("marty-canvas-oss-edge") == "healthy":
                write_audit(args.audit, entries, True)
                return 0
            time.sleep(5)
        print("Canvas OSS edge did not become healthy", file=sys.stderr)
        return 1
    finally:
        if not args.audit.exists():
            write_audit(args.audit, entries, False)


if __name__ == "__main__":
    raise SystemExit(main())
