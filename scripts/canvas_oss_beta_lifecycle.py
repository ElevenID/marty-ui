#!/usr/bin/env python3
"""Protect the live beta fixture while an ephemeral Canvas replaces its LMS."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


BETA_ORIGIN = "https://beta.elevenidllc.com"
CANVAS_ORIGIN = "https://canvas-test.elevenidllc.com"
STOP_ALLOWLIST = (
    "marty-canvas-real",
    "marty-canvas-sandbox",
    "marty-issuance-canvas-localhost-bridge",
)


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def get(url: str) -> tuple[int, bytes]:
    request = urllib.request.Request(url, headers={"Cache-Control": "no-cache", "User-Agent": "canvas-oss-portability/1"})
    with urllib.request.urlopen(request, timeout=20) as response:  # noqa: S310 - fixed public origins
        return response.status, response.read()


def assert_beta() -> dict[str, str]:
    status, ready = get(f"{BETA_ORIGIN}/ready")
    if status != 200:
        raise RuntimeError("beta readiness check failed")
    services = json.loads(get(f"{BETA_ORIGIN}/.well-known/marty-release")[1])
    ui = json.loads(get(f"{BETA_ORIGIN}/marty-ui-release.json")[1])
    if services.get("release_version") != ui.get("release_version") or services.get("marty_ui_sha") != ui.get("marty_ui_sha"):
        raise RuntimeError("beta UI and services release markers differ")
    return {"release_version": services["release_version"], "source_id": services["marty_ui_sha"]}


def is_running(name: str) -> bool:
    result = subprocess.run(
        ["docker", "inspect", name, "--format", "{{.State.Running}}"],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0 and result.stdout.strip() == "true"


def prepare(state_path: Path) -> None:
    subprocess.run(["docker", "network", "inspect", "marty-infra-network"], check=True, capture_output=True)
    release = assert_beta()
    running = [name for name in STOP_ALLOWLIST if is_running(name)]
    state = {
        "schema_version": 1,
        "prepared_at": now(),
        "stop_allowlist": list(STOP_ALLOWLIST),
        "previously_running": running,
        "beta_release": release,
        "docker_desktop_stopped": False,
        "beta_core_stopped": False,
        "selfhost_production_touched": False,
    }
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for name in running:
        subprocess.run(["docker", "stop", "--time", "30", name], check=True)
    assert_beta()


def restore(state_path: Path) -> None:
    state = json.loads(state_path.read_text(encoding="utf-8"))
    if state.get("stop_allowlist") != list(STOP_ALLOWLIST):
        raise RuntimeError("beta lifecycle state allowlist was modified")
    for name in state.get("previously_running", []):
        if name not in STOP_ALLOWLIST or "selfhost" in name:
            raise RuntimeError(f"refusing to restore non-allowlisted container: {name}")
        subprocess.run(["docker", "start", name], check=True)
    assert_beta()


def assert_canvas() -> None:
    status, body = get(f"{CANVAS_ORIGIN}/login/canvas")
    if status != 200 or not body:
        raise RuntimeError("public Canvas login is not healthy")


def monitor(output: Path, stop_file: Path, interval: int) -> None:
    report = {"schema_version": 1, "started_at": now(), "finished_at": None, "checks": 0, "failures": 0}
    output.parent.mkdir(parents=True, exist_ok=True)
    while not stop_file.exists():
        report["checks"] += 1
        try:
            assert_beta()
        except Exception:
            report["failures"] += 1
        output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        time.sleep(interval)
    report["finished_at"] = now()
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def assert_monitor(path: Path) -> None:
    report = json.loads(path.read_text(encoding="utf-8"))
    if report.get("checks", 0) < 1 or report.get("failures") != 0 or not report.get("finished_at"):
        raise RuntimeError("beta continuity monitor recorded an outage or did not finish")


def main() -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("prepare", "restore"):
        sub = commands.add_parser(name)
        sub.add_argument("--state", type=Path, required=True)
    commands.add_parser("assert-beta")
    commands.add_parser("assert-canvas")
    mon = commands.add_parser("monitor")
    mon.add_argument("--output", type=Path, required=True)
    mon.add_argument("--stop-file", type=Path, required=True)
    mon.add_argument("--interval", type=int, default=30)
    check = commands.add_parser("assert-monitor")
    check.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            prepare(args.state)
        elif args.command == "restore":
            restore(args.state)
        elif args.command == "assert-beta":
            assert_beta()
        elif args.command == "assert-canvas":
            assert_canvas()
        elif args.command == "monitor":
            monitor(args.output, args.stop_file, args.interval)
        else:
            assert_monitor(args.output)
    except Exception as exc:
        print(f"Canvas OSS beta lifecycle failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
