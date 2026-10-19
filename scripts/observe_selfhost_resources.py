#!/usr/bin/env python3
"""Observe only disposable self-host projects during an installed rehearsal.

Run before starting the projects, then create --stop-file after their teardown.
The report contains numeric resource data and fixed Compose role names only.
It is supplemental evidence; the signed release and installed gates are separate.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import threading
import time
from pathlib import Path


APP_PROJECT = re.compile(r"marty-selfhost-qual-[0-9a-f]{16}\Z")
BAO_PROJECT = re.compile(r"marty-preview-[0-9a-f]{16}\Z")
BYTES = re.compile(r"([0-9]+(?:\.[0-9]+)?)(B|KiB|MiB|GiB|TiB)\Z")
ROLE = re.compile(r"[a-z][a-z0-9-]{0,80}\Z")
UNITS = {"B": 1, "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3,
         "TiB": 1024**4}


def docker(*args: str) -> str:
    result = subprocess.run(["docker", *args], capture_output=True, text=True,
                            timeout=30, check=True)
    return result.stdout


def bytes_used(memory_usage: str) -> int:
    match = BYTES.fullmatch(memory_usage.partition(" / ")[0])
    if not match:
        raise ValueError("Docker memory usage has an unexpected format")
    return round(float(match[1]) * UNITS[match[2]])


def host_memory() -> tuple[int, int, int]:
    values = {}
    for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines():
        name, _, value = line.partition(":")
        if name in {"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"}:
            number, unit = value.split()
            if unit != "kB":
                raise ValueError("Linux memory counter unit changed")
            values[name] = int(number) * 1024
    if len(values) != 4:
        raise ValueError("Linux memory counters are incomplete")
    return (values["MemTotal"], values["MemTotal"] - values["MemAvailable"],
            values["SwapTotal"] - values["SwapFree"])


def event_reader(project: str, events: list[int], errors: list[str],
                 ready: threading.Event) -> subprocess.Popen[str]:
    process = subprocess.Popen(
        ["docker", "events", "--filter", "type=container", "--filter",
         "event=oom", "--filter", f"label=com.docker.compose.project={project}",
         "--format", "{{json .}}"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
    )

    def read() -> None:
        ready.set()
        assert process.stdout is not None
        try:
            for line in process.stdout:
                item = json.loads(line)
                attributes = item.get("Actor", {}).get("Attributes", {})
                if (item.get("Action") == "oom"
                        and attributes.get("com.docker.compose.project") == project):
                    events.append(int(item.get("timeNano", 0)))
        except (TypeError, ValueError):
            errors.append("invalid Docker OOM event")

    threading.Thread(target=read, daemon=True).start()
    return process


def observe(app: str, bao: str, stop: Path, max_seconds: int,
            interval: float) -> dict:
    projects = (app, bao)
    events: dict[str, list[int]] = {project: [] for project in projects}
    errors: list[str] = []
    ready = [threading.Event() for _ in projects]
    watchers = [event_reader(project, events[project], errors, gate)
                for project, gate in zip(projects, ready)]
    if not all(gate.wait(5) for gate in ready):
        raise RuntimeError("Docker OOM watcher did not start")
    started = time.time()
    samples = 0
    max_host_used = 0
    max_host_swap = 0
    ram_bytes = None
    peak_by_role: dict[str, int] = {}
    observed_roles: set[str] = set()
    observed_oom_roles: set[str] = set()
    transient_sample_errors = 0
    try:
        while time.time() - started < max_seconds and not stop.exists():
            total, used, swap = host_memory()
            ram_bytes = total
            max_host_used = max(max_host_used, used)
            max_host_swap = max(max_host_swap, swap)
            for project in projects:
                running = docker("ps", "-q", "--filter",
                                 f"label=com.docker.compose.project={project}").split()
                if running:
                    try:
                        stat_lines = docker("stats", "--no-stream", "--format",
                                            "{{json .}}", *running).splitlines()
                    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                        # A one-shot or service may exit between ps and stats.
                        transient_sample_errors += 1
                        stat_lines = []
                    for line in stat_lines:
                        item = json.loads(line)
                        name = item["Name"]
                        prefix = project + "-"
                        if not name.startswith(prefix) or not name.endswith("-1"):
                            raise ValueError("Docker role name escaped the owned project")
                        role = name[len(prefix):-2]
                        if not ROLE.fullmatch(role):
                            raise ValueError("Docker role name is invalid")
                        key = ("app:" if project == app else "openbao:") + role
                        observed_roles.add(key)
                        peak_by_role[key] = max(peak_by_role.get(key, 0),
                                                bytes_used(item["MemUsage"]))
                all_ids = docker("ps", "-aq", "--filter",
                                 f"label=com.docker.compose.project={project}").split()
                if all_ids:
                    try:
                        inspect_lines = docker("inspect", "--format", "{{json .}}",
                                               *all_ids).splitlines()
                    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                        # Teardown can remove a container between listing and inspect.
                        transient_sample_errors += 1
                        inspect_lines = []
                    for line in inspect_lines:
                        item = json.loads(line)
                        if item.get("State", {}).get("OOMKilled") is True:
                            role = item.get("Config", {}).get("Labels", {}).get(
                                "com.docker.compose.service", "")
                            if not ROLE.fullmatch(role):
                                raise ValueError("OOM role name is invalid")
                            observed_oom_roles.add(
                                ("app:" if project == app else "openbao:") + role)
            samples += 1
            time.sleep(interval)
        # Let the daemon deliver any final OOM event before closing the streams.
        time.sleep(2)
    finally:
        watcher_health = all(process.poll() is None for process in watchers)
        for process in watchers:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=5)
    return {
        "schema": "marty.selfhost-resource-observation/v1",
        "qualification": "unqualified",
        "app_project": app,
        "openbao_project": bao,
        "linux_visible_ram_bytes": ram_bytes,
        "sample_count": samples,
        "max_observed_host_used_memory_bytes": max_host_used,
        "max_observed_host_swap_used_bytes": max_host_swap,
        "max_observed_container_memory_bytes_by_role": dict(sorted(peak_by_role.items())),
        "observed_role_count": len(observed_roles),
        "transient_sample_errors": transient_sample_errors,
        "oom_event_count": sum(len(value) for value in events.values()),
        "oom_inspect_roles": sorted(observed_oom_roles),
        "oom_event_stream_complete": watcher_health and not errors,
        "stopped_by_operator": stop.exists(),
        "elapsed_seconds": round(time.time() - started, 1),
        "limits": ["container memory peaks are sampled, not cgroup high-water marks",
                   "this report alone does not qualify a release or RAM minimum"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app-project", required=True)
    parser.add_argument("--openbao-project", required=True)
    parser.add_argument("--stop-file", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--max-seconds", type=int, default=1800)
    parser.add_argument("--interval", type=float, default=2.0)
    args = parser.parse_args()
    if (not APP_PROJECT.fullmatch(args.app_project)
            or not BAO_PROJECT.fullmatch(args.openbao_project)
            or args.max_seconds < 1 or args.max_seconds > 3600
            or not 0.5 <= args.interval <= 10
            or not args.stop_file.is_absolute() or args.stop_file.is_symlink()
            or args.stop_file.exists()
            or not args.output.is_absolute() or args.output.is_symlink()
            or args.stop_file.parent != args.output.parent
            or not args.output.parent.is_dir() or args.output.exists()):
        parser.error("resource observation inputs are not isolated and fresh")
    report = observe(args.app_project, args.openbao_project,
                     args.stop_file, args.max_seconds, args.interval)
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as sink:
        json.dump(report, sink, sort_keys=True, indent=2)
        sink.write("\n")
    print("Wrote redacted disposable resource observation")


if __name__ == "__main__":
    main()
