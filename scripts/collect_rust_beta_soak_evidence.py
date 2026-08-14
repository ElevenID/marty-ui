#!/usr/bin/env python3
"""Collect fail-closed, sanitized beta soak evidence for Rust services."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.request import Request, urlopen


SHA_RE = re.compile(r"^[0-9a-f]{40}$")
PROMETHEUS_SAMPLE_RE = re.compile(
    r"^([^#\s]+)\s+([-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?)$"
)
EXPECTED_REVOCATION_CAPABILITIES = {
    "profile-lifecycle",
    "status-allocation",
    "status-mutation",
    "status-document",
    "cascade-revocation",
    "revocation-batch",
}
SERVICE_PORTS = {
    "event-stream": "8015/tcp",
    "revocation-profile": "8013/tcp",
}


class EvidenceError(RuntimeError):
    pass


CommandRunner = Callable[[list[str]], str]
JsonLoader = Callable[[str], dict[str, Any]]
TextLoader = Callable[[str], str]


def _run(command: list[str]) -> str:
    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise EvidenceError(f"Command failed: {' '.join(command[:3])}") from exc
    output = result.stdout
    if command[:2] == ["docker", "logs"] and result.stderr:
        output += "\n" + result.stderr
    return output.strip()


def _load_json_url(url: str) -> dict[str, Any]:
    try:
        request = Request(
            url,
            headers={
                "Accept": "application/json",
                "Cache-Control": "no-cache",
                "User-Agent": "rust-beta-soak-evidence/1",
            },
        )
        with urlopen(request, timeout=15) as response:
            value = json.load(response)
    except Exception as exc:  # urllib exposes several transport-specific errors.
        raise EvidenceError(f"Could not read JSON evidence endpoint: {url}") from exc
    if not isinstance(value, dict):
        raise EvidenceError(f"Evidence endpoint did not return an object: {url}")
    return value


def _load_text_url(url: str) -> str:
    try:
        request = Request(
            url,
            headers={"Accept": "text/plain", "User-Agent": "rust-beta-soak-evidence/1"},
        )
        with urlopen(request, timeout=15) as response:
            return response.read().decode("utf-8")
    except Exception as exc:  # urllib exposes several transport-specific errors.
        raise EvidenceError(f"Could not read text evidence endpoint: {url}") from exc


def _parse_prometheus(text: str, allowed_prefix: str) -> dict[str, float]:
    metrics: dict[str, float] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        match = PROMETHEUS_SAMPLE_RE.fullmatch(line)
        if match and match.group(1).startswith(allowed_prefix):
            metrics[match.group(1)] = float(match.group(2))
    return metrics


def _container_id(project: str, service: str, run: CommandRunner) -> str:
    output = run(
        [
            "docker",
            "ps",
            "--filter",
            f"label=com.docker.compose.project={project}",
            "--filter",
            f"label=com.docker.compose.service={service}",
            "--format",
            "{{.ID}}",
        ]
    )
    ids = [line.strip() for line in output.splitlines() if line.strip()]
    if len(ids) != 1:
        raise EvidenceError(
            f"Expected one running {project}/{service} container, found {len(ids)}"
        )
    return ids[0]


def _container_evidence(
    project: str, service: str, run: CommandRunner, lookback_hours: int
) -> dict[str, Any]:
    container_id = _container_id(project, service, run)
    inspection = json.loads(run(["docker", "inspect", container_id]))
    if not isinstance(inspection, list) or len(inspection) != 1:
        raise EvidenceError(f"Docker inspect returned an invalid record for {service}")
    record = inspection[0]
    state = record.get("State") or {}
    config = record.get("Config") or {}
    labels = config.get("Labels") or {}
    ports = (record.get("NetworkSettings") or {}).get("Ports") or {}
    bindings = ports.get(SERVICE_PORTS[service]) or []
    host_ports = {
        str(binding.get("HostPort") or "")
        for binding in bindings
        if str(binding.get("HostPort") or "").isdigit()
    }
    if len(host_ports) != 1:
        raise EvidenceError(f"Could not resolve the published HTTP port for {service}")
    host_port = next(iter(host_ports))

    stats_raw = run(
        ["docker", "stats", "--no-stream", "--format", "{{json .}}", container_id]
    )
    try:
        stats = json.loads(stats_raw)
    except json.JSONDecodeError as exc:
        raise EvidenceError(
            f"Docker stats returned invalid JSON for {service}"
        ) from exc
    logs = run(["docker", "logs", "--since", f"{lookback_hours}h", container_id])
    log_counts = {
        "error": len(re.findall(r'"level":"ERROR"|\bERROR\b', logs, re.IGNORECASE)),
        "warning": len(
            re.findall(r'"level":"WARN"|\bWARN(?:ING)?\b', logs, re.IGNORECASE)
        ),
        "panic": len(re.findall(r"\bpanic(?:ked)?\b", logs, re.IGNORECASE)),
    }

    return {
        "service": service,
        "container_id": str(record.get("Id") or container_id)[:12],
        "configured_image": config.get("Image"),
        "image_id": record.get("Image"),
        "release_version": labels.get("org.opencontainers.image.version"),
        "source_revision": labels.get("org.opencontainers.image.revision"),
        "started_at": state.get("StartedAt"),
        "running": state.get("Status") == "running",
        "health": (state.get("Health") or {}).get("Status"),
        "restart_count": int(record.get("RestartCount") or 0),
        "http_origin": f"http://127.0.0.1:{host_port}",
        "resources": {
            "cpu_percent": stats.get("CPUPerc"),
            "memory_usage": stats.get("MemUsage"),
            "network_io": stats.get("NetIO"),
            "block_io": stats.get("BlockIO"),
            "pids": stats.get("PIDs"),
        },
        "log_lookback_hours": lookback_hours,
        "log_counts": log_counts,
    }


def _check(
    checks: list[dict[str, Any]], check_id: str, condition: bool, observed: Any
) -> None:
    checks.append(
        {
            "id": check_id,
            "status": "pass" if condition else "fail",
            "observed": observed,
        }
    )


def collect(
    *,
    project: str,
    beta_origin: str,
    release_version: str,
    source_revision: str,
    lookback_hours: int,
    run: CommandRunner = _run,
    load_json: JsonLoader = _load_json_url,
    load_text: TextLoader = _load_text_url,
) -> dict[str, Any]:
    if not SHA_RE.fullmatch(source_revision):
        raise EvidenceError(
            "source_revision must be a full lowercase commit or source-snapshot ID"
        )
    if not beta_origin.startswith("https://"):
        raise EvidenceError("beta_origin must use HTTPS")
    if not project or not release_version or lookback_hours < 1:
        raise EvidenceError(
            "project, release_version, and a positive lookback are required"
        )

    services_marker = load_json(f"{beta_origin.rstrip('/')}/.well-known/marty-release")
    ui_marker = load_json(f"{beta_origin.rstrip('/')}/marty-ui-release.json")
    containers = {
        name: _container_evidence(project, name, run, lookback_hours)
        for name in SERVICE_PORTS
    }
    event = containers["event-stream"]
    revocation = containers["revocation-profile"]
    event_health = {
        path: load_json(f"{event['http_origin']}{path}")
        for path in ("/health", "/ready", "/startup")
    }
    revocation_health = {
        path: load_json(f"{revocation['http_origin']}{path}")
        for path in ("/health", "/ready", "/startup", "/health/native-backend")
    }
    event_metrics = _parse_prometheus(
        load_text(f"{event['http_origin']}/metrics"),
        "marty_event_stream_",
    )
    revocation_metrics = _parse_prometheus(
        load_text(f"{revocation['http_origin']}/metrics"),
        "marty_revocation_profile_",
    )

    checks: list[dict[str, Any]] = []
    for name, marker in (("services", services_marker), ("ui", ui_marker)):
        _check(
            checks,
            f"runtime-{name}-release",
            marker.get("release_version") == release_version,
            marker.get("release_version"),
        )
        _check(
            checks,
            f"runtime-{name}-source",
            marker.get("marty_ui_sha") == source_revision,
            marker.get("marty_ui_sha"),
        )
    for name, container in containers.items():
        _check(
            checks,
            f"{name}-running",
            container["running"] is True,
            container["running"],
        )
        _check(
            checks,
            f"{name}-healthy",
            container["health"] == "healthy",
            container["health"],
        )
        _check(
            checks,
            f"{name}-zero-restarts",
            container["restart_count"] == 0,
            container["restart_count"],
        )
        _check(
            checks,
            f"{name}-release",
            container["release_version"] == release_version,
            container["release_version"],
        )
        _check(
            checks,
            f"{name}-source",
            container["source_revision"] == source_revision,
            container["source_revision"],
        )
        _check(
            checks,
            f"{name}-no-errors",
            container["log_counts"]["error"] == 0,
            container["log_counts"]["error"],
        )
        _check(
            checks,
            f"{name}-no-panics",
            container["log_counts"]["panic"] == 0,
            container["log_counts"]["panic"],
        )

    _check(
        checks,
        "event-health",
        event_health["/health"].get("status") == "healthy",
        event_health["/health"].get("status"),
    )
    _check(
        checks,
        "event-ready",
        event_health["/ready"].get("status") == "ready",
        event_health["/ready"].get("status"),
    )
    _check(
        checks,
        "event-started",
        event_health["/startup"].get("status") == "started",
        event_health["/startup"].get("status"),
    )
    _check(
        checks,
        "event-zero-drops",
        event_metrics.get("marty_event_stream_dropped_total") == 0,
        event_metrics.get("marty_event_stream_dropped_total"),
    )

    ready = revocation_health["/ready"]
    native = revocation_health["/health/native-backend"]
    _check(
        checks, "revocation-ready", ready.get("status") == "ready", ready.get("status")
    )
    expected_dependencies = {"organization": True, "postgres": True, "redis": True}
    _check(
        checks,
        "revocation-dependencies",
        ready.get("components") == expected_dependencies,
        ready.get("components"),
    )
    _check(
        checks,
        "revocation-native-available",
        native.get("available") is True,
        native.get("available"),
    )
    _check(
        checks,
        "revocation-native-backend",
        native.get("backend") == "marty-status-rust",
        native.get("backend"),
    )
    _check(
        checks,
        "revocation-native-release",
        native.get("release_version") == release_version,
        native.get("release_version"),
    )
    _check(
        checks,
        "revocation-native-source",
        native.get("build_revision") == source_revision,
        native.get("build_revision"),
    )
    _check(
        checks,
        "revocation-native-capabilities",
        set(native.get("capabilities") or []) == EXPECTED_REVOCATION_CAPABILITIES,
        sorted(native.get("capabilities") or []),
    )
    _check(
        checks,
        "revocation-native-metric",
        revocation_metrics.get("marty_revocation_profile_native_backend_ready") == 1,
        revocation_metrics.get("marty_revocation_profile_native_backend_ready"),
    )

    failed = [item["id"] for item in checks if item["status"] != "pass"]
    return {
        "schema": "marty.rust-beta-soak/v1",
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "beta_origin": beta_origin.rstrip("/"),
        "compose_project": project,
        "release_version": release_version,
        "source_revision": source_revision,
        "overall_valid": not failed,
        "failed_checks": failed,
        "checks": checks,
        "runtime_markers": {"services": services_marker, "ui": ui_marker},
        "services": containers,
        "health": {
            "event_stream": event_health,
            "revocation_profile": revocation_health,
        },
        "metrics": {
            "event_stream": event_metrics,
            "revocation_profile": revocation_metrics,
        },
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--compose-project", required=True)
    parser.add_argument("--beta-origin", required=True)
    parser.add_argument("--release-version", required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--log-lookback-hours", type=int, default=24)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    try:
        report = collect(
            project=args.compose_project,
            beta_origin=args.beta_origin,
            release_version=args.release_version,
            source_revision=args.source_revision,
            lookback_hours=args.log_lookback_hours,
        )
    except EvidenceError as exc:
        report = {
            "schema": "marty.rust-beta-soak/v1",
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "beta_origin": args.beta_origin.rstrip("/"),
            "compose_project": args.compose_project,
            "release_version": args.release_version,
            "source_revision": args.source_revision,
            "overall_valid": False,
            "failed_checks": ["collector-error"],
            "collector_error": str(exc),
        }
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Rust beta soak evidence: {'PASS' if report['overall_valid'] else 'FAIL'}")
    if report["failed_checks"]:
        print("Failed checks: " + ", ".join(report["failed_checks"]))
    return 0 if report["overall_valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
