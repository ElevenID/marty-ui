from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "collect_rust_beta_soak_evidence",
    ROOT / "scripts/collect_rust_beta_soak_evidence.py",
)
assert SPEC and SPEC.loader
COLLECTOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COLLECTOR)

RELEASE = "1.1.160"
SOURCE = "a" * 40
BETA = "https://beta.elevenidllc.com"


def _inspection(service: str, port: str, *, restarts: int = 0) -> dict:
    return {
        "Id": f"{service}-container-id",
        "Image": f"sha256:{'b' * 64}",
        "RestartCount": restarts,
        "State": {
            "Status": "running",
            "StartedAt": "2026-08-13T21:41:49Z",
            "Health": {"Status": "healthy"},
        },
        "Config": {
            "Image": f"elevenid-local/{service}:{RELEASE}",
            "Labels": {
                "org.opencontainers.image.version": RELEASE,
                "org.opencontainers.image.revision": SOURCE,
            },
        },
        "NetworkSettings": {
            "Ports": {
                f"{port}/tcp": [
                    {"HostIp": "0.0.0.0", "HostPort": port},
                    {"HostIp": "::", "HostPort": port},
                ]
            }
        },
    }


def _dependencies(*, restarts: int = 0, dropped: int = 0):
    ids = {"event-stream": "event-id", "revocation-profile": "revocation-id"}
    inspections = {
        "event-id": _inspection("event-stream", "8015", restarts=restarts),
        "revocation-id": _inspection("revocation-profile", "8013"),
    }

    def run(command: list[str]) -> str:
        if command[:2] == ["docker", "ps"]:
            service_filter = next(
                item
                for item in command
                if item.startswith("label=com.docker.compose.service=")
            )
            return ids[service_filter.rsplit("=", 1)[1]]
        if command[:2] == ["docker", "inspect"]:
            return json.dumps([inspections[command[2]]])
        if command[:2] == ["docker", "stats"]:
            return json.dumps(
                {
                    "CPUPerc": "0.00%",
                    "MemUsage": "4MiB / 16GiB",
                    "NetIO": "1kB / 2kB",
                    "BlockIO": "3kB / 0B",
                    "PIDs": "25",
                }
            )
        if command[:2] == ["docker", "logs"]:
            return '{"level":"INFO","fields":{"message":"healthy"}}'
        raise AssertionError(command)

    json_documents = {
        f"{BETA}/.well-known/marty-release": {
            "component": "services",
            "release_version": RELEASE,
            "marty_ui_sha": SOURCE,
        },
        f"{BETA}/marty-ui-release.json": {
            "component": "ui",
            "release_version": RELEASE,
            "marty_ui_sha": SOURCE,
        },
        "http://127.0.0.1:8015/health": {
            "status": "healthy",
            "service": "event-stream",
        },
        "http://127.0.0.1:8015/ready": {"status": "ready", "service": "event-stream"},
        "http://127.0.0.1:8015/startup": {
            "status": "started",
            "service": "event-stream",
        },
        "http://127.0.0.1:8013/health": {
            "status": "healthy",
            "service": "revocation-profile-service",
        },
        "http://127.0.0.1:8013/ready": {
            "status": "ready",
            "components": {"organization": True, "postgres": True, "redis": True},
        },
        "http://127.0.0.1:8013/startup": {
            "status": "started",
            "service": "revocation-profile-service",
        },
        "http://127.0.0.1:8013/health/native-backend": {
            "available": True,
            "backend": "marty-status-rust",
            "release_version": RELEASE,
            "build_revision": SOURCE,
            "capabilities": sorted(COLLECTOR.EXPECTED_REVOCATION_CAPABILITIES),
        },
    }

    def load_json(url: str) -> dict:
        return json_documents[url]

    def load_text(url: str) -> str:
        if url.endswith(":8015/metrics"):
            return "\n".join(
                [
                    "marty_event_stream_subscribers 0",
                    "marty_event_stream_published_total 15",
                    "marty_event_stream_delivered_total 1",
                    f"marty_event_stream_dropped_total {dropped}",
                ]
            )
        if url.endswith(":8013/metrics"):
            return "\n".join(
                [
                    'marty_revocation_profile_backend_ready{backend="organization"} 1',
                    'marty_revocation_profile_backend_ready{backend="postgres"} 1',
                    'marty_revocation_profile_backend_ready{backend="redis"} 1',
                    "marty_revocation_profile_native_backend_ready 1",
                ]
            )
        raise AssertionError(url)

    return run, load_json, load_text


def _collect(*, restarts: int = 0, dropped: int = 0) -> dict:
    run, load_json, load_text = _dependencies(restarts=restarts, dropped=dropped)
    return COLLECTOR.collect(
        project="elevenid-beta",
        beta_origin=BETA,
        release_version=RELEASE,
        source_revision=SOURCE,
        lookback_hours=24,
        run=run,
        load_json=load_json,
        load_text=load_text,
    )


def test_collects_sanitized_passing_beta_soak_evidence() -> None:
    report = _collect()

    assert report["schema"] == "marty.rust-beta-soak/v1"
    assert report["overall_valid"] is True
    assert report["failed_checks"] == []
    assert report["services"]["event-stream"]["restart_count"] == 0
    assert report["metrics"]["event_stream"]["marty_event_stream_published_total"] == 15
    assert "logs" not in json.dumps(report).lower()


@pytest.mark.parametrize(
    "restarts,dropped,failed_check",
    [
        (1, 0, "event-stream-zero-restarts"),
        (0, 1, "event-zero-drops"),
    ],
)
def test_operational_regressions_fail_closed(
    restarts: int, dropped: int, failed_check: str
) -> None:
    report = _collect(restarts=restarts, dropped=dropped)

    assert report["overall_valid"] is False
    assert failed_check in report["failed_checks"]


def test_invalid_source_revision_is_rejected_before_collection() -> None:
    with pytest.raises(COLLECTOR.EvidenceError, match="source_revision"):
        COLLECTOR.collect(
            project="elevenid-beta",
            beta_origin=BETA,
            release_version=RELEASE,
            source_revision="short",
            lookback_hours=24,
        )


def test_prometheus_parser_keeps_only_service_metrics() -> None:
    parsed = COLLECTOR._parse_prometheus(
        "# comment\nmarty_event_stream_dropped_total 0\nother_metric 9\n",
        "marty_event_stream_",
    )

    assert parsed == {"marty_event_stream_dropped_total": 0.0}
