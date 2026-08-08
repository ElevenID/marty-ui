"""Production Compose must not silently retain development gRPC authentication."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]

GRPC_SERVICES = {
    "gateway",
    "auth",
    "organization",
    "credential-template",
    "trust-profile",
    "issuance",
    "applicant",
    "notification",
    "compliance-profile",
    "presentation-policy",
    "deployment-profile",
    "flow",
    "verification",
    "revocation-profile",
    "device-registration",
    "event-stream",
}


def test_production_profile_requires_auth_for_every_grpc_service() -> None:
    base = yaml.safe_load(
        (ROOT / "docker-compose.base.yml").read_text(encoding="utf-8")
    )
    profile = yaml.safe_load(
        (ROOT / "docker-compose.profile.prod.yml").read_text(encoding="utf-8")
    )

    discovered_grpc_services = {
        name
        for name, service in base["services"].items()
        if any("GRPC" in key for key in (service.get("environment") or {}))
    }
    assert discovered_grpc_services == GRPC_SERVICES

    configured_services = {
        name
        for name, service in profile["services"].items()
        if (service.get("environment") or {}).get("GRPC_SERVICE_TOKEN")
    }
    assert configured_services == GRPC_SERVICES

    for service_name in GRPC_SERVICES:
        environment = profile["services"][service_name]["environment"]
        assert environment["ENVIRONMENT"] == "production"
        assert environment["GRPC_SERVICE_TOKEN"] == (
            "${GRPC_SERVICE_TOKEN:?GRPC_SERVICE_TOKEN must be set}"
        )


def _compose_environment() -> dict[str, str]:
    return {
        **os.environ,
        "MARTY_RS_URI": "https://example.invalid/marty-rs.whl",
        "MARTY_RS_DIGEST": "a" * 64,
        "MARTY_COMMON_URI": "https://example.invalid/marty-common.whl",
        "MARTY_COMMON_DIGEST": "b" * 64,
        "MARTY_ISSUANCE_IMAGE": "example.invalid/issuance@sha256:" + "c" * 64,
        "MARTY_DOCS_IMAGE": "example.invalid/docs@sha256:" + "d" * 64,
        "FLOW_WEBHOOK_SECRET": "flow-webhook-secret-at-least-32-bytes",
    }


@pytest.mark.skipif(
    shutil.which("docker") is None, reason="Docker Compose CLI unavailable"
)
def test_rendered_production_profile_carries_service_auth() -> None:
    environment = _compose_environment()
    environment["GRPC_SERVICE_TOKEN"] = "g" * 48
    result = subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            "docker-compose.base.yml",
            "-f",
            "docker-compose.profile.prod.yml",
            "config",
            "--format",
            "json",
        ],
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    services = json.loads(result.stdout)["services"]

    for service_name in GRPC_SERVICES:
        rendered_environment = services[service_name]["environment"]
        assert rendered_environment["ENVIRONMENT"] == "production"
        assert rendered_environment["GRPC_SERVICE_TOKEN"] == "g" * 48


@pytest.mark.skipif(
    shutil.which("docker") is None, reason="Docker Compose CLI unavailable"
)
def test_rendered_production_profile_rejects_missing_service_auth() -> None:
    environment = _compose_environment()
    environment.pop("GRPC_SERVICE_TOKEN", None)

    result = subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            "docker-compose.base.yml",
            "-f",
            "docker-compose.profile.prod.yml",
            "config",
        ],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "GRPC_SERVICE_TOKEN must be set" in result.stderr
