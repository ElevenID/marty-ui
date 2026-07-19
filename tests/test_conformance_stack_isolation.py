"""Tests for project-scoped official interoperability deployments."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "conformance_stack", ROOT / "scripts" / "conformance_stack.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load conformance stack helper")
stack = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stack)


def test_project_name_is_narrowly_scoped() -> None:
    assert stack.validate_project("marty-conformance-20260719-a1") == "marty-conformance-20260719-a1"
    for unsafe in ("marty", "default", "marty-conformance-", "MARTY-conformance-run", "marty-conformance-../prod"):
        with pytest.raises(ValueError, match="project must match"):
            stack.validate_project(unsafe)


def test_isolation_accepts_only_project_resources_and_tls_ports() -> None:
    project = "marty-conformance-test1"
    config = {
        "services": {
            "gateway": {},
            "oidf-tls-proxy": {"ports": [{"published": "28443", "target": 443}]},
        },
        "networks": {"marty-network": {"name": f"{project}_marty-network"}},
        "volumes": {"postgres": {"name": f"{project}_postgres"}},
    }

    assert stack.validate_isolation(config, project) == [28443]


def test_isolation_rejects_global_resources() -> None:
    project = "marty-conformance-test1"
    base = {
        "services": {"gateway": {}},
        "networks": {"marty-network": {"name": f"{project}_marty-network"}},
        "volumes": {},
    }
    base["services"]["gateway"]["container_name"] = "marty-gateway"
    with pytest.raises(ValueError, match="fixed container names"):
        stack.validate_isolation(base, project)


def test_isolation_rejects_unexpected_published_port() -> None:
    project = "marty-conformance-test1"
    config = {
        "services": {"gateway": {"ports": [{"published": "28000", "target": 8000}]}},
        "networks": {"marty-network": {"name": f"{project}_marty-network"}},
        "volumes": {},
    }
    with pytest.raises(ValueError, match="unexpectedly publishes"):
        stack.validate_isolation(config, project)


def test_optional_suite_overlays_are_explicit_and_isolation_is_last() -> None:
    command = stack.compose_command(
        "marty-conformance-test1",
        include_eudi=True,
        include_w3c=True,
    )
    files = [command[index + 1] for index, value in enumerate(command) if value == "--file"]

    assert files[-2].endswith("docker-compose.profile.conformance.yml")
    assert files[-1].endswith("docker-compose.profile.conformance-eudi.yml")
    assert any(path.endswith("docker-compose.profile.w3c-vc.yml") for path in files)


def test_existing_project_requires_explicit_resume(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(stack, "project_container_ids", lambda _project: ["container-1"])
    monkeypatch.setattr(stack.subprocess, "run", lambda *args, **kwargs: type("Result", (), {"stdout": ""})())

    with pytest.raises(ValueError, match="already has containers"):
        stack.assert_ports_available([], "marty-conformance-test1")
    stack.assert_ports_available([], "marty-conformance-test1", resume=True)


def test_ghcr_profile_keeps_dedicated_issuance_artifact() -> None:
    profile = (ROOT / "docker-compose.profile.ghcr.yml").read_text(encoding="utf-8")

    assert "  issuance:\n    image: ${MARTY_ISSUANCE_IMAGE" in profile
