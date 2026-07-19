"""Tests for project-scoped official interoperability deployments."""

from __future__ import annotations

import importlib.util
import re
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


def test_reviewer_bootstrap_requires_the_exact_existing_project(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(stack, "rendered_config", lambda *_args, **_kwargs: {"services": {}, "networks": {}, "volumes": {}})
    monkeypatch.setattr(stack, "validate_isolation", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(stack, "project_container_ids", lambda _project: [])
    monkeypatch.setattr(stack.sys, "argv", ["conformance_stack.py", "--project", "marty-conformance-test1", "bootstrap-reviewer"])

    with pytest.raises(ValueError, match="requires an existing"):
        stack.main()


def test_ghcr_profile_keeps_dedicated_issuance_artifact() -> None:
    profile = (ROOT / "docker-compose.profile.ghcr.yml").read_text(encoding="utf-8")

    assert "  issuance:\n    image: ${MARTY_ISSUANCE_IMAGE" in profile


def test_oidf_profile_propagates_public_origin_to_seeded_and_runtime_urls() -> None:
    profile = (ROOT / "docker-compose.profile.oidf.yml").read_text(encoding="utf-8")
    public_origin = (
        "${OIDF_PUBLIC_BASE_URL:?set OIDF_PUBLIC_BASE_URL to the HTTPS verifier URL}"
    )

    for service in ("db-migrate", "gateway", "presentation-policy"):
        match = re.search(
            rf"(?ms)^  {re.escape(service)}:\n(.*?)(?=^  [a-zA-Z0-9_-]+:\n|\Z)",
            profile,
        )
        assert match is not None
        section = match.group(1)
        assert f"PUBLIC_API_URL: {public_origin}" in section
    assert f"ISSUER_BASE_URL: {public_origin}" in profile


def test_conformance_profile_uses_a_disposable_reviewer_via_normal_oidc() -> None:
    profile = (ROOT / "docker-compose.profile.conformance.yml").read_text(encoding="utf-8")

    assert "MARTY_CONFORMANCE_REVIEWER_PASSWORD:?set a disposable reviewer password" in profile
    assert "DEMO_REVIEWER_EMAIL: ${MARTY_CONFORMANCE_REVIEWER_EMAIL" in profile
    assert "DEMO_REVIEWER_PASSWORD: ${MARTY_CONFORMANCE_REVIEWER_PASSWORD" in profile
    assert "MARTY_ORG_REVIEWER_EMAIL: ${MARTY_CONFORMANCE_REVIEWER_EMAIL" in profile
    assert "MARTY_ORG_ADMIN_EMAIL: ${MARTY_CONFORMANCE_ADMIN_EMAIL" in profile
    assert "MARTY_ORG_ADMIN_PASSWORD: ${MARTY_CONFORMANCE_ADMIN_PASSWORD" in profile


def test_keycloak_configurator_bootstraps_missing_application_roles() -> None:
    script = (ROOT / "scripts" / "setup-keycloak.sh").read_text(encoding="utf-8")

    assert "ensure_realm_role()" in script
    assert 'kcadm_safe create roles -r "$REALM"' in script
    grant = script.split("grant_realm_role_to_user()", 1)[1].split("ensure_marty_org_exists()", 1)[0]
    assert 'ensure_realm_role "$role_name" || return 1' in grant
    assert "ensure_marty_org_admin_user()" in script
    assert 'grant_realm_role_to_user "$user_id" "$MARTY_ORG_ADMIN_EMAIL" "administrator"' in script


def test_oidf_profile_registers_its_published_origin_with_keycloak() -> None:
    profile = (ROOT / "docker-compose.profile.oidf.yml").read_text(encoding="utf-8")
    setup = (ROOT / "scripts" / "setup-keycloak.sh").read_text(encoding="utf-8")

    assert "  keycloak-configurator:\n    environment:" in profile
    assert "UI_BASE_URL: ${OIDF_PUBLIC_BASE_URL" in profile
    assert 'KEYCLOAK_REPLACE_UI_ORIGINS: "true"' in profile
    assert '[ -z "$PUBLIC_DOMAIN" ] && [ -z "$UI_BASE_URL" ]' in setup


def test_oidf_runner_can_join_only_the_project_scoped_tls_proxy_bridge() -> None:
    profile = (ROOT / "docker-compose.profile.oidf.yml").read_text(encoding="utf-8")

    assert "oidf-runner-network:" in profile
    assert "${MARTY_CONFORMANCE_PROJECT:?set MARTY_CONFORMANCE_PROJECT}_oidf-runner" in profile
    assert "internal: true" in profile
    proxy = profile.split("  oidf-tls-proxy:\n", 1)[1].split("\n  auth:\n", 1)[0]
    assert "marty-network: {}" in proxy
    assert "oidf-runner-network:" in proxy
    assert "OIDF_CONFORMANCE_BRIDGE_ALIAS" in proxy
