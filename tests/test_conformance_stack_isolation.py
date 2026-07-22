"""Tests for project-scoped official interoperability deployments."""

from __future__ import annotations

import importlib.util
import json
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


def test_issuer_profile_identity_returns_only_public_did_material(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = {
        "issuer_profile_id": "ip-marty-oid4vp-verifier",
        "issuer_did": "did:web:marty.example",
        "verification_method_id": "did:web:marty.example#oid4vp",
        "public_jwk": {"kty": "EC", "crv": "P-256", "x": "x", "y": "y"},
        "key_purpose": "oid4vp_request_signing",
        "algorithm": "ES256",
    }
    captured: list[str] = []

    def fake_run(command: list[str], **_kwargs: object) -> object:
        captured.extend(command)
        return type(
            "Result",
            (),
            {"returncode": 0, "stdout": json.dumps(payload), "stderr": ""},
        )()

    monkeypatch.setattr(stack.subprocess, "run", fake_run)
    assert stack.issuer_profile_identity(["docker", "compose"]) == payload
    rendered = " ".join(captured)
    assert "exec -T gateway python -c" in rendered
    assert "SIGNING_KEYS_INTERNAL_API_KEY" in rendered
    assert "dev-signing-keys-internal-api-key" not in rendered


def test_issuer_profile_identity_rejects_private_jwk_material(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = {
        "issuer_profile_id": "ip-marty-oid4vp-verifier",
        "issuer_did": "did:web:marty.example",
        "verification_method_id": "did:web:marty.example#oid4vp",
        "public_jwk": {"kty": "EC", "crv": "P-256", "x": "x", "y": "y", "d": "private"},
        "key_purpose": "oid4vp_request_signing",
        "algorithm": "ES256",
    }
    monkeypatch.setattr(
        stack.subprocess,
        "run",
        lambda *_args, **_kwargs: type(
            "Result",
            (),
            {"returncode": 0, "stdout": json.dumps(payload), "stderr": ""},
        )(),
    )
    with pytest.raises(ValueError, match="public ES256 DID identity"):
        stack.issuer_profile_identity(["docker", "compose"])


def test_project_name_is_narrowly_scoped() -> None:
    assert (
        stack.validate_project("marty-conformance-20260719-a1")
        == "marty-conformance-20260719-a1"
    )
    for unsafe in (
        "marty",
        "default",
        "marty-conformance-",
        "MARTY-conformance-run",
        "marty-conformance-../prod",
    ):
        with pytest.raises(ValueError, match="project must match"):
            stack.validate_project(unsafe)


def test_project_environment_is_derived_from_the_validated_cli_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("MARTY_CONFORMANCE_PROJECT", raising=False)
    stack.configure_project_environment("marty-conformance-test1")
    assert stack.os.environ["MARTY_CONFORMANCE_PROJECT"] == "marty-conformance-test1"

    monkeypatch.setenv("MARTY_CONFORMANCE_PROJECT", "marty-conformance-other")
    with pytest.raises(ValueError, match="conflicts"):
        stack.configure_project_environment("marty-conformance-test1")


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


def test_public_service_targets_follow_the_rendered_tls_listener() -> None:
    config = {
        "services": {
            "gateway": {},
            "oidf-tls-proxy": {"ports": [{"published": "28443", "target": 28443}]},
        }
    }

    assert stack.public_service_targets(config) == {"oidf-tls-proxy": [28443]}


def test_public_service_targets_reject_an_incomplete_port_mapping() -> None:
    config = {"services": {"oidf-tls-proxy": {"ports": [{"published": "28443"}]}}}

    with pytest.raises(ValueError, match="without a target"):
        stack.public_service_targets(config)


def test_compose_ps_parser_accepts_array_and_stream_formats() -> None:
    row = '{"Service":"db-migrate","State":"exited","ExitCode":0}'
    assert stack.parse_compose_ps(f"[{row}]")[0]["Service"] == "db-migrate"
    assert len(stack.parse_compose_ps(f"{row}\n{row}")) == 2


def test_one_shot_wait_requires_every_initializer_to_exit_zero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = sorted(stack.ONE_SHOT_SERVICES)
    payload = [
        {"Service": service, "State": "exited", "ExitCode": 0} for service in expected
    ]
    monkeypatch.setattr(
        stack.subprocess,
        "run",
        lambda *_args, **_kwargs: type(
            "Result", (), {"stdout": stack.json.dumps(payload)}
        )(),
    )

    stack.wait_for_one_shots(
        ["docker", "compose"],
        {"services": {service: {} for service in expected}},
        timeout_seconds=0,
        poll_seconds=0,
    )


def test_one_shot_wait_rejects_a_failed_initializer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = [{"Service": "db-migrate", "State": "exited", "ExitCode": 17}]
    monkeypatch.setattr(
        stack.subprocess,
        "run",
        lambda *_args, **_kwargs: type(
            "Result", (), {"stdout": stack.json.dumps(payload)}
        )(),
    )

    with pytest.raises(ValueError, match="db-migrate.*17"):
        stack.wait_for_one_shots(
            ["docker", "compose"],
            {"services": {"db-migrate": {}}},
            timeout_seconds=0,
            poll_seconds=0,
        )


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


def test_haip_and_w3c_overlays_are_explicit_and_isolation_is_last() -> None:
    command = stack.compose_command(
        "marty-conformance-test1",
        include_haip=True,
        include_w3c=True,
    )
    files = [
        command[index + 1] for index, value in enumerate(command) if value == "--file"
    ]

    assert files[-1].endswith("docker-compose.profile.conformance.yml")
    assert any(path.endswith("docker-compose.profile.oidf-haip.yml") for path in files)
    assert any(path.endswith("docker-compose.profile.w3c-vc.yml") for path in files)
    assert any(
        path.endswith("docker-compose.profile.conformance-images.yml") for path in files
    )


def test_release_profile_removes_builds_and_pins_infrastructure() -> None:
    ghcr = (ROOT / "docker-compose.profile.ghcr.yml").read_text(encoding="utf-8")
    infrastructure = (ROOT / "docker-compose.profile.conformance-images.yml").read_text(
        encoding="utf-8"
    )

    assert "build: !reset null" in ghcr
    assert "marty-envoy:latest" not in infrastructure
    for service in (
        "postgres",
        "redis",
        "keycloak",
        "mailpit",
        "openbao",
        "envoy",
    ):
        section = infrastructure.split(f"  {service}:\n", 1)[1].split("\n  ", 1)[0]
        assert "@sha256:" in section


def test_local_build_requires_digest_pinned_bootstrap_artifacts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in stack.LOCAL_BUILD_ARGS:
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(ValueError, match="MARTY_RS_URI"):
        stack.local_build_arguments()

    for name in stack.LOCAL_BUILD_ARGS:
        monkeypatch.setenv(name, f"value-for-{name}")

    assert stack.local_build_arguments() == [
        "--build-arg",
        "MARTY_RS_URI=value-for-MARTY_RS_URI",
        "--build-arg",
        "MARTY_RS_DIGEST=value-for-MARTY_RS_DIGEST",
        "--build-arg",
        "MARTY_COMMON_URI=value-for-MARTY_COMMON_URI",
        "--build-arg",
        "MARTY_COMMON_DIGEST=value-for-MARTY_COMMON_DIGEST",
    ]


def test_all_shared_service_builds_receive_the_verified_bootstrap_artifacts() -> None:
    """A source-built conformance stack must not silently omit Docker build args.

    Services share ``services/Dockerfile``, which downloads the released
    marty-rs and marty-common wheels and checks their digests.  Compose does
    not automatically forward environment variables as build arguments, so
    each service must inherit the explicit build-argument mapping.
    """
    compose = (ROOT / "docker-compose.base.yml").read_text(encoding="utf-8")
    assert "x-marty-service-build-artifacts: &marty_service_build_artifacts" in compose
    for service in (
        "gateway",
        "auth",
        "organization",
        "credential-template",
        "trust-profile",
        "applicant",
        "notification",
        "compliance-profile",
        "presentation-policy",
        "deployment-profile",
        "flow",
        "revocation-profile",
        "device-registration",
        "event-stream",
        "verification",
    ):
        section = re.search(
            rf"(?ms)^  {re.escape(service)}:\n(.*?)(?=^  [a-zA-Z0-9_-]+:\n|\Z)",
            compose,
        )
        assert section is not None
        assert "<<: *marty_service_build_artifacts" in section.group(1)


def test_oidf_bridge_listener_uses_the_published_https_port(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OIDF_PUBLIC_BASE_URL", "https://marty-oidf.test:28443")
    monkeypatch.delenv("OIDF_INTERNAL_TLS_PORT", raising=False)

    stack.configure_oidf_internal_tls_port()

    assert stack.os.environ["OIDF_INTERNAL_TLS_PORT"] == "28443"
    monkeypatch.setenv("OIDF_INTERNAL_TLS_PORT", "443")
    with pytest.raises(ValueError, match="must equal"):
        stack.configure_oidf_internal_tls_port()


def test_existing_project_requires_explicit_resume(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        stack, "project_container_ids", lambda _project: ["container-1"]
    )
    monkeypatch.setattr(
        stack.subprocess,
        "run",
        lambda *args, **kwargs: type("Result", (), {"stdout": ""})(),
    )

    with pytest.raises(ValueError, match="already has containers"):
        stack.assert_ports_available([], "marty-conformance-test1")
    stack.assert_ports_available([], "marty-conformance-test1", resume=True)


def test_reviewer_bootstrap_requires_the_exact_existing_project(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        stack,
        "rendered_config",
        lambda *_args, **_kwargs: {"services": {}, "networks": {}, "volumes": {}},
    )
    monkeypatch.setattr(stack, "validate_isolation", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(stack, "project_container_ids", lambda _project: [])
    monkeypatch.setattr(
        stack.sys,
        "argv",
        [
            "conformance_stack.py",
            "--project",
            "marty-conformance-test1",
            "bootstrap-reviewer",
        ],
    )

    with pytest.raises(ValueError, match="requires an existing"):
        stack.main()


def test_ghcr_profile_keeps_dedicated_issuance_artifact() -> None:
    profile = (ROOT / "docker-compose.profile.ghcr.yml").read_text(encoding="utf-8")
    base = (ROOT / "docker-compose.base.yml").read_text(encoding="utf-8")

    assert "  issuance:\n    image: ${MARTY_ISSUANCE_IMAGE" in profile
    assert "  issuance-migrations:\n    image: ${MARTY_ISSUANCE_IMAGE" in base


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


def test_oidf_final_profile_selects_the_standard_redirect_uri_client_id() -> None:
    profile = (ROOT / "docker-compose.profile.oidf.yml").read_text(encoding="utf-8")
    flow = profile.split("  flow:\n", 1)[1].split("\n  issuance:\n", 1)[0]

    assert "OID4VP_CLIENT_ID_PREFIX: ${OIDF_CLIENT_ID_PREFIX:-redirect_uri}" in flow


def test_conformance_profile_uses_a_disposable_reviewer_via_normal_oidc() -> None:
    profile = (ROOT / "docker-compose.profile.conformance.yml").read_text(
        encoding="utf-8"
    )

    assert (
        "MARTY_CONFORMANCE_REVIEWER_PASSWORD:?set a disposable reviewer password"
        in profile
    )
    assert "DEMO_REVIEWER_EMAIL: ${MARTY_CONFORMANCE_REVIEWER_EMAIL" in profile
    assert "DEMO_REVIEWER_PASSWORD: ${MARTY_CONFORMANCE_REVIEWER_PASSWORD" in profile
    assert "MARTY_ORG_REVIEWER_EMAIL: ${MARTY_CONFORMANCE_REVIEWER_EMAIL" in profile
    assert "MARTY_ORG_ADMIN_EMAIL: ${MARTY_CONFORMANCE_ADMIN_EMAIL" in profile
    assert "MARTY_ORG_ADMIN_PASSWORD: ${MARTY_CONFORMANCE_ADMIN_PASSWORD" in profile
    organization = profile.split("  organization:\n", 1)[1].split(
        "\n  credential-template:\n", 1
    )[0]
    assert "MARTY_ORG_ADMIN_EMAIL: ${MARTY_CONFORMANCE_ADMIN_EMAIL" in organization
    assert (
        "MARTY_ORG_REVIEWER_EMAIL: ${MARTY_CONFORMANCE_REVIEWER_EMAIL" in organization
    )


def test_credentials_migration_is_a_required_one_shot() -> None:
    profile = (ROOT / "docker-compose.profile.conformance.yml").read_text(
        encoding="utf-8"
    )
    assert "issuance-migrations" in stack.ONE_SHOT_SERVICES
    assert "  issuance-migrations:\n    container_name: !reset null" in profile


def test_keycloak_configurator_bootstraps_missing_application_roles() -> None:
    script = (ROOT / "scripts" / "setup-keycloak.sh").read_text(encoding="utf-8")

    assert "ensure_realm_role()" in script
    assert 'kcadm_safe create roles -r "$REALM"' in script
    grant = script.split("grant_realm_role_to_user()", 1)[1].split(
        "ensure_marty_org_exists()", 1
    )[0]
    assert 'ensure_realm_role "$role_name" || return 1' in grant
    assert "ensure_marty_org_admin_user()" in script
    assert (
        'grant_realm_role_to_user "$user_id" "$MARTY_ORG_ADMIN_EMAIL" "administrator"'
        in script
    )


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
    assert (
        "${MARTY_CONFORMANCE_PROJECT:?set MARTY_CONFORMANCE_PROJECT}_oidf-runner"
        in profile
    )
    assert "internal: true" in profile
    proxy = profile.split("  oidf-tls-proxy:\n", 1)[1].split("\n  auth:\n", 1)[0]
    assert "marty-network: {}" in proxy
    assert "oidf-runner-network:" in proxy
    assert "OIDF_CONFORMANCE_BRIDGE_ALIAS" in proxy
    assert "OIDF_INTERNAL_TLS_PORT" in proxy
    assert "nginx.conf.template" in proxy


def test_oidf_tls_proxy_refreshes_compose_upstream_addresses() -> None:
    config = (ROOT / "services" / "oidf-tls-proxy" / "nginx.conf.template").read_text(
        encoding="utf-8"
    )

    assert "resolver 127.0.0.11 valid=5s ipv6=off;" in config
    assert "set $gateway_upstream http://gateway:8000;" in config
    assert "set $keycloak_upstream http://keycloak:8080;" in config
    assert "proxy_pass $gateway_upstream;" in config
    assert "proxy_pass $keycloak_upstream;" in config
    assert "proxy_pass http://gateway:8000;" not in config
    assert "proxy_pass http://keycloak:8080;" not in config
