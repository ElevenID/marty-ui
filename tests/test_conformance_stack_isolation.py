"""Tests for project-scoped official interoperability deployments."""

from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path

import pytest
import yaml
from yaml.nodes import MappingNode, ScalarNode, SequenceNode


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "conformance_stack", ROOT / "scripts" / "conformance_stack.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load conformance stack helper")
stack = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stack)


def _assert_unique_yaml_keys(node: yaml.Node, path: Path, location: str = "root") -> None:
    if isinstance(node, MappingNode):
        seen: dict[str, int] = {}
        for key_node, value_node in node.value:
            if isinstance(key_node, ScalarNode):
                key = key_node.value
                line = key_node.start_mark.line + 1
                if key in seen:
                    pytest.fail(
                        f"{path.name}:{line}: duplicate mapping key {key!r}; "
                        f"first declared at line {seen[key]} ({location})"
                    )
                seen[key] = line
                child_location = f"{location}.{key}"
            else:
                child_location = location
            _assert_unique_yaml_keys(value_node, path, child_location)
    else:
        for child in getattr(node, "value", ()):
            if isinstance(child, yaml.Node):
                _assert_unique_yaml_keys(child, path, location)


def _mapping_value(node: yaml.Node, key: str) -> yaml.Node:
    if not isinstance(node, MappingNode):
        raise AssertionError(f"expected YAML mapping while resolving {key!r}")
    for key_node, value_node in node.value:
        if isinstance(key_node, ScalarNode) and key_node.value == key:
            return value_node
    raise AssertionError(f"missing YAML mapping key {key!r}")


def test_compose_files_have_no_duplicate_mapping_keys() -> None:
    for path in sorted(ROOT.glob("docker-compose*.yml")):
        document = yaml.compose(path.read_text(encoding="utf-8"))
        assert document is not None, f"{path.name} is empty"
        _assert_unique_yaml_keys(document, path)


def test_base_stack_host_publications_are_loopback_only() -> None:
    compose = yaml.safe_load(
        (ROOT / "docker-compose.base.yml").read_text(encoding="utf-8")
    )
    published_ports = {
        service: [str(port) for port in definition.get("ports", [])]
        for service, definition in compose["services"].items()
        if definition.get("ports")
    }

    assert published_ports
    for service, ports in published_ports.items():
        assert all(port.startswith("127.0.0.1:") for port in ports), (
            f"{service} publishes a non-loopback host port: {ports}"
        )


def test_conformance_overlay_resets_every_base_global_resource() -> None:
    base = yaml.safe_load(
        (ROOT / "docker-compose.base.yml").read_text(encoding="utf-8")
    )
    overlay = yaml.compose(
        (ROOT / "docker-compose.profile.conformance.yml").read_text(encoding="utf-8")
    )
    assert overlay is not None
    overlay_services = _mapping_value(overlay, "services")

    for service_name, definition in base["services"].items():
        fields = []
        if definition.get("container_name") is not None:
            fields.append("container_name")
        if definition.get("ports"):
            fields.append("ports")
        if not fields:
            continue

        service = _mapping_value(overlay_services, service_name)
        for field in fields:
            reset = _mapping_value(service, field)
            assert reset.tag == "!reset", (
                f"conformance overlay must reset {service_name}.{field}"
            )
            if field == "ports":
                assert isinstance(reset, SequenceNode) and not reset.value


def test_issuer_did_identity_returns_only_public_did_material(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = {
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
    assert stack.issuer_did_identity(["docker", "compose"]) == payload
    rendered = " ".join(captured)
    assert "exec -T gateway python -c" in rendered
    assert "SIGNING_KEYS_INTERNAL_API_KEY" in rendered
    assert "dev-signing-keys-internal-api-key" not in rendered
    assert "OID4VP_ISSUER_PROFILE_ID" not in rendered
    assert "/resolve-issuer-did" in rendered


def test_issuer_did_identity_rejects_private_jwk_material(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = {
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
    with pytest.raises(ValueError, match="public ES256 identity"):
        stack.issuer_did_identity(["docker", "compose"])


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


def test_haip_overlay_is_explicit_and_isolation_is_last() -> None:
    command = stack.compose_command(
        "marty-conformance-test1",
        include_haip=True,
    )
    files = [
        command[index + 1] for index, value in enumerate(command) if value == "--file"
    ]

    assert files[-1].endswith("docker-compose.profile.conformance.yml")
    assert any(path.endswith("docker-compose.profile.oidf-haip.yml") for path in files)
    assert any(
        path.endswith("docker-compose.profile.conformance-images.yml") for path in files
    )


def test_didcomm_authcrypt_overlay_is_explicit_and_isolation_is_last() -> None:
    default_command = stack.compose_command("marty-conformance-test1")
    default_files = [
        default_command[index + 1]
        for index, value in enumerate(default_command)
        if value == "--file"
    ]
    assert not any(
        path.endswith(stack.DIDCOMM_AUTHCRYPT_FILE) for path in default_files
    )

    command = stack.compose_command(
        "marty-conformance-test1",
        include_didcomm_authcrypt=True,
    )
    files = [
        command[index + 1] for index, value in enumerate(command) if value == "--file"
    ]
    assert files[-2].endswith(stack.DIDCOMM_AUTHCRYPT_FILE)
    assert files[-1].endswith(stack.ISOLATION_FILE)


def test_didcomm_authcrypt_policy_is_mounted_only_into_issuance() -> None:
    overlay = yaml.safe_load(
        (ROOT / stack.DIDCOMM_AUTHCRYPT_FILE).read_text(encoding="utf-8")
    )
    assert set(overlay["services"]) == {"issuance"}
    issuance = overlay["services"]["issuance"]
    assert issuance["environment"] == {
        "DIDCOMM_ENCRYPTION_POLICY_FILE": (
            "/run/secrets/didcomm-authcrypt/didcomm-encryption-policy.json"
        )
    }
    assert issuance["volumes"] == [
        "${DIDCOMM_ENCRYPTION_POLICY_DIR:?set DIDCOMM_ENCRYPTION_POLICY_DIR to an exact policy directory}:/run/secrets/didcomm-authcrypt:ro"
    ]


def test_didcomm_holder_receiver_bridge_is_conformance_only() -> None:
    isolation = (ROOT / stack.ISOLATION_FILE).read_text(encoding="utf-8")
    issuance = isolation.split("  issuance:\n", 1)[1].split(
        "  canvas-sync-worker:\n", 1
    )[0]

    assert '"host.docker.internal:host-gateway"' in issuance
    assert "DIDCOMM_TLS_CA_FILE:" in issuance
    assert 'DIDCOMM_ALLOW_PRIVATE_IPS: "true"' in issuance
    assert "didcomm-conformance-root-ca.pem:ro" in issuance
    for production_file in (
        "docker-compose.base.yml",
        "docker-compose.selfhost.prod.yml",
        "docker-compose.ui-prod.yml",
        "docker-compose.ui-release.yml",
    ):
        assert "host.docker.internal:host-gateway" not in (
            ROOT / production_file
        ).read_text(encoding="utf-8")
        assert "DIDCOMM_TLS_CA_FILE" not in (
            ROOT / production_file
        ).read_text(encoding="utf-8")
    base = yaml.safe_load((ROOT / "docker-compose.base.yml").read_text(encoding="utf-8"))
    issuance_environment = base["services"]["issuance"]["environment"]
    assert issuance_environment["DIDCOMM_ALLOW_PRIVATE_IPS"] == (
        "${DIDCOMM_ALLOW_PRIVATE_IPS:-false}"
    )
    assert issuance_environment["DIDCOMM_DID_WEB_INTERNAL_BASE_URL"] == (
        "${DIDCOMM_DID_WEB_INTERNAL_BASE_URL:-http://gateway:8000}"
    )


def test_trust_registry_private_adapter_is_conformance_only() -> None:
    isolation = (ROOT / stack.ISOLATION_FILE).read_text(encoding="utf-8")
    trust_profile = isolation.split("  trust-profile:\n", 1)[1].split(
        "  deployment-profile:\n", 1
    )[0]

    assert "TRUST_REGISTRY_PRIVATE_HOST_ALLOWLIST: trust-registry-fixture" in trust_profile
    assert "TRUST_REGISTRY_TLS_CA_FILE:" in trust_profile
    assert 'TRUST_REGISTRY_SYNC_POLL_SECONDS: "86400"' in trust_profile
    assert "trust-registry-conformance-root-ca.pem:ro" in trust_profile
    for production_file in (
        "docker-compose.base.yml",
        "docker-compose.selfhost.prod.yml",
        "docker-compose.ui-prod.yml",
        "docker-compose.ui-release.yml",
    ):
        production = (ROOT / production_file).read_text(encoding="utf-8")
        assert "TRUST_REGISTRY_PRIVATE_HOST_ALLOWLIST" not in production
        assert "TRUST_REGISTRY_TLS_CA_FILE" not in production


def test_local_build_defines_ui_without_release_image_overlays() -> None:
    command = stack.compose_command(
        "marty-conformance-test1",
        use_ghcr=False,
    )
    files = [
        command[index + 1] for index, value in enumerate(command) if value == "--file"
    ]

    assert files[-1].endswith("docker-compose.profile.conformance.yml")
    assert any(path.endswith("docker-compose.profile.local-build.yml") for path in files)
    assert not any(path.endswith("docker-compose.profile.ghcr.yml") for path in files)
    assert not any(
        path.endswith("docker-compose.profile.conformance-images.yml") for path in files
    )

    source_profile = (ROOT / stack.LOCAL_BUILD_FILE).read_text(encoding="utf-8")
    ui_section = source_profile.split("  ui:\n", 1)[1]
    assert "context: ./ui" in ui_section
    assert "dockerfile: Dockerfile.prod" in ui_section
    assert "gateway:" in ui_section


def test_local_ui_image_is_reproducible_and_installs_postinstall_script() -> None:
    dockerfile = (ROOT / "ui" / "Dockerfile.prod").read_text(encoding="utf-8")

    assert "oven/bun:1.3.14-alpine@sha256:" in dockerfile
    assert "nginx:1.29.1-alpine@sha256:" in dockerfile
    assert dockerfile.index("COPY scripts/patch-prerenderer-ts-deepmerge.cjs") < dockerfile.index(
        "RUN bun install --frozen-lockfile"
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

    assert "GET /ready HTTP/1.1" in infrastructure
    assert "Connection: close" in infrastructure
    assert "HTTP/1.0" not in infrastructure


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
        "presentation-policy",
        "flow",
        "revocation-profile",
        "event-stream",
    ):
        section = re.search(
            rf"(?ms)^  {re.escape(service)}:\n(.*?)(?=^  [a-zA-Z0-9_-]+:\n|\Z)",
            compose,
        )
        assert section is not None
        assert "<<: *marty_service_build_artifacts" in section.group(1)

    for service, target in (
        ("compliance-profile", "compliance_profile"),
        ("deployment-profile", "deployment_profile"),
        ("verification", "verification"),
    ):
        native = re.search(
            rf"(?ms)^  {re.escape(service)}:\n(.*?)(?=^  [a-zA-Z0-9_-]+:\n|\Z)",
            compose,
        )
        assert native is not None
        assert "dockerfile: rust/services/Dockerfile.ci" in native.group(1)
        assert f"target: {target}" in native.group(1)

    native_device = re.search(
        r"(?ms)^  device-registration:\n(.*?)(?=^  [a-zA-Z0-9_-]+:\n|\Z)",
        compose,
    )
    assert native_device is not None
    assert "dockerfile: rust/services/Dockerfile.ci" in native_device.group(1)
    assert "target: device_registration" in native_device.group(1)


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


def test_issuance_token_limiter_is_configurable_without_weakening_default() -> None:
    compose = (ROOT / "docker-compose.base.yml").read_text(encoding="utf-8")
    issuance = re.search(
        r"(?ms)^  issuance:\n(.*?)(?=^  [a-zA-Z0-9_-]+:\n|\Z)",
        compose,
    )

    assert issuance is not None
    assert "TOKEN_RATE_LIMIT: ${TOKEN_RATE_LIMIT:-30}" in issuance.group(1)


def test_vcdm_related_resource_allowlist_is_forwarded_fail_closed() -> None:
    compose = (ROOT / "docker-compose.base.yml").read_text(encoding="utf-8")
    issuance = re.search(
        r"(?ms)^  issuance:\n(.*?)(?=^  [a-zA-Z0-9_-]+:\n|\Z)",
        compose,
    )

    assert issuance is not None
    assert (
        "VCDM_RELATED_RESOURCE_URLS: ${VCDM_RELATED_RESOURCE_URLS:-}"
        in issuance.group(1)
    )
    assert "https://www.w3.org/ns/credentials/v2" not in issuance.group(1)


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
    assert "set $ui_upstream http://ui:80;" in config
    assert "proxy_pass $gateway_upstream;" in config
    assert "proxy_pass $keycloak_upstream;" in config
    assert "proxy_pass $ui_upstream;" in config
    assert "proxy_pass http://gateway:8000;" not in config
    assert "proxy_pass http://keycloak:8080;" not in config
    assert "proxy_pass http://ui:80;" not in config


def test_oidf_tls_proxy_preserves_the_complete_public_authority() -> None:
    config = (ROOT / "services" / "oidf-tls-proxy" / "nginx.conf.template").read_text(
        encoding="utf-8"
    )

    # Nginx $host normalizes away a non-default port. DPoP signs the absolute
    # target URI, so all upstream locations must use the original authority.
    assert config.count("proxy_set_header Host $http_host;") == 3
    assert config.count("proxy_set_header X-Forwarded-Host $http_host;") == 3
    assert "proxy_set_header Host $host;" not in config
    assert "proxy_set_header X-Forwarded-Host $host;" not in config


def test_released_conformance_stack_serves_the_exact_ui_artifact() -> None:
    profile = (ROOT / "docker-compose.profile.ghcr.yml").read_text(encoding="utf-8")
    oidf = (ROOT / "docker-compose.profile.oidf.yml").read_text(encoding="utf-8")
    proxy = (ROOT / "services" / "oidf-tls-proxy" / "nginx.conf.template").read_text(
        encoding="utf-8"
    )

    assert "image: ${MARTY_UI_IMAGE:?" in profile
    assert "condition: service_healthy" in profile.split("  ui:\n", 1)[1].split(
        "\n  db-migrate:\n", 1
    )[0]
    assert "  ui:\n        condition: service_healthy" in oidf
    assert "console(?:/|$)" in proxy
    assert "locales/" in proxy
    assert "config\\.json$" in proxy
    assert "runtime-config\\.js$" in proxy
    assert "startup\\.js$" in proxy


def test_oidf_tls_proxy_rejects_legacy_tls12_cipher_suites() -> None:
    config = (ROOT / "services" / "oidf-tls-proxy" / "nginx.conf.template").read_text(
        encoding="utf-8"
    )

    cipher_line = next(
        line.strip()
        for line in config.splitlines()
        if line.strip().startswith("ssl_ciphers ")
    )
    assert "GCM" in cipher_line
    assert "CHACHA20-POLY1305" in cipher_line
    assert "CBC" not in cipher_line
    assert "AES128-SHA" not in cipher_line
    assert "ssl_prefer_server_ciphers on;" in config


def test_conformance_stack_exposes_timestamped_service_logs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[list[str], dict[str, object]]] = []
    monkeypatch.setattr(
        stack.subprocess,
        "run",
        lambda command, **kwargs: (
            calls.append((command, kwargs)) or type("Result", (), {"returncode": 17})()
        ),
    )

    assert stack.emit_service_logs(["docker", "compose"]) == 17
    assert calls == [
        (
            ["docker", "compose", "logs", "--no-color", "--timestamps"],
            {"cwd": stack.ROOT, "check": False},
        )
    ]
