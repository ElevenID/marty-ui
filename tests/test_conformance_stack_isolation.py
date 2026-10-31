"""Tests for project-scoped official interoperability deployments."""

from __future__ import annotations

import importlib.util
import hashlib
import json
import re
from pathlib import Path
from types import SimpleNamespace

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


def _assert_unique_yaml_keys(
    node: yaml.Node, path: Path, location: str = "root"
) -> None:
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


def test_applicant_uses_image_nonroot_user_in_conformance_and_selfhost() -> None:
    base = yaml.safe_load((ROOT / "docker-compose.base.yml").read_text(encoding="utf-8"))
    selfhost = yaml.safe_load(
        (ROOT / "docker-compose.selfhost.prod.yml").read_text(encoding="utf-8")
    )
    beta = yaml.safe_load((ROOT / "docker-compose.beta.yml").read_text(encoding="utf-8"))
    applicant_base = base["services"]["applicant"]
    applicant_selfhost = selfhost["services"]["applicant"]
    assert "user" not in applicant_base
    assert "group_add" not in applicant_base
    assert "user" not in beta["services"]["applicant"]
    assert "user" not in applicant_selfhost
    assert applicant_selfhost["group_add"] == [
        "${APPLICANT_STATE_GID:?APPLICANT_STATE_GID must match the provisioned state group}"
    ]
    assert "docker-compose.base.yml" in stack.BASE_FILES


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


def _identity_query(monkeypatch, payload, *, project="marty-conformance-test1", service="gateway", running=True, selected=None, curl_code=0):
    calls = []
    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        if "ps" in command:
            output = selected if selected is not None else "a" * 64
        elif command[:3] == ["docker", "container", "inspect"]:
            output = json.dumps([{"Config": {
                "Labels": {"com.docker.compose.project": project, "com.docker.compose.service": service},
                "Env": ["MARTY_ISSUER_DID=did:web:marty.example", "SIGNING_KEYS_INTERNAL_API_KEY=private-test-key"],
            }, "State": {"Running": running}}])
        else:
            output = json.dumps(payload)
        return type("Result", (), {"returncode": curl_code if "curl" in command else 0,
                                   "stdout": output, "stderr": "private-test-key" if curl_code else ""})()
    monkeypatch.setattr(stack.subprocess, "run", fake_run)
    return calls


def _public_identity():
    return {
        "issuer_did": "did:web:marty.example",
        "verification_method_id": "did:web:marty.example#oid4vp",
        "public_jwk": {"kty": "EC", "crv": "P-256", "x": "x", "y": "y"},
        "did_document": None,
        "key_purpose": "oid4vp_request_signing", "algorithm": "ES256",
    }


IDENTITY_COMMAND = ["docker", "compose", "--project-name", "marty-conformance-test1"]


def test_issuer_did_identity_returns_only_public_did_material(monkeypatch):
    payload = _public_identity()
    calls = _identity_query(monkeypatch, {**payload, "issuer_profile": {"signing_key_reference": "private-ref"}})
    assert stack.issuer_did_identity(IDENTITY_COMMAND) == payload
    rendered = " ".join(" ".join(command) for command, _ in calls)
    assert "exec -T gateway curl --config -" in rendered
    assert "python" not in rendered and "private-test-key" not in rendered
    assert "X-Api-Key: private-test-key" in calls[-1][1]["input"]
    assert "/resolve-issuer-did" in calls[-1][1]["input"]


def test_issuer_did_identity_rejects_private_jwk_material(monkeypatch):
    payload = _public_identity()
    payload["public_jwk"]["d"] = "private"
    _identity_query(monkeypatch, payload)
    with pytest.raises(ValueError, match="public ES256 identity"):
        stack.issuer_did_identity(IDENTITY_COMMAND)


@pytest.mark.parametrize("fault", [{"project": "foreign"}, {"service": "auth"}, {"running": False}])
def test_issuer_identity_refuses_foreign_or_inactive_containers(monkeypatch, fault):
    calls = _identity_query(monkeypatch, _public_identity(), **fault)
    with pytest.raises(ValueError, match="owned running container"):
        stack.issuer_did_identity(IDENTITY_COMMAND)
    assert len(calls) == 2 and all("curl" not in command for command, _ in calls)


def test_issuer_identity_refuses_ambiguous_container_selection(monkeypatch):
    calls = _identity_query(monkeypatch, _public_identity(), selected="a" * 64 + "\n" + "b" * 64)
    with pytest.raises(ValueError, match="exactly one"):
        stack.issuer_did_identity(IDENTITY_COMMAND)
    assert len(calls) == 1


def test_issuer_identity_query_failure_does_not_expose_credentials(monkeypatch):
    _identity_query(monkeypatch, _public_identity(), curl_code=22)
    with pytest.raises(ValueError) as failure:
        stack.issuer_did_identity(IDENTITY_COMMAND)
    assert "private-test-key" not in str(failure.value)


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


def test_local_source_issuance_migration_uses_exact_binary_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "marty-issuance-service"
    binary.write_bytes(b"current-source-native-migrator")
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    monkeypatch.setenv("MARTY_CONFORMANCE_SOURCE_VOLUME_ROOT", str(tmp_path))
    monkeypatch.setenv("MARTY_CONFORMANCE_SOURCE_MIGRATION_BINARY", str(binary))
    monkeypatch.setenv("MARTY_CONFORMANCE_SOURCE_MIGRATION_SHA256", digest)

    command = stack.compose_command("marty-conformance-test1")
    files = [command[index + 1] for index, value in enumerate(command) if value == "--file"]
    assert Path(files[-3]).name == stack.LOCAL_SOURCE_MIGRATION_FILE
    assert Path(files[-1]).name == stack.ISOLATION_FILE
    overlay = yaml.safe_load((ROOT / stack.LOCAL_SOURCE_MIGRATION_FILE).read_text())
    assert set(overlay["services"]) == {"issuance-migrations"}
    assert overlay["services"]["issuance-migrations"]["volumes"][0]["read_only"] is True

    binary.write_bytes(b"changed-native-migrator")
    with pytest.raises(ValueError, match="digest changed"):
        stack.compose_command("marty-conformance-test1")
    with pytest.raises(ValueError, match="native immutable-image mode"):
        stack.compose_command("marty-conformance-test1", use_ghcr=False)


def test_local_source_migration_receipt_requires_exact_owned_terminal_container(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    product = tmp_path / "product"
    migrations = product / "rust/services/issuance/migrations"
    migrations.mkdir(parents=True)
    (migrations / "0009.sql").write_text("SELECT 1;", encoding="utf-8")
    binary = tmp_path / "marty-issuance-service"
    binary.write_bytes(b"native")
    receipt = tmp_path / "migration.json"
    revision = "a" * 40
    project = "marty-conformance-test1"
    other_id, owned_id = "b" * 64, "a" * 64
    monkeypatch.setattr(stack, "ROOT", product)
    monkeypatch.setattr(stack, "project_container_ids", lambda _project: [other_id, owned_id])
    monkeypatch.setenv("MARTY_CONFORMANCE_SOURCE_VOLUME_ROOT", str(tmp_path))
    monkeypatch.setenv("MARTY_CONFORMANCE_SOURCE_MIGRATION_BINARY", str(binary))
    monkeypatch.setenv("MARTY_CONFORMANCE_SOURCE_MIGRATION_SHA256", hashlib.sha256(binary.read_bytes()).hexdigest())
    monkeypatch.setenv("MARTY_CONFORMANCE_SOURCE_REVISION", revision)
    monkeypatch.setenv("MARTY_CONFORMANCE_SOURCE_MIGRATION_RECEIPT", str(receipt))
    row = {
        "Id": owned_id,
        "Path": "/usr/local/bin/marty-issuance-service", "Args": ["migrate"],
        "State": {"Status": "exited", "ExitCode": 0, "OOMKilled": False},
        "Config": {"Image": "sha256:baseline", "Entrypoint": ["/usr/local/bin/marty-issuance-service"],
                   "Cmd": ["migrate"], "Labels": {
            "com.docker.compose.project": project,
            "com.docker.compose.service": "issuance-migrations",
        }},
        "Mounts": [{"Source": str(binary), "Destination": "/usr/local/bin/marty-issuance-service", "RW": False}],
    }
    other = {"Id": other_id, "Config": {"Labels": {
        "com.docker.compose.project": project, "com.docker.compose.service": "postgres",
    }}}

    def output(command, **_kwargs):
        return revision if command[0] == "git" else json.dumps([other, row])

    monkeypatch.setattr(stack.subprocess, "check_output", output)
    config = {"services": {"issuance-migrations": {
        "image": "sha256:baseline", "entrypoint": ["/usr/local/bin/marty-issuance-service"],
        "command": ["migrate"],
    }}}
    with pytest.raises(ValueError, match="prior local migrator lacks"):
        stack.attest_local_source_migration(
            project, config, resume=True, preexisting_container_id=owned_id,
        )
    assert not receipt.exists()
    # A canonical --resume can mean only OpenBao was prebootstrapped. This is
    # the first full-stack up, so its freshly completed migrator gets a receipt.
    stack.attest_local_source_migration(project, config, resume=True)
    assert json.loads(receipt.read_text())["containerId"] == owned_id
    stack.attest_local_source_migration(
        project, config, resume=True, preexisting_container_id=owned_id,
    )
    row["Mounts"][0]["RW"] = True
    with pytest.raises(ValueError, match="did not complete"):
        stack.attest_local_source_migration(
            project, config, resume=True, preexisting_container_id=owned_id,
        )
    row["Mounts"][0]["RW"] = False
    binary.write_bytes(b"changed-after-migration")
    with pytest.raises(ValueError, match="did not complete"):
        stack.attest_local_source_migration(
            project, config, resume=True, preexisting_container_id=owned_id,
        )


def test_source_migration_prior_container_probe_distinguishes_kms_only_resume(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[list[str]] = []
    output = ""

    def inspect(command, **_kwargs):
        observed.append(command)
        return output

    monkeypatch.setattr(stack.subprocess, "check_output", inspect)
    project = "marty-conformance-local-test1"
    assert stack.source_migration_container_before_up(project) is None
    assert f"label=com.docker.compose.project={project}" in observed[0]
    assert "label=com.docker.compose.service=issuance-migrations" in observed[0]
    output = "a" * 64 + "\n"
    assert stack.source_migration_container_before_up(project) == "a" * 64
    output = "a" * 64 + "\n" + "b" * 64 + "\n"
    with pytest.raises(ValueError, match="ambiguous"):
        stack.source_migration_container_before_up(project)


def test_project_inventory_uses_full_ids_for_migration_readback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed = []

    def inventory(command, **_kwargs):
        observed.append(command)
        return SimpleNamespace(stdout="a" * 64 + "\n" + "b" * 64 + "\n")

    monkeypatch.setattr(stack.subprocess, "run", inventory)
    assert stack.project_container_ids("marty-conformance-local-test1") == ["a" * 64, "b" * 64]
    assert "--no-trunc" in observed[0]


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
    assert [Path(path).name for path in files[-3:]] == [
        stack.DIDCOMM_AUTHCRYPT_FILE,
        stack.NATIVE_CA_FILE,
        stack.ISOLATION_FILE,
    ]


def test_didcomm_authcrypt_rejects_legacy_issuance_owner() -> None:
    with pytest.raises(ValueError, match="requires the native issuance owner"):
        stack.compose_command(
            "marty-conformance-test1",
            issuance_owner="legacy",
            include_didcomm_authcrypt=True,
        )


def test_didcomm_authcrypt_policy_is_mounted_only_into_native_issuance() -> None:
    overlay = yaml.safe_load(
        (ROOT / stack.DIDCOMM_AUTHCRYPT_FILE).read_text(encoding="utf-8")
    )
    assert set(overlay["services"]) == {"issuance-native"}
    issuance = overlay["services"]["issuance-native"]
    assert issuance["environment"] == {
        "DIDCOMM_ENCRYPTION_POLICY_FILE": (
            "/run/secrets/didcomm-authcrypt/didcomm-encryption-policy.json"
        ),
    }
    assert [mount["target"] for mount in issuance["volumes"]] == [
        "/run/secrets/didcomm-authcrypt/didcomm-encryption-policy.json",
    ]
    assert issuance["volumes"][0]["read_only"] is True
    assert issuance["volumes"][0]["bind"] == {"create_host_path": False}
    base = yaml.safe_load(
        (ROOT / "docker-compose.base.yml").read_text(encoding="utf-8")
    )
    native = yaml.safe_load(
        (ROOT / "docker-compose.profile.issuance-native.yml").read_text(
            encoding="utf-8"
        )
    )["services"]["issuance-native"]
    direct_kms_fields = {
        "DIDCOMM_KMS_ADDR", "DIDCOMM_KMS_CA_CERT_FILE", "DIDCOMM_KMS_TOKEN_FILE"
    }
    assert direct_kms_fields.isdisjoint(native["environment"])
    assert direct_kms_fields.isdisjoint(base["services"]["issuance"]["environment"])
    assert native["environment"]["INTEGRATION_SECRET_KMS_URL"] == (
        "https://signing-keys:8018/internal"
    )
    assert (
        native["environment"]["INTEGRATION_SECRET_KMS_CA_FILE"]
        == "/run/secrets/dev_integration_secret_ca"
    )
    assert (
        native["environment"]["ISSUANCE_CREDENTIAL_SIGN_GRANT_MINT_TOKEN_FILE"]
        == "/bao/issuance-credential-grant/token"
    )
    assert (
        "openbao_issuance_credential_grant:/bao/issuance-credential-grant:ro"
        in native["volumes"]
    )
    signing = base["services"]["signing-keys"]
    assert signing["environment"]["DIDCOMM_KMS_TOKEN_FILE"] == (
        "/bao/didcomm-issuance-token/token"
    )
    assert native["environment"]["SIGNING_KEYS_ISSUER_SIGN_KEY"] == (
        signing["environment"]["SIGNING_KEYS_ISSUER_SIGN_KEY"]
    )
    assert signing["environment"]["SIGNING_KEYS_GRANT_VERIFY_TOKEN_FILE"] == (
        "/bao/verify-grant/token"
    )
    assert (
        "openbao_verify_grant:/bao/verify-grant:ro" in signing["volumes"]
    )
    token_mount = "openbao_didcomm_issuance_token:/bao/didcomm-issuance-token:ro"
    assert token_mount in signing["volumes"]
    for service in (native, base["services"]["issuance"]):
        assert not any("openbao_didcomm_issuance_token:" in mount
                       for mount in service.get("volumes", []))
    assert (
        base["services"]["openbao-init"]["environment"][
            "BAO_DIDCOMM_ISSUANCE_TOKEN_FILE"
        ]
        == "/bao/didcomm-issuance-token/token"
    )


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
        assert "DIDCOMM_TLS_CA_FILE" not in (ROOT / production_file).read_text(
            encoding="utf-8"
        )
    base = yaml.safe_load(
        (ROOT / "docker-compose.base.yml").read_text(encoding="utf-8")
    )
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

    assert (
        "TRUST_REGISTRY_PRIVATE_HOST_ALLOWLIST: trust-registry-fixture" in trust_profile
    )
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
    assert any(
        path.endswith("docker-compose.profile.local-build.yml") for path in files
    )
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
    dockerignore = (ROOT / "ui" / ".dockerignore").read_text(encoding="utf-8")

    assert "oven/bun:1.3.14-alpine@sha256:" in dockerfile
    assert "nginx:1.29.1-alpine@sha256:" in dockerfile
    assert dockerfile.index(
        "COPY scripts/patch-prerenderer-ts-deepmerge.cjs"
    ) < dockerfile.index("RUN bun install --frozen-lockfile")
    assert "node_modules" in dockerignore.splitlines()
    assert "dist" in dockerignore.splitlines()
    assert ".env" in dockerignore.splitlines()


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
        "mailpit",
        "envoy",
    ):
        section = infrastructure.split(f"  {service}:\n", 1)[1].split("\n  ", 1)[0]
        assert "@sha256:" in section

    for service in ("openbao", "openbao-init"):
        section = infrastructure.split(f"  {service}:\n", 1)[1].split("\n  ", 1)[0]
        assert "${MARTY_OPENBAO_DIDCOMM_IMAGE:?" in section
        assert "quay.io/openbao/openbao@" not in section

    for service in ("keycloak", "keycloak-configurator"):
        section = infrastructure.split(f"  {service}:\n", 1)[1].split("\n  ", 1)[0]
        assert "ghcr.io/elevenid/marty-ui-oss/keycloak@${KEYCLOAK_KMS_IMAGE_DIGEST:?" in section

    assert "GET /ready HTTP/1.1" in infrastructure
    assert "Connection: close" in infrastructure
    assert "HTTP/1.0" not in infrastructure


def test_local_build_needs_no_python_wheel_artifacts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in ("MARTY_RS_URI", "MARTY_COMMON_URI"):
        monkeypatch.delenv(name, raising=False)
    assert stack.local_build_arguments() == []


def test_rust_migrations_have_no_python_artifact_inputs() -> None:
    """Rust services and migrations have no Python wheel build inputs."""
    compose = (ROOT / "docker-compose.base.yml").read_text(encoding="utf-8")
    assert "x-marty-migration-build-artifacts" not in compose
    migration = re.search(
        r"(?ms)^  db-migrate:\n(.*?)(?=^  [a-zA-Z0-9_-]+:\n|\Z)", compose
    )
    assert migration is not None
    assert "dockerfile: services/Dockerfile.migrations" in migration.group(1)
    assert "MARTY_RS_URI" not in migration.group(1)

    for service in (
        "revocation-profile-migrate",
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
        "signing-keys",
    ):
        section = re.search(
            rf"(?ms)^  {re.escape(service)}:\n(.*?)(?=^  [a-zA-Z0-9_-]+:\n|\Z)",
            compose,
        )
        assert section is not None
        assert "dockerfile: services/Dockerfile" in section.group(1)
        assert "marty_migration_build_artifacts" not in section.group(1)
        assert "SERVICE_NAME:" in section.group(1)

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
    native_spec = importlib.util.spec_from_file_location(
        "conformance_native_test_model", ROOT / "tests" / "test_conformance_native.py"
    )
    if native_spec is None or native_spec.loader is None:
        raise RuntimeError("could not load native conformance test model")
    native_test = importlib.util.module_from_spec(native_spec)
    native_spec.loader.exec_module(native_test)
    monkeypatch.setattr(
        stack,
        "rendered_config",
        lambda *_args, **_kwargs: native_test.model(),
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


def test_ghcr_profile_uses_shared_rust_image_for_issuance() -> None:
    profile = (ROOT / "docker-compose.profile.ghcr.yml").read_text(encoding="utf-8")
    base = (ROOT / "docker-compose.base.yml").read_text(encoding="utf-8")

    native = profile.split("  issuance-native:\n", 1)[1].split("\n  ", 1)[0]
    alias = profile.split("  issuance:\n", 1)[1].split("\n  ", 1)[0]
    assert "<<: *service-image" in native
    assert "<<: *service-image" in alias
    assert "  issuance-migrations:" in profile
    assert "image: ${MARTY_SERVICES_IMAGE" in profile
    assert "MARTY_ISSUANCE_IMAGE" not in base
    assert 'command: ["migrate"]' in base


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
    assert "OIDF_EDGE_BIND" in proxy
    assert "OIDF_EDGE_TLS_KMS_TOKEN_FILE" in proxy
    assert "tls.key" not in proxy


def test_oidf_tls_edge_uses_live_upstream_dns_and_shared_service_image() -> None:
    source = (
        ROOT / "rust/crates/passport-keyless-edge/src/bin/oidf_edge.rs"
    ).read_text(encoding="utf-8")
    image = (ROOT / "services/Dockerfile").read_text(encoding="utf-8")
    build = (ROOT / "scripts/build-rust-service-binaries.sh").read_text(
        encoding="utf-8"
    )
    released = (ROOT / "docker-compose.profile.ghcr.yml").read_text(encoding="utf-8")
    for peer in ("gateway:8000", "keycloak:8080", "ui:80"):
        assert peer in source
    assert "TcpStream::connect(upstream)" in source
    assert "--bin marty-oidf-keyless-edge" in build
    assert "/usr/local/bin/marty-oidf-keyless-edge" in image
    document = yaml.compose(released)
    edge = _mapping_value(_mapping_value(document, "services"), "oidf-tls-proxy")
    shared = _mapping_value(document, "x-service-image")
    assert _mapping_value(edge, "<<") is shared
    assert _mapping_value(shared, "image").value == (
        "${MARTY_SERVICES_IMAGE:?set MARTY_SERVICES_IMAGE to an immutable digest}"
    )
    assert _mapping_value(shared, "pull_policy").value == "always"
    # Older Compose loses !reset inherited through an alias. The edge must
    # retain the shared image and explicitly reset its source build locally.
    assert _mapping_value(edge, "build").tag == "!reset"
    assert _mapping_value(edge, "build").value == "null"


def test_oidf_tls_edge_preserves_the_complete_public_authority() -> None:
    source = (
        ROOT / "rust/crates/passport-keyless-edge/src/bin/oidf_edge.rs"
    ).read_text(encoding="utf-8")
    # The Rust proxy test exercises a non-default public port through Gateway.
    assert '"example.test:8443"' in source
    assert 'headers.insert("x-forwarded-host", host)' in source
    assert '"x-forwarded-port"' in source
    assert "|8443|https|127.0.0.1|" in source
    assert "gateway_upgrade_tunnels_bidirectional_bytes" in source


def test_released_conformance_stack_serves_the_exact_ui_artifact() -> None:
    profile = (ROOT / "docker-compose.profile.ghcr.yml").read_text(encoding="utf-8")
    oidf = (ROOT / "docker-compose.profile.oidf.yml").read_text(encoding="utf-8")
    proxy = (ROOT / "rust/crates/passport-keyless-edge/src/bin/oidf_edge.rs").read_text(
        encoding="utf-8"
    )

    assert "image: ${MARTY_UI_IMAGE:?" in profile
    assert (
        "condition: service_healthy"
        in profile.split("  ui:\n", 1)[1].split("\n  db-migrate:\n", 1)[0]
    )
    assert "  ui:\n        condition: service_healthy" in oidf
    assert '"/console"' in proxy
    assert '"/locales/"' in proxy
    assert '"/config.json"' in proxy
    assert '"/runtime-config.js"' in proxy
    assert '"/startup.js"' in proxy


def test_oidf_tls_edge_requires_remote_nonexportable_signing_identity() -> None:
    profile = (ROOT / "docker-compose.profile.oidf.yml").read_text(encoding="utf-8")
    edge = (ROOT / "rust/crates/passport-keyless-edge/src/bin/oidf_edge.rs").read_text(
        encoding="utf-8"
    )
    shared = (ROOT / "rust/crates/passport-keyless-edge/src/lib.rs").read_text(
        encoding="utf-8"
    )
    selector = (ROOT / "rust/crates/service-runtime/src/tls.rs").read_text(
        encoding="utf-8"
    )
    assert 'keyless_tls_config("OIDF_EDGE")' in edge
    assert "RemoteTlsIdentityFiles::from_values" in shared
    assert "OpenBao(OpenBaoTlsIdentityFiles)" in selector
    assert "AwsKms(AwsKmsTlsIdentityFiles)" in selector
    assert "keyless_https_server_config" in shared
    assert "OIDF_EDGE_TLS_KMS_KEY_VERSION" in profile
    assert "tls.key" not in profile


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
