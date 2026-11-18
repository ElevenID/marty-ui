"""Closed renderer/launch ownership guards; runtime evidence is a separate gate."""

from copy import deepcopy
from pathlib import Path
import re
import runpy
import shutil
import subprocess
import sys

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = runpy.run_path(str(ROOT / "scripts/render_base_native_runtime_fixture.py"))




@pytest.fixture
def spec(tmp_path):
    (tmp_path / "ca.pem").write_text(
        "-----BEGIN CERTIFICATE-----\nsynthetic stat-only CA control\n-----END CERTIFICATE-----\n"
    )
    (tmp_path / "didcomm-encryption-policy.json").write_text(
        "synthetic stat-only policy control"
    )
    (tmp_path / "grpc-tls-token").write_text("synthetic scoped token")
    return {
        "inputs": dict.fromkeys(FIXTURE["INPUT_KEYS"], "synthetic"),
        "http_port": 28105,
        "grpc_port": 29105,
        "gateway_port": 28100,
        "database_url": "postgresql://synthetic:owned@127.0.0.1:25432/owned",
        "redis_url": "redis://127.0.0.1:26379",
        "peer_origin": "http://127.0.0.1:28500",
        "grpc_peer_origin": "https://127.0.0.1:28502",
        "grpc_ca_file": str(tmp_path / "ca.pem"),
        "grpc_tls_certificate_file": str(tmp_path / "ca.pem"),
        "grpc_tls_token_file": str(tmp_path / "grpc-tls-token"),
        "grpc_tls_key_name": "platform_grpc_tls_synthetic",
        "legacy_origin": "http://127.0.0.1:28501",
        "ca_file": str(tmp_path / "ca.pem"),
        "policy_directory": str(tmp_path),
        "kms_url": "https://127.0.0.1:28200",
        "kms_ca_file": str(tmp_path / "ca.pem"),
        "integration_secret_kms_url": "https://127.0.0.1:28201/internal",
        "integration_secret_kms_ca_file": str(tmp_path / "ca.pem"),
        "authcrypt": True,
        "allow_private_ips": False,
    }


def test_spec_has_only_owned_explicit_addresses_and_paths(spec):
    FIXTURE["validate_spec"](spec)


@pytest.mark.parametrize(
    "field,value",
    [
        ("http_port", True),
        ("http_port", 0),
        ("grpc_port", 28105),
        ("gateway_port", 65536),
        ("allow_private_ips", "false"),
        ("database_url", "postgresql://production.example/db"),
        ("redis_url", "redis://production.example:6379"),
        ("peer_origin", "http://user:password@127.0.0.1:28500"),
        ("legacy_origin", "http://127.0.0.1:28500"),
        ("grpc_peer_origin", "http://127.0.0.1:28502"),
        ("grpc_ca_file", "absent"),
        ("grpc_tls_certificate_file", "absent"),
        ("grpc_tls_token_file", "absent"),
        ("grpc_tls_key_name", "wrong-key"),
        ("ca_file", "absent"),
        ("policy_directory", "relative"),
        ("kms_url", "http://production.example:8200"),
        ("kms_url", "http://127.0.0.1:28200"),
        ("kms_url", "http://user:password@127.0.0.1:28200"),
        ("kms_ca_file", "absent"),
        ("integration_secret_kms_url", "http://127.0.0.1:28201/internal"),
        ("integration_secret_kms_url", "https://production.example:8018/internal"),
        (
            "integration_secret_kms_url",
            "https://user:password@127.0.0.1:28201/internal",
        ),
        ("integration_secret_kms_ca_file", "absent"),
    ],
)
def test_spec_rejects_unowned_or_ambiguous_inputs(spec, field, value):
    spec[field] = value
    with pytest.raises(AssertionError):
        FIXTURE["validate_spec"](spec)


@pytest.mark.parametrize(
    "fault", ["extra-input", "missing-input", "newline", "extra-spec"]
)
def test_spec_rejects_ambient_configuration_and_env_file_injection(spec, fault):
    if fault == "extra-input":
        spec["inputs"]["BAO_TOKEN"] = "synthetic"
    elif fault == "missing-input":
        spec["inputs"].pop("TOKEN_HMAC_KEY")
    elif fault == "newline":
        spec["inputs"]["PUBLIC_API_URL"] = "synthetic\nBAO_TOKEN=injected"
    else:
        spec["operator_env_file"] = ".env"
    with pytest.raises(AssertionError):
        FIXTURE["validate_spec"](spec)


def model():
    gateway = dict.fromkeys(
        FIXTURE["GATEWAY_PEER_URLS"]
        | {"ISSUANCE_SERVICE_URL", "ISSUANCE_NATIVE_SERVICE_URL"},
        "http://synthetic:8000",
    )
    gateway["REDIS_DB_GATEWAY"] = "2"
    gateway["GATEWAY_REQUIRED_READY_SERVICES"] = "preserved-roster"
    return {
        "services": {
            "gateway": {"environment": gateway},
            "issuance-native": {
                "environment": {
                    "DIDCOMM_ALLOW_PRIVATE_IPS": "false",
                    "ISSUANCE_GRPC_ENABLED": "true",
                }
            },
            "flow": {"environment": {"ISSUANCE_GRPC_TARGET": "issuance:9005"}},
        },
        "volumes": {"preserved": {}},
    }


def test_fixture_overlay_is_addresses_and_paths_not_new_service_graph(spec):
    selected = model()
    overlay = FIXTURE["fixture_overlay"](spec, selected)
    actual = deepcopy(selected)
    for name, service in overlay["services"].items():
        actual["services"][name]["environment"].update(service["environment"])
    FIXTURE["assert_fixture_delta"](selected, actual, overlay, spec)
    assert (
        "DIDCOMM_ALLOW_PRIVATE_IPS"
        not in overlay["services"]["issuance-native"]["environment"]
    )
    assert "REDIS_DB_GATEWAY" not in overlay["services"]["gateway"]["environment"]
    assert (
        "GATEWAY_REQUIRED_READY_SERVICES"
        not in overlay["services"]["gateway"]["environment"]
    )
    for name, key, value in (
        ("issuance-native", "TOKEN_HMAC_KEY", "foreign"),
        ("issuance-native", "DIDCOMM_ALLOW_PRIVATE_IPS", "true"),
        ("issuance-native", "ISSUANCE_GRPC_ENABLED", "false"),
        ("gateway", "REDIS_DB_GATEWAY", "0"),
        ("gateway", "GATEWAY_REQUIRED_READY_SERVICES", "issuance-native"),
    ):
        changed, changed_overlay = deepcopy(actual), deepcopy(overlay)
        changed["services"][name]["environment"][key] = value
        changed_overlay["services"][name]["environment"][key] = value
        with pytest.raises(AssertionError):
            FIXTURE["assert_fixture_delta"](selected, changed, changed_overlay, spec)


def test_actual_base_compose_render_keeps_provider_ingress_out_of_peer_overlay(spec):
    if shutil.which("docker") is None:
        pytest.skip("Docker Compose is unavailable")
    gate = FIXTURE["GATE"]
    required = gate["required_compose_inputs"](
        "docker-compose.base.yml", gate["PROFILE"]
    )
    inputs = {**required, **spec["inputs"]}
    directory = Path(spec["policy_directory"])
    (directory / "images.env").write_text(
        "".join(f"{key}={value}\n" for key, value in sorted(inputs.items())),
        encoding="utf-8",
    )
    selected = gate["BIND"]["render_binding"](
        directory,
        ["docker", "compose"],
        *gate["files"](native=True, local=True, authcrypt=False),
        project=gate["PROJECT"],
    )
    gateway = selected["services"]["gateway"]["environment"]
    assert gateway["PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED"] == "false"
    assert "PASSPORT_PROVIDER_INGRESS_SERVICE_URL" not in gateway
    overlay = FIXTURE["fixture_overlay"](spec, selected)
    assert (
        "PASSPORT_PROVIDER_INGRESS_SERVICE_URL"
        not in overlay["services"]["gateway"]["environment"]
    )


def test_actual_authcrypt_render_binds_registered_https_owner_without_plugin_token(spec):
    if shutil.which("docker") is None:
        pytest.skip("Docker Compose is unavailable")
    rendered = FIXTURE["render"](spec, ["docker", "compose"])
    native = rendered["native_environment"]
    assert not {"DIDCOMM_KMS_ADDR", "DIDCOMM_KMS_CA_CERT_FILE", "DIDCOMM_KMS_TOKEN_FILE"} & set(native)
    assert native["INTEGRATION_SECRET_KMS_URL"] == spec["integration_secret_kms_url"]
    assert (
        native["INTEGRATION_SECRET_KMS_CA_FILE"]
        == spec["integration_secret_kms_ca_file"]
    )
    assert native["DIDCOMM_ENCRYPTION_POLICY_FILE"] == str(
        Path(spec["policy_directory"]) / "didcomm-encryption-policy.json"
    )


def test_shared_renderer_bootstrap_retains_frozen_hash_and_verifies_before_execution():
    script = (ROOT / "scripts/ci/install-compose-renderer.sh").read_text()
    assert "set -euo pipefail" in script
    assert (
        "https://github.com/docker/compose/releases/download/v5.4.0/docker-compose-linux-x86_64"
        in script
    )
    assert "837fd1d35bf6a494f41b5b5988269a7be79de337cf1a1a6ff0e45ab51bb4e9be" in script
    assert (
        script.index("curl --fail")
        < script.index("sha256sum --check --strict")
        < script.index("chmod +x")
    )
    assert 'compose_renderer="$RUNNER_TEMP/compose-render-v5.4.0"' in script
