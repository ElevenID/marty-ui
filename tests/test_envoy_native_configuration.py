"""Inert source and negative model guards; no Docker daemon or credentials."""

from copy import deepcopy
from pathlib import Path
import runpy

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
GATE = runpy.run_path(str(ROOT / "scripts/test_envoy_native_compose.py"))


def test_generated_override_only_replaces_default_native_envoy_config():
    profile = yaml.safe_load(GATE["PROFILE"].read_text(encoding="utf-8"))
    assert set(profile) == {"services"}
    assert set(profile["services"]) == {"envoy"}
    envoy = profile["services"]["envoy"]
    assert set(envoy) == {"volumes", "depends_on"}
    assert envoy["depends_on"] == {"issuance-native": {"condition": "service_healthy"}}
    assert envoy["volumes"] == [
        {
            "type": "bind",
            "source": "${MARTY_ENVOY_NATIVE_CONFIG:?Render and select the qualified native Envoy configuration}",
            "target": "/etc/envoy/envoy.yaml",
            "read_only": True,
            "bind": {"create_host_path": False},
        }
    ]
    canonical = yaml.safe_load(
        (ROOT / "config/envoy/envoy.yaml").read_text(encoding="utf-8")
    )
    assert any(
        cluster["name"] == "issuance_native_grpc"
        for cluster in canonical["static_resources"]["clusters"]
    )


def test_native_envoy_requires_local_keyless_bridge_and_remote_server_identity():
    base = yaml.safe_load(
        (ROOT / "docker-compose.base.yml").read_text(encoding="utf-8")
    )
    profile = yaml.safe_load(
        (ROOT / "docker-compose.profile.issuance-native.yml").read_text(
            encoding="utf-8"
        )
    )
    canonical = yaml.safe_load(
        (ROOT / "config/envoy/envoy.yaml").read_text(encoding="utf-8")
    )
    cluster = next(
        value
        for value in canonical["static_resources"]["clusters"]
        if value["name"] == "issuance_native_grpc"
    )
    socket = cluster["load_assignment"]["endpoints"][0]["lb_endpoints"][0]["endpoint"][
        "address"
    ]["socket_address"]
    assert socket == {"address": "127.0.0.1", "port_value": 19006}

    bridge = base["services"]["envoy-issuance-bridge"]
    assert bridge["entrypoint"] == ["/usr/local/bin/marty-keyless-grpc-bridge"]
    assert "-p marty-keyless-grpc-bridge --bin marty-keyless-grpc-bridge" in (
        ROOT / "scripts/build-rust-service-binaries.sh"
    ).read_text(encoding="utf-8")
    assert "target/release/marty-keyless-grpc-bridge" in (
        ROOT / "services/Dockerfile"
    ).read_text(encoding="utf-8")
    assert bridge["network_mode"] == "service:envoy"
    assert bridge["environment"]["KEYLESS_BRIDGE_LISTEN"] == "127.0.0.1:19006"
    assert bridge["environment"]["KEYLESS_BRIDGE_UPSTREAM_HOST"] == "issuance-native"
    assert bridge["environment"]["KEYLESS_BRIDGE_UPSTREAM_PORT"] == "9005"
    assert bridge["secrets"] == [
        "workload_identity_ca_cert",
        "envoy_issuance_client_cert",
        "openbao_tls_ca_cert",
        "envoy_issuance_tls_kms_token",
    ]
    assert all(
        "PRIVATE_KEY" not in key and not key.endswith("_KEY_FILE")
        for key in bridge["environment"]
    )
    assert (
        "ENVOY_ISSUANCE_TLS_KMS_TOKEN_FILE"
        in base["secrets"]["envoy_issuance_tls_kms_token"]["file"]
    )

    native = profile["services"]["issuance-native"]
    assert (
        native["environment"]["GRPC_WORKLOAD_TLS_SERVER_CERT"]
        == "/run/secrets/issuance_workload_server_cert"
    )
    assert (
        native["environment"]["GRPC_WORKLOAD_TLS_CA_CERT"]
        == "/run/secrets/workload_identity_ca_cert"
    )
    assert (
        native["environment"]["GRPC_WORKLOAD_TLS_SERVER_KMS_TOKEN_FILE"]
        == "/run/secrets/issuance_tls_kms_token"
    )
    assert "GRPC_WORKLOAD_TLS_SERVER_KEY" not in native["environment"]


def fixture(path):
    baseline = {
        "services": {
            "envoy": {
                "ports": ["127.0.0.1:9000:9000"],
                "depends_on": {
                    "issuance": {"condition": "service_healthy", "required": True}
                },
                "volumes": [
                    {
                        "type": "bind",
                        "source": "./config/envoy/envoy.yaml",
                        "target": "/etc/envoy/envoy.yaml",
                        "read_only": True,
                    },
                    {
                        "type": "bind",
                        "source": "./config/envoy/proto_descriptor.pb",
                        "target": "/etc/envoy/proto_descriptor.pb",
                        "read_only": True,
                    },
                ],
            },
            "issuance-native": {"environment": {"GRPC_SERVICE_TOKEN": "synthetic"}},
            "issuance": {"environment": {"GRPC_SERVICE_TOKEN": "synthetic"}},
        }
    }
    selected = deepcopy(baseline)
    selected["services"]["envoy"]["volumes"][0] = {
        "type": "bind",
        "source": path.as_posix(),
        "target": "/etc/envoy/envoy.yaml",
        "read_only": True,
        "bind": {"create_host_path": False},
    }
    selected["services"]["envoy"]["depends_on"]["issuance-native"] = {
        "condition": "service_healthy",
        "required": True,
    }
    return baseline, selected


@pytest.mark.parametrize("kind", range(7))
def test_complete_model_guard_rejects_unrelated_changes_and_mount_weakening(
    tmp_path, kind
):
    path = tmp_path / "candidate.yaml"
    path.write_text("synthetic", encoding="utf-8")
    baseline, selected = fixture(path)
    GATE["assert_model"](baseline, selected, path)
    envoy = selected["services"]["envoy"]
    if kind == 0:
        envoy["ports"] = ["0.0.0.0:9000:9000"]
    elif kind == 1:
        envoy["environment"] = {"GRPC_SERVICE_TOKEN": "injected"}
    elif kind == 2:
        envoy["volumes"][0]["read_only"] = False
    elif kind == 3:
        envoy["volumes"][0]["bind"]["create_host_path"] = True
    elif kind == 4:
        envoy["volumes"][1]["source"] = "unrelated-descriptor.pb"
    elif kind == 5:
        del envoy["depends_on"]["issuance"]
    else:
        selected["services"]["issuance"]["environment"]["GRPC_SERVICE_TOKEN"] = (
            "changed"
        )
    with pytest.raises(AssertionError, match="unrelated Compose"):
        GATE["assert_model"](baseline, selected, path)


def test_regular_file_guard_does_not_confuse_config_render_with_file_existence(
    tmp_path,
):
    path = tmp_path / "absent.yaml"
    baseline, selected = fixture(path)
    with pytest.raises(AssertionError, match="existing regular file"):
        GATE["assert_model"](baseline, selected, path)


def require_model_gate(workflow):
    steps = workflow["jobs"]["test-rust-service-images"]["steps"]
    selected = [step for step in steps if "scripts/test_envoy_native_compose.py" in step.get("run", "")]
    assert len(selected) == 1
    assert "if" not in selected[0]
    assert not selected[0].get("continue-on-error")


def test_current_envoy_compose_model_gate_is_mandatory():
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    require_model_gate(workflow)


def test_scalar_yaml_contract_retains_its_fast_renderer_owner():
    name = "feature_unified_renderer_emits_scalar_ports_for_external_yaml_consumers"
    renderer = (ROOT / "rust/crates/release-evidence/src/envoy_config.rs").read_text(
        encoding="utf-8"
    )
    runtime = (
        ROOT / "rust/services/issuance/tests/support/envoy_runtime_sidecar.rs"
    ).read_text(encoding="utf-8")
    manifest = (ROOT / "rust/crates/release-evidence/Cargo.toml").read_text(
        encoding="utf-8"
    )
    assert f"#[test]\n    fn {name}()" in renderer
    assert name not in runtime
    assert (
        'serde_json = { workspace = true, features = ["arbitrary_precision"] }'
        in manifest
    )


@pytest.mark.parametrize("fault", ["missing", "optional", "conditional"])
def test_disconnected_or_optional_model_gate_is_rejected(fault):
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    steps = workflow["jobs"]["test-rust-service-images"]["steps"]
    step = next(step for step in steps if "scripts/test_envoy_native_compose.py" in step.get("run", ""))
    if fault == "missing":
        steps.remove(step)
    elif fault == "optional":
        step["continue-on-error"] = True
    else:
        step["if"] = "false"
    with pytest.raises(AssertionError):
        require_model_gate(workflow)
