"""Closed test-renderer boundaries; actual loader/RPC proof is a configured gate."""

from copy import deepcopy
from pathlib import Path
import runpy
import shutil

import pytest

ROOT = Path(__file__).resolve().parents[1]
GATE = runpy.run_path(str(ROOT / "scripts/render_flow_native_runtime_fixture.py"))


def spec(directory):
    return {
        "native_rpc": "http://127.0.0.1:51001",
        "legacy_rpc": "http://127.0.0.1:51002",
        "legacy_http": "http://127.0.0.1:51003",
        "directory": directory.as_posix(),
    }


def service(owner):
    return {
        "environment": {
            "ISSUANCE_GRPC_TARGET": owner,
            "ISSUANCE_SERVICE_URL": "http://issuance:8005",
            "ISSUANCE_API_KEY_FILE": "/run/secrets/issuance_api_key",
            "SIGNING_KEYS_INTERNAL_API_KEY_FILE": "/run/secrets/issuance_api_key",
            "GRPC_WORKLOAD_TLS_CA_CERT": "/run/secrets/workload_identity_ca_cert",
            "DATABASE_URL_TEMPLATE": "postgresql://marty:${MARTY_DB_PASSWORD}@postgres:5432/marty",
            "GRPC_INSECURE_ALLOWED": "true",
            "KEEP": "unchanged",
        },
        "secrets": [
            {"source": "issuance_api_key"},
            {"source": "workload_identity_ca_cert"},
        ],
    }


def test_flow_fixture_renders_frozen_selfhost_with_closed_native_additions(tmp_path):
    if shutil.which("docker") is None:
        pytest.skip("Docker Compose is needed to render the deployment model")
    result = GATE["render"](spec(tmp_path), ["docker", "compose"])
    assert result["schema"] == "marty.flow-rendered-selection/v1"
    assert set(result["profiles"]) == {"base", "base_native", "selfhost"}
    assert (
        result["profiles"]["selfhost"]["original_environment"][
            "ISSUANCE_GRPC_TARGET"
        ]
        == "issuance-native:9005"
    )


def test_flow_selfhost_additions_require_closed_interpolation():
    selfhost = GATE["SELFHOST"]
    additions = selfhost["rendered_additions"](
        selfhost["NATIVE_ADDITIVE"],
        {
            "CANVAS_MIRROR_WORKER_ENABLED": "true",
            "CANVAS_MIRROR_WORKER_BATCH_LIMIT": "7",
        },
    )
    assert additions["CANVAS_MIRROR_WORKER_ENABLED"] == "true"
    assert additions["CANVAS_MIRROR_WORKER_BATCH_LIMIT"] == "7"
    assert additions["CANVAS_MIRROR_PUBLISH_INTERVAL_SECONDS"] == "300"
    with pytest.raises(AssertionError, match="Unsupported closed interpolation"):
        selfhost["rendered_additions"](
            {"CANVAS_MIRROR_WORKER_ENABLED": "unreviewed"}, {}
        )


@pytest.mark.parametrize(
    "owner,target",
    [
        ("issuance:9005", "legacy_rpc"),
        ("issuance-native:9005", "native_rpc"),
    ],
)
def test_target_mapping_preserves_selection_and_all_unrelated_values(
    tmp_path, owner, target
):
    inputs = spec(tmp_path)
    assert GATE["validate_spec"](inputs) == tmp_path
    original = service(owner)
    baseline = deepcopy(original)
    actual = GATE["mapped_environment"](original, inputs)
    expected = dict(original["environment"])
    expected.update(
        ISSUANCE_GRPC_TARGET=inputs[target],
        ISSUANCE_SERVICE_URL=inputs["legacy_http"],
        ISSUANCE_API_KEY_FILE=(tmp_path / "issuance_api_key").as_posix(),
        SIGNING_KEYS_INTERNAL_API_KEY_FILE=(tmp_path / "issuance_api_key").as_posix(),
        GRPC_WORKLOAD_TLS_CA_CERT=(tmp_path / "workload_identity_ca_cert").as_posix(),
    )
    assert actual == expected
    assert original == baseline


@pytest.mark.parametrize(
    "fault", ["public", "credentials", "path", "same", "unknown", "nonempty"]
)
def test_fixture_scope_is_closed(tmp_path, fault):
    inputs = spec(tmp_path)
    if fault == "public":
        inputs["native_rpc"] = "http://example.com:9005"
    elif fault == "credentials":
        inputs["native_rpc"] = "http://synthetic@127.0.0.1:9005"
    elif fault == "path":
        inputs["native_rpc"] += "/unexpected"
    elif fault == "same":
        inputs["legacy_rpc"] = inputs["native_rpc"]
    elif fault == "unknown":
        inputs["operational"] = True
    else:
        (tmp_path / "existing").write_text("synthetic")
    with pytest.raises(AssertionError):
        GATE["validate_spec"](inputs)


@pytest.mark.parametrize("fault", ["target", "physical", "mount", "path", "unowned"])
def test_mapping_cannot_hide_missing_or_unowned_bindings(tmp_path, fault):
    value = service("issuance-native:9005")
    if fault == "target":
        value["environment"]["ISSUANCE_GRPC_TARGET"] = "other:9005"
    elif fault == "physical":
        value["environment"]["ISSUANCE_SERVICE_URL"] = "http://issuance-native:8005"
    elif fault == "mount":
        value["secrets"] = []
    elif fault == "path":
        value["environment"]["ISSUANCE_API_KEY_FILE"] = "/operator/issuance_api_key"
    else:
        value["environment"]["UNOWNED_FILE"] = "/run/secrets/unowned"
        value["secrets"].append({"source": "unowned"})
    with pytest.raises((AssertionError, KeyError)):
        GATE["mapped_environment"](value, spec(tmp_path))


def test_actual_loader_factory_and_mandatory_gate_are_registered():
    source = (
        ROOT / "rust/services/issuance/tests/support/flow_rendered_selection.rs"
    ).read_text()
    assert "FlowServiceConfig::from_env()" in source
    assert "FlowGrpcChannelFactories::from_config(&config)" in source
    assert '.join("scripts/load-secrets-env.sh")' in source
    assert ".env_clear()" in source
    assert "GrpcIssuanceProvider::new" not in source
    script = (ROOT / "scripts/ci/run-published-canvas-contracts.sh").read_text()
    assert (
        "grep -Fx 'flow_rendered_settings_select_native_rpc_and_preserve_legacy_http: test'"
        in script
    )
