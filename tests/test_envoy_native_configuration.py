"""Inert source and negative model guards; no Docker daemon or credentials."""

from copy import deepcopy
from pathlib import Path
import runpy
import re

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


def assert_registration(source, runner, workflow):
    for name in (
        "base_profile_envoy_composition_isolated",
        "base_profile_envoy_composition_child",
        "envoy_actual_image_validates_candidate",
    ):
        matches = re.findall(
            r"((?:#\[[^\n]+\]\s*)+)async fn " + name + r"\(\)\s*\{", source
        )
        assert matches == ["#[tokio::test]\n"], name
        assert f"'{name}: test'" in runner, name
    assert '"${executables[0]}" --skip "$serial_test" --nocapture --test-threads=2' in runner
    jobs = workflow["jobs"]
    steps = jobs["test-rust-services"]["steps"]
    builds = [
        step
        for step in steps
        if "docker build --tag marty-envoy:native-contract config/envoy"
        in step.get("run", "")
    ]
    assert len(builds) == 1
    assert not builds[0].get("continue-on-error") and "if" not in builds[0]
    assert "MARTY_ENVOY_TEST_IMAGE=%s" in builds[0]["run"]
    compose = [
        step
        for step in jobs["test-rust-service-images"]["steps"]
        if "scripts/test_envoy_native_compose.py" in step.get("run", "")
    ]
    assert (
        len(compose) == 1
        and "if" not in compose[0]
        and not compose[0].get("continue-on-error")
    )


def registration_inputs():
    return (
        (
            ROOT / "rust/services/issuance/tests/canvas_published_schema_contract.rs"
        ).read_text(encoding="utf-8"),
        (ROOT / "scripts/ci/run-published-canvas-contracts.sh").read_text(
            encoding="utf-8"
        ),
        yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")),
    )


def test_actual_envoy_gate_is_mandatory_and_unignored():
    assert_registration(*registration_inputs())


@pytest.mark.parametrize(
    "kind",
    (
        "ignored",
        "cfg",
        "missing-body",
        "missing-runner",
        "missing-image",
        "optional-image",
        "missing-compose",
    ),
)
def test_disconnected_or_optional_runtime_gate_is_rejected(kind):
    source, runner, workflow = registration_inputs()
    name = "base_profile_envoy_composition_isolated"
    if kind == "ignored":
        source = source.replace(f"async fn {name}", f"#[ignore]\nasync fn {name}")
    elif kind == "cfg":
        source = source.replace(f"async fn {name}", f"#[cfg(any())]\nasync fn {name}")
    elif kind == "missing-body":
        source = source.replace(f"async fn {name}", "async fn disconnected")
    elif kind == "missing-runner":
        runner = runner.replace(f"'{name}: test'", "'disconnected: test'")
    elif kind in ("missing-image", "optional-image"):
        steps = workflow["jobs"]["test-rust-services"]["steps"]
        step = next(
            step
            for step in steps
            if "docker build --tag marty-envoy:native-contract config/envoy"
            in step.get("run", "")
        )
        if kind == "missing-image":
            steps.remove(step)
        else:
            step["continue-on-error"] = True
    else:
        steps = workflow["jobs"]["test-rust-service-images"]["steps"]
        steps[:] = [
            step
            for step in steps
            if "scripts/test_envoy_native_compose.py" not in step.get("run", "")
        ]
    with pytest.raises(AssertionError):
        assert_registration(source, runner, workflow)
