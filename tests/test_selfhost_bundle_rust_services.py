"""Read-only rendered-model gate unit tests; no service startup or image pulls."""

from copy import deepcopy
from pathlib import Path
import runpy

import pytest


@pytest.fixture
def gate():
    root = Path(__file__).resolve().parents[1]
    return runpy.run_path(str(root / "scripts/test_canvas_worker_compose_render.py"))


@pytest.mark.parametrize(
    "value,expected",
    [
        (
            {"EMPTY": "", "INHERITED": None, "VALUE": "a=b"},
            {"EMPTY": "", "INHERITED": None, "VALUE": "a=b"},
        ),
        (
            ["EMPTY=", "INHERITED", "VALUE=a=b"],
            {"EMPTY": "", "INHERITED": None, "VALUE": "a=b"},
        ),
        ([], {}),
        ({}, {}),
    ],
)
def test_environment_mapping_preserves_empty_inherited_and_embedded_equals(
    gate, value, expected
):
    original = deepcopy(value)
    result = gate["environment_mapping"](value)
    assert result == expected
    result["NEW"] = "independent"
    assert value == original


@pytest.mark.parametrize(
    "value", [None, "NAME=value", [17], ["=value"], [""], ["A=1", "A=2"], ["A", "A=2"]]
)
def test_environment_mapping_rejects_ambiguous_or_malformed_list(gate, value):
    with pytest.raises(AssertionError):
        gate["environment_mapping"](value)


@pytest.fixture
def models():
    runtime = {
        "image": "synthetic/base:tag",
        "pull_policy": "missing",
        "environment": {"SECRET_FILE": "/run/secrets/synthetic", "INHERITED": None},
        "secrets": [{"source": "synthetic", "target": "synthetic"}],
        "volumes": [
            {
                "type": "bind",
                "source": "./synthetic",
                "target": "/config",
                "read_only": True,
            }
        ],
        "depends_on": {
            "migration": {
                "condition": "service_completed_successfully",
                "required": True,
            }
        },
        "networks": {"internal": None},
        "restart": "unless-stopped",
        "healthcheck": {"test": ["CMD", "synthetic-health"], "interval": "10s"},
        "future_runtime_field": {"nested": ["must", "survive"]},
    }
    base = {
        "services": {
            name: deepcopy(runtime)
            for name in ("from-environment", "from-args", "from-target")
        }
    }
    alpha, beta, gamma = base["services"].values()
    alpha["build"] = {
        "dockerfile": "services/Dockerfile",
        "args": {"SERVICE_NAME": "ignored-default"},
    }
    alpha["environment"]["SERVICE_NAME"] = "synthetic-alpha"
    beta["build"] = {
        "dockerfile": "services/Dockerfile",
        "args": ["SERVICE_NAME=synthetic-beta"],
    }
    beta["environment"] = ["SECRET_FILE=/run/secrets/synthetic", "INHERITED"]
    gamma["build"] = {
        "dockerfile": "rust/services/Dockerfile.ci",
        "target": "synthetic-gamma",
    }
    base["services"]["not-converted"] = {"build": {"dockerfile": "other/Dockerfile"}}
    anchor = {
        "image": "${REGISTRY:-synthetic.invalid}/services:${SELFHOST_IMAGE_TAG:?required}",
        "pull_policy": "always",
    }
    bundle = {
        "x-selfhost-service-image": anchor,
        "services": deepcopy(base["services"]),
    }
    for name, selector in (
        ("from-environment", "synthetic_alpha"),
        ("from-args", "synthetic_beta"),
        ("from-target", "synthetic_gamma"),
    ):
        service = bundle["services"][name]
        del service["build"]
        service.update(anchor)
        service["environment"] = {
            "SECRET_FILE": "/run/secrets/synthetic",
            "INHERITED": None,
            "SERVICE_NAME": selector,
        }
    return base, bundle


def test_gate_derives_converted_inventory_and_preserves_entire_runtime(gate, models):
    base, bundle = models
    snapshot = deepcopy(models)
    assert gate["assert_shared_rust_services"](base, bundle) == [
        "from-environment",
        "from-args",
        "from-target",
    ]
    assert models == snapshot


def test_rendered_environment_list_is_equivalent_to_mapping(gate, models):
    base, bundle = models
    bundle["services"]["from-target"]["environment"] = [
        "SECRET_FILE=/run/secrets/synthetic",
        "INHERITED",
        "SERVICE_NAME=synthetic_gamma",
    ]
    assert len(gate["assert_shared_rust_services"](base, bundle)) == 3


@pytest.mark.parametrize(
    "mutation",
    [
        "missing-override",
        "wrong-selector",
        "swapped-image",
        "surviving-build",
        "command",
        "entrypoint",
        "lost-secret",
        "lost-secret-file",
        "dependency",
        "future-field",
        "restart",
        "healthcheck",
        "mount",
        "network",
        "pull-policy",
    ],
)
def test_gate_rejects_incomplete_conversion_or_runtime_feature_loss(
    gate, models, mutation
):
    base, bundle = models
    service = bundle["services"]["from-target"]
    if mutation == "missing-override":
        bundle["services"]["from-target"] = deepcopy(base["services"]["from-target"])
    elif mutation == "wrong-selector":
        service["environment"]["SERVICE_NAME"] = "synthetic_alpha"
    elif mutation == "swapped-image":
        service["image"] = "synthetic/wrong-image:tag"
    elif mutation == "surviving-build":
        service["build"] = deepcopy(base["services"]["from-target"]["build"])
    elif mutation in {"command", "entrypoint"}:
        service[mutation] = ["synthetic-wrong-executable"]
    elif mutation == "lost-secret":
        service["secrets"] = []
    elif mutation == "lost-secret-file":
        del service["environment"]["SECRET_FILE"]
    elif mutation == "dependency":
        service["depends_on"]["migration"]["condition"] = "service_started"
    elif mutation == "future-field":
        service["future_runtime_field"]["nested"].pop()
    elif mutation == "restart":
        service["restart"] = "no"
    elif mutation == "healthcheck":
        del service["healthcheck"]
    elif mutation == "mount":
        service["volumes"][0]["read_only"] = False
    elif mutation == "network":
        service["networks"] = {}
    elif mutation == "pull-policy":
        service["pull_policy"] = "missing"
    else:
        pytest.fail(f"Unhandled mutation: {mutation}")
    with pytest.raises(
        AssertionError, match="preserve converted Rust service: from-target"
    ):
        gate["assert_shared_rust_services"](base, bundle)


@pytest.mark.parametrize("field", ["command", "entrypoint"])
def test_base_explicit_launch_override_requires_review(gate, models, field):
    base, bundle = models
    base["services"]["from-target"][field] = ["synthetic-command"]
    bundle["services"]["from-target"][field] = ["synthetic-command"]
    with pytest.raises(AssertionError, match="Review explicit Rust launch override"):
        gate["assert_shared_rust_services"](base, bundle)


def test_gate_rejects_missing_base_selector(gate, models):
    base, bundle = models
    del base["services"]["from-target"]["build"]["target"]
    with pytest.raises(AssertionError, match="Missing base selector: from-target"):
        gate["assert_shared_rust_services"](base, bundle)


def test_gate_rejects_empty_derived_inventory(gate, models):
    base, bundle = models
    base["services"] = {"not-converted": base["services"]["not-converted"]}
    with pytest.raises(AssertionError, match="No converted Rust services inspected"):
        gate["assert_shared_rust_services"](base, bundle)


@pytest.mark.parametrize(
    "field,value", [("pull_policy", "missing"), ("image", "synthetic/other:latest")]
)
def test_gate_rejects_invalid_shared_image_anchor(gate, models, field, value):
    base, bundle = models
    bundle["x-selfhost-service-image"][field] = value
    with pytest.raises(AssertionError):
        gate["assert_shared_rust_services"](base, bundle)
