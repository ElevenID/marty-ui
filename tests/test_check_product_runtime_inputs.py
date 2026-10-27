"""A complete file/image preflight is required before candidate runtime work."""

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location(
    "check_product_runtime_inputs", ROOT / "scripts/check_product_runtime_inputs.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def candidate():
    return {
        "schema": "marty.product-package/v1",
        "product": "marty-server",
        "version": "0.1.0",
        "tag": "server-v0.1.0",
        "source": {"repository": "ElevenID/marty-ui", "commit": "a" * 40},
        "api": {"http": "v1", "mip": "0.5.0"},
        "images": [
            {
                "role": role,
                "uri": f"ghcr.io/elevenid/marty-server/{role}",
                "digest": "sha256:" + "b" * 64,
                "platform": "linux/amd64",
            }
            for role in ("keycloak", "migrations", "openbao-didcomm", "services")
        ],
    }


def prepared(tmp_path, package):
    secret = tmp_path / "secret"
    secret.write_text("synthetic")
    mounted = tmp_path / "runtime.conf"
    mounted.write_text("fixture")
    owned = MODULE.COMPOSE["package_images"](package)
    external = "docker.io/library/nginx@sha256:" + "1234abcd" * 8
    services = {
        "edge": {
            "image": external,
            "environment": {"SELFHOST_CONSOLE_ENABLED": "false"},
            "depends_on": {"gateway": {"condition": "service_started"}},
            "volumes": [{"type": "bind", "source": str(mounted), "target": "/etc/runtime.conf"}],
        },
        "gateway": {"image": owned["services"]},
        "auth": {"image": owned["services"]},
        "flow": {"image": owned["services"]},
        "keycloak": {"image": owned["keycloak"]},
        "postgres": {"image": "docker.io/library/postgres@sha256:" + "abcd1234" * 8},
        "redis": {"image": "docker.io/library/redis@sha256:" + "abcd5678" * 8},
    }
    return {
        "x-marty-product": MODULE.COMPOSE["metadata"](package),
        "secrets": {"example": {"file": str(secret)}},
        "services": services,
    }


def test_prepared_model_is_only_ready_for_an_attempt(tmp_path):
    package = candidate()
    result = MODULE.assess(prepared(tmp_path, package), package)
    assert result["result"] == "ready_for_runtime_attempt"
    assert result["external_kms_runtime_proven"] is False
    assert result["business_journey_proven"] is False
    assert set(result["checks"].values()) == {0}


def test_missing_deployment_inputs_and_synthetic_pins_block(tmp_path):
    package = candidate()
    model = prepared(tmp_path, package)
    Path(model["secrets"]["example"]["file"]).unlink()
    Path(model["services"]["edge"]["volumes"][0]["source"]).unlink()
    model["services"]["postgres"]["image"] = "postgres@sha256:" + "2" * 64
    result = MODULE.assess(model, package)
    assert result["result"] == "blocked_missing_runtime_inputs"
    assert result["checks"]["missing_secret_files"] == 1
    assert result["checks"]["missing_bind_sources"] == 1
    assert result["checks"]["placeholder_external_images"] == 1


@pytest.mark.parametrize("contents", [b"", b" \t\n"])
def test_empty_secret_file_blocks_runtime_attempt(tmp_path, contents):
    package = candidate()
    model = prepared(tmp_path, package)
    Path(model["secrets"]["example"]["file"]).write_bytes(contents)
    result = MODULE.assess(model, package)
    assert result["result"] == "blocked_missing_runtime_inputs"
    assert result["checks"]["missing_secret_files"] == 1


def test_wrong_product_image_or_console_dependency_cannot_pass(tmp_path):
    package = candidate()
    model = prepared(tmp_path, package)
    model["services"]["gateway"]["image"] = "ghcr.io/elevenid/marty-server/services@sha256:" + "c" * 64
    assert MODULE.assess(model, package)["checks"]["wrong_product_images"] == 1
    model = prepared(tmp_path, package)
    model["services"]["ui"] = {"image": "example@sha256:" + "d" * 64}
    with pytest.raises(ValueError, match="retains console"):
        MODULE.assess(model, package)
