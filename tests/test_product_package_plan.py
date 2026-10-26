"""Independent source/build boundaries; no registry or installer operations."""

import copy
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("product_package_plan", ROOT / "scripts/product_package_plan.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
SHA = "a" * 40


def repository(tmp_path, product):
    catalog = json.loads((ROOT / "release/product-packages.json").read_bytes())
    (tmp_path / "release").mkdir()
    (tmp_path / "release/product-packages.json").write_text(json.dumps(catalog))
    selected = catalog["products"][product]
    for image in selected["images"].values():
        target = tmp_path / image["dockerfile"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("FROM scratch\n")
    if product == "marty-server":
        (tmp_path / "release/server-version.txt").write_text("2.3.4\n")
    else:
        (tmp_path / "release/console-version.txt").write_text("5.6.7\n")
        (tmp_path / "release/stack-lock.json").write_bytes((ROOT / "release/stack-lock.json").read_bytes())
    return tmp_path


def test_server_build_needs_no_console_source_version_or_npm_lock(tmp_path):
    root = repository(tmp_path, "marty-server")
    plan = MODULE.build_plan(root, "marty-server", SHA)
    assert not (root / "ui").exists()
    assert not (root / "release/stack-lock.json").exists()
    assert plan["version"] == "2.3.4"
    assert plan["tag"] == "server-v2.3.4"
    assert {image["role"] for image in plan["images"]} == {"services", "migrations", "openbao-didcomm", "keycloak"}
    assert all(image["image"].startswith("ghcr.io/elevenid/marty-server/") for image in plan["images"])
    assert all(set(image["build_args"]) == {"MARTY_RELEASE_VERSION", "MARTY_UI_SHA"} for image in plan["images"])
    assert plan["dependency_lock_sha256"] is None
    assert plan["qualification"] == "unqualified"


def test_console_build_has_its_own_version_and_no_native_server_build(tmp_path):
    root = repository(tmp_path, "marty-console")
    plan = MODULE.build_plan(root, "marty-console", SHA)
    assert not (root / "release/server-version.txt").exists()
    assert not (root / "rust").exists()
    assert plan["version"] == "5.6.7"
    assert plan["tag"] == "console-v5.6.7"
    assert len(plan["images"]) == 1
    image = plan["images"][0]
    assert image["role"] == "ui"
    assert image["target"] == "selfhost"
    assert image["build_args"]["UI_VARIANT"] == "selfhost"
    assert image["build_args"]["NGINX_CONFIG"] == "nginx.spa.conf"
    assert image["build_args"]["MARTY_RELEASE_VERSION"] == "5.6.7"
    assert image["build_args"]["MARTY_API_CORE_VERSION"] == "0.3.6"


@pytest.mark.parametrize("version", ["latest", "01.2.3", "1.2.3\nextra", "1.2", "1.2.3-unknown"])
def test_server_version_must_be_an_exact_stable_semver(tmp_path, version):
    root = repository(tmp_path, "marty-server")
    (root / "release/server-version.txt").write_text(version)
    with pytest.raises(ValueError, match="version is invalid"):
        MODULE.build_plan(root, "marty-server", SHA)


@pytest.mark.parametrize("mutation", ["role", "namespace", "tag", "version_source", "path", "api"])
def test_product_boundary_drift_is_rejected(tmp_path, mutation):
    root = repository(tmp_path, "marty-server")
    path = root / "release/product-packages.json"
    catalog = json.loads(path.read_bytes())
    spec = catalog["products"]["marty-server"]
    if mutation == "role":
        spec["images"]["ui"] = copy.deepcopy(spec["images"]["services"])
    elif mutation == "namespace":
        spec["image_namespace"] = "ghcr.io/other/server"
    elif mutation == "tag":
        spec["tag_prefix"] = "v"
    elif mutation == "version_source":
        spec["version"] = {"path": "ui/package.json", "json_field": "version"}
    elif mutation == "path":
        spec["images"]["services"]["dockerfile"] = "../outside/Dockerfile"
    else:
        spec["api"]["mip"] = "unsupported"
    path.write_text(json.dumps(catalog))
    with pytest.raises(ValueError):
        MODULE.build_plan(root, "marty-server", SHA)


def test_actual_product_plans_are_deterministic_and_have_disjoint_images():
    server = MODULE.build_plan(ROOT, "marty-server", SHA)
    console = MODULE.build_plan(ROOT, "marty-console", SHA)
    assert server == MODULE.build_plan(ROOT, "marty-server", SHA)
    assert console == MODULE.build_plan(ROOT, "marty-console", SHA)
    assert not {image["image"] for image in server["images"]} & {image["image"] for image in console["images"]}
    assert server["api"] == console["api"] == {"http": "v1", "mip": "0.5.0"}
    assert server["tag"] != console["tag"]
