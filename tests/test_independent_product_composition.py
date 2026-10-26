"""Product composition source contracts; no installer or release verification."""

import copy
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "compose_product_packages", ROOT / "scripts/compose_product_packages.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def package(product, version="0.1.0"):
    prefix, roles = MODULE.PLAN["PRODUCTS"][product]
    return {
        "schema": "marty.product-package/v1",
        "product": product,
        "version": version,
        "tag": prefix + version,
        "source": {"repository": "ElevenID/marty-ui", "commit": "a" * 40},
        "api": {"http": "v1", "mip": "0.5.0"},
        "images": [
            {
                "role": role,
                "uri": f"ghcr.io/elevenid/{product}/{role}",
                "digest": "sha256:" + "1" * 64,
                "platform": "linux/amd64",
            }
            for role in sorted(roles)
        ],
    }


@pytest.fixture(scope="module")
def source_model():
    env = dict(
        os.environ,
        SELFHOST_STATE_DIR=str(ROOT / "_test_state"),
        SELFHOST_SECRET_DIR=str(ROOT / "_test_secrets"),
        MARTY_KEYCLOAK_KMS_IMAGE="ghcr.io/elevenid/marty-ui-oss/keycloak@sha256:"
        + "e" * 64,
    )
    env.pop("COMPOSE_PROFILES", None)
    completed = subprocess.run(
        [
            "docker",
            "compose",
            "--profile",
            "*",
            "--env-file",
            ".env.selfhost.production.example",
            "-f",
            "docker-compose.selfhost.prod.yml",
            "-f",
            "docker-compose.selfhost.bundle.override.yml",
            "config",
            "--format",
            "json",
        ],
        cwd=ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )
    return json.loads(completed.stdout)


def pinned_base(source_model):
    base = copy.deepcopy(source_model)
    # Synthetic external pins exercise composition only; no image is pulled.
    for name, uri in [("postgres", "postgres"), ("redis", "redis"), ("edge", "nginx")]:
        base["services"][name]["image"] = uri + "@sha256:" + "2" * 64
    return base


def test_actual_source_server_dag_loses_only_console_and_tunnel_dependencies(
    source_model,
):
    base = pinned_base(source_model)
    original = copy.deepcopy(base)
    result = MODULE.server_composition(base, package("marty-server", "2.3.4"))
    assert base == original
    assert set(result["services"]) == set(base["services"]) - MODULE.REMOVED_SERVICES
    assert len(result["services"]) == 28
    assert (
        result["services"]["edge"]["environment"]["SELFHOST_CONSOLE_ENABLED"] == "false"
    )
    assert "ui" not in result["services"]["edge"]["depends_on"]
    for name, service in result["services"].items():
        assert "build" not in service
        assert "extends" not in service
        assert "@sha256:" in service["image"]
        assert not set(service.get("depends_on", {})) & MODULE.REMOVED_SERVICES
        for field in ["secrets", "volumes", "entrypoint", "command", "healthcheck"]:
            assert service.get(field) == base["services"][name].get(field)
        if name in MODULE.SHARED_SERVICES:
            assert (
                service["environment"]["SERVICE_NAME"] == MODULE.SHARED_SERVICES[name]
            )
            assert service["environment"]["MARTY_RELEASE_VERSION"] == "2.3.4"
            assert service["environment"]["MARTY_UI_SHA"] == "a" * 40
    assert "canvas-sync-worker" in result["services"]
    assert "google_analytics_measurement_id" not in result["secrets"]
    assert "google_site_verification" not in result["secrets"]
    assert "cloudflare_tunnel_token" not in result["secrets"]


def test_console_is_one_independent_image_with_no_backend_startup_or_secret_dependency():
    result = MODULE.console_composition(
        package("marty-console", "7.8.9"), "https://api.example.com:8443", 3100
    )
    assert set(result["services"]) == {"console"}
    console = result["services"]["console"]
    assert (
        "depends_on" not in console
        and "secrets" not in console
        and "build" not in console
    )
    assert console["image"].startswith("ghcr.io/elevenid/marty-console/ui@sha256:")
    assert console["environment"] == {
        "MARTY_SERVER_ORIGIN": "https://api.example.com:8443"
    }
    assert result["x-marty-product"]["version"] == "7.8.9"
    assert console["ports"] == ["127.0.0.1:3100:80"]


@pytest.mark.parametrize(
    "mutation",
    [
        "mutable_external",
        "unknown_build",
        "hidden_ui",
        "ui_mount",
        "include",
        "extends",
    ],
)
def test_server_rejects_hidden_builds_mutable_images_and_frontend_dependencies(
    source_model, mutation
):
    base = pinned_base(source_model)
    if mutation == "mutable_external":
        base["services"]["redis"]["image"] = "redis:latest"
    elif mutation == "unknown_build":
        base["services"]["unbound"] = {"build": "."}
    elif mutation == "hidden_ui":
        base["services"]["gateway"]["network_mode"] = "service:ui"
    elif mutation == "ui_mount":
        base["services"]["gateway"]["volumes"].append(
            {"type": "bind", "source": "/checkout/ui/dist", "target": "/ui"}
        )
    elif mutation == "include":
        base["include"] = ["another-compose.yml"]
    else:
        base["services"]["gateway"]["extends"] = {
            "file": "other.yml",
            "service": "gateway",
        }
    with pytest.raises(ValueError):
        MODULE.server_composition(base, package("marty-server"))


@pytest.mark.parametrize(
    "origin",
    [
        "",
        "ftp://api.example",
        "https://user:pass@api.example",
        "https://api.example/path",
        "https://api.example?x=1",
        "https://api.example#x",
        "https://api.example\ninjected",
        "https://api.example:0",
        "https://api.example:65536",
    ],
)
def test_console_rejects_non_origin_and_credential_bearing_configuration(origin):
    with pytest.raises(ValueError):
        MODULE.console_composition(package("marty-console"), origin)


@pytest.mark.parametrize(
    "field,value",
    [("version", "latest"), ("tag", "v0.1.0"), ("api", {"http": "v2", "mip": "0.5.0"})],
)
def test_composition_rejects_inconsistent_package_identity(field, value):
    source = package("marty-console")
    source[field] = value
    with pytest.raises(ValueError):
        MODULE.console_composition(source, "https://api.example")


def test_actual_cli_renders_both_products_as_valid_compose_models(
    source_model, tmp_path
):
    base = tmp_path / "base.json"
    base.write_text(json.dumps(pinned_base(source_model)))
    for product in ("marty-server", "marty-console"):
        manifest, output = (
            tmp_path / (product + ".json"),
            tmp_path / (product + "-compose.json"),
        )
        manifest.write_text(json.dumps(package(product)))
        args = [
            sys.executable,
            str(ROOT / "scripts/compose_product_packages.py"),
            "--package",
            str(manifest),
            "--output",
            str(output),
        ]
        args += (
            ["--base", str(base)]
            if product == "marty-server"
            else ["--server-origin", "https://api.example"]
        )
        subprocess.run(args, check=True)
        # Avoid any workstation env-file lookup; this JSON has explicit inputs.
        empty = tmp_path / "empty.env"
        empty.touch()
        subprocess.run(
            [
                "docker",
                "compose",
                "--env-file",
                str(empty),
                "-f",
                str(output),
                "config",
                "--quiet",
            ],
            check=True,
            capture_output=True,
            text=True,
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("uri", "ghcr.io/elevenid/marty-server/ui"),
        ("digest", "latest"),
        ("platform", "linux/arm64"),
    ],
)
def test_console_cannot_bind_another_product_mutable_image_or_platform(field, value):
    source = package("marty-console")
    source["images"][0][field] = value
    with pytest.raises(ValueError):
        MODULE.console_composition(source, "https://api.example")


def test_source_console_template_requires_only_its_own_image_and_server_origin(
    tmp_path,
):
    empty = tmp_path / "empty.env"
    empty.touch()
    env = dict(
        os.environ,
        MARTY_CONSOLE_IMAGE="ghcr.io/elevenid/marty-console/ui@sha256:" + "1" * 64,
        MARTY_SERVER_ORIGIN="https://api.example",
        MARTY_CONSOLE_PORT="3100",
    )
    command = [
        "docker",
        "compose",
        "--env-file",
        str(empty),
        "-f",
        str(ROOT / "docker-compose.console.yml"),
        "config",
        "--format",
        "json",
    ]
    result = json.loads(subprocess.check_output(command, env=env, text=True))
    assert set(result["services"]) == {"console"}
    console = result["services"]["console"]
    assert console["image"] == env["MARTY_CONSOLE_IMAGE"]
    assert "depends_on" not in console and "secrets" not in console
    env.pop("MARTY_SERVER_ORIGIN")
    assert (
        subprocess.run(command, env=env, check=False, capture_output=True).returncode
        != 0
    )


@pytest.mark.parametrize("product", ["marty-server", "marty-console"])
def test_shipped_renderer_needs_no_repository_frontend_or_nonstdlib_install(source_model, tmp_path, product):
    plan = MODULE.PLAN["build_plan"](ROOT, product, "a" * 40)
    receipts = tmp_path / "receipts"
    receipts.mkdir()
    for image in plan["images"]:
        (receipts / (image["role"] + ".json")).write_text(json.dumps({
            "product": product, "version": plan["version"], "source_sha": "a" * 40,
            "role": image["role"], "image": image["image"], "digest": "sha256:" + "1" * 64,
            "run_id": "123", "run_attempt": "1",
        }))
    selected = MODULE.PLAN["assemble_package"](ROOT, plan, receipts, "123", "1")
    bundle = tmp_path / "downloaded-package"
    MODULE.PLAN["write_bundle"](ROOT, plan, selected, bundle)
    assert not (bundle / "ui").exists() and not (bundle / "rust").exists()
    assert (bundle / "LICENSE").read_bytes() == (ROOT / "LICENSE").read_bytes()
    assert (bundle / "docker-compose.console.yml").exists() == (product == "marty-console")
    assert (bundle / "runtime").exists() == (product == "marty-server")
    if product == "marty-server":
        actual = {path.relative_to(bundle / "runtime").as_posix() for path in (bundle / "runtime").rglob("*") if path.is_file()}
        assert actual == set(MODULE.PLAN["SERVER_RUNTIME_FILES"])
        for relative in actual:
            payload = (bundle / "runtime" / relative).read_bytes()
            if relative == "config/keycloak/11id-realm.json":
                original = json.loads((ROOT / relative).read_bytes())
                sanitized = json.loads(payload)
                assert "users" not in sanitized
                assert all("secret" not in client for client in sanitized["clients"])
                original.pop("users")
                for client in original["clients"]:
                    client.pop("secret", None)
                assert sanitized == original
            else:
                assert payload == (ROOT / relative).read_bytes()

    base = tmp_path / "base.json"
    base.write_text(json.dumps(pinned_base(source_model)))
    output = tmp_path / "selected-compose.json"
    args = [sys.executable, str(bundle / "scripts/compose_product_packages.py"), "--package", str(bundle / "product-package.json"), "--output", str(output)]
    args += ["--base", str(base), "--runtime-dir", str(bundle / "runtime")] if product == "marty-server" else ["--server-origin", "https://api.example"]
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    subprocess.run(args, cwd=tmp_path, env=env, check=True)
    assert json.loads(output.read_bytes())["x-marty-product"]["product"] == product
    with pytest.raises(ValueError, match="must be new"):
        MODULE.PLAN["write_bundle"](ROOT, plan, selected, bundle)


def test_packaged_runtime_replaces_only_known_static_mounts(tmp_path, source_model):
    runtime = tmp_path / "runtime"
    for relative in MODULE.PLAN["SERVER_RUNTIME_FILES"]:
        path = runtime / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((ROOT / relative).read_bytes())
    base = pinned_base(source_model)
    original = copy.deepcopy(base)
    result = MODULE.server_composition(base, package("marty-server"), runtime)
    assert base == original
    mapped = 0
    for name, service in result["services"].items():
        targets = MODULE.PLAN["SERVER_RUNTIME_MOUNTS"].get(name, {})
        for mount in service.get("volumes", []):
            if mount.get("type") != "bind":
                continue
            previous = next(v for v in base["services"][name]["volumes"] if v["target"] == mount["target"])
            if mount["target"] in targets:
                assert mount["source"] == str((runtime / targets[mount["target"]]).resolve())
                assert {k: v for k, v in mount.items() if k != "source"} == {k: v for k, v in previous.items() if k != "source"}
                mapped += 1
            else:
                assert mount == previous
    assert mapped == 12
    assert result["secrets"] == MODULE.server_composition(base, package("marty-server"))["secrets"]
    (runtime / "scripts/load-secrets-env.sh").unlink()
    with pytest.raises(ValueError, match="source path escapes or is missing"):
        MODULE.server_composition(base, package("marty-server"), runtime)
