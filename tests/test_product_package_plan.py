"""Independent source/build boundaries; no registry or installer operations."""

import copy
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

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


def image_receipts(root, plan):
    output = root / "receipts"
    output.mkdir()
    for image in plan["images"]:
        (output / (image["role"] + ".json")).write_text(json.dumps({
            "product": plan["product"], "version": plan["version"], "source_sha": SHA,
            "role": image["role"], "image": image["image"], "digest": "sha256:" + "1" * 64,
            "run_id": "123", "run_attempt": "2",
        }))
    return output


@pytest.mark.parametrize("product", ["marty-server", "marty-console"])
def test_assembled_package_freezes_only_its_complete_producer_attempt(tmp_path, product):
    root = repository(tmp_path, product)
    plan = MODULE.build_plan(root, product, SHA)
    output = image_receipts(root, plan)
    package = MODULE.assemble_package(root, plan, output, "123", "2")
    assert package["product"] == product
    assert package["version"] == plan["version"]
    assert package["source"]["commit"] == SHA
    assert {image["role"] for image in package["images"]} == {image["role"] for image in plan["images"]}
    assert all(image["digest"] == "sha256:" + "1" * 64 for image in package["images"])
    assert package["qualification"] == "unqualified"
    assert package["support_state"] == "experimental"
    assert package == MODULE.assemble_package(root, plan, output, "123", "2")
    schema = json.loads((ROOT / "deploy-config/schemas/product-package.schema.json").read_bytes())
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    validator.validate(package)
    for mutated in [dict(package, qualification="qualified"), dict(package, support_state="supported"), dict(package, product="marty-combined")]:
        assert not validator.is_valid(mutated)


@pytest.mark.parametrize("field,value", [
    ("product", "marty-console"), ("version", "9.9.9"), ("source_sha", "b" * 40),
    ("role", "ui"), ("image", "ghcr.io/other/image"), ("digest", "latest"),
    ("run_id", "124"), ("run_attempt", "1"), ("extra", True),
])
def test_cross_product_source_run_and_mutable_image_receipts_are_rejected(tmp_path, field, value):
    root = repository(tmp_path, "marty-server")
    plan = MODULE.build_plan(root, "marty-server", SHA)
    output = image_receipts(root, plan)
    path = output / (plan["images"][0]["role"] + ".json")
    receipt = json.loads(path.read_bytes())
    receipt[field] = value
    path.write_text(json.dumps(receipt))
    with pytest.raises(ValueError):
        MODULE.assemble_package(root, plan, output, "123", "2")


@pytest.mark.parametrize("mutation", ["missing", "extra", "changed_source", "supported_claim"])
def test_incomplete_attempts_and_changed_frozen_plans_cannot_assemble(tmp_path, mutation):
    root = repository(tmp_path, "marty-server")
    plan = MODULE.build_plan(root, "marty-server", SHA)
    output = image_receipts(root, plan)
    if mutation == "missing":
        (output / (plan["images"][0]["role"] + ".json")).unlink()
    elif mutation == "extra":
        (output / "ui.json").write_text("{}")
    elif mutation == "changed_source":
        (root / "services/Dockerfile").write_text("FROM changed\n")
    else:
        plan["qualification"] = "qualified"
    with pytest.raises(ValueError):
        MODULE.assemble_package(root, plan, output, "123", "2")


def test_producer_workflow_consumes_the_selected_plan_and_keeps_qualification_separate():
    import yaml

    workflow = yaml.safe_load((ROOT / ".github/workflows/product-packages.yml").read_bytes())
    assert workflow["permissions"] == {"contents": "read"}
    assert "refs/heads/main" in workflow["jobs"]["plan"]["steps"][0]["run"]
    assert "uses" not in workflow["jobs"]["plan"]["steps"][0]
    matrix = workflow["jobs"]["build"]["strategy"]["matrix"]
    assert matrix == "${{ fromJSON(needs.plan.outputs.matrix) }}"
    image = next(step["with"] for step in workflow["jobs"]["build"]["steps"] if step.get("id") == "image")
    assert image["file"] == "${{ matrix.dockerfile }}"
    assert image["sbom"] is True
    assert image["provenance"] == "mode=max"
    assert "push-by-digest=true" in image["outputs"]
    assert "unqualified" in image["labels"]
    assert workflow["jobs"]["package"]["needs"] == ["plan", "build"]
    for job in workflow["jobs"].values():
        for step in job["steps"]:
            if "uses" in step:
                assert len(step["uses"].split("@")[-1]) == 40
            assert "installer" not in step.get("run", "")


@pytest.mark.parametrize("product", ["marty-server", "marty-console"])
def test_actual_cli_produces_and_assembles_the_selected_source_plan(tmp_path, product):
    root = repository(tmp_path, product)
    script = ROOT / "scripts/product_package_plan.py"
    plan_path = tmp_path / "build-plan.json"
    base = [sys.executable, str(script), "--root", str(root), "--product", product, "--source-sha", SHA]
    subprocess.run([*base, "--output", str(plan_path)], check=True)
    plan = json.loads(plan_path.read_bytes())
    receipts = image_receipts(root, plan)
    output = tmp_path / "package.json"
    subprocess.run([*base, "--input-plan", str(plan_path), "--images-dir", str(receipts),
                    "--build-run-id", "123", "--build-run-attempt", "2", "--output", str(output)], check=True)
    assert json.loads(output.read_bytes()) == MODULE.assemble_package(root, plan, receipts, "123", "2")
    invalid_output = tmp_path / "incomplete.json"
    assert subprocess.run([*base, "--input-plan", str(plan_path), "--output", str(invalid_output)], check=False, capture_output=True).returncode != 0
    assert not invalid_output.exists()
