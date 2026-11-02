"""Verify release audience/source binding without a registry or deployment."""

from __future__ import annotations

import copy
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import ui_release as release  # noqa: E402

SOURCE = "a" * 40
IMAGE_DIGEST = "sha256:" + "b" * 64


@pytest.fixture
def source(tmp_path):
    for name in ("release/stack-lock.json", "docker/ui.Dockerfile"):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((ROOT / name).read_bytes())
    return tmp_path


def metadata(plan, audience="production"):
    return {"component": "ui", "release_version": plan["version"], "marty_ui_sha": SOURCE,
            "audience": audience, "ui_variant": "public" if audience == "production" else "selfhost"}


def record(source, plan, **overrides):
    arguments = {"source_sha": SOURCE, "image_digest": IMAGE_DIGEST, "run_id": "123",
                 "run_attempt": "2", "metadata": metadata(plan)}
    arguments.update(overrides)
    return release.production_release(source, plan, **arguments)


@pytest.mark.parametrize("profile", ["full", "tester"])
def test_customer_profiles_cannot_select_marketing(profile):
    target, args = release.build_profile("customer", profile)
    assert target == "selfhost"
    assert args == {"UI_VARIANT": "selfhost", "SELFHOST_PUBLIC_PROFILE": profile,
                    "NGINX_CONFIG": "nginx.spa.conf"}
    assert release.build_profile("production", profile) == (
        "public", {"UI_VARIANT": "public", "SELFHOST_PUBLIC_PROFILE": "full",
                   "NGINX_CONFIG": "nginx.prod.conf"})


@pytest.mark.parametrize("audience,profile", [("unknown", "full"), ("customer", "marketing"),
                                              ("production", "full\nUI_VARIANT=selfhost")])
def test_unknown_profile_or_audience_fails_closed(audience, profile):
    with pytest.raises(ValueError, match="unknown"):
        release.build_profile(audience, profile)


def test_website_plan_is_deterministic_and_separate_from_customer_coordinates(source):
    plan = release.production_plan(source, SOURCE)
    assert plan == release.production_plan(source, SOURCE)
    assert plan["image"] == "ghcr.io/elevenid/marty-ui-oss/ui-public"
    assert plan["target"] == "public"
    assert plan["audience"] == "production"
    assert plan["build_args"]["UI_VARIANT"] == "public"
    assert plan["build_args"]["NGINX_CONFIG"] == "nginx.prod.conf"
    assert plan["build_args"]["MARTY_UI_SHA"] == SOURCE
    assert plan["dependency_lock_sha256"] == release.digest((source / "release/stack-lock.json").read_bytes())
    lock = release.read(source / "release/stack-lock.json")
    for name, prefix in (("marty-api-core", "MARTY_API_CORE"), ("marty-blog", "MARTY_BLOG")):
        component = next(item for item in lock["components"] if item["name"] == name)
        artifact = next(item for item in component["artifacts"] if item["type"] == "npm")
        assert plan["build_args"][prefix + "_VERSION"] == component["version"]
        assert plan["build_args"][prefix + "_URI"] == artifact["uri"]
        assert plan["build_args"][prefix + "_DIGEST"] == artifact["digest"]


@pytest.mark.parametrize("mutation", ["foreign-uri", "missing-digest", "duplicate", "bad-version"])
def test_website_plan_rejects_unlocked_or_ambiguous_dependencies(source, mutation):
    path = source / "release/stack-lock.json"
    lock = release.read(path)
    component = next(item for item in lock["components"] if item["name"] == "marty-blog")
    artifact = next(item for item in component["artifacts"] if item["type"] == "npm")
    if mutation == "foreign-uri":
        artifact["uri"] = "https://example.com/untrusted.tgz"
    elif mutation == "missing-digest":
        artifact["digest"] = "latest"
    elif mutation == "duplicate":
        lock["components"].append(copy.deepcopy(component))
    else:
        lock["release"] = "marty-ui@latest"
    path.write_bytes(release.canonical(lock))
    with pytest.raises(ValueError):
        release.production_plan(source, SOURCE)


def test_production_manifest_binds_only_its_digest_plan_source_and_attempt(source):
    plan = release.production_plan(source, SOURCE)
    value = record(source, plan)
    assert value["schema"] == "marty.production-web-release/v1"
    assert value["image"] == {"uri": plan["image"], "digest": IMAGE_DIGEST, "platform": "linux/amd64"}
    assert value["producer"] == {"workflow": release.WORKFLOW, "ref": "refs/heads/main",
                                 "run_id": "123", "run_attempt": "2"}
    assert value["build_plan_sha256"] == release.digest(release.canonical(plan))
    assert value["image_metadata"]["audience"] == "production"
    assert value["source_sha"] == SOURCE
    assert "services" not in json.dumps(value)


@pytest.mark.parametrize("field,value", [("image", "ghcr.io/elevenid/marty-ui-oss/ui"),
                                         ("target", "selfhost"), ("source_sha", "c" * 40),
                                         ("version", "9.9.9")])
def test_production_manifest_rejects_cross_audience_or_stale_plans(source, field, value):
    plan = release.production_plan(source, SOURCE)
    plan[field] = value
    with pytest.raises(ValueError, match="build plan differs"):
        record(source, plan)


def test_changed_source_inputs_cannot_reuse_a_prepared_plan(source):
    plan = release.production_plan(source, SOURCE)
    with (source / "docker/ui.Dockerfile").open("a") as file:
        file.write("\n# changed after planning\n")
    with pytest.raises(ValueError, match="build plan differs"):
        record(source, plan)


@pytest.mark.parametrize("field,value", [("audience", "customer"), ("ui_variant", "selfhost"),
                                         ("marty_ui_sha", "c" * 40), ("release_version", "9.9.9")])
def test_image_metadata_rejects_wrong_audience_source_and_version(source, field, value):
    plan = release.production_plan(source, SOURCE)
    wrong = metadata(plan)
    wrong[field] = value
    with pytest.raises(ValueError, match="audience, source or version differs"):
        record(source, plan, metadata=wrong)


def test_customer_validator_rejects_a_production_image(source):
    plan = release.production_plan(source, SOURCE)
    assert release.check_image(metadata(plan, "customer"), audience="customer",
                               source_sha=SOURCE, version=plan["version"])
    with pytest.raises(ValueError, match="audience, source or version differs"):
        release.check_image(metadata(plan), audience="customer", source_sha=SOURCE, version=plan["version"])


@pytest.mark.parametrize("field,value", [("image_digest", "latest"), ("run_id", "0"),
                                         ("run_attempt", "2\nother"), ("source_sha", "main")])
def test_manifest_rejects_mutable_or_invalid_producer_identity(source, field, value):
    plan = release.production_plan(source, SOURCE)
    with pytest.raises(ValueError):
        record(source, plan, **{field: value})


def test_cli_round_trip_records_the_exact_emitted_plan_bytes(source):
    plan_path, metadata_path, output_path = (source / name for name in ("plan.json", "metadata.json", "manifest.json"))
    command = [sys.executable, str(ROOT / "scripts/ui_release.py")]
    subprocess.run(command + ["plan", "--root", str(source), "--source-sha", SOURCE,
                              "--output", str(plan_path)], check=True, capture_output=True)
    plan = release.read(plan_path)
    metadata_path.write_bytes(release.canonical(metadata(plan)))
    subprocess.run(command + ["record", "--root", str(source), "--source-sha", SOURCE,
        "--input-plan", str(plan_path), "--image-metadata", str(metadata_path),
        "--image-digest", IMAGE_DIGEST, "--run-id", "123", "--run-attempt", "2",
        "--output", str(output_path)], check=True, capture_output=True)
    assert release.read(output_path) == record(source, plan)
    assert release.read(output_path)["build_plan_sha256"] == release.digest(plan_path.read_bytes())


def test_website_workflow_separates_source_build_signature_and_deployment():
    workflow = yaml.safe_load((ROOT / release.WORKFLOW).read_text())
    assert set(workflow.get("on", workflow.get(True))) == {"workflow_dispatch"}
    assert workflow["permissions"] == {"contents": "read"}
    assert workflow["env"]["IMAGE"] == release.PUBLIC_IMAGE
    job = workflow["jobs"]["release"]
    steps = job["steps"]
    assert job["if"] == "github.repository == 'ElevenID/marty-ui'"
    assert job["permissions"]["contents"] == "read"
    checkout = next(step for step in steps if step.get("uses", "").startswith("actions/checkout@"))
    assert checkout["with"]["ref"] == "${{ github.sha }}"
    guard = next(index for index, step in enumerate(steps) if "Require the exact protected-main" in step.get("name", ""))
    login = next(index for index, step in enumerate(steps) if step.get("uses", "").startswith("docker/login-action@"))
    assert guard < login
    assert 'test "$GITHUB_REF" = refs/heads/main' in steps[guard]["run"]
    assert 'git rev-parse' in steps[guard]["run"] and 'git merge-base --is-ancestor' in steps[guard]["run"]
    build = next(step["with"] for step in steps if step.get("id") == "build")
    assert build["file"] == "docker/ui.Dockerfile" and build["target"] == "public"
    assert "push-by-digest=true" in build["outputs"]
    assert "tags" not in build
    assert build["provenance"] == "mode=max" and build["sbom"] is True
    shell = "\n".join(step.get("run", "") for step in steps)
    assert "check-image --audience production" in shell
    assert "cosign sign --yes" in shell and "cosign sign-blob --yes" in shell
    attestations = [step["with"] for step in steps if step.get("uses", "").startswith("actions/attest-build-provenance@")]
    assert len(attestations) == 2
    assert any(item.get("subject-path") == "production-web/production-web-release.json" for item in attestations)
    assert not any(command in shell for command in ("kubectl", "helm upgrade", "gh release create", "ssh "))
    for step in steps:
        if "uses" in step:
            assert re.fullmatch(r"[^\s]+@[0-9a-f]{40}", step["uses"])
        if "run" in step:
            subprocess.run(["bash", "-n"], input=step["run"], text=True, check=True, capture_output=True)


def test_all_customer_producers_check_the_image_audience():
    for name, job in (("nightly-release.yml", "build-images"), ("product-packages.yml", "build"),
                      ("cd.yml", "build-selfhost-lock-roles")):
        workflow = yaml.safe_load((ROOT / ".github/workflows" / name).read_text())
        steps = workflow["jobs"][job]["steps"]
        assert any("check-image --audience customer" in step.get("run", "") for step in steps)
        assert not any(release.PUBLIC_IMAGE in str(step) for step in steps)


@pytest.mark.parametrize("case", ["valid", "bare-spa", "customer-portal", "wrong-product-page",
                                  "unrendered-product", "unprerendered-home"])
def test_production_smoke_requires_rendered_marketing_pages(tmp_path, case):
    workflow = yaml.safe_load((ROOT / release.WORKFLOW).read_text())
    smoke = next(step["run"] for step in workflow["jobs"]["release"]["steps"]
                 if step.get("name") == "Verify the production image and prerendered homepage")
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    marker = '<meta name="prerender-status-code" content="200" />'
    schema = '<script type="application/ld+json" data-seo-jsonld="true">{}</script>'
    homepage = ('<title>ElevenID</title>' + marker + schema
                + '<link rel="canonical" href="https://elevenidllc.com/">')
    product = (marker + schema + '<link rel="canonical" href="https://elevenidllc.com/product">'
               + '<h1 class="heading">Product catalog</h1>')
    if case == "bare-spa":
        homepage = '<title>ElevenID</title><div id="root"></div>'
    elif case == "customer-portal":
        homepage = '<title>ElevenID Application Portal</title><h1>Application portal</h1>'
    elif case == "wrong-product-page":
        product = homepage + '<h1>Website</h1>'
    elif case == "unrendered-product":
        product = product.replace('<h1 class="heading">Product catalog</h1>', '')
    elif case == "unprerendered-home":
        homepage = homepage.replace(marker, '')
    (fixtures / "homepage.html").write_text(homepage)
    (fixtures / "product.html").write_text(product)
    (fixtures / "metadata.json").write_bytes(release.canonical({
        "component": "ui", "release_version": "1.2.3", "marty_ui_sha": SOURCE,
        "audience": "production", "ui_variant": "public",
    }))

    # Execute the real workflow smoke step; replace only registry/container/HTTP
    # access with deterministic fixture delivery. The image identity checker and
    # content gates themselves run unchanged.
    binaries = tmp_path / "bin"
    binaries.mkdir()
    (binaries / "python").symlink_to(sys.executable)
    mocks = {
        "docker": "import sys\nif sys.argv[1] == 'inspect': print('production')\n",
        "curl": """import os, sys
from pathlib import Path
from urllib.parse import urlsplit
url = next(arg for arg in sys.argv if arg.startswith('http://'))
name = {'/': 'homepage.html', '/product/': 'product.html',
        '/marty-ui-release.json': 'metadata.json'}[urlsplit(url).path]
output = sys.argv[sys.argv.index('--output') + 1]
Path(output).write_bytes((Path(os.environ['SMOKE_FIXTURES']) / name).read_bytes())
""",
    }
    for name, body in mocks.items():
        executable = binaries / name
        executable.write_text(f"#!{sys.executable}\n" + body)
        executable.chmod(0o755)
    (tmp_path / "scripts").symlink_to(ROOT / "scripts", target_is_directory=True)
    (tmp_path / "production-web").mkdir()
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    result = subprocess.run(["bash", "-c", smoke], cwd=tmp_path, text=True, capture_output=True,
        env={"PATH": str(binaries) + os.pathsep + os.environ["PATH"],
             "RUNNER_TEMP": str(runtime), "SMOKE_FIXTURES": str(fixtures),
             "IMAGE": release.PUBLIC_IMAGE, "DIGEST": IMAGE_DIGEST,
             "VERSION": "1.2.3", "GITHUB_SHA": SOURCE})
    assert (result.returncode == 0) == (case == "valid"), result.stderr
