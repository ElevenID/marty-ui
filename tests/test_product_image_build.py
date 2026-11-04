"""The shared builder accepts only complete source-owned recipes."""
import copy
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("product_image_build", ROOT / "scripts/product_image_build.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
SHA = "a" * 40


@pytest.mark.parametrize("product", ["marty-server", "marty-console"])
def test_every_product_role_keeps_exact_recipe_and_product_cache(product):
    for row in MODULE.product_plan(ROOT, product, SHA)["images"]:
        recipe = MODULE.recipe(ROOT, producer="product", source_sha=SHA, row=row, product=product)
        assert recipe["image"] == row["image"]
        assert recipe["dockerfile"] == row["dockerfile"]
        assert recipe["target"] == row["target"]
        assert recipe["platform"] == "linux/amd64"
        assert f"MARTY_UI_SHA={SHA}" in recipe["build-args"]
        assert recipe["cache-to"] == f"type=gha,mode=max,scope=product-{product}-{row['role']}"
        assert recipe["secret-envs"] == ""


@pytest.mark.parametrize("field,value", [("role", "extra"), ("context", "/tmp/foreign"),
    ("dockerfile", "foreign.Dockerfile"), ("target", "foreign"), ("platform", "linux/arm64"),
    ("image", "ghcr.io/foreign/image"), ("version_tag", "latest"), ("dockerfile_sha256", "sha256:" + "0" * 64),
    ("unexpected", True), ("build_args", {"MARTY_UI_SHA": "b" * 40})])
def test_product_matrix_cannot_override_source(field, value):
    row = copy.deepcopy(MODULE.product_plan(ROOT, "marty-console", SHA)["images"][0])
    row[field] = value
    with pytest.raises(ValueError, match="authoritative"):
        MODULE.recipe(ROOT, producer="product", source_sha=SHA, row=row, product="marty-console")


def nightly():
    lock = json.loads((ROOT / "release/stack-lock.json").read_text())
    version = lock["release"].split("@", 1)[1] + "-nightly.20261103.42"
    return version, MODULE.nightly_plan({"source_sha": SHA, "version": version}, lock)


def test_all_nightly_roles_preserve_customer_recipe_and_read_only_cache():
    version, rows = nightly()
    assert len(rows) == 6
    for row in rows:
        recipe = MODULE.recipe(ROOT, producer="nightly", source_sha=SHA, row=row, version=version)
        assert recipe["build-args"] == row["build_args"]
        assert recipe["cache-from"] == "type=gha,scope=marty-ui-public-services"
        assert recipe["cache-to"] == ""
        assert recipe["secret-envs"].endswith("sccache_mode=SCCACHE_GHA_RW_MODE")


@pytest.mark.parametrize("field,value", [("role", "foreign"), ("image", "ghcr.io/foreign/image"),
    ("target", "production"), ("build_args", "MARTY_UI_SHA=" + "b" * 40), ("context", ".")])
def test_nightly_matrix_cannot_override_source(field, value):
    version, rows = nightly()
    row = copy.deepcopy(rows[0]); row[field] = value
    with pytest.raises(ValueError, match="authoritative"):
        MODULE.recipe(ROOT, producer="nightly", source_sha=SHA, row=row, version=version)


@pytest.mark.parametrize("version", ["1.2.3", "1.2.3-nightly.20261103.42", "1.1.264-nightly.20261103.0", "latest\nINJECTED=1"])
def test_nightly_identity_must_match_eligible_source_lock(version):
    _, rows = nightly()
    with pytest.raises(ValueError):
        MODULE.recipe(ROOT, producer="nightly", source_sha=SHA, row=rows[0], version=version)


def test_producer_boundaries_are_closed():
    row = MODULE.product_plan(ROOT, "marty-console", SHA)["images"][0]
    for args in [{"producer": "unknown"}, {"producer": "product", "product": "foreign"},
                 {"producer": "product", "product": "marty-console", "version": "1.2.3"},
                 {"producer": "nightly", "product": "marty-console"}]:
        with pytest.raises(ValueError):
            MODULE.recipe(ROOT, source_sha=SHA, row=row, **args)
    with pytest.raises(ValueError):
        MODULE.decode(b'{"role":"ui","role":"services"}')


def test_real_checkout_and_cache_authority(tmp_path):
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=tmp_path, stderr=subprocess.DEVNULL, text=True).strip()
    git("init"); git("config", "user.name", "Test"); git("config", "user.email", "test@example.invalid")
    file = tmp_path / "source"; file.write_text("source\n")
    git("add", "source"); git("commit", "-m", "fixture")
    sha = git("rev-parse", "HEAD")
    env = {"GITHUB_REPOSITORY": "ElevenID/marty-ui", "GITHUB_REF": "refs/heads/main",
           "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_SHA": sha,
           "GITHUB_WORKFLOW_REF": "ElevenID/marty-ui/.github/workflows/nightly-release.yml@refs/heads/main",
           "SCCACHE_GHA_RW_MODE": "READ_ONLY"}
    MODULE.trusted_checkout(tmp_path, "nightly", sha, env)
    for key, value in [("GITHUB_EVENT_NAME", "pull_request"), ("GITHUB_REF", "refs/heads/topic"),
                       ("GITHUB_REPOSITORY", "foreign/repo"), ("GITHUB_SHA", SHA),
                       ("GITHUB_WORKFLOW_REF", env["GITHUB_WORKFLOW_REF"].replace("nightly-release", "other")),
                       ("SCCACHE_GHA_RW_MODE", "READ_WRITE")]:
        with pytest.raises(ValueError):
            MODULE.trusted_checkout(tmp_path, "nightly", sha, {**env, key: value})
    file.write_text("mutated\n")
    with pytest.raises(ValueError, match="tracked modifications"):
        MODULE.trusted_checkout(tmp_path, "nightly", sha, env)


def test_composite_keeps_digest_only_build_and_original_caller_attestation():
    action = yaml.safe_load((ROOT / ".github/actions/build-product-image/action.yml").read_text())
    build = action["runs"]["steps"][1]["with"]
    assert "push-by-digest=true" in build["outputs"]
    assert build["provenance"] == "mode=max" and build["sbom"] is True
    assert "steps.recipe.outputs" in build["file"]
    workflow = yaml.safe_load((ROOT / ".github/workflows/product-packages.yml").read_text())
    steps = workflow["jobs"]["build"]["steps"]
    shared = [step for step in steps if step.get("uses") == "./.github/actions/build-product-image"]
    assert len(shared) == 1 and shared[0]["id"] == "image"
    assert shared[0]["with"]["producer"] == "product"
    assert any(step.get("uses", "").startswith("actions/attest-build-provenance@") for step in steps)
    assert not any(step.get("uses", "").startswith("docker/build-push-action@") for step in steps)


def test_nightly_reuses_verified_recipe_without_changing_signer_or_cache_authority():
    workflow = yaml.safe_load((ROOT / ".github/workflows/nightly-release.yml").read_text())
    steps = workflow["jobs"]["build-images"]["steps"]
    shared = [step for step in steps if step.get("uses") == "./.github/actions/build-product-image"]
    assert len(shared) == 1 and shared[0]["id"] == "build"
    assert shared[0]["with"] == {
        "producer": "nightly", "source-sha": "${{ github.sha }}",
        "version": "${{ needs.admit.outputs.version }}", "image-plan": "${{ toJSON(matrix) }}",
    }
    assert not any(step.get("uses", "").startswith("docker/build-push-action@") for step in steps)
    cache = next(step for step in steps if step.get("name") == "Expose existing read-only compiler cache")
    assert "core.exportVariable('SCCACHE_GHA_RW_MODE', 'READ_ONLY')" in cache["with"]["script"]
    attestation = next(step for step in steps if step.get("uses", "").startswith("actions/attest-build-provenance@"))
    assert attestation["with"]["subject-digest"] == "${{ steps.build.outputs.digest }}"
    signer = next(step for step in steps if step.get("name") == "Sign and record exact image identity")
    assert signer["env"]["DIGEST"] == "${{ steps.build.outputs.digest }}"
