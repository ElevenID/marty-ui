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


def test_retained_cli_grammar_records_exact_plan_bytes_for_a_synthetic_legacy_target(source):
    # This unit fixture proves retained plan/receipt grammar, not a current
    # production build. Current-source producer refusal has its own CLI tests.
    dockerfile = source / "docker/ui.Dockerfile"
    dockerfile.write_text(dockerfile.read_text() + "\nFROM scratch AS public\n")
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


def test_current_workflow_preserves_application_publication_and_original_release_composition():
    workflow = yaml.safe_load((ROOT / release.WORKFLOW).read_text())
    triggers = workflow.get("on", workflow.get(True))
    assert set(triggers) == {"workflow_dispatch", "push"}
    assert triggers["push"] == {
        "branches": ["main"],
        "paths": [".github/release-inputs/website-composition.json"],
    }
    assert workflow["permissions"] == {"contents": "read"}
    assert "env" not in workflow
    dispatch = triggers["workflow_dispatch"]["inputs"]
    assert dispatch["mode"]["default"] == "application"
    assert dispatch["mode"]["options"] == ["application", "compose"]
    assert dispatch["website_repository"]["default"] == "ElevenID/website"
    # Original Marty receipts remain selectable without a current Marty website producer.
    assert dispatch["website_repository"]["options"] == ["ElevenID/marty-ui", "ElevenID/website"]
    jobs = workflow["jobs"]
    assert set(jobs) == {"request", "application", "compose"}
    assert jobs["request"]["permissions"] == {"contents": "read"}
    assert len(jobs["request"]["steps"]) == 1
    assert "uses" not in jobs["request"]["steps"][0]
    assert "if" not in jobs["request"]
    for name in ("application", "compose"):
        assert jobs[name]["needs"] == ["request"]
        steps = jobs[name]["steps"]
        assert steps[0]["with"] == {
            "ref": "${{ github.sha }}", "fetch-depth": 0, "persist-credentials": False,
        }
        guard = steps[1]
        assert "Require the exact protected-main" in guard["name"]
        assert 'test "$GITHUB_REF" = refs/heads/main' in guard["run"]
        assert "git rev-parse" in guard["run"] and "git merge-base --is-ancestor" in guard["run"]
    application = jobs["application"]
    assert "inputs.mode == 'application'" in application["if"]
    assert "github.event_name == 'workflow_dispatch'" in application["if"]
    build = next(step["with"] for step in application["steps"] if step.get("id") == "build")
    assert build["file"] == "docker/application.Dockerfile"
    assert "push-by-digest=true" in build["outputs"] and "tags" not in build
    assert build["provenance"] == "mode=max" and build["sbom"] is True
    # A reviewed manifest push only composes authenticated original receipts.
    compose = jobs["compose"]
    assert compose["if"] == (
        "github.repository == 'ElevenID/marty-ui' && github.repository_id == '1140864197' && "
        "((github.event_name == 'workflow_dispatch' && inputs.mode == 'compose') || "
        "(github.event_name == 'push' && github.ref == 'refs/heads/main' && "
        "github.ref_protected && !github.event.deleted))"
    )
    assert compose["permissions"]["packages"] == "read" and compose["permissions"]["actions"] == "read"
    compose_shell = "\n".join(step.get("run", "") for step in compose["steps"])
    assert "web_release_intake.py website" in compose_shell and "web_release_intake.py application" in compose_shell
    assert "--producer-source-sha" in compose_shell and "package_web_composition.py" in compose_shell
    assert not any(step.get("uses", "").startswith("docker/build-push-action") for step in compose["steps"])
    verifier = (ROOT / "scripts/install_web_verifiers.sh").read_text()
    assert "gh_2.103.2_linux_amd64.tar.gz" in verifier
    assert "62ccf747115ddc61237efffdde66a3c8f70ba249433dc64f70801089b59c59c8" in verifier
    assert '"$RUNNER_TEMP/web-verifiers/gh"' in compose_shell
    for job in jobs.values():
        assert "continue-on-error" not in job
        for step in job["steps"]:
            assert "continue-on-error" not in step
            if "uses" in step:
                assert re.fullmatch(r"[^\s]+@[0-9a-f]{40}", step["uses"])
            if "run" in step:
                assert not any(command in step["run"] for command in (
                    "kubectl", "helm upgrade", "gh release create", "ssh ",
                    "ui_release.py plan --audience production", "website_release.py plan",
                ))
                subprocess.run(["bash", "-n"], input=step["run"], text=True, check=True, capture_output=True)


@pytest.mark.parametrize("changes,allowed", [
    ({}, True),
    ({"RELEASE_MODE": "compose"}, True),
    ({"RELEASE_EVENT": "push", "RELEASE_MODE": "", "RELEASE_PUSH_DELETED": "false"}, True),
    ({"RELEASE_MODE": "combined"}, False),
    ({"RELEASE_MODE": "website"}, False),
    ({"RELEASE_MODE": "unknown"}, False),
    ({"RELEASE_MODE": "application\n"}, False),
    ({"RELEASE_MODE": ""}, False),
    ({"RELEASE_EVENT": "push"}, False),
    ({"RELEASE_EVENT": "pull_request"}, False),
    ({"RELEASE_EVENT": "push", "RELEASE_MODE": "", "RELEASE_PUSH_DELETED": "true"}, False),
    ({"RELEASE_EVENT": "push", "RELEASE_MODE": "", "RELEASE_PUSH_DELETED": ""}, False),
    ({"RELEASE_REPOSITORY": "fork/marty-ui"}, False),
    ({"RELEASE_REPOSITORY_ID": "1140864198"}, False),
    ({"RELEASE_REF": "refs/heads/topic"}, False),
    ({"RELEASE_REF_PROTECTED": "false"}, False),
])
def test_current_release_request_fails_before_any_publisher_for_retired_or_invalid_modes(tmp_path, changes, allowed):
    workflow = yaml.safe_load((ROOT / release.WORKFLOW).read_text())
    guard = workflow["jobs"]["request"]["steps"][0]
    marker = tmp_path / "publisher-reachable"
    environment = {
        **os.environ, "RELEASE_MODE": "application", "RELEASE_EVENT": "workflow_dispatch",
        "RELEASE_REPOSITORY": "ElevenID/marty-ui", "RELEASE_REPOSITORY_ID": "1140864197",
        "RELEASE_REF": "refs/heads/main", "RELEASE_REF_PROTECTED": "true", "RELEASE_PUSH_DELETED": "",
        "NEXT_PUBLISHER_MARKER": str(marker), **changes,
    }
    result = subprocess.run(
        ["bash", "--noprofile", "--norc"],
        input=guard["run"] + '\nprintf reached > "$NEXT_PUBLISHER_MARKER"\n',
        env=environment, text=True, capture_output=True, check=False,
    )
    assert (result.returncode == 0) is allowed, result.stderr
    assert marker.exists() is allowed
    if changes.get("RELEASE_MODE") in {"combined", "website"}:
        assert "producers are retired" in result.stderr


def test_full_production_binds_both_sources_and_the_private_producer(source):
    private_sha = "c" * 40
    options = dict(production_pages="full", commerce_source_sha=private_sha)
    plan = release.production_plan(source, SOURCE, **options)
    assert plan["image"] == release.COMMERCE_IMAGE
    assert plan["workflow"] == release.COMMERCE_WORKFLOW
    assert plan["build_args"]["MARTY_PRODUCTION_PAGES"] == "full"
    full_metadata = {**metadata(plan), "production_pages": "full",
                     "commerce_extension": {"repository": release.COMMERCE_REPOSITORY, "source_sha": private_sha}}
    value = record(source, plan, metadata=full_metadata, **options)
    assert value["producer"]["source_sha"] == private_sha
    assert value["source_sha"] == SOURCE
    assert release.validate_production_release(source, value, SOURCE) == value
    wrong = copy.deepcopy(value)
    wrong["producer"]["source_sha"] = SOURCE
    with pytest.raises(ValueError, match="producer identity"):
        release.validate_production_release(source, wrong, SOURCE)
    with pytest.raises(ValueError, match="audience, source or version"):
        record(source, plan, metadata=metadata(plan), **options)


def test_full_production_refuses_missing_private_source(source):
    with pytest.raises(ValueError, match="exact private commerce source"):
        release.production_plan(source, SOURCE, production_pages="full")


def test_all_customer_producers_check_the_image_audience():
    for name, job in (("nightly-release.yml", "build-images"), ("product-packages.yml", "build"),
                      ("cd.yml", "build-selfhost-lock-roles")):
        workflow = yaml.safe_load((ROOT / ".github/workflows" / name).read_text())
        steps = workflow["jobs"][job]["steps"]
        assert any("check-image --audience customer" in step.get("run", "") for step in steps)
        assert not any(release.PUBLIC_IMAGE in str(step) for step in steps)
