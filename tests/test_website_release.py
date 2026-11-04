"""Website independence and the additive combined-application cutover boundary."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import ui_release as ui
import website_release as web

SOURCE = "a" * 40
PRIVATE = "c" * 40
DIGEST = "sha256:" + "b" * 64


@pytest.fixture
def source(tmp_path):
    for name in ("release/stack-lock.json", "docker/ui.Dockerfile", web.ROUTE_PATH):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((ROOT / name).read_bytes())
    return tmp_path


def candidate(source, *, full=False):
    options = dict(production_pages="full" if full else "public", commerce_source_sha=PRIVATE if full else None)
    plan = web.plan(source, SOURCE, **options)
    return web.record(source, plan, source_sha=SOURCE, metadata=web.image_metadata(plan),
                      digest=DIGEST, run_id="123", run_attempt="2", **options)


@pytest.mark.parametrize("full", [False, True])
def test_website_revision_and_producer_bind_only_exact_sources(source, full):
    value = candidate(source, full=full)
    plan = value["build_plan"]
    assert plan["target"] == "website"
    assert plan["build_args"]["UI_SURFACE"] == "website"
    assert plan["build_args"]["NGINX_CONFIG"] == "nginx.website.conf"
    assert "version" not in plan and "MARTY_RELEASE_VERSION" not in plan["build_args"]
    assert value["revision"] == SOURCE + ("-" + PRIVATE if full else "")
    assert value["producer"]["source_sha"] == (PRIVATE if full else SOURCE)
    assert value["producer"]["repository"] == (ui.COMMERCE_REPOSITORY if full else ui.REPOSITORY)
    assert value["image"]["uri"] == (web.COMMERCE_IMAGE if full else web.PUBLIC_IMAGE)
    assert value["image_metadata"]["surface"] == "website"
    assert web.validate_release(value, source_sha=SOURCE, commerce_source_sha=PRIVATE if full else None) == value
    assert "backend" not in json.dumps(value)


def test_website_plan_does_not_require_stack_release_eligibility_or_version(source):
    path = source / "release/stack-lock.json"
    lock = ui.read(path)
    lock["release"] = "marty-ui@not-a-release"
    lock["channel"] = "development"
    path.write_bytes(ui.canonical(lock))
    assert web.plan(source, SOURCE)["revision"] == SOURCE


@pytest.mark.parametrize("fault", ["foreign-uri", "missing-digest", "duplicate"])
def test_independence_does_not_weaken_dependency_lock(source, fault):
    path = source / "release/stack-lock.json"
    lock = ui.read(path)
    dependency = next(item for item in lock["components"] if item["name"] == "marty-blog")
    npm = next(item for item in dependency["artifacts"] if item["type"] == "npm")
    if fault == "foreign-uri":
        npm["uri"] = "https://example.invalid/a.tgz"
    elif fault == "missing-digest":
        npm["digest"] = "latest"
    else:
        lock["components"].append(copy.deepcopy(dependency))
    path.write_bytes(ui.canonical(lock))
    with pytest.raises(ValueError):
        web.plan(source, SOURCE)


@pytest.mark.parametrize("field,value", [
    ("target", "public"), ("image", ui.PUBLIC_IMAGE), ("source_sha", "d" * 40),
    ("revision", "latest"), ("schema", "marty.production-web-build-plan/v1"),
    ("platform", "linux/arm64"), ("extra", "ignored"),
])
def test_website_record_cannot_reuse_mutated_build_plan(source, field, value):
    plan = web.plan(source, SOURCE)
    metadata = web.image_metadata(plan)
    plan[field] = value
    with pytest.raises(ValueError, match="exact source"):
        web.record(source, plan, source_sha=SOURCE, metadata=metadata, digest=DIGEST,
                   run_id="123", run_attempt="1")


def test_plan_detects_source_change_between_build_and_sign(source):
    plan = web.plan(source, SOURCE)
    metadata = web.image_metadata(plan)
    (source / "docker/ui.Dockerfile").write_text("changed source")
    with pytest.raises(ValueError, match="exact source"):
        web.record(source, plan, source_sha=SOURCE, metadata=metadata, digest=DIGEST,
                   run_id="123", run_attempt="1")


@pytest.mark.parametrize("path,value", [
    (("schema",), ui.RELEASE_SCHEMA), (("source_sha",), "d" * 40),
    (("revision",), "latest"), (("producer", "source_sha"), "d" * 40),
    (("producer", "repository"), "attacker/repo"), (("producer", "ref"), "refs/heads/topic"),
    (("producer", "run_attempt"), "0"), (("image", "uri"), ui.PUBLIC_IMAGE),
    (("image", "digest"), "sha256:bad"), (("image_metadata", "surface"), "combined"),
    (("build_plan", "build_args", "EXTRA_COMMAND"), "arbitrary"),
    (("build_plan_sha256",), "sha256:" + "f" * 64),
])
def test_release_rejects_wrong_producer_metadata_or_plan(source, path, value):
    release = candidate(source, full=True)
    target = release
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(ValueError):
        web.validate_release(release)


def test_full_release_requires_expected_private_source(source):
    release = candidate(source, full=True)
    with pytest.raises(ValueError, match="commerce source"):
        web.validate_release(release, source_sha=SOURCE)
    with pytest.raises(ValueError, match="commerce source"):
        web.validate_release(release, source_sha=SOURCE, commerce_source_sha="d" * 40)


def test_route_identity_is_stable_across_json_formatting_and_matches_frontend():
    contract = web.read(ROOT / web.ROUTE_PATH)
    identity = web.route_identity(contract)
    assert identity == web.route_identity(json.loads(json.dumps(contract, indent=8)))
    script = ("import { WEB_ROUTE_CONTRACT } from './ui/scripts/web-surface-contract.mjs'; "
              "process.stdout.write(JSON.stringify(WEB_ROUTE_CONTRACT));")
    process = subprocess.run(["node", "--input-type=module", "-e", script], cwd=ROOT,
                             text=True, capture_output=True, check=True)
    assert identity == json.loads(process.stdout)


@pytest.mark.parametrize("fault", ["extra", "version", "duplicate", "injection", "pattern", "fallback"])
def test_invalid_route_contract_fails_closed(fault):
    contract = web.read(ROOT / web.ROUTE_PATH)
    if fault == "extra":
        contract["extra"] = True
    elif fault == "version":
        contract["schema_version"] = True
    elif fault == "duplicate":
        contract["website"]["exact_paths"].append("/")
    elif fault == "injection":
        contract["website"]["exact_paths"].append('/"; return 200; #')
    elif fault == "pattern":
        contract["website"]["filename_patterns"] = [".*"]
    else:
        contract["fallback"] = "website"
    with pytest.raises(ValueError):
        web.route_identity(contract)


@pytest.mark.parametrize("full", [False, True])
def test_combined_compatibility_is_additive_and_binds_the_original_image(source, full):
    options = dict(production_pages="full" if full else "public", commerce_source_sha=PRIVATE if full else None)
    plan = ui.production_plan(source, SOURCE, **options)
    metadata = {"component": "ui", "release_version": plan["version"], "marty_ui_sha": SOURCE,
                "audience": "production", "ui_variant": "public"}
    if full:
        metadata.update(production_pages="full", commerce_extension=plan["commerce_extension"])
    release = ui.production_release(source, plan, source_sha=SOURCE, image_digest=DIGEST,
                                    run_id="12", run_attempt="1", metadata=metadata, **options)
    assert web.validate_combined_release(release) == ui.validate_production_release(source, release, SOURCE)
    marker = web.application_marker(source, SOURCE)
    raw = ui.canonical(release)
    compatibility = web.compatibility_record(release, marker, raw)
    assert compatibility["application_release_sha256"] == ui.digest(raw)
    assert compatibility["image"] == release["image"]
    assert compatibility["producer"]["source_sha"] == (PRIVATE if full else SOURCE)
    with pytest.raises(ValueError, match="marker"):
        web.compatibility_record(release, {**marker, "surface": "application"}, raw)
    with pytest.raises(ValueError, match="marker"):
        web.compatibility_record(release, {**marker, "source_sha": PRIVATE}, raw)


def test_json_duplicate_keys_are_rejected(tmp_path):
    path = tmp_path / "manifest.json"
    path.write_text('{"source_sha":"a","source_sha":"b"}')
    with pytest.raises(ValueError, match="duplicate"):
        web.read(path)
