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


@pytest.mark.parametrize("fault", [None, "source", "routes", "slim"])
def test_prepublication_combined_marker_check_matches_exact_source_contract(source, fault):
    marker = web.application_marker(source, SOURCE)
    if fault == "source":
        marker["source_sha"] = "9" * 40
    elif fault == "routes":
        marker["route_contract"]["sha256"] = "sha256:" + "9" * 64
    elif fault == "slim":
        marker["surface"] = "application"
    path = source / "image-marker.json"
    path.write_bytes(ui.canonical(marker))
    result = subprocess.run([sys.executable, str(ROOT / "scripts/website_release.py"), "check-application",
                             "--root", str(source), "--source-sha", SOURCE, "--application-marker", str(path)],
                            capture_output=True, text=True)
    assert (result.returncode == 0) == (fault is None), result.stderr


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


@pytest.fixture
def standalone_release():
    plan = web.standalone_plan(
        SOURCE,
        input_sha256={name: "sha256:" + "1" * 64 for name in web.STANDALONE_INPUTS},
        output={"directory": "ui/dist-website", "inventory_sha256": "sha256:" + "2" * 64,
                "file_count": 123, "total_bytes": 456789},
        route_contract=web.route_identity(web.read(ROOT / web.ROUTE_PATH)),
    )
    return web.standalone_record(plan, metadata=web.image_metadata(plan), digest=DIGEST,
                                 run_id="345", run_attempt="2")


def test_standalone_contract_describes_prebuilt_static_output_without_application_dependencies(standalone_release, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Standalone contract must not use application source dependencies")
    monkeypatch.setattr(web, "console_dependencies", forbidden)
    value = standalone_release
    assert web.validate_release(value, source_sha=SOURCE) == value
    assert value["schema"] == "marty.website-release/v2"
    assert value["producer"] == {
        "repository": "ElevenID/website", "workflow": ".github/workflows/production-website-release.yml",
        "source_sha": SOURCE, "ref": "refs/heads/main", "run_id": "345", "run_attempt": "2",
    }
    assert value["image"]["uri"] == "ghcr.io/elevenid/website"
    assert value["image_metadata"]["schema"] == "marty.website-image/v2"
    plan = value["build_plan"]
    assert plan["dockerfile"] == "Dockerfile.website"
    assert plan["dependency_lock"] == "package-lock.json"
    assert plan["build_kind"] == "prebuilt-static"
    assert plan["build_args"] == {"WEBSITE_SOURCE_SHA": SOURCE, "WEBSITE_REVISION": SOURCE,
                                  "WEBSITE_ROUTE_CONTRACT_SHA256": plan["route_contract"]["sha256"]}
    assert set(plan["input_sha256"]) == set(web.STANDALONE_INPUTS)
    assert value["build_plan_sha256"] == ui.digest(ui.canonical(plan))
    assert value["production_pages"] == "public" and value["commerce_extension"] is None
    assert not {"local_image_id", "registry_published", "qualification"}.intersection(value)


@pytest.mark.parametrize("path,value", [
    (("repository",), ui.REPOSITORY), (("schema",), web.PLAN_SCHEMA),
    (("source_sha",), "development"), (("revision",), "latest"),
    (("production_pages",), "full"), (("commerce_extension",), {"repository": ui.COMMERCE_REPOSITORY, "source_sha": PRIVATE}),
    (("workflow",), ui.WORKFLOW), (("image",), web.PUBLIC_IMAGE),
    (("platform",), "linux/arm64"), (("dockerfile",), "docker/ui.Dockerfile"),
    (("build_kind",), "source-checkout"), (("dependency_lock",), "ui/package-lock.json"),
    (("base_image",), "nginx:latest"), (("base_image",), "nginx:1.29.1-alpine@sha256:" + "0" * 64),
    (("input_sha256", "package-lock.json"), "sha256:bad"), (("input_sha256", "application/secret"), DIGEST),
    (("output", "directory"), "../application/ui/dist"), (("output", "inventory_sha256"), "latest"),
    (("output", "file_count"), 0), (("output", "file_count"), True), (("output", "file_count"), 10001),
    (("output", "total_bytes"), 0), (("output", "total_bytes"), True),
    (("output", "total_bytes"), 512 * 1024 * 1024 + 1), (("output", "extra"), "ignored"),
    (("route_contract", "version"), True), (("route_contract", "sha256"), "sha256:bad"),
    (("build_args", "MARTY_UI_SHA"), SOURCE), (("build_args", "WEBSITE_SOURCE_SHA"), PRIVATE),
    (("build_args", "WEBSITE_REVISION"), PRIVATE), (("build_args", "WEBSITE_ROUTE_CONTRACT_SHA256"), DIGEST),
    (("extra",), "ignored"),
])
def test_standalone_plan_rejects_cross_owner_legacy_private_or_unbounded_inputs(standalone_release, path, value):
    changed = copy.deepcopy(standalone_release["build_plan"])
    target = changed
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(ValueError):
        web.validate_standalone_plan(changed)


@pytest.mark.parametrize("path,value", [
    (("schema",), web.RELEASE_SCHEMA), (("source_sha",), PRIVATE), (("revision",), PRIVATE),
    (("production_pages",), "full"), (("commerce_extension",), {"repository": ui.COMMERCE_REPOSITORY, "source_sha": PRIVATE}),
    (("producer", "repository"), ui.REPOSITORY), (("producer", "workflow"), ui.WORKFLOW),
    (("producer", "source_sha"), PRIVATE), (("producer", "ref"), "refs/heads/topic"),
    (("producer", "run_attempt"), "0"), (("producer", "run_id"), 345),
    (("image", "uri"), web.PUBLIC_IMAGE), (("image", "digest"), "latest"),
    (("image", "platform"), "linux/arm64"), (("image", "local_image_id"), DIGEST),
    (("image_metadata", "schema"), web.IMAGE_SCHEMA), (("image_metadata", "repository"), ui.REPOSITORY),
    (("image_metadata", "source_sha"), PRIVATE), (("image_metadata", "surface"), "application"),
    (("image_metadata", "route_contract", "version"), True),
    (("image_metadata", "route_contract", "sha256"), DIGEST),
    (("build_plan_sha256",), DIGEST), (("extra",), "ignored"),
])
def test_standalone_release_cannot_substitute_other_identity_or_local_qualification_fields(standalone_release, path, value):
    target = standalone_release
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(ValueError):
        web.validate_release(standalone_release)


def test_standalone_release_requires_explicit_matching_source_and_rejects_commerce_expectation(standalone_release):
    with pytest.raises(ValueError, match="expected source"):
        web.validate_release(standalone_release, source_sha=PRIVATE)
    with pytest.raises(ValueError, match="commerce source"):
        web.validate_release(standalone_release, commerce_source_sha=PRIVATE)


def test_legacy_envelope_cannot_relabel_a_standalone_plan_as_legacy_authority(standalone_release):
    # Even a self-consistent Frankenstein receipt must not bridge schema/owner
    # boundaries through the legacy validator's generic image_metadata helper.
    standalone_release["schema"] = web.RELEASE_SCHEMA
    standalone_release["producer"] = web.producer(SOURCE, None, "345", "2")
    with pytest.raises(ValueError, match="original plan schema"):
        web.validate_release(standalone_release)


def test_standalone_envelope_rejects_legacy_plan_even_with_recomputed_plan_hash(source):
    release = candidate(source)
    release["schema"] = web.STANDALONE_RELEASE_SCHEMA
    release["producer"] = web.standalone_producer(SOURCE, "123", "2")
    with pytest.raises(ValueError, match="standalone website plan"):
        web.validate_release(release)


def test_qualification_is_not_a_release_receipt():
    qualification = {"schema": "marty.website-qualification/v1", "source_sha": SOURCE,
                     "local_image_id": DIGEST, "cryptographic_provenance_verified": False}
    with pytest.raises(ValueError):
        web.validate_release(qualification)


def test_standalone_fixture_matches_javascript_producer_and_canonical_plan_hash():
    fixture = web.read(ROOT / "tests/fixtures/standalone-website-release-v2.json")
    assert fixture["purpose"] == "synthetic-contract-fixture-not-release-evidence"
    release = fixture["release"]
    assert web.validate_release(release, source_sha=SOURCE) == release
    plan = release["build_plan"]
    assert plan == web.standalone_plan(SOURCE, input_sha256=plan["input_sha256"],
                                       output=plan["output"], route_contract=plan["route_contract"])
    assert release == web.standalone_record(plan, metadata=web.image_metadata(plan),
                                            digest=release["image"]["digest"], run_id="1234567890", run_attempt="2")
    assert ui.digest(ui.canonical(plan)) == "sha256:651dc6a6bf9ed66ba7b2a58edfe72a6efd266924fa71f4a82aa514ddd7b8f609"


def test_bun_standalone_fixture_matches_javascript_without_replacing_retained_v2_evidence():
    fixture = web.read(ROOT / "tests/fixtures/standalone-website-release-v3.json")
    assert fixture["purpose"] == "synthetic-contract-fixture-not-release-evidence"
    release = fixture["release"]
    assert web.validate_release(release, source_sha=SOURCE) == release
    plan = release["build_plan"]
    assert plan["package_manager"] == "bun@1.4.4"
    assert plan["dependency_lock"] == "bun.lock"
    assert {"bun.lock", "package-lock.json"} <= plan["input_sha256"].keys()
    assert plan == web.standalone_plan(SOURCE, input_sha256=plan["input_sha256"],
                                       output=plan["output"], route_contract=plan["route_contract"], version=3)
    assert release == web.standalone_record(plan, metadata=web.image_metadata(plan),
                                            digest=release["image"]["digest"], run_id="1234567890", run_attempt="2")
    assert ui.digest(ui.canonical(plan)) == "sha256:9f128218d4c9999664620f59363ee61ee8703c4b50c57c7ce3f4d8c04aef8b72"
    retained = web.read(ROOT / "tests/fixtures/standalone-website-release-v2.json")["release"]
    assert web.validate_release(retained) == retained


@pytest.mark.parametrize("path,value", [
    (("package_manager",), "bun@latest"),
    (("package_manager",), "npm@11"),
    (("dependency_lock",), "package-lock.json"),
    (("input_sha256", "bun.lock"), "missing"),
    (("input_sha256", "package-lock.json"), "missing"),
])
def test_bun_standalone_plan_rejects_package_manager_and_lock_substitution(path, value):
    release = web.read(ROOT / "tests/fixtures/standalone-website-release-v3.json")["release"]
    target = release["build_plan"]
    for key in path[:-1]:
        target = target[key]
    if value == "missing":
        del target[path[-1]]
    else:
        target[path[-1]] = value
    release["build_plan_sha256"] = ui.digest(ui.canonical(release["build_plan"]))
    with pytest.raises(ValueError):
        web.validate_release(release)


@pytest.mark.parametrize("field", ["schema", "image_metadata"])
def test_bun_standalone_receipt_rejects_mixed_version_envelopes(field):
    release = web.read(ROOT / "tests/fixtures/standalone-website-release-v3.json")["release"]
    retained = web.read(ROOT / "tests/fixtures/standalone-website-release-v2.json")["release"]
    release[field] = retained[field]
    with pytest.raises(ValueError):
        web.validate_release(release)


def test_retained_v2_receipt_cannot_silently_acquire_bun_fields():
    release = web.read(ROOT / "tests/fixtures/standalone-website-release-v2.json")["release"]
    release["build_plan"]["package_manager"] = "bun@1.4.4"
    release["build_plan_sha256"] = ui.digest(ui.canonical(release["build_plan"]))
    with pytest.raises(ValueError):
        web.validate_release(release)
