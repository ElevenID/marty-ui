"""Contract boundaries for independently published application evidence.

Small inert fixtures exercise validation; they never pass producer validation or
claim a real browser/image run. Production uses the existing Node validators.
"""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import application_release as app
import ui_release as ui

SOURCE = "a" * 40
TREE = "c" * 40
DIGEST = "sha256:" + "b" * 64


def make_assets(directory: Path) -> dict:
    """Return a structurally valid inert signed-evidence fixture for trust tests."""
    directory.mkdir(parents=True, exist_ok=True)
    def write(name, value):
        raw = value if isinstance(value, bytes) else ui.canonical(value)
        (directory / name).write_bytes(raw)
        return app.file_record(raw)
    source = {"repository": ui.REPOSITORY, "commit": SOURCE, "tree": TREE, "object_format": "sha1", "working_tree_dirty": False}
    route = {"version": 1, "sha256": "sha256:" + "d" * 64}
    wasm = {"path": "assets/marty_api_client_bg-example.wasm", "bytes": 11, "sha256": "sha256:" + "e" * 64}
    files = [{"path": name, "bytes": len(name), "sha256": ui.digest(name.encode()), "mode": 0o644}
             for name in ("index.html", "console/index.html", "runtime-config.js")]
    files.append({**wasm, "mode": 0o644})
    output = {"files": files, "inventory_sha256": ui.digest(app.compact(files)), "public_resources": []}
    context_inventory = [{**row, "path": "html/" + row["path"]} for row in files]
    context = {"schema": "marty.application-runtime-context/v1", "source_commit": SOURCE, "effective_source_sha": SOURCE,
               "exact_committed_source": True, "base_image": app.BASE_IMAGE, "sdk_wasm": wasm["path"],
               "context_inventory": context_inventory, "output_inventory": output}
    context_pin = write("application-runtime-context.json", context)
    source_files = [{"path": "ui/package-lock.json", "bytes": 2, "sha256": ui.digest(b"{}")},
                    {"path": "ui/src/main.jsx", "bytes": 1, "sha256": ui.digest(b"x")}]
    manifest = {"schema": "marty.application-source-package/v1", "fixture": False, "source": source,
                "route_contract": route, "files": source_files, "source_inventory_sha256": ui.digest(app.compact(source_files))}
    manifest_pin = write("application-source-origin.json", manifest)
    archive_pin = write("application-source-package.zip", b"inert archive fixture; never executed or extracted by the verifier")
    baseline = {"schema": "marty.application-source-closure-rehearsal/v5", "status": "passed", "plan": {"source": {"commit": SOURCE}}}
    baseline_pin = write("application-profile-source-closure.json", baseline)
    producer = {"schema": "marty.application-source-package-producer/v1", "status": "passed", "fixture": False,
                "source_commit": SOURCE, "source_tree": TREE, "source_preserved": True, "archive_manifest_identical": True,
                "archive": archive_pin, "manifest": manifest_pin, "baseline_report": baseline_pin}
    producer_pin = write("application-source-package.json", producer)
    sdk = {"name": "@elevenid/marty-api-core", "version": "0.3.6",
           "resolved": "https://github.com/ElevenID/marty-cli/releases/download/v0.3.6/elevenid-marty-api-core-0.3.6.tgz",
           "integrity": "sha512-" + "A" * 86 + "==",
           "wasm": {**wasm, "path": "node_modules/@elevenid/marty-api-core/src/wasm/marty_api_client_bg.wasm"},
           "initialized_in_node": True}
    consumer = {"schema": "marty.application-source-package-consumer/v1", "status": "passed", "fixture": False,
                "source": source, "source_inventory_sha256": manifest["source_inventory_sha256"],
                "inputs": {"archive": archive_pin, "manifest": manifest_pin, "producer_report": producer_pin, "baseline_report": baseline_pin},
                "preservation": {"pinned_inputs_unchanged": True, "restored_source_unchanged": True},
                "cleanup": {"process_group_cleanup_completed": True, "source_removed": True, "cache_removed": True,
                            "runtime_adapter_removed": True, "temporary_removed": True, "runtime_context_removed": False},
                "runtime_context": {**context, "path": "/inert-fixture/context", "manifest_sha256": context_pin["sha256"]},
                "output": output, "dependency_install": {"sdk": sdk}}
    consumer_pin = write("application-package-consumer.json", consumer)
    recipe = {"path": app.DOCKERFILE, "bytes": 123, "sha256": ui.digest(b"reviewed recipe"), "mode": 0o644}
    plan = {"schema": app.PLAN_SCHEMA, "repository": ui.REPOSITORY, "source_sha": SOURCE, "source_tree": TREE,
            "workflow": ui.WORKFLOW, "audience": "production", "surface": "application", "production_pages": "public",
            "commerce_extension": None, "image": app.IMAGE, "platform": "linux/amd64", "build_kind": "verified-source-package-static",
            "dockerfile": app.DOCKERFILE, "dockerfile_sha256": recipe["sha256"], "recipe_input": recipe, "base_image": app.BASE_IMAGE,
            "inputs": dict(zip(app.INPUT_FILES, (archive_pin, manifest_pin, producer_pin, baseline_pin, consumer_pin, context_pin))),
            "source_inventory_sha256": manifest["source_inventory_sha256"], "dependency_lock_sha256": source_files[0]["sha256"],
            "route_contract": route,
            "runtime_context": {"manifest_sha256": context_pin["sha256"], "payload_sha256": ui.digest(app.compact(context_inventory)), "source_sha": SOURCE},
            "output": {"inventory_sha256": output["inventory_sha256"], "file_count": len(files), "total_bytes": sum(row["bytes"] for row in files)},
            "sdk": {**{key: sdk[key] for key in ("name", "version", "resolved", "integrity", "wasm")}, "emitted_wasm": wasm},
            "build_args": {"APPLICATION_SOURCE_SHA": SOURCE, "APPLICATION_CONTEXT_SHA": context_pin["sha256"]}}
    runtime_identity = {"schema": "marty.application-image-check/v1", "image_mode": "published-digest", "image_reference": app.IMAGE + "@" + DIGEST,
                        "recipe_input": recipe, "context_sha256": context_pin["sha256"], "image_id": "sha256:" + "1" * 64,
                        "container_id": "2" * 64, "endpoint": {"host": "127.0.0.1", "port": 23456}, "cleanup": dict(app.IMAGE_CLEANUP)}
    source_identity = {"source_commit": SOURCE, "effective_source_sha": SOURCE, "exact_committed_source": True,
                       "context_sha256": context_pin["sha256"]}
    browser = {"schema": "marty.application-browser-startup/v1", "status": "passed", "fixture": False, **source_identity,
               "origin": "http://127.0.0.1:23456", "browser": {"channel": "chrome", "sandboxed": True, "version": "123.0.0.0"},
               "runtime": runtime_identity, "qualification": {"browser_startup_observed": True, "sdk_wasm_initialized_in_browser": True,
                   "host_deployment_tested": False, "oidc_journey_tested": False, "published": False, "activated": False},
               "cleanup": {"browser_closed": True, "chromium_exited": True, "contexts_closed": True, "profile_removed": True},
               "process_evidence": {"status": "passed", "descendants_reaped": True},
               "routes": [{"route": route, "ready": True, "root_populated": True, "context_closed": True,
                   "page_errors": [], "aborted_wasm_requests": 0, "wasm": {**wasm, "status": 200,
                   "content_type": "application/wasm", "from_cache": False, "from_service_worker": False}} for route in app.BROWSER_ROUTES],
               "negative_control": {"route": app.BROWSER_ROUTES[0], "ready": False, "root_populated": False,
                   "wasm": None, "aborted_wasm_requests": 1, "context_closed": True, "recovery": {"visible": True}}}
    browser_pin = write(app.BROWSER_REPORT, browser)
    image = {**runtime_identity, **source_identity, "status": "passed", "fixture": False, "base_image": app.BASE_IMAGE,
             "qualification": dict(app.IMAGE_QUALIFICATION), "all_output_resources_readable": [row["path"] for row in files],
             "output_resources_verified": files, "runtime_transformations": [
                 {"path": row["path"], "original_sha256": row["sha256"], "runtime_sha256": row["sha256"], "mode": 0o644}
                 for row in files if row["path"] == "runtime-config.js" or row["path"].endswith(".html")],
             "browser_startup": {**browser_pin, "schema": browser["schema"], "status": "passed",
                                 "sdk_wasm_initialized_in_browser": True, "worker_descendants_reaped": True}}
    image_pin = write(app.IMAGE_CHECK, image)
    release = app._release(plan, image_digest=DIGEST, run_id="231", run_attempt="2",
                           evidence={app.IMAGE_CHECK: image_pin, app.BROWSER_REPORT: browser_pin})
    write(app.RECEIPT, release)
    return release


def test_fixed_inert_assets_roundtrip(tmp_path, monkeypatch):
    release = make_assets(tmp_path)
    monkeypatch.setattr(app, "_command", lambda *_args: pytest.fail("consumer executed a producer command"))
    assert app.validate_release(deepcopy(release), source_sha=SOURCE) == release
    assert app.validate_assets(tmp_path, source_sha=SOURCE) == release
    assert release["image"]["uri"] != ui.PUBLIC_IMAGE
    assert "version" not in release and "backend" not in release


@pytest.mark.parametrize("path,value", [
    (("schema",), "marty.production-web-release/v1"), (("repository",), "ElevenID/website"),
    (("producer", "workflow"), ".github/workflows/ci.yml"), (("producer", "source_sha"), "f" * 40),
    (("producer", "run_id"), "0"), (("producer", "run_attempt"), "03"),
    (("image", "uri"), ui.PUBLIC_IMAGE), (("image", "digest"), "latest"),
    (("build_plan", "build_args", "APPLICATION_SOURCE_SHA"), "development"),
    (("build_plan", "runtime_context", "source_sha"), "f" * 40),
    (("build_plan", "base_image"), "nginx:latest"), (("build_plan", "recipe_input", "mode"), 0o777),
    (("build_plan", "sdk", "emitted_wasm", "sha256"), "sha256:" + "f" * 64),
    (("build_plan", "output", "file_count"), True), (("qualification", "activated"), True),
])
def test_closed_release_rejects_changed_identity(tmp_path, path, value):
    release = make_assets(tmp_path)
    target = release
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(ValueError):
        app.validate_release(release)


@pytest.mark.parametrize("name", app.INPUT_FILES + app.EVIDENCE_FILES)
def test_every_transitively_signed_file_is_byte_bound(tmp_path, name):
    make_assets(tmp_path)
    with (tmp_path / name).open("ab") as stream:
        stream.write(b"\n")
    with pytest.raises(ValueError, match="bytes differ"):
        app.validate_assets(tmp_path)


def load_evidence(directory):
    return app.read(directory / app.IMAGE_CHECK), app.read(directory / app.BROWSER_REPORT), app.read(directory / "application-runtime-context.json")


@pytest.mark.parametrize("target,path,value", [
    ("image", ("fixture",), True), ("image", ("status",), "fixture-passed"),
    ("image", ("schema",), "marty.application-runtime-container/v1"),
    ("image", ("image_mode",), "local-release-build"), ("image", ("image_reference",), None),
    ("image", ("qualification", "immutable_image_verified"), False),
    ("image", ("qualification", "browser_startup_observed"), False),
    ("image", ("cleanup", "container_removed"), False),
    ("image", ("recipe_input", "sha256"), "sha256:" + "f" * 64),
    ("browser", ("browser", "sandboxed"), False), ("browser", ("fixture",), True),
    ("browser", ("cleanup", "chromium_exited"), False),
    ("browser", ("process_evidence", "descendants_reaped"), False),
    ("browser", ("source_commit",), "f" * 40),
    ("browser", ("runtime", "image_reference"), app.IMAGE + "@sha256:" + "f" * 64),
    ("browser", ("negative_control", "aborted_wasm_requests"), 0),
])
def test_observation_semantics_fail_even_when_hashes_are_rebound(tmp_path, target, path, value):
    release = make_assets(tmp_path)
    image, browser, context = load_evidence(tmp_path)
    selected = {"image": image, "browser": browser}[target]
    for key in path[:-1]:
        selected = selected[key]
    selected[path[-1]] = value
    pin = app.file_record(ui.canonical(browser))
    image["browser_startup"].update(pin)
    with pytest.raises(ValueError):
        app.validate_image_evidence(release["build_plan"], image, browser, image_digest=DIGEST, browser_record=pin, context=context)


@pytest.mark.parametrize("change", ["extra", "missing", "bytes", "wasm", "route"])
def test_actual_image_and_browser_payload_membership(tmp_path, change):
    release = make_assets(tmp_path)
    image, browser, context = load_evidence(tmp_path)
    if change == "extra":
        image["output_resources_verified"].append({"path": "marketing.html", "bytes": 1, "sha256": ui.digest(b"x"), "mode": 0o644})
    elif change == "missing":
        image["output_resources_verified"].pop()
    elif change == "bytes":
        image["output_resources_verified"][-1]["sha256"] = ui.digest(b"different")
    elif change == "wasm":
        browser["routes"][0]["wasm"]["from_cache"] = True
    else:
        browser["routes"][0]["route"] = "/"
    pin = app.file_record(ui.canonical(browser))
    image["browser_startup"].update(pin)
    with pytest.raises(ValueError):
        app.validate_image_evidence(release["build_plan"], image, browser, image_digest=DIGEST, browser_record=pin, context=context)


def test_symlink_and_duplicate_json_are_rejected(tmp_path):
    make_assets(tmp_path)
    held = tmp_path / app.BROWSER_REPORT
    original = tmp_path / "original.json"
    held.rename(original)
    held.symlink_to(original)
    with pytest.raises(ValueError, match="non-symlink"):
        app.validate_assets(tmp_path)
    with pytest.raises(ValueError, match="duplicate"):
        app.parse(b'{"schema":1,"schema":2}')
    with pytest.raises(ValueError, match="nonfinite"):
        app.parse(b'{"value":NaN}')


def test_record_revalidates_live_source_context_and_reports(tmp_path, monkeypatch):
    release = make_assets(tmp_path)
    plan = release["build_plan"]
    calls = []
    def live_plan(*args, **kwargs):
        calls.append((args, kwargs))
        return deepcopy(plan)
    monkeypatch.setattr(app, "production_plan", live_plan)
    recorded = app.production_release(app.ROOT, plan, source_sha=SOURCE, assets=tmp_path, context=tmp_path / "context",
        image_check=tmp_path / app.IMAGE_CHECK, browser_report=tmp_path / app.BROWSER_REPORT,
        image_digest=DIGEST, run_id="231", run_attempt="2")
    assert recorded == release and len(calls) == 2
    assert all(call[1]["browser_report"] == tmp_path / app.BROWSER_REPORT for call in calls)
    def drift(*args, **kwargs):
        changed = deepcopy(plan)
        changed["source_tree"] = "f" * 40
        return changed
    monkeypatch.setattr(app, "production_plan", drift)
    with pytest.raises(ValueError, match="freshly verified"):
        app.production_release(app.ROOT, plan, source_sha=SOURCE, assets=tmp_path, context=tmp_path / "context",
            image_check=tmp_path / app.IMAGE_CHECK, browser_report=tmp_path / app.BROWSER_REPORT,
            image_digest=DIGEST, run_id="231", run_attempt="2")
