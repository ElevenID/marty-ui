#!/usr/bin/env python3
"""Package-built application publication, without a backend or promotion claim.

Only the producer's plan/record operations invoke the fixed reviewed Node bridge.
Receipt and asset validation are inert and may run before original provenance is
authenticated. They never execute a script selected by downloaded evidence.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess

import ui_release as ui
import verify_installer_provenance as verifier
import website_release as web

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "ghcr.io/elevenid/marty-ui-oss/application"
PLAN_SCHEMA = "marty.application-build-plan/v1"
RELEASE_SCHEMA = "marty.application-release/v1"
BUN_PLAN_SCHEMA = "marty.application-build-plan/v2"
BUN_RELEASE_SCHEMA = "marty.application-release/v2"
BUN_PACKAGE_MANAGER = {"name": "bun", "version": "1.4.4", "lock_file": "bun.lock"}
BASE_IMAGE = web.STANDALONE_BASE_IMAGE
DOCKERFILE = "docker/application.Dockerfile"
INPUT_BRIDGE = "scripts/application_release_inputs.mjs"
RECEIPT = "application-release.json"
IMAGE_CHECK = "application-image-check.json"
BROWSER_REPORT = "application-image-browser.json"
INPUT_FILES = (
    "application-source-package.zip", "application-source-origin.json", "application-source-package.json",
    "application-profile-source-closure.json", "application-package-consumer.json", "application-runtime-context.json",
)
EVIDENCE_FILES = (IMAGE_CHECK, BROWSER_REPORT)
ASSET_FILES = (RECEIPT, *INPUT_FILES, *EVIDENCE_FILES)
JSON_LIMIT = 8 * 1024 * 1024
ARCHIVE_LIMIT = 128 * 1024 * 1024
PLAN_FIELDS = {"schema", "repository", "source_sha", "source_tree", "workflow", "audience", "surface",
               "production_pages", "commerce_extension", "image", "platform", "build_kind", "dockerfile",
               "dockerfile_sha256", "recipe_input", "base_image", "inputs", "source_inventory_sha256",
               "dependency_lock_sha256", "route_contract", "runtime_context", "output", "sdk", "build_args"}
RELEASE_FIELDS = {"schema", "repository", "source_sha", "audience", "surface", "production_pages",
                  "commerce_extension", "producer", "image", "build_plan", "build_plan_sha256", "evidence", "qualification"}
QUALIFICATION = {"source_package_verified": True, "package_build_qualified": True, "immutable_image_verified": True,
                 "container_resources_checked": True, "browser_startup_observed": True, "sdk_wasm_initialized_in_browser": True,
                 "source_extraction_complete": False, "package_graph_minimized": False, "host_deployment_tested": False,
                 "oidc_journey_tested": False, "activated": False}
IMAGE_QUALIFICATION = {"context_prepared": True, "container_image_built": False, "immutable_image_verified": True,
                       "container_resources_checked": True, "browser_startup_observed": True,
                       "host_deployment_tested": False, "oidc_journey_tested": False, "published": False, "activated": False}
IMAGE_CLEANUP = {"container_removed": True, "image_removed": False, "image_cache_retained": True}
BROWSER_ROUTES = ("/login?next=%2Fconsole&lng=en", "/console?lng=en")


def compact(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _pairs(items: list) -> dict:
    result = {}
    for key, value in items:
        ui.require(key not in result, "duplicate application evidence field")
        result[key] = value
    return result


def parse(raw: bytes) -> dict:
    def constant(_value: str) -> None:
        raise ValueError("nonfinite application evidence value")
    try:
        ui.require(0 < len(raw) <= JSON_LIMIT, "application JSON exceeds its bound")
        value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=constant)
        ui.require(isinstance(value, dict), "application evidence must be an object")
        return value
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise ValueError("invalid application evidence JSON") from None


def read_bytes(path: Path, maximum: int = JSON_LIMIT) -> bytes:
    verifier.local_file(path, maximum=maximum)
    before = path.stat()
    with path.open("rb") as stream:
        raw = stream.read(maximum + 1)
    after = path.stat()
    ui.require(0 < len(raw) <= maximum and len(raw) == before.st_size == after.st_size
               and (before.st_dev, before.st_ino, before.st_mtime_ns) == (after.st_dev, after.st_ino, after.st_mtime_ns),
               "application input changed while reading")
    return raw


def read(path: Path) -> dict:
    return parse(read_bytes(path))


def file_record(raw: bytes) -> dict:
    return {"bytes": len(raw), "sha256": ui.digest(raw)}


def _number(value: object, maximum: int, label: str) -> None:
    ui.require(type(value) is int and 0 < value <= maximum, f"invalid {label}")


def _pin(value: dict, label: str, maximum: int = JSON_LIMIT) -> None:
    web.object_keys(value, {"bytes", "sha256"}, label)
    _number(value["bytes"], maximum, label + " bytes")
    web.image_digest(value["sha256"])


def _path(value: object) -> str:
    ui.require(isinstance(value, str) and 0 < len(value) < 1024
               and re.fullmatch(r"[A-Za-z0-9_./@-]+", value) is not None
               and all(part not in {"", ".", ".."} for part in value.split("/")), "unsafe application relative path")
    return value


def _file(value: dict, label: str) -> None:
    web.object_keys(value, {"path", "bytes", "sha256"}, label)
    _path(value["path"])
    _pin({key: value[key] for key in ("bytes", "sha256")}, label, 64 * 1024 * 1024)


def _input_pins(value: dict) -> None:
    web.object_keys(value, set(INPUT_FILES), "application input files")
    for name, record in value.items():
        _pin(record, name, ARCHIVE_LIMIT if name.endswith(".zip") else JSON_LIMIT)


def validate_plan(value: dict) -> dict:
    bun = isinstance(value, dict) and value.get("schema") == BUN_PLAN_SCHEMA
    web.object_keys(value, PLAN_FIELDS | ({"package_manager"} if bun else set()), "application build plan")
    if bun:
        ui.require(value["package_manager"] == BUN_PACKAGE_MANAGER, "application package manager differs")
    source = web.full_sha(value["source_sha"])
    web.full_sha(value["source_tree"], "tree")
    expected = {"schema": BUN_PLAN_SCHEMA if bun else PLAN_SCHEMA, "repository": ui.REPOSITORY, "workflow": ui.WORKFLOW,
                "audience": "production", "surface": "application", "production_pages": "public", "commerce_extension": None,
                "image": IMAGE, "platform": "linux/amd64", "build_kind": "verified-source-package-static",
                "dockerfile": DOCKERFILE, "base_image": BASE_IMAGE}
    ui.require(all(value[key] == item for key, item in expected.items()), "application build identity differs")
    _input_pins(value["inputs"])
    for key in ("source_inventory_sha256", "dependency_lock_sha256", "dockerfile_sha256"):
        web.image_digest(value[key])
    recipe = value["recipe_input"]
    web.object_keys(recipe, {"path", "bytes", "sha256", "mode"}, "application recipe")
    _file({key: recipe[key] for key in ("path", "bytes", "sha256")}, "application recipe")
    ui.require(recipe["path"] == DOCKERFILE and recipe["sha256"] == value["dockerfile_sha256"]
               and type(recipe["mode"]) is int and recipe["mode"] == 0o644, "application recipe differs")
    web.validate_route_identity(value["route_contract"])
    context = value["runtime_context"]
    web.object_keys(context, {"manifest_sha256", "payload_sha256", "source_sha"}, "application runtime context")
    web.image_digest(context["payload_sha256"])
    ui.require(context["manifest_sha256"] == value["inputs"]["application-runtime-context.json"]["sha256"]
               and context["source_sha"] == source, "application context identity differs")
    output = value["output"]
    web.object_keys(output, {"inventory_sha256", "file_count", "total_bytes"}, "application output")
    web.image_digest(output["inventory_sha256"])
    _number(output["file_count"], 4096, "application output count")
    _number(output["total_bytes"], 256 * 1024 * 1024, "application output bytes")
    sdk = value["sdk"]
    web.object_keys(sdk, {"name", "version", "resolved", "integrity", "wasm", "emitted_wasm"}, "application SDK")
    ui.require(sdk["name"] == "@elevenid/marty-api-core" and isinstance(sdk["version"], str)
               and ui.VERSION.fullmatch(sdk["version"]) is not None, "application SDK identity differs")
    version = sdk["version"]
    ui.require(sdk["resolved"] == f"https://github.com/ElevenID/marty-cli/releases/download/v{version}/elevenid-marty-api-core-{version}.tgz"
               and isinstance(sdk["integrity"], str) and re.fullmatch(r"sha512-[A-Za-z0-9+/]{86}==", sdk["integrity"]) is not None,
               "application SDK package pin differs")
    for key in ("wasm", "emitted_wasm"):
        _file(sdk[key], "application SDK " + key)
    ui.require(sdk["wasm"]["path"] == "node_modules/@elevenid/marty-api-core/src/wasm/marty_api_client_bg.wasm"
               and re.fullmatch(r"assets/marty_api_client_bg[-.A-Za-z0-9_]*\.wasm", sdk["emitted_wasm"]["path"]) is not None
               and all(sdk["wasm"][key] == sdk["emitted_wasm"][key] for key in ("bytes", "sha256")),
               "installed and emitted SDK WASM differ")
    ui.require(value["build_args"] == {"APPLICATION_SOURCE_SHA": source, "APPLICATION_CONTEXT_SHA": context["manifest_sha256"]},
               "application build arguments differ")
    return value


def _environment() -> dict:
    return {key: value for key, value in os.environ.items() if key in {"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "SYSTEMROOT"}}


def _command(arguments: list[str], root: Path) -> str:
    try:
        result = subprocess.run(arguments, cwd=root, env=_environment(), capture_output=True, text=True,
                                timeout=90, check=False)
    except (OSError, subprocess.SubprocessError):
        raise ValueError("application producer validation failed") from None
    ui.require(result.returncode == 0 and len(result.stdout) <= JSON_LIMIT,
               "application producer validation failed: " + result.stderr[-1800:].strip())
    return result.stdout


def _clean_source(root: Path, source_sha: str) -> str:
    web.full_sha(source_sha)
    ui.require(root == ROOT and root.is_dir() and not any(part.is_symlink() for part in (root, *root.parents)),
               "application producer must use this reviewed source checkout")
    git = ["git", "-c", "core.fsmonitor=false", "-C", str(root)]
    ui.require(_command([*git, "rev-parse", "--show-toplevel"], root).strip() == str(root)
               and _command([*git, "rev-parse", "HEAD^{commit}"], root).strip() == source_sha
               and _command([*git, "status", "--porcelain", "--untracked-files=all"], root) == "",
               "application producer requires the clean exact source commit")
    return web.full_sha(_command([*git, "rev-parse", "HEAD^{tree}"], root).strip(), "tree")


def production_plan(root: Path, source_sha: str, *, assets: Path, context: Path, browser_report: Path | None = None) -> dict:
    root, assets, context = root.absolute(), assets.absolute(), context.absolute()
    tree = _clean_source(root, source_sha)
    arguments = ["node", str(root / INPUT_BRIDGE), "--source-sha", source_sha, "--assets", str(assets), "--context", str(context)]
    if browser_report is not None:
        ui.require(browser_report.absolute() == assets / BROWSER_REPORT, "producer browser validation requires its fixed evidence path")
        arguments += ["--browser-report", str(browser_report.absolute())]
    result = parse(_command(arguments, root).encode())
    bun = result.get("schema") == "marty.application-release-inputs/v2"
    fields = {"schema", "source", "inputs", "source_inventory_sha256", "dependency_lock_sha256",
              "route_contract", "runtime_context", "output", "sdk"}
    if bun:
        fields.add("package_manager")
    web.object_keys(result, fields, "reviewed application input validation")
    ui.require(result["schema"] == f"marty.application-release-inputs/v{2 if bun else 1}" and result["source"] == {
        "repository": ui.REPOSITORY, "commit": source_sha, "tree": tree, "object_format": "sha1", "working_tree_dirty": False},
        "validated application source differs")
    recipe = read_bytes(root / DOCKERFILE)
    ui.require((root / DOCKERFILE).stat().st_mode & 0o777 == 0o644, "application recipe mode differs")
    plan = {"schema": BUN_PLAN_SCHEMA if bun else PLAN_SCHEMA, "repository": ui.REPOSITORY, "source_sha": source_sha, "source_tree": tree,
            "workflow": ui.WORKFLOW, "audience": "production", "surface": "application", "production_pages": "public",
            "commerce_extension": None, "image": IMAGE, "platform": "linux/amd64", "build_kind": "verified-source-package-static",
            "dockerfile": DOCKERFILE, "dockerfile_sha256": ui.digest(recipe),
            "recipe_input": {"path": DOCKERFILE, **file_record(recipe), "mode": 0o644}, "base_image": BASE_IMAGE,
            **{key: result[key] for key in fields - {"schema", "source"}},
            "build_args": {"APPLICATION_SOURCE_SHA": source_sha, "APPLICATION_CONTEXT_SHA": result["runtime_context"]["manifest_sha256"]}}
    validate_plan(plan)
    ui.require(_clean_source(root, source_sha) == tree, "application source changed while planning")
    _validate_input_assets(assets, plan)
    return plan


def _source(value: dict, source: str, context_sha: str) -> None:
    ui.require(value.get("source_commit") == source and value.get("effective_source_sha") == source
               and value.get("exact_committed_source") is True and value.get("context_sha256") == context_sha,
               "application observation source or context differs")


def validate_image_evidence(plan: dict, image_check: dict, browser: dict, *, image_digest: str,
                            browser_record: dict, context: dict) -> None:
    validate_plan(plan)
    reference = IMAGE + "@" + web.image_digest(image_digest)
    source, context_sha = plan["source_sha"], plan["runtime_context"]["manifest_sha256"]
    for value in (image_check, browser):
        ui.require(value.get("status") == "passed" and value.get("fixture") is False,
                   "application publication requires actual successful image and browser checks")
        _source(value, source, context_sha)
    ui.require(image_check.get("schema") == "marty.application-image-check/v1"
               and image_check.get("image_mode") == "published-digest" and image_check.get("image_reference") == reference
               and image_check.get("base_image") == BASE_IMAGE and image_check.get("recipe_input") == plan["recipe_input"],
               "application image check differs from the published recipe or immutable image")
    web.image_digest(image_check.get("image_id"))
    ui.require(isinstance(image_check.get("container_id"), str)
               and re.fullmatch(r"[0-9a-f]{64}", image_check["container_id"]) is not None,
               "application container identity is invalid")
    ui.require(image_check.get("qualification") == IMAGE_QUALIFICATION and image_check.get("cleanup") == IMAGE_CLEANUP,
               "application image qualification or cleanup is incomplete")
    endpoint = image_check.get("endpoint")
    web.object_keys(endpoint, {"host", "port"}, "application endpoint")
    ui.require(endpoint["host"] == "127.0.0.1", "application endpoint is not owned loopback")
    _number(endpoint["port"], 65535, "application endpoint port")
    expected_runtime = {key: image_check[key] for key in ("schema", "image_mode", "image_reference", "recipe_input",
                        "context_sha256", "image_id", "container_id", "endpoint", "cleanup")}
    ui.require(browser.get("schema") == "marty.application-browser-startup/v1" and browser.get("runtime") == expected_runtime
               and browser.get("origin") == f"http://127.0.0.1:{endpoint['port']}", "application browser belongs to a different runtime")
    browser_identity = browser.get("browser", {})
    ui.require(browser_identity.get("channel") == "chrome" and browser_identity.get("sandboxed") is True
               and isinstance(browser_identity.get("version"), str) and 0 < len(browser_identity["version"]) <= 256,
               "application browser was not sandboxed Chrome")
    ui.require(browser.get("qualification") == {"browser_startup_observed": True, "sdk_wasm_initialized_in_browser": True,
               "host_deployment_tested": False, "oidc_journey_tested": False, "published": False, "activated": False},
               "application browser qualification differs")
    ui.require(all(browser.get("cleanup", {}).get(key) is True for key in
                   ("browser_closed", "chromium_exited", "contexts_closed", "profile_removed"))
               and browser.get("process_evidence", {}).get("status") == "passed"
               and browser["process_evidence"].get("descendants_reaped") is True,
               "application browser cleanup is incomplete")
    linked = image_check.get("browser_startup", {})
    ui.require(all(linked.get(key) == item for key, item in browser_record.items())
               and linked.get("schema") == browser["schema"] and linked.get("status") == "passed"
               and linked.get("sdk_wasm_initialized_in_browser") is True and linked.get("worker_descendants_reaped") is True,
               "application image check does not bind the browser evidence")
    output = context["output_inventory"]["files"]
    paths = [item["path"] for item in output]
    ui.require(image_check.get("all_output_resources_readable") == paths, "application image output roster differs")
    observed = image_check.get("output_resources_verified")
    ui.require(isinstance(observed, list) and len(observed) == len(output), "application image output evidence is incomplete")
    transformed = {row["path"]: row for row in image_check.get("runtime_transformations", [])}
    expected_transforms = {row["path"] for row in output if row["path"] == "runtime-config.js" or row["path"].endswith(".html")}
    ui.require(set(transformed) == expected_transforms and len(transformed) == len(image_check["runtime_transformations"]),
               "application startup transformations differ")
    for original, actual in zip(output, observed):
        web.object_keys(actual, {"path", "bytes", "sha256", "mode"}, "application runtime file")
        _file({key: actual[key] for key in ("path", "bytes", "sha256")}, "application runtime file")
        ui.require(actual["path"] == original["path"] and actual["mode"] == 0o644, "application runtime path or mode differs")
        if actual["path"] in transformed:
            change = transformed[actual["path"]]
            ui.require(change == {"path": actual["path"], "original_sha256": original["sha256"],
                       "runtime_sha256": actual["sha256"], "mode": 0o644}, "application startup transform binding differs")
        else:
            ui.require(all(actual[key] == original[key] for key in ("bytes", "sha256")), "application runtime bytes differ")
    wasm = plan["sdk"]["emitted_wasm"]
    routes = browser.get("routes")
    ui.require(isinstance(routes, list) and [route.get("route") for route in routes] == list(BROWSER_ROUTES),
               "application browser omitted a required route")
    for route in routes:
        ui.require(route.get("ready") is True and route.get("root_populated") is True and route.get("context_closed") is True
                   and route.get("page_errors") == [] and route.get("aborted_wasm_requests") == 0,
                   "application browser route did not start successfully")
        observed_wasm = route.get("wasm", {})
        ui.require(all(observed_wasm.get(key) == item for key, item in wasm.items())
                   and observed_wasm.get("status") == 200 and observed_wasm.get("content_type") == "application/wasm"
                   and observed_wasm.get("from_cache") is False and observed_wasm.get("from_service_worker") is False,
                   "application browser SDK WASM differs")
    negative = browser.get("negative_control", {})
    ui.require(negative.get("route") == BROWSER_ROUTES[0] and negative.get("ready") is False
               and negative.get("root_populated") is False and negative.get("wasm") is None
               and negative.get("aborted_wasm_requests") == 1 and negative.get("context_closed") is True
               and negative.get("recovery", {}).get("visible") is True, "application browser negative control is incomplete")


def _validate_input_assets(directory: Path, plan: dict) -> dict:
    documents = {}
    for name in INPUT_FILES:
        raw = read_bytes(directory / name, ARCHIVE_LIMIT if name.endswith(".zip") else JSON_LIMIT)
        ui.require(file_record(raw) == plan["inputs"][name], "application input bytes differ: " + name)
        if not name.endswith(".zip"):
            documents[name] = parse(raw)
    manifest = documents["application-source-origin.json"]
    producer = documents["application-source-package.json"]
    consumer = documents["application-package-consumer.json"]
    baseline = documents["application-profile-source-closure.json"]
    context = documents["application-runtime-context.json"]
    bun = plan["schema"] == BUN_PLAN_SCHEMA
    package_version = 2 if bun else 1
    source = {"repository": ui.REPOSITORY, "commit": plan["source_sha"], "tree": plan["source_tree"],
              "object_format": "sha1", "working_tree_dirty": False}
    ui.require(manifest.get("schema") == f"marty.application-source-package/v{package_version}" and manifest.get("fixture") is False
               and manifest.get("source") == source and manifest.get("route_contract") == plan["route_contract"]
               and manifest.get("source_inventory_sha256") == plan["source_inventory_sha256"]
               and ui.digest(compact(manifest.get("files"))) == plan["source_inventory_sha256"],
               "application source manifest differs from its signed plan")
    lock_path = "ui/bun.lock" if bun else "ui/package-lock.json"
    lock = [row for row in manifest["files"] if row.get("path") == lock_path]
    ui.require(len(lock) == 1 and lock[0]["sha256"] == plan["dependency_lock_sha256"], "application lock differs")
    manager_evidence = (
        manifest.get("dependency_profile", {}).get("package_manager"),
        baseline.get("plan", {}).get("package_manager"),
        baseline.get("plan", {}).get("dependency_profile", {}).get("package_manager"),
        baseline.get("build", {}).get("package_manager"),
        baseline.get("dependency_install", {}).get("package_manager"),
        baseline.get("dependency_profile", {}).get("package_manager"),
        consumer.get("environment", {}).get("package_manager"),
        consumer.get("dependency_install", {}).get("package_manager"),
    )
    if bun:
        ui.require(all(item == BUN_PACKAGE_MANAGER for item in manager_evidence),
                   "application package manager evidence differs")
        ui.require(baseline.get("plan", {}).get("schema") == "marty.application-source-closure-plan/v7",
                   "application baseline plan schema differs")
        for observation in (baseline["dependency_install"], consumer["dependency_install"]):
            ui.require(observation.get("status") == "passed" and observation.get("mode") == "fresh-bun-frozen"
                       and observation.get("dependency_profile") == "application"
                       and observation.get("bun_version") == BUN_PACKAGE_MANAGER["version"]
                       and observation.get("bun_lock_selected") is True
                       and observation.get("independent_dependency_installation") is True,
                       "application observed Bun installation differs")
        ui.require(consumer.get("environment", {}).get("bun_version") == BUN_PACKAGE_MANAGER["version"],
                   "application observed Bun consumer version differs")
        ui.require(baseline.get("build", {}).get("dependency_mode") == "fresh-bun-frozen"
                   and baseline["build"].get("dependency_lock_sha256") == plan["dependency_lock_sha256"],
                   "application frozen Bun installation differs")
        reference_lock = [row for row in manifest["files"] if row.get("path") == "ui/package-lock.json"]
        ui.require(len(reference_lock) == 1
                   and baseline["build"].get("package_lock_sha256") == reference_lock[0]["sha256"],
                   "application npm reference lock differs")
    else:
        ui.require(all(item is None for item in manager_evidence),
                   "legacy application evidence cannot select a different package manager")
    ui.require(producer.get("schema") == f"marty.application-source-package-producer/v{package_version}"
               and producer.get("status") == "passed" and producer.get("fixture") is False
               and producer.get("source_commit") == plan["source_sha"] and producer.get("source_tree") == plan["source_tree"]
               and producer.get("source_preserved") is True and producer.get("archive_manifest_identical") is True,
               "application source producer was not qualified")
    for key, name in (("archive", INPUT_FILES[0]), ("manifest", INPUT_FILES[1]), ("baseline_report", INPUT_FILES[3])):
        ui.require(producer.get(key) == plan["inputs"][name], "application source producer pins differ")
    ui.require(baseline.get("schema") == f"marty.application-source-closure-rehearsal/v{7 if bun else 5}" and baseline.get("status") == "passed"
               and baseline.get("fixture", False) is False and baseline.get("plan", {}).get("source", {}).get("commit") == plan["source_sha"],
               "application baseline differs")
    ui.require(consumer.get("schema") == f"marty.application-source-package-consumer/v{package_version}" and consumer.get("status") == "passed"
               and consumer.get("fixture") is False and consumer.get("source") == source
               and consumer.get("source_inventory_sha256") == plan["source_inventory_sha256"]
               and consumer.get("preservation") == {"pinned_inputs_unchanged": True, "restored_source_unchanged": True},
               "application source consumer was not qualified")
    ui.require(consumer.get("cleanup") == {"process_group_cleanup_completed": True, "source_removed": True, "cache_removed": True,
               "runtime_adapter_removed": True, "temporary_removed": True, "runtime_context_removed": False},
               "application source consumer cleanup is incomplete")
    for key, name in (("archive", INPUT_FILES[0]), ("manifest", INPUT_FILES[1]), ("producer_report", INPUT_FILES[2]), ("baseline_report", INPUT_FILES[3])):
        pin = consumer.get("inputs", {}).get(key, {})
        ui.require({field: pin.get(field) for field in ("bytes", "sha256")} == plan["inputs"][name], "application consumer pins differ")
    ui.require(context.get("schema") == "marty.application-runtime-context/v1" and context.get("source_commit") == plan["source_sha"]
               and context.get("effective_source_sha") == plan["source_sha"] and context.get("exact_committed_source") is True
               and context.get("base_image") == BASE_IMAGE
               and ui.digest(compact(context.get("context_inventory"))) == plan["runtime_context"]["payload_sha256"],
               "application runtime context differs")
    held = consumer.get("runtime_context", {})
    ui.require({key: item for key, item in held.items() if key not in {"path", "manifest_sha256"}} == context
               and held.get("manifest_sha256") == plan["runtime_context"]["manifest_sha256"], "application consumer context differs")
    output = context.get("output_inventory", {})
    files = output.get("files")
    ui.require(isinstance(files, list) and len(files) == plan["output"]["file_count"] and consumer.get("output") == output,
               "application output inventory differs")
    for row in files:
        web.object_keys(row, {"path", "bytes", "sha256", "mode"}, "application output file")
        _file({key: row[key] for key in ("path", "bytes", "sha256")}, "application output file")
        ui.require(row["mode"] == 0o644, "application package output mode differs")
    ui.require(len({row["path"] for row in files}) == len(files)
               and sum(row["bytes"] for row in files) == plan["output"]["total_bytes"]
               and output.get("inventory_sha256") == ui.digest(compact(files)) == plan["output"]["inventory_sha256"],
               "application output digest or bounds differ")
    sdk = consumer.get("dependency_install", {}).get("sdk", {})
    actual_sdk = {key: sdk.get(key) for key in ("name", "version", "resolved", "integrity")}
    actual_sdk["wasm"] = {key: sdk.get("wasm", {}).get(key) for key in ("path", "bytes", "sha256")}
    emitted = [row for row in files if row["path"] == context.get("sdk_wasm")]
    ui.require(len(emitted) == 1, "application emitted SDK is missing")
    actual_sdk["emitted_wasm"] = {key: emitted[0][key] for key in ("path", "bytes", "sha256")}
    ui.require(actual_sdk == plan["sdk"] and sdk.get("initialized_in_node") is True, "application SDK evidence differs")
    return context


def _producer(source: str, run_id: str, run_attempt: str) -> dict:
    ui.require(all(isinstance(item, str) and re.fullmatch(r"[1-9][0-9]{0,19}", item) for item in (run_id, run_attempt)),
               "invalid application producer invocation")
    return {"repository": ui.REPOSITORY, "workflow": ui.WORKFLOW, "ref": web.REF,
            "source_sha": source, "run_id": run_id, "run_attempt": run_attempt}


def _release(plan: dict, *, image_digest: str, run_id: str, run_attempt: str, evidence: dict) -> dict:
    validate_plan(plan)
    web.object_keys(evidence, set(EVIDENCE_FILES), "application release evidence")
    for name, pin in evidence.items():
        _pin(pin, name)
    return {"schema": BUN_RELEASE_SCHEMA if plan["schema"] == BUN_PLAN_SCHEMA else RELEASE_SCHEMA,
            "repository": ui.REPOSITORY, "source_sha": plan["source_sha"],
            "audience": "production", "surface": "application", "production_pages": "public", "commerce_extension": None,
            "producer": _producer(plan["source_sha"], run_id, run_attempt),
            "image": {"uri": IMAGE, "digest": web.image_digest(image_digest), "platform": "linux/amd64"},
            "build_plan": plan, "build_plan_sha256": ui.digest(ui.canonical(plan)), "evidence": evidence,
            "qualification": dict(QUALIFICATION)}


def validate_release(value: dict, *, source_sha: str | None = None) -> dict:
    """Pure closed-schema validation; this is not signature authentication."""
    web.object_keys(value, RELEASE_FIELDS, "application release")
    web.object_keys(value["producer"], {"repository", "workflow", "ref", "source_sha", "run_id", "run_attempt"}, "application producer")
    web.object_keys(value["image"], {"uri", "digest", "platform"}, "application release image")
    expected = _release(value["build_plan"], image_digest=value["image"]["digest"],
                        run_id=value["producer"]["run_id"], run_attempt=value["producer"]["run_attempt"], evidence=value["evidence"])
    ui.require(value == expected and (source_sha is None or value["source_sha"] == web.full_sha(source_sha)),
               "application release differs from its plan or original producer")
    return value


def validate_assets(directory: Path, *, source_sha: str | None = None) -> dict:
    """Validate fixed inert evidence, without Git, Node, archive execution or network."""
    directory = directory.absolute()
    release = validate_release(read(directory / RECEIPT), source_sha=source_sha)
    context = _validate_input_assets(directory, release["build_plan"])
    evidence = {}
    for name in EVIDENCE_FILES:
        raw = read_bytes(directory / name)
        ui.require(file_record(raw) == release["evidence"][name], "application qualification bytes differ: " + name)
        evidence[name] = parse(raw)
    validate_image_evidence(release["build_plan"], evidence[IMAGE_CHECK], evidence[BROWSER_REPORT],
                            image_digest=release["image"]["digest"], browser_record=release["evidence"][BROWSER_REPORT], context=context)
    return release


def production_release(root: Path, plan: dict, *, source_sha: str, assets: Path, context: Path,
                       image_check: Path, browser_report: Path, image_digest: str, run_id: str, run_attempt: str) -> dict:
    """Revalidate the still-present source/context and exact successful observations."""
    ui.require(plan == production_plan(root, source_sha, assets=assets, context=context, browser_report=browser_report),
               "application plan differs from freshly verified source and package inputs")
    ui.require(image_check.absolute() == assets.absolute() / IMAGE_CHECK and browser_report.absolute() == assets.absolute() / BROWSER_REPORT,
               "application qualification must use its fixed evidence paths")
    raws = {IMAGE_CHECK: read_bytes(image_check.absolute()), BROWSER_REPORT: read_bytes(browser_report.absolute())}
    evidence = {name: file_record(raw) for name, raw in raws.items()}
    context_document = _validate_input_assets(assets.absolute(), plan)
    validate_image_evidence(plan, parse(raws[IMAGE_CHECK]), parse(raws[BROWSER_REPORT]), image_digest=image_digest,
                            browser_record=evidence[BROWSER_REPORT], context=context_document)
    ui.require(plan == production_plan(root, source_sha, assets=assets, context=context, browser_report=browser_report),
               "application inputs changed during recording")
    for name, raw in raws.items():
        ui.require(read_bytes(assets.absolute() / name) == raw, "application observation changed during recording")
    return _release(plan, image_digest=image_digest, run_id=run_id, run_attempt=run_attempt, evidence=evidence)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "record", "validate"))
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--source-sha")
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument("--context", type=Path)
    for name in ("output", "input-plan", "image-check", "browser-report"):
        parser.add_argument("--" + name, type=Path)
    for name in ("image-digest", "run-id", "run-attempt"):
        parser.add_argument("--" + name)
    args = parser.parse_args()
    if args.command == "validate":
        result = validate_assets(args.assets, source_sha=args.source_sha)
    else:
        ui.require(args.source_sha is not None and args.context is not None, "producer requires --source-sha and --context")
        if args.command == "plan":
            result = production_plan(args.root, args.source_sha, assets=args.assets, context=args.context)
        else:
            for name in ("input_plan", "image_check", "browser_report", "image_digest", "run_id", "run_attempt"):
                ui.require(getattr(args, name) is not None, "--" + name.replace("_", "-") + " is required")
            result = production_release(args.root, read(args.input_plan.absolute()), source_sha=args.source_sha,
                assets=args.assets, context=args.context, image_check=args.image_check, browser_report=args.browser_report,
                image_digest=args.image_digest, run_id=args.run_id, run_attempt=args.run_attempt)
    raw = ui.canonical(result)
    if args.output:
        with args.output.absolute().open("xb") as stream:
            stream.write(raw)
        args.output.chmod(0o600)
    else:
        print(raw.decode(), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
