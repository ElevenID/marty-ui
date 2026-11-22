#!/usr/bin/env python3
"""Source-bound website releases, independent of a stack version or backend claim.

The existing combined/customer release contracts remain in ui_release.py. This
module never treats a production combined image as an independent website.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

import ui_release as ui
import website_producer_policy as policy
from product_package_plan import console_dependencies

ROOT = Path(__file__).resolve().parents[1]
PLAN_SCHEMA = "marty.website-build-plan/v1"
RELEASE_SCHEMA = "marty.website-release/v1"
IMAGE_SCHEMA = "marty.website-image/v1"
COMPATIBILITY_SCHEMA = "marty.application-web-compatibility-release/v1"
MARKER_SCHEMA = "marty.application-web-compatibility/v1"
PUBLIC_IMAGE = "ghcr.io/elevenid/marty-ui-oss/website"
COMMERCE_IMAGE = "ghcr.io/elevenid/marty-subscriptions/website"
REPOSITORIES = {ui.REPOSITORY: "1140864197", ui.COMMERCE_REPOSITORY: "1207411806"}
REF = "refs/heads/main"
ROUTE_PATH = "contracts/web-surface-routes.json"
PLAN_FIELDS = {"schema", "repository", "source_sha", "revision", "production_pages",
               "commerce_extension", "workflow", "image", "dockerfile", "target", "platform",
               "dockerfile_sha256", "dependency_lock_sha256", "route_contract", "build_args"}
RELEASE_FIELDS = {"schema", "source_sha", "revision", "production_pages", "commerce_extension",
                  "producer", "image", "build_plan", "build_plan_sha256", "image_metadata"}
STANDALONE_PLAN_SCHEMA = "marty.website-build-plan/v2"
STANDALONE_RELEASE_SCHEMA = "marty.website-release/v2"
STANDALONE_IMAGE_SCHEMA = "marty.website-image/v2"
STANDALONE_BUN_PLAN_SCHEMA = "marty.website-build-plan/v3"
STANDALONE_BUN_RELEASE_SCHEMA = "marty.website-release/v3"
STANDALONE_BUN_IMAGE_SCHEMA = "marty.website-image/v3"
STANDALONE_FULL_PLAN_SCHEMA = "marty.website-build-plan/v4"
STANDALONE_FULL_RELEASE_SCHEMA = "marty.website-release/v4"
STANDALONE_FULL_IMAGE_SCHEMA = "marty.website-image/v4"
STANDALONE_PACKAGE_MANAGER = "bun@1.4.4"
STANDALONE_REPOSITORY = policy.STANDALONE_REPOSITORY
STANDALONE_WORKFLOW = policy.STANDALONE_WORKFLOW
STANDALONE_IMAGE = policy.STANDALONE_IMAGE
STANDALONE_BASE_IMAGE = "nginx:1.29.1-alpine@sha256:42a516af16b852e33b7682d5ef8acbd5d13fe08fecadc7ed98605ba5e3b26ab8"
STANDALONE_INPUTS = (
    "package.json", "package-lock.json", "Dockerfile.website", ROUTE_PATH,
    "scripts/build-website-image.mjs", "scripts/prerender-website.mjs",
    "scripts/website-prerender-plan.mjs", "ui/nginx.website.conf", "ui/nginx.website.headers.conf",
    "ui/scripts/render-website-nginx.mjs", "ui/vite.config.mjs",
)
STANDALONE_BUN_INPUTS = (*STANDALONE_INPUTS, "bun.lock")
STANDALONE_FULL_INPUTS = (
    *("Dockerfile.website.full" if name == "Dockerfile.website" else name for name in STANDALONE_BUN_INPUTS),
    "ui/scripts/production-build-contract.mjs", "ui/scripts/web-surface-build-contract.mjs",
)
STANDALONE_PLAN_FIELDS = {
    "schema", "repository", "source_sha", "revision", "production_pages", "commerce_extension",
    "workflow", "image", "platform", "dockerfile", "build_kind", "dependency_lock",
    "input_sha256", "output", "base_image", "route_contract", "build_args",
}


def object_keys(value: object, keys: set[str], label: str) -> None:
    ui.require(isinstance(value, dict) and set(value) == keys, f"{label} fields differ")


def full_sha(value: object, label: str = "source") -> str:
    ui.require(isinstance(value, str) and ui.SHA.fullmatch(value) is not None, f"invalid {label} SHA")
    return value


def image_digest(value: object) -> str:
    ui.require(isinstance(value, str) and ui.DIGEST.fullmatch(value) is not None, "invalid digest")
    return value


def read(path: Path) -> dict:
    def pairs(items):
        result = {}
        for key, value in items:
            ui.require(key not in result, "duplicate JSON field")
            result[key] = value
        return result
    value = json.loads(path.read_bytes(), object_pairs_hook=pairs)
    ui.require(isinstance(value, dict), "JSON input must be an object")
    return value


def route_identity(contract: dict) -> dict:
    object_keys(contract, {"schema_version", "website", "fallback"}, "route contract")
    ui.require(type(contract["schema_version"]) is int and contract["schema_version"] == 1
               and contract["fallback"] == "application", "unsupported route contract")
    website = contract["website"]
    object_keys(website, {"exact_paths", "path_prefixes", "filename_patterns"}, "website routes")
    for key in ("exact_paths", "path_prefixes"):
        items = website[key]
        ui.require(isinstance(items, list) and all(isinstance(item, str) for item in items)
                   and len(items) == len(set(items)), "invalid or duplicate website paths")
        for item in items:
            ui.require(re.fullmatch(r"/[A-Za-z0-9._/-]*", item) is not None
                       and "//" not in item and not any(part in {".", ".."} for part in item.split("/")),
                       "unsafe website path")
            if key == "path_prefixes":
                ui.require(item != "/" and item.endswith("/"), "invalid website prefix")
    ui.require("/" in website["exact_paths"], "website homepage is missing")
    ui.require(website["filename_patterns"] == [r"^/sitemap-[^/]+\.xml$"],
               "unsupported website filename patterns")
    # Match the frontend's sorted compact JSON, not host-dependent formatting.
    raw = json.dumps(contract, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return {"version": 1, "sha256": ui.digest(raw)}


def validate_route_identity(value: dict) -> None:
    object_keys(value, {"version", "sha256"}, "route identity")
    ui.require(type(value["version"]) is int and value["version"] == 1, "unsupported route version")
    image_digest(value["sha256"])


def revision(source_sha: str, commerce_source_sha: str | None = None) -> str:
    full_sha(source_sha)
    return source_sha if commerce_source_sha is None else source_sha + "-" + full_sha(commerce_source_sha, "commerce")


def producer(source_sha: str, extension: dict | None, run_id: str, run_attempt: str) -> dict:
    full_sha(source_sha)
    ui.require(isinstance(run_id, str) and ui.RUN.fullmatch(run_id) is not None
               and isinstance(run_attempt, str) and ui.RUN.fullmatch(run_attempt) is not None,
               "invalid website producer attempt")
    return {"repository": ui.COMMERCE_REPOSITORY if extension else ui.REPOSITORY,
            "workflow": ui.COMMERCE_WORKFLOW if extension else ui.WORKFLOW, "ref": REF,
            "source_sha": extension["source_sha"] if extension else source_sha,
            "run_id": run_id, "run_attempt": run_attempt}


def plan(root: Path, source_sha: str, *, production_pages: str = "public",
         commerce_source_sha: str | None = None) -> dict:
    full_sha(source_sha)
    extension = ui.commerce_identity(production_pages, commerce_source_sha)
    dependencies, lock_digest = console_dependencies(root)
    routes = route_identity(read(root / ROUTE_PATH))
    args = {**dependencies, "UI_VARIANT": "public", "UI_SURFACE": "website",
            "SELFHOST_PUBLIC_PROFILE": "full", "NGINX_CONFIG": "nginx.website.conf",
            "MARTY_UI_SHA": source_sha, "MARTY_WEBSITE_REVISION": revision(source_sha, commerce_source_sha),
            "MARTY_PRODUCTION_PAGES": production_pages}
    if extension:
        args["MARTY_COMMERCE_SOURCE_SHA"] = commerce_source_sha
    return {"schema": PLAN_SCHEMA, "repository": ui.REPOSITORY, "source_sha": source_sha,
            "revision": revision(source_sha, commerce_source_sha), "production_pages": production_pages,
            "commerce_extension": extension, "workflow": ui.COMMERCE_WORKFLOW if extension else ui.WORKFLOW,
            "image": COMMERCE_IMAGE if extension else PUBLIC_IMAGE, "dockerfile": "docker/ui.Dockerfile",
            "target": "website", "platform": "linux/amd64",
            "dockerfile_sha256": ui.digest((root / "docker/ui.Dockerfile").read_bytes()),
            "dependency_lock_sha256": lock_digest, "route_contract": routes, "build_args": args}


def validate_plan(value: dict) -> dict:
    if isinstance(value, dict) and value.get("schema") == STANDALONE_FULL_PLAN_SCHEMA:
        return validate_full_standalone_plan(value)
    if isinstance(value, dict) and value.get("schema") in (STANDALONE_PLAN_SCHEMA, STANDALONE_BUN_PLAN_SCHEMA):
        return validate_standalone_plan(value)
    object_keys(value, PLAN_FIELDS, "website plan")
    source_sha = full_sha(value["source_sha"])
    extension = value["commerce_extension"]
    private_sha = extension.get("source_sha") if isinstance(extension, dict) else None
    expected_extension = ui.commerce_identity(value["production_pages"], private_sha)
    ui.require(extension == expected_extension, "commerce identity differs")
    ui.require(value["schema"] == PLAN_SCHEMA and value["repository"] == ui.REPOSITORY
               and value["revision"] == revision(source_sha, private_sha)
               and value["workflow"] == (ui.COMMERCE_WORKFLOW if extension else ui.WORKFLOW)
               and value["image"] == (COMMERCE_IMAGE if extension else PUBLIC_IMAGE)
               and value["dockerfile"] == "docker/ui.Dockerfile" and value["target"] == "website"
               and value["platform"] == "linux/amd64", "website build identity differs")
    for key in ("dockerfile_sha256", "dependency_lock_sha256"):
        image_digest(value[key])
    validate_route_identity(value["route_contract"])
    expected = {"UI_VARIANT": "public", "UI_SURFACE": "website", "SELFHOST_PUBLIC_PROFILE": "full",
                "NGINX_CONFIG": "nginx.website.conf", "MARTY_UI_SHA": source_sha,
                "MARTY_WEBSITE_REVISION": value["revision"], "MARTY_PRODUCTION_PAGES": value["production_pages"]}
    if extension:
        expected["MARTY_COMMERCE_SOURCE_SHA"] = private_sha
    args = value["build_args"]
    ui.require(isinstance(args, dict), "invalid website build arguments")
    for name, prefix, repository in (("marty-api-core", "MARTY_API_CORE", "ElevenID/marty-cli"),
                                    ("marty-blog", "MARTY_BLOG", "ElevenID/marty-blog")):
        version = args.get(prefix + "_VERSION")
        ui.require(isinstance(version, str) and ui.VERSION.fullmatch(version) is not None,
                   "invalid website dependency version")
        expected.update({prefix + "_VERSION": version, prefix + "_DIGEST": image_digest(args.get(prefix + "_DIGEST")),
                         prefix + "_URI": f"https://github.com/{repository}/releases/download/v{version}/elevenid-{name}-{version}.tgz"})
    ui.require(args == expected, "website build arguments differ")
    return value


def image_metadata(build_plan: dict) -> dict:
    validate_plan(build_plan)
    if build_plan["schema"] == STANDALONE_FULL_PLAN_SCHEMA:
        return {"schema": STANDALONE_FULL_IMAGE_SCHEMA, "audience": "production", "surface": "website",
                "repository": STANDALONE_REPOSITORY, "source_sha": build_plan["source_sha"],
                "revision": build_plan["revision"], "production_pages": "full",
                "route_contract": build_plan["route_contract"], "commerce_extension": build_plan["commerce_extension"]}
    if build_plan["schema"] in {STANDALONE_PLAN_SCHEMA, STANDALONE_BUN_PLAN_SCHEMA}:
        schema = STANDALONE_BUN_IMAGE_SCHEMA if build_plan["schema"] == STANDALONE_BUN_PLAN_SCHEMA else STANDALONE_IMAGE_SCHEMA
        return {"schema": schema, "audience": "production", "surface": "website",
                "repository": STANDALONE_REPOSITORY, "source_sha": build_plan["source_sha"],
                "revision": build_plan["revision"], "production_pages": "public",
                "route_contract": build_plan["route_contract"], "commerce_extension": None}
    return {"schema": IMAGE_SCHEMA, "audience": "production", "surface": "website",
            "repository": ui.REPOSITORY, "source_sha": build_plan["source_sha"],
            "revision": build_plan["revision"], "production_pages": build_plan["production_pages"],
            "route_contract": build_plan["route_contract"], "commerce_extension": build_plan["commerce_extension"]}


def record(root: Path, build_plan: dict, *, source_sha: str, metadata: dict, digest: str,
           run_id: str, run_attempt: str, production_pages: str = "public",
           commerce_source_sha: str | None = None) -> dict:
    ui.require(build_plan == plan(root, source_sha, production_pages=production_pages,
                                  commerce_source_sha=commerce_source_sha), "website plan differs from exact source")
    ui.require(metadata == image_metadata(build_plan), "website image metadata differs")
    return {"schema": RELEASE_SCHEMA, "source_sha": source_sha, "revision": build_plan["revision"],
            "production_pages": production_pages, "commerce_extension": build_plan["commerce_extension"],
            "producer": producer(source_sha, build_plan["commerce_extension"], run_id, run_attempt),
            "image": {"uri": build_plan["image"], "digest": image_digest(digest), "platform": "linux/amd64"},
            "build_plan": build_plan, "build_plan_sha256": ui.digest(ui.canonical(build_plan)), "image_metadata": metadata}


def validate_release(value: dict, *, source_sha: str | None = None, commerce_source_sha: str | None = None) -> dict:
    if isinstance(value, dict) and value.get("schema") == STANDALONE_FULL_RELEASE_SCHEMA:
        return validate_full_standalone_release(value, source_sha=source_sha, commerce_source_sha=commerce_source_sha)
    if isinstance(value, dict) and value.get("schema") in (STANDALONE_RELEASE_SCHEMA, STANDALONE_BUN_RELEASE_SCHEMA):
        return validate_standalone_release(value, source_sha=source_sha, commerce_source_sha=commerce_source_sha)
    object_keys(value, RELEASE_FIELDS, "website release")
    build_plan = validate_plan(value["build_plan"])
    ui.require(build_plan["schema"] == PLAN_SCHEMA, "legacy website release requires its original plan schema")
    expected_producer = value["producer"]
    object_keys(expected_producer, {"repository", "workflow", "ref", "source_sha", "run_id", "run_attempt"}, "producer")
    expected = {"schema": RELEASE_SCHEMA, "source_sha": build_plan["source_sha"], "revision": build_plan["revision"],
                "production_pages": build_plan["production_pages"], "commerce_extension": build_plan["commerce_extension"],
                "producer": producer(build_plan["source_sha"], build_plan["commerce_extension"],
                                     expected_producer["run_id"], expected_producer["run_attempt"]),
                "image": {"uri": build_plan["image"], "digest": image_digest(value.get("image", {}).get("digest")),
                          "platform": "linux/amd64"}, "build_plan": build_plan,
                "build_plan_sha256": ui.digest(ui.canonical(build_plan)), "image_metadata": image_metadata(build_plan)}
    ui.require(value == expected, "website release differs from its original build and producer")
    if source_sha is not None:
        ui.require(value["source_sha"] == full_sha(source_sha), "website source differs from expected source")
        ui.require(value["commerce_extension"] == ui.commerce_identity(
            "public" if commerce_source_sha is None else "full", commerce_source_sha), "website commerce source differs")
    return value


def standalone_producer(source_sha: str, run_id: str, run_attempt: str) -> dict:
    """Describe the reserved standalone identity; this is not a verified proof."""
    return policy.validate_producer({
        "repository": STANDALONE_REPOSITORY, "workflow": STANDALONE_WORKFLOW,
        "ref": REF, "source_sha": full_sha(source_sha), "run_id": run_id, "run_attempt": run_attempt,
    }, role="website")


def standalone_plan(source_sha: str, *, input_sha256: dict, output: dict, route_contract: dict, version: int = 2) -> dict:
    """Describe supplied immutable inputs, without importing application source.

    A producer must compute these fingerprints from its verified clean checkout
    and final output. This pure contract builder does not authenticate a source,
    an unsigned qualification receipt, or a published container.
    """
    source_sha = full_sha(source_sha)
    ui.require(type(version) is int and version in {2, 3}, "unsupported standalone website plan version")
    value = {
        "schema": STANDALONE_BUN_PLAN_SCHEMA if version == 3 else STANDALONE_PLAN_SCHEMA,
        "repository": STANDALONE_REPOSITORY,
        "source_sha": source_sha, "revision": source_sha, "production_pages": "public",
        "commerce_extension": None, "workflow": STANDALONE_WORKFLOW, "image": STANDALONE_IMAGE,
        "platform": "linux/amd64", "dockerfile": "Dockerfile.website", "build_kind": "prebuilt-static",
        "dependency_lock": "bun.lock" if version == 3 else "package-lock.json",
        **({"package_manager": STANDALONE_PACKAGE_MANAGER} if version == 3 else {}),
        "input_sha256": input_sha256, "output": output,
        "base_image": STANDALONE_BASE_IMAGE, "route_contract": route_contract,
        "build_args": {"WEBSITE_SOURCE_SHA": source_sha, "WEBSITE_REVISION": source_sha,
                       "WEBSITE_ROUTE_CONTRACT_SHA256": route_contract.get("sha256") if isinstance(route_contract, dict) else None},
    }
    return validate_standalone_plan(value)


def validate_standalone_plan(value: dict) -> dict:
    bun = isinstance(value, dict) and value.get("schema") == STANDALONE_BUN_PLAN_SCHEMA
    object_keys(value, STANDALONE_PLAN_FIELDS | ({"package_manager"} if bun else set()), "standalone website plan")
    source = full_sha(value["source_sha"])
    expected = {
        "schema": STANDALONE_BUN_PLAN_SCHEMA if bun else STANDALONE_PLAN_SCHEMA,
        "repository": STANDALONE_REPOSITORY,
        "revision": source, "production_pages": "public", "commerce_extension": None,
        "workflow": STANDALONE_WORKFLOW, "image": STANDALONE_IMAGE, "platform": "linux/amd64",
        "dockerfile": "Dockerfile.website", "build_kind": "prebuilt-static",
        "dependency_lock": "bun.lock" if bun else "package-lock.json", "base_image": STANDALONE_BASE_IMAGE,
        **({"package_manager": STANDALONE_PACKAGE_MANAGER} if bun else {}),
    }
    ui.require(all(value[key] == item for key, item in expected.items()), "standalone website build identity differs")
    object_keys(value["input_sha256"], set(STANDALONE_BUN_INPUTS if bun else STANDALONE_INPUTS), "standalone website input fingerprints")
    for fingerprint in value["input_sha256"].values():
        image_digest(fingerprint)
    output = value["output"]
    object_keys(output, {"directory", "inventory_sha256", "file_count", "total_bytes"}, "standalone website output")
    ui.require(output["directory"] == "ui/dist-website", "standalone website output directory differs")
    image_digest(output["inventory_sha256"])
    ui.require(type(output["file_count"]) is int and 0 < output["file_count"] <= 10000
               and type(output["total_bytes"]) is int and 0 < output["total_bytes"] <= 512 * 1024 * 1024,
               "standalone website output bounds differ")
    validate_route_identity(value["route_contract"])
    ui.require(value["build_args"] == {
        "WEBSITE_SOURCE_SHA": source, "WEBSITE_REVISION": source,
        "WEBSITE_ROUTE_CONTRACT_SHA256": value["route_contract"]["sha256"],
    }, "standalone website build arguments differ")
    return value


def standalone_record(build_plan: dict, *, metadata: dict, digest: str, run_id: str, run_attempt: str) -> dict:
    """Build a version-matched receipt to be signed by the original hosted producer."""
    validate_standalone_plan(build_plan)
    source = build_plan["source_sha"]
    value = {
        "schema": STANDALONE_BUN_RELEASE_SCHEMA if build_plan["schema"] == STANDALONE_BUN_PLAN_SCHEMA else STANDALONE_RELEASE_SCHEMA,
        "source_sha": source, "revision": source,
        "production_pages": "public", "commerce_extension": None,
        "producer": standalone_producer(source, run_id, run_attempt),
        "image": {"uri": STANDALONE_IMAGE, "digest": image_digest(digest), "platform": "linux/amd64"},
        "build_plan": build_plan, "build_plan_sha256": ui.digest(ui.canonical(build_plan)),
        "image_metadata": metadata,
    }
    return validate_standalone_release(value)


def validate_standalone_release(value: dict, *, source_sha: str | None = None,
                                commerce_source_sha: str | None = None) -> dict:
    object_keys(value, RELEASE_FIELDS, "standalone website release")
    ui.require(value["schema"] in (STANDALONE_RELEASE_SCHEMA, STANDALONE_BUN_RELEASE_SCHEMA), "standalone website release schema differs")
    build_plan = validate_standalone_plan(value["build_plan"])
    source = build_plan["source_sha"]
    selected = policy.validate_producer(value["producer"], role="website")
    object_keys(value["image"], {"uri", "digest", "platform"}, "standalone website image")
    object_keys(value["image_metadata"], {
        "schema", "audience", "surface", "repository", "source_sha", "revision",
        "production_pages", "route_contract", "commerce_extension",
    }, "standalone website image metadata")
    validate_route_identity(value["image_metadata"]["route_contract"])
    expected = {
        "schema": STANDALONE_BUN_RELEASE_SCHEMA if build_plan["schema"] == STANDALONE_BUN_PLAN_SCHEMA else STANDALONE_RELEASE_SCHEMA,
        "source_sha": source, "revision": source,
        "production_pages": "public", "commerce_extension": None,
        "producer": standalone_producer(source, selected["run_id"], selected["run_attempt"]),
        "image": {"uri": STANDALONE_IMAGE, "digest": image_digest(value["image"]["digest"]), "platform": "linux/amd64"},
        "build_plan": build_plan, "build_plan_sha256": ui.digest(ui.canonical(build_plan)),
        "image_metadata": image_metadata(build_plan),
    }
    ui.require(value == expected, "standalone website release differs from its original build and producer")
    ui.require(commerce_source_sha is None, "standalone website cannot claim a commerce source")
    if source_sha is not None:
        ui.require(source == full_sha(source_sha), "website source differs from expected source")
    return value


def full_standalone_plan(source_sha: str, *, commerce_source_sha: str, input_sha256: dict,
                         output: dict, route_contract: dict) -> dict:
    """Describe full standalone output without granting the public website private authority.

    The protected private producer must qualify these exact source/output bytes
    and authenticate the resulting receipt and image. This pure declaration does
    not execute or authenticate a checkout, build, extension or proof.
    """
    source_sha = full_sha(source_sha)
    private_sha = full_sha(commerce_source_sha, "commerce")
    value = {
        "schema": STANDALONE_FULL_PLAN_SCHEMA, "repository": STANDALONE_REPOSITORY,
        "source_sha": source_sha, "revision": revision(source_sha, private_sha), "production_pages": "full",
        "commerce_extension": ui.commerce_identity("full", private_sha),
        "workflow": ui.COMMERCE_WORKFLOW, "image": COMMERCE_IMAGE,
        "platform": "linux/amd64", "dockerfile": "Dockerfile.website.full", "build_kind": "prebuilt-static",
        "dependency_lock": "bun.lock", "package_manager": STANDALONE_PACKAGE_MANAGER,
        "input_sha256": input_sha256, "output": output, "base_image": STANDALONE_BASE_IMAGE,
        "route_contract": route_contract,
        "build_args": {"WEBSITE_SOURCE_SHA": source_sha, "WEBSITE_REVISION": revision(source_sha, private_sha),
                       "WEBSITE_ROUTE_CONTRACT_SHA256": route_contract.get("sha256") if isinstance(route_contract, dict) else None,
                       "COMMERCE_SOURCE_SHA": private_sha},
    }
    return validate_full_standalone_plan(value)


def validate_full_standalone_plan(value: dict) -> dict:
    object_keys(value, STANDALONE_PLAN_FIELDS | {"package_manager"}, "full standalone website plan")
    source = full_sha(value["source_sha"])
    object_keys(value["commerce_extension"], {"repository", "source_sha"}, "full standalone commerce identity")
    private_sha = full_sha(value["commerce_extension"]["source_sha"], "commerce")
    expected = {
        "schema": STANDALONE_FULL_PLAN_SCHEMA, "repository": STANDALONE_REPOSITORY,
        "revision": revision(source, private_sha), "production_pages": "full",
        "commerce_extension": ui.commerce_identity("full", private_sha),
        "workflow": ui.COMMERCE_WORKFLOW, "image": COMMERCE_IMAGE, "platform": "linux/amd64",
        "dockerfile": "Dockerfile.website.full", "build_kind": "prebuilt-static",
        "dependency_lock": "bun.lock", "base_image": STANDALONE_BASE_IMAGE,
        "package_manager": STANDALONE_PACKAGE_MANAGER,
    }
    ui.require(all(value[key] == item for key, item in expected.items()), "full standalone website build identity differs")
    object_keys(value["input_sha256"], set(STANDALONE_FULL_INPUTS), "full standalone website input fingerprints")
    for fingerprint in value["input_sha256"].values():
        image_digest(fingerprint)
    output = value["output"]
    object_keys(output, {"directory", "inventory_sha256", "file_count", "total_bytes"}, "full standalone website output")
    ui.require(output["directory"] == "ui/dist-website", "full standalone website output directory differs")
    image_digest(output["inventory_sha256"])
    ui.require(type(output["file_count"]) is int and 0 < output["file_count"] <= 10000
               and type(output["total_bytes"]) is int and 0 < output["total_bytes"] <= 512 * 1024 * 1024,
               "full standalone website output bounds differ")
    validate_route_identity(value["route_contract"])
    ui.require(value["build_args"] == {
        "WEBSITE_SOURCE_SHA": source, "WEBSITE_REVISION": revision(source, private_sha),
        "WEBSITE_ROUTE_CONTRACT_SHA256": value["route_contract"]["sha256"], "COMMERCE_SOURCE_SHA": private_sha,
    }, "full standalone website build arguments differ")
    return value


def full_standalone_record(build_plan: dict, *, metadata: dict, digest: str, run_id: str, run_attempt: str) -> dict:
    """Build the full-only receipt owned by the original private hosted producer."""
    validate_full_standalone_plan(build_plan)
    value = {
        "schema": STANDALONE_FULL_RELEASE_SCHEMA, "source_sha": build_plan["source_sha"],
        "revision": build_plan["revision"], "production_pages": "full", "commerce_extension": build_plan["commerce_extension"],
        "producer": producer(build_plan["source_sha"], build_plan["commerce_extension"], run_id, run_attempt),
        "image": {"uri": COMMERCE_IMAGE, "digest": image_digest(digest), "platform": "linux/amd64"},
        "build_plan": build_plan, "build_plan_sha256": ui.digest(ui.canonical(build_plan)), "image_metadata": metadata,
    }
    return validate_full_standalone_release(value)


def validate_full_standalone_release(value: dict, *, source_sha: str | None = None,
                                     commerce_source_sha: str | None = None) -> dict:
    object_keys(value, RELEASE_FIELDS, "full standalone website release")
    build_plan = validate_full_standalone_plan(value["build_plan"])
    source = build_plan["source_sha"]
    extension = build_plan["commerce_extension"]
    selected = policy.validate_producer(value["producer"], role="website")
    object_keys(value["image"], {"uri", "digest", "platform"}, "full standalone website image")
    object_keys(value["image_metadata"], {
        "schema", "audience", "surface", "repository", "source_sha", "revision",
        "production_pages", "route_contract", "commerce_extension",
    }, "full standalone website image metadata")
    validate_route_identity(value["image_metadata"]["route_contract"])
    expected = {
        "schema": STANDALONE_FULL_RELEASE_SCHEMA, "source_sha": source, "revision": build_plan["revision"],
        "production_pages": "full", "commerce_extension": extension,
        "producer": producer(source, extension, selected["run_id"], selected["run_attempt"]),
        "image": {"uri": COMMERCE_IMAGE, "digest": image_digest(value["image"]["digest"]), "platform": "linux/amd64"},
        "build_plan": build_plan, "build_plan_sha256": ui.digest(ui.canonical(build_plan)),
        "image_metadata": image_metadata(build_plan),
    }
    ui.require(value == expected, "full standalone website release differs from its original build and private producer")
    if source_sha is not None:
        ui.require(source == full_sha(source_sha), "website source differs from expected source")
        ui.require(commerce_source_sha is not None, "full standalone website requires an expected commerce source")
    if commerce_source_sha is not None:
        ui.require(extension["source_sha"] == full_sha(commerce_source_sha, "commerce"), "website commerce source differs")
    return value


def application_marker(root: Path, source_sha: str, *, surface: str = "combined") -> dict:
    ui.require(surface in {"combined", "application"}, "unknown application surface")
    return {"schema": MARKER_SCHEMA, "source_sha": full_sha(source_sha), "surface": surface,
            "route_contract": route_identity(read(root / ROUTE_PATH))}


def validate_combined_release(value: dict) -> dict:
    """Closed legacy schema at the new boundary, after authenticating its producer."""
    full = value.get("schema") == "marty.production-web-release/v2"
    fields = {"schema", "audience", "repository", "source_sha", "version", "producer", "image",
              "build_plan_sha256", "dependency_lock_sha256", "image_metadata"}
    object_keys(value, fields | ({"production_pages", "commerce_extension"} if full else set()), "combined release")
    source = full_sha(value["source_sha"])
    ui.require(value["schema"] == ("marty.production-web-release/v2" if full else ui.RELEASE_SCHEMA)
               and value["audience"] == "production" and value["repository"] == ui.REPOSITORY
               and isinstance(value["version"], str) and ui.VERSION.fullmatch(value["version"]) is not None,
               "combined release identity differs")
    if full:
        object_keys(value["commerce_extension"], {"repository", "source_sha"}, "combined commerce extension")
    private_sha = value["commerce_extension"]["source_sha"] if full else None
    extension = ui.commerce_identity("full" if full else "public", private_sha)
    if full:
        ui.require(value["production_pages"] == "full" and value["commerce_extension"] == extension,
                   "combined commerce identity differs")
    p = value["producer"]
    ui.require(isinstance(p, dict), "combined producer must be an object")
    expected_p = producer(source, extension, p.get("run_id"), p.get("run_attempt"))
    legacy_p = {key: item for key, item in expected_p.items() if key not in {"repository", "source_sha"}}
    if full:
        legacy_p.update(repository=ui.COMMERCE_REPOSITORY, source_sha=private_sha)
    ui.require(p == legacy_p, "combined producer identity differs")
    object_keys(value["image"], {"uri", "digest", "platform"}, "combined image")
    ui.require(value["image"] == {"uri": ui.COMMERCE_IMAGE if full else ui.PUBLIC_IMAGE,
               "digest": image_digest(value["image"]["digest"]), "platform": "linux/amd64"},
               "combined image differs")
    ui.check_image(value["image_metadata"], audience="production", source_sha=source, version=value["version"],
                   production_pages="full" if full else "public", commerce_source_sha=private_sha)
    image_digest(value["build_plan_sha256"])
    image_digest(value["dependency_lock_sha256"])
    return value


def compatibility_record(release: dict, marker: dict, release_bytes: bytes) -> dict:
    validate_combined_release(release)
    object_keys(marker, {"schema", "source_sha", "surface", "route_contract"}, "application marker")
    validate_route_identity(marker["route_contract"])
    ui.require(marker["schema"] == MARKER_SCHEMA and marker["surface"] == "combined"
               and marker["source_sha"] == release["source_sha"], "combined application marker differs")
    extension = release.get("commerce_extension")
    return {"schema": COMPATIBILITY_SCHEMA, "application_release_sha256": ui.digest(release_bytes),
            "source_sha": release["source_sha"], "image": release["image"], "marker": marker,
            "producer": producer(release["source_sha"], extension, release["producer"]["run_id"],
                                 release["producer"]["run_attempt"])}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "record", "check-image", "check-application", "compatibility"))
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--production-pages", choices=("public", "full"), default="public")
    parser.add_argument("--commerce-source-sha")
    for name in ("output", "input-plan", "image-metadata", "application-release", "application-marker"):
        parser.add_argument("--" + name, type=Path)
    for name in ("image-digest", "run-id", "run-attempt"):
        parser.add_argument("--" + name)
    args = parser.parse_args()
    options = dict(production_pages=args.production_pages, commerce_source_sha=args.commerce_source_sha)
    if args.command in {"check-application", "compatibility"}:
        ui.require(args.application_marker is not None, "application marker required")
        marker = read(args.application_marker)
        ui.require(marker == application_marker(args.root, args.source_sha), "marker differs from exact source routes")
        if args.command == "compatibility":
            ui.require(args.application_release is not None, "application release required")
            application = ui.validate_production_release(args.root, read(args.application_release), args.source_sha)
            result = compatibility_record(application, marker, args.application_release.read_bytes())
        else:
            result = marker
    elif args.command == "plan":
        result = plan(args.root, args.source_sha, **options)
    elif args.command == "check-image":
        ui.require(args.image_metadata is not None, "image metadata required")
        result = read(args.image_metadata)
        ui.require(result == image_metadata(plan(args.root, args.source_sha, **options)), "website image metadata differs")
    else:
        ui.require(all(getattr(args, key) is not None for key in
                       ("input_plan", "image_metadata", "image_digest", "run_id", "run_attempt")), "record inputs required")
        result = record(args.root, read(args.input_plan), source_sha=args.source_sha,
                        metadata=read(args.image_metadata), digest=args.image_digest,
                        run_id=args.run_id, run_attempt=args.run_attempt, **options)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(ui.canonical(result))


if __name__ == "__main__":
    main()
