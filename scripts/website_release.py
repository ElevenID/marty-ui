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
    object_keys(value, RELEASE_FIELDS, "website release")
    build_plan = validate_plan(value["build_plan"])
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
    private_sha = value.get("commerce_extension", {}).get("source_sha") if full else None
    extension = ui.commerce_identity("full" if full else "public", private_sha)
    if full:
        ui.require(value["production_pages"] == "full" and value["commerce_extension"] == extension,
                   "combined commerce identity differs")
    p = value["producer"]
    expected_p = producer(source, extension, p.get("run_id"), p.get("run_attempt"))
    legacy_p = {key: item for key, item in expected_p.items() if key not in {"repository", "source_sha"}}
    if full:
        legacy_p.update(repository=ui.COMMERCE_REPOSITORY, source_sha=private_sha)
    ui.require(p == legacy_p, "combined producer identity differs")
    ui.require(value["image"] == {"uri": ui.COMMERCE_IMAGE if full else ui.PUBLIC_IMAGE,
               "digest": image_digest(value.get("image", {}).get("digest")), "platform": "linux/amd64"},
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
    parser.add_argument("command", choices=("plan", "record", "check-image", "compatibility"))
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
    if args.command == "compatibility":
        ui.require(args.application_release is not None and args.application_marker is not None, "application inputs required")
        application = ui.validate_production_release(args.root, read(args.application_release), args.source_sha)
        marker = read(args.application_marker)
        ui.require(marker == application_marker(args.root, args.source_sha), "marker differs from exact source routes")
        result = compatibility_record(application, marker, args.application_release.read_bytes())
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
