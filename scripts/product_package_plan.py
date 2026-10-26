#!/usr/bin/env python3
"""Resolve independent product build inputs without installing either product."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

PRODUCTS = {
    "marty-server": ("server-v", {"services", "migrations", "openbao-didcomm", "keycloak"}),
    "marty-console": ("console-v", {"ui"}),
}
VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")
SHA = re.compile(r"[0-9a-f]{40}")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def source_file(root: Path, relative: str) -> Path:
    require(isinstance(relative, str) and bool(relative), "source path is required")
    path = (root / relative).resolve()
    require(path.is_relative_to(root.resolve()) and path.is_file(), "source path escapes or is missing")
    return path


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def console_dependencies(root: Path) -> tuple[dict[str, str], str]:
    lock_path = source_file(root, "release/stack-lock.json")
    lock = json.loads(lock_path.read_bytes())
    require(lock.get("schema") == "marty.stack-lock/v1", "console dependency lock schema changed")
    args = {}
    for name, prefix in [("marty-api-core", "MARTY_API_CORE"), ("marty-blog", "MARTY_BLOG")]:
        selected = [item for item in lock["components"] if item.get("name") == name]
        require(len(selected) == 1, "console dependency is missing or duplicated")
        component = selected[0]
        artifacts = [item for item in component["artifacts"] if item.get("type") == "npm"]
        require(len(artifacts) == 1, "console dependency must have one npm artifact")
        artifact = artifacts[0]
        require(VERSION.fullmatch(component["version"]) is not None, "console dependency version is invalid")
        require(re.fullmatch(r"sha256:[0-9a-f]{64}", artifact["digest"]) is not None, "console dependency digest is invalid")
        repository = "ElevenID/marty-cli" if name == "marty-api-core" else "ElevenID/marty-blog"
        expected = f"https://github.com/{repository}/releases/download/v{component['version']}/elevenid-{name}-{component['version']}.tgz"
        require(component["repository"] == repository and artifact["uri"] == expected, "console dependency identity changed")
        args.update({prefix + "_VERSION": component["version"], prefix + "_URI": artifact["uri"], prefix + "_DIGEST": artifact["digest"]})
    return args, digest(lock_path)


def build_plan(root: Path, product: str, source_sha: str) -> dict:
    require(product in PRODUCTS, "unknown product")
    require(isinstance(source_sha, str) and SHA.fullmatch(source_sha) is not None, "source SHA is invalid")
    catalog_path = source_file(root, "release/product-packages.json")
    catalog = json.loads(catalog_path.read_bytes())
    require(set(catalog) == {"schema", "products"} and catalog["schema"] == "marty.product-packages/v1", "package catalog schema changed")
    require(set(catalog["products"]) == set(PRODUCTS), "package catalog products changed")
    spec = catalog["products"][product]
    require(set(spec) == {"version", "tag_prefix", "image_namespace", "api", "images"}, "product fields changed")
    prefix, roles = PRODUCTS[product]
    require(spec["tag_prefix"] == prefix, "product tag namespace changed")
    require(spec["image_namespace"] == "ghcr.io/elevenid/" + product, "product image namespace changed")
    require(set(spec["images"]) == roles, "product image roles changed")
    require(spec["api"] == {"http": "v1", "mip": "0.5.0"}, "declared API contract changed")
    version_source = spec["version"]
    require(set(version_source) == {"path", "json_field"}, "version source fields changed")
    expected_source = ({"path": "release/server-version.txt", "json_field": None} if product == "marty-server"
                       else {"path": "release/console-version.txt", "json_field": None})
    require(version_source == expected_source, "product version source changed")
    version_path = source_file(root, version_source["path"])
    version = (json.loads(version_path.read_bytes())[version_source["json_field"]]
               if version_source["json_field"] else version_path.read_text(encoding="utf-8").strip())
    require(isinstance(version, str) and VERSION.fullmatch(version) is not None, "product version is invalid")
    build_args = {"MARTY_RELEASE_VERSION": version, "MARTY_UI_SHA": source_sha}
    dependency_lock_sha256 = None
    if product == "marty-console":
        dependencies, dependency_lock_sha256 = console_dependencies(root)
        build_args.update(dependencies)
        build_args.update(UI_VARIANT="selfhost", NGINX_CONFIG="nginx.spa.conf", SELFHOST_PUBLIC_PROFILE="full")
    images = []
    for role, image in sorted(spec["images"].items()):
        require(set(image) == {"dockerfile", "target"}, "image fields changed")
        require(isinstance(image["target"], str) and re.fullmatch(r"[a-z0-9-]*", image["target"]) is not None, "build target is invalid")
        dockerfile = source_file(root, image["dockerfile"])
        images.append({
            "role": role, "context": ".", "dockerfile": image["dockerfile"],
            "dockerfile_sha256": digest(dockerfile), "target": image["target"],
            "image": spec["image_namespace"] + "/" + role,
            "version_tag": version, "platform": "linux/amd64",
            "build_args": build_args,
        })
    return {
        "schema": "marty.product-build-plan/v1", "product": product,
        "version": version, "tag": prefix + version,
        "repository": "ElevenID/marty-ui", "source_sha": source_sha,
        "version_source": version_source, "version_source_sha256": digest(version_path),
        "catalog_sha256": digest(catalog_path), "api": spec["api"],
        "dependency_lock_sha256": dependency_lock_sha256,
        "qualification": "unqualified", "images": images,
    }


def assemble_package(root: Path, plan: dict, images_dir: Path, run_id: str, attempt: str) -> dict:
    """Bind this producer attempt's complete role set; do not qualify payloads."""
    require(isinstance(plan, dict), "build plan must be an object")
    require(plan == build_plan(root, plan.get("product"), plan.get("source_sha")), "frozen build plan differs from source")
    require(re.fullmatch(r"[1-9][0-9]*", run_id) is not None, "producer run ID is invalid")
    require(re.fullmatch(r"[1-9][0-9]*", attempt) is not None, "producer attempt is invalid")
    expected = {image["role"] + ".json" for image in plan["images"]}
    entries = list(images_dir.iterdir())
    require({path.name for path in entries} == expected, "producer image receipts are incomplete or unexpected")
    require(all(path.is_file() and not path.is_symlink() for path in entries), "producer receipt must be a regular file")
    images = []
    for image in plan["images"]:
        path = images_dir / (image["role"] + ".json")
        require(path.stat().st_size <= 65536, "producer receipt is too large")
        receipt = json.loads(path.read_bytes())
        identity = {
            "product": plan["product"], "version": plan["version"], "source_sha": plan["source_sha"],
            "role": image["role"], "image": image["image"], "run_id": run_id, "run_attempt": attempt,
        }
        require(set(receipt) == set(identity) | {"digest"}, "producer receipt fields changed")
        require(all(receipt[key] == value for key, value in identity.items()), "producer receipt identity differs")
        require(isinstance(receipt["digest"], str) and re.fullmatch(r"sha256:[0-9a-f]{64}", receipt["digest"]) is not None, "producer image digest is invalid")
        images.append({"role": image["role"], "uri": image["image"], "digest": receipt["digest"], "platform": image["platform"]})
    canonical_plan = json.dumps(plan, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        "schema": "marty.product-package/v1", "product": plan["product"], "version": plan["version"],
        "tag": plan["tag"], "source": {"repository": plan["repository"], "commit": plan["source_sha"]},
        "api": plan["api"], "platforms": ["linux/amd64"], "images": images,
        "build_plan_sha256": "sha256:" + hashlib.sha256(canonical_plan).hexdigest(),
        "producer": {"workflow": ".github/workflows/product-packages.yml", "run_id": run_id, "run_attempt": attempt},
        "support_state": "experimental", "qualification": "unqualified",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--product", choices=PRODUCTS, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--input-plan", type=Path)
    parser.add_argument("--images-dir", type=Path)
    parser.add_argument("--build-run-id")
    parser.add_argument("--build-run-attempt")
    args = parser.parse_args()
    plan = build_plan(args.root, args.product, args.source_sha)
    assembly = (args.input_plan, args.images_dir, args.build_run_id, args.build_run_attempt)
    if any(value is not None for value in assembly):
        require(all(value is not None for value in assembly), "all package assembly arguments are required")
        frozen = json.loads(args.input_plan.read_bytes())
        require(frozen == plan, "input plan differs from selected source/product")
        plan = assemble_package(args.root, frozen, args.images_dir, args.build_run_id, args.build_run_attempt)
    args.output.write_text(json.dumps(plan, sort_keys=True, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
