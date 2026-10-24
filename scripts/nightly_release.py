#!/usr/bin/env python3
"""Identity and artifact contracts for installation-test nightly prereleases.

Nightly preparation is separate from stable release transactions. The original
no-write claim remains immutable; this record binds the images built from it.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from copy import deepcopy
from pathlib import Path

from build_stack_manifest import build_manifest
from nightly_claim import validate_intake
from release_transaction import IMAGE_URIS, file_digest
from stack_tag_gate import classify_release_tag

SCHEMA = "elevenid.nightly-installation-candidate/v1"
WORKFLOW = ".github/workflows/nightly-release.yml"
IMAGE_COORDINATES = {
    **IMAGE_URIS,
    "ui_selfhost": "ghcr.io/elevenid/marty-ui-oss/ui-selfhost",
    "cloudflared_wrapper": "ghcr.io/elevenid/marty-ui-oss/cloudflared-wrapper",
}
SHA = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
RUN = re.compile(r"[1-9][0-9]*\Z")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def read(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(value, dict), f"{path.name} must be an object")
    return value


def base_version(tag: str) -> str:
    tier, version = classify_release_tag(tag)
    require(tier == "nightly", "installation candidate must have a nightly tag")
    return version.split("-nightly.", 1)[0]


def admit(claim: dict, run: dict, source: str, policy: dict, lock: dict) -> dict:
    accepted = validate_intake(claim, run, current_main_sha=source, policy=policy)
    require(lock.get("schema") == "marty.stack-lock/v1"
            and lock.get("release_state") == "eligible"
            and lock.get("release") == f"marty-ui@{base_version(accepted['tag'])}",
            "nightly source lock differs from the accepted claim")
    return accepted


def build_plan(claim: dict, lock: dict) -> list[dict]:
    components = {item["name"]: item for item in lock["components"]}
    args = {"MARTY_RELEASE_VERSION": claim["version"], "MARTY_UI_SHA": claim["source_sha"]}
    for name, prefix, kind in (
        ("marty-api-core", "MARTY_API_CORE", "npm"),
        ("marty-blog", "MARTY_BLOG", "npm"),
        ("marty-core-python", "MARTY_RS", "python"),
        ("marty-verification-python", "MARTY_VERIFICATION", "python"),
        ("marty-iso18013-python", "MARTY_ISO18013", "python"),
    ):
        component = components[name]
        artifacts = [item for item in component["artifacts"] if item["type"] == kind]
        require(len(artifacts) == 1, f"ambiguous build input: {name}")
        args.update({prefix + "_VERSION": component["version"],
                     prefix + "_URI": artifacts[0]["uri"],
                     prefix + "_DIGEST": artifacts[0]["digest"]})
    recipes = {
        "ui": ("docker/ui.Dockerfile", "", {}),
        "services": ("services/Dockerfile", "", {"SERVICE_NAME": "gateway"}),
        "migrations": ("services/Dockerfile.migrations", "", {}),
        "openbao_didcomm": ("openbao/didcomm-authcrypt/Dockerfile", "", {}),
        "keycloak": ("keycloak/openbao-provider/Dockerfile", "", {}),
        "ui_selfhost": ("docker/ui.Dockerfile", "selfhost", {
            "UI_VARIANT": "selfhost", "SELFHOST_PUBLIC_PROFILE": "tester",
            "NGINX_CONFIG": "nginx.spa.conf"}),
        "cloudflared_wrapper": ("docker/cloudflared-wrapper.Dockerfile", "", {}),
    }
    result = []
    for role, (dockerfile, target, overrides) in recipes.items():
        build_args = {**args, **overrides}
        require(all(isinstance(value, str) and not any(c in value for c in "\r\n")
                    for value in build_args.values()), "multiline image build input")
        result.append({"role": role, "image": IMAGE_COORDINATES[role],
                       "dockerfile": dockerfile, "target": target,
                       "build_args": "\n".join(f"{key}={value}" for key, value in build_args.items())})
    return result


def validate_candidate(candidate: dict) -> dict:
    require(set(candidate) == {"schema", "state", "tag", "version", "source_sha",
            "claim_run_id", "stack_lock_sha256", "image_uris", "images", "build_run_id"},
            "nightly candidate fields changed")
    require(candidate["schema"] == SCHEMA and candidate["state"] == "prepared",
            "not a prepared nightly candidate")
    base_version(candidate["tag"])
    require(candidate["version"] == candidate["tag"][1:], "nightly version differs from tag")
    require(SHA.fullmatch(candidate["source_sha"]) is not None, "invalid nightly source")
    require(RUN.fullmatch(candidate["claim_run_id"]) is not None
            and RUN.fullmatch(candidate["build_run_id"]) is not None, "invalid nightly run")
    require(candidate["tag"].endswith("." + candidate["claim_run_id"]),
            "nightly tag differs from claim run")
    require(DIGEST.fullmatch(candidate["stack_lock_sha256"]) is not None,
            "invalid nightly lock digest")
    require(candidate["image_uris"] == IMAGE_COORDINATES
            and set(candidate["images"]) == set(IMAGE_COORDINATES), "nightly image roles changed")
    for role, uri in IMAGE_COORDINATES.items():
        image = candidate["images"][role]
        require(set(image) == {"uri", "digest", "build_run_id"}
                and image["uri"] == uri and DIGEST.fullmatch(image["digest"]) is not None
                and image["build_run_id"] == candidate["build_run_id"],
                f"nightly image identity differs: {role}")
    return candidate


def record(claim: dict, lock_path: Path, directory: Path, run_id: str) -> dict:
    require(RUN.fullmatch(run_id) is not None, "invalid image producer run")
    files = list(directory.glob("*/image.json"))
    require(len(files) == len(IMAGE_COORDINATES), "nightly image evidence is incomplete")
    images = {}
    for path in files:
        item = read(path)
        require(set(item) == {"role", "uri", "digest", "source_sha", "version", "run_id"},
                "image evidence fields changed")
        role = item["role"]
        require(role in IMAGE_COORDINATES and role not in images, "unknown or duplicate image role")
        require(item["uri"] == IMAGE_COORDINATES[role]
                and item["source_sha"] == claim["source_sha"]
                and item["version"] == claim["version"] and item["run_id"] == run_id,
                "image evidence does not belong to this candidate")
        images[role] = {"uri": item["uri"], "digest": item["digest"], "build_run_id": run_id}
    return validate_candidate({"schema": SCHEMA, "state": "prepared",
        "tag": claim["tag"], "version": claim["version"], "source_sha": claim["source_sha"],
        "claim_run_id": claim["claim_run_id"], "stack_lock_sha256": file_digest(lock_path),
        "image_uris": IMAGE_COORDINATES, "images": images, "build_run_id": run_id})


def validate_preparation(value: dict, *, source_sha: str, stack_lock: Path,
                         claim_run_id: str) -> dict:
    candidate = validate_candidate(value)
    require(candidate["source_sha"] == source_sha and candidate["claim_run_id"] == claim_run_id
            and candidate["stack_lock_sha256"] == file_digest(stack_lock),
            "nightly preparation source, claim or lock changed")
    lock = read(stack_lock)
    require(lock.get("release") == f"marty-ui@{base_version(candidate['tag'])}",
            "nightly base version differs from source lock")
    return candidate


def product_manifest(candidate: dict, lock_path: Path, timestamp: str) -> dict:
    validate_preparation(candidate, source_sha=candidate["source_sha"],
                         stack_lock=lock_path, claim_run_id=candidate["claim_run_id"])
    lock = deepcopy(read(lock_path))
    lock["release"] = "marty-ui@" + candidate["version"]
    artifacts = []
    for role in IMAGE_URIS:
        image = candidate["images"][role]
        artifacts.append({"type": "oci", "uri": image["uri"], "digest": image["digest"],
            "sbom": f"https://github.com/ElevenID/marty-ui/releases/download/{candidate['tag']}/{role}.sbom.cdx.json",
            "provenance": "https://github.com/ElevenID/marty-ui/attestations"})
    require(not any(c["name"] == "marty-ui" for c in lock["components"]),
            "source lock already contains product images")
    lock["components"].append({"name": "marty-ui", "repository": "ElevenID/marty-ui",
        "version": candidate["version"], "commit": candidate["source_sha"], "artifacts": artifacts})
    return build_manifest(lock, generated_at=timestamp)


def image_lock(candidate: dict, model: dict, source: Path, external: dict) -> dict:
    """Reuse production Compose ownership and independent-image checks."""
    from build_selfhost_image_lock import (
        KEYCLOAK_SERVICES, LEGACY_ROLE, _exact_image, _ownership,
        _validate_external_services, _verify_source_files,
    )

    validate_preparation(candidate, source_sha=candidate["source_sha"],
        stack_lock=source / "release/stack-lock.json", claim_run_id=candidate["claim_run_id"])
    base = source / "docker-compose.selfhost.prod.yml"
    override = source / "docker-compose.selfhost.bundle.override.yml"
    _verify_source_files(source, candidate["source_sha"],
        (source / "release/stack-lock.json", base, override,
         source / "docker-compose.selfhost.openbao.yml"))
    names, roles = _ownership(base, override)
    services = model["services"]
    require(set(services) == names, "nightly Compose service set changed")
    _validate_external_services(services, roles, external)
    role_map = {"services": "services", "db-migrate": "migrations",
                "ui-selfhost": "ui_selfhost", "cloudflared-wrapper": "cloudflared_wrapper"}
    resolved = {}
    for name, service in services.items():
        require("build" not in service, "nightly bundle contains a source build")
        if name in roles:
            matched = LEGACY_ROLE.fullmatch(service["image"])
            require(matched is not None and matched["role"] == roles[name]
                    and matched["version"] == base_version(candidate["tag"]),
                    "nightly source image role/version changed")
            image = candidate["images"][role_map[roles[name]]]
            resolved[name] = image["uri"] + "@" + image["digest"]
        elif name in KEYCLOAK_SERVICES:
            image = candidate["images"]["keycloak"]
            resolved[name] = image["uri"] + "@" + image["digest"]
            require(service["image"] == resolved[name], "nightly Keycloak image changed")
        else:
            resolved[name] = external[name]
        _exact_image(resolved[name], name)
    plugin = candidate["images"]["openbao_didcomm"]
    return {"schema": "marty.selfhost-image-lock/v1", "release": "marty-ui@" + candidate["version"],
            "services": dict(sorted(resolved.items())),
            "openbao_didcomm_image": plugin["uri"] + "@" + plugin["digest"]}


def pin_external_images(model: dict, source: Path) -> dict:
    from build_selfhost_image_lock import KEYCLOAK_SERVICES, _ownership, _repository

    _, roles = _ownership(source / "docker-compose.selfhost.prod.yml",
                          source / "docker-compose.selfhost.bundle.override.yml")
    pinned = {}
    cache = {}
    for name, service in model["services"].items():
        if name in roles or name in KEYCLOAK_SERVICES:
            continue
        image = service["image"]
        if image not in cache:
            result = subprocess.run(["docker", "buildx", "imagetools", "inspect", "--raw", image],
                                    check=True, capture_output=True, timeout=120)
            import hashlib

            cache[image] = _repository(image) + "@sha256:" + hashlib.sha256(result.stdout).hexdigest()
        pinned[name] = cache[image]
    return pinned


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["admit", "record", "manifest"])
    parser.add_argument("--claim", type=Path)
    parser.add_argument("--run-json", type=Path)
    parser.add_argument("--source-sha")
    parser.add_argument("--policy", type=Path, default=Path(".github/stack-tag-policy.json"))
    parser.add_argument("--stack-lock", type=Path, default=Path("release/stack-lock.json"))
    parser.add_argument("--images-dir", type=Path)
    parser.add_argument("--run-id")
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--timestamp")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.command in {"admit", "record"}:
        claim = admit(read(args.claim), read(args.run_json), args.source_sha,
                      read(args.policy), read(args.stack_lock))
        result = ({"claim": claim, "include": build_plan(claim, read(args.stack_lock))}
                  if args.command == "admit" else
                  record(claim, args.stack_lock, args.images_dir, args.run_id))
    else:
        result = product_manifest(read(args.candidate), args.stack_lock, args.timestamp)
    with args.output.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
