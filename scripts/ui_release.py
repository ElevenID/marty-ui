#!/usr/bin/env python3
"""Keep customer UI images separate from the production website release."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

REPOSITORY = "ElevenID/marty-ui"
WORKFLOW = ".github/workflows/production-web-release.yml"
PUBLIC_IMAGE = "ghcr.io/elevenid/marty-ui-oss/ui-public"
PLAN_SCHEMA = "marty.production-web-build-plan/v1"
RELEASE_SCHEMA = "marty.production-web-release/v1"
SHA = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
RUN = re.compile(r"[1-9][0-9]*\Z")
VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def read(path: Path) -> dict:
    value = json.loads(path.read_bytes())
    require(isinstance(value, dict), f"{path.name} must be an object")
    return value


def canonical(value: dict) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def build_profile(audience: str, profile: str = "tester") -> tuple[str, dict[str, str]]:
    """The marketing audience can only select the public Docker target."""
    require(audience in {"customer", "production"}, "unknown UI audience")
    require(profile in {"full", "tester"}, "unknown customer UI profile")
    if audience == "customer":
        return "selfhost", {"UI_VARIANT": "selfhost", "SELFHOST_PUBLIC_PROFILE": profile,
                            "NGINX_CONFIG": "nginx.spa.conf"}
    return "public", {"UI_VARIANT": "public", "SELFHOST_PUBLIC_PROFILE": "full",
                      "NGINX_CONFIG": "nginx.prod.conf"}


def check_image(metadata: dict, *, audience: str, source_sha: str, version: str) -> dict:
    target, _ = build_profile(audience)
    require(SHA.fullmatch(source_sha) is not None, "invalid UI source SHA")
    require(metadata == {"component": "ui", "release_version": version,
                         "marty_ui_sha": source_sha, "audience": audience,
                         "ui_variant": "selfhost" if target == "selfhost" else "public"},
            "UI image audience, source or version differs from the release")
    return metadata


def production_plan(root: Path, source_sha: str) -> dict:
    # Reuse the independent console's exact npm identity/digest checks. These
    # dependencies are shared by both variants; the Docker target is separate.
    from product_package_plan import console_dependencies

    require(SHA.fullmatch(source_sha) is not None, "invalid production website source SHA")
    dependencies, lock_digest = console_dependencies(root)
    lock = read(root / "release/stack-lock.json")
    release = lock.get("release", "")
    require(isinstance(release, str) and release.startswith("marty-ui@"),
            "production website source release is missing")
    version = release.removeprefix("marty-ui@")
    require(VERSION.fullmatch(version) is not None, "production website version is invalid")
    target, profile = build_profile("production")
    dockerfile = "docker/ui.Dockerfile"
    return {"schema": PLAN_SCHEMA, "audience": "production", "repository": REPOSITORY,
            "source_sha": source_sha, "version": version, "workflow": WORKFLOW,
            "image": PUBLIC_IMAGE, "dockerfile": dockerfile, "target": target,
            "platform": "linux/amd64", "dockerfile_sha256": digest((root / dockerfile).read_bytes()),
            "dependency_lock_sha256": lock_digest,
            "build_args": {"MARTY_RELEASE_VERSION": version, "MARTY_UI_SHA": source_sha,
                           **dependencies, **profile}}


def production_release(root: Path, plan: dict, *, source_sha: str, image_digest: str,
                       run_id: str, run_attempt: str, metadata: dict) -> dict:
    require(plan == production_plan(root, source_sha),
            "production website build plan differs from exact source inputs")
    require(DIGEST.fullmatch(image_digest) is not None, "invalid production website image digest")
    require(RUN.fullmatch(run_id) is not None and RUN.fullmatch(run_attempt) is not None,
            "invalid production website producer attempt")
    check_image(metadata, audience="production", source_sha=source_sha, version=plan["version"])
    return {"schema": RELEASE_SCHEMA, "audience": "production", "repository": REPOSITORY,
            "source_sha": source_sha, "version": plan["version"],
            "producer": {"workflow": WORKFLOW, "ref": "refs/heads/main", "run_id": run_id,
                         "run_attempt": run_attempt},
            "image": {"uri": PUBLIC_IMAGE, "digest": image_digest, "platform": plan["platform"]},
            "build_plan_sha256": digest(canonical(plan)),
            "dependency_lock_sha256": plan["dependency_lock_sha256"],
            "image_metadata": metadata}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "record", "check-image"))
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--input-plan", type=Path)
    parser.add_argument("--image-metadata", type=Path)
    parser.add_argument("--image-digest")
    parser.add_argument("--run-id")
    parser.add_argument("--run-attempt")
    parser.add_argument("--audience", choices=("customer", "production"))
    parser.add_argument("--version")
    args = parser.parse_args()
    if args.command == "plan":
        result = production_plan(args.root, args.source_sha)
    elif args.command == "record":
        for name in ("input_plan", "image_metadata", "image_digest", "run_id", "run_attempt"):
            require(getattr(args, name) is not None, f"--{name.replace('_', '-')} is required")
        result = production_release(args.root, read(args.input_plan), source_sha=args.source_sha,
            image_digest=args.image_digest, run_id=args.run_id, run_attempt=args.run_attempt,
            metadata=read(args.image_metadata))
    else:
        for name in ("image_metadata", "audience", "version"):
            require(getattr(args, name) is not None, f"--{name.replace('_', '-')} is required")
        result = check_image(read(args.image_metadata), audience=args.audience,
                             source_sha=args.source_sha, version=args.version)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(canonical(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
