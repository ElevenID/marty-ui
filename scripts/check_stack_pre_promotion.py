#!/usr/bin/env python3
"""Recheck the claimed source and unused coordinates just before promotion."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from collections.abc import Callable
from pathlib import Path

if __package__:
    from .check_release_absent import (
        RegistryTagAlreadyExists,
        ReleaseAlreadyExists,
        ReleaseLookupError,
        ensure_registry_tag_absent,
        ensure_release_absent,
    )
else:
    from check_release_absent import (
        RegistryTagAlreadyExists,
        ReleaseAlreadyExists,
        ReleaseLookupError,
        ensure_registry_tag_absent,
        ensure_release_absent,
    )


class PrePromotionError(ValueError):
    """The claimed release cannot be promoted safely."""


def git(*arguments: str) -> str:
    try:
        result = subprocess.run(
            ["git", *arguments], check=True, capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise PrePromotionError("Could not verify the current release source") from error
    return result.stdout.strip()


def registry_digest(image: str, version: str) -> str:
    try:
        result = subprocess.run(
            ["docker", "buildx", "imagetools", "inspect", "--raw", f"{image}:{version}"],
            check=True, capture_output=True, timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise PrePromotionError("Recorded version tag is unavailable") from error
    return "sha256:" + hashlib.sha256(result.stdout).hexdigest()


def check(
    transaction: dict[str, object], *, source_sha: str, claim_run_id: str,
    tag: str, repository: str, git_command: Callable[..., str] = git,
    release_absent: Callable[[str, str, str], None] = ensure_release_absent,
    registry_absent: Callable[[str, str, str, str], None] = ensure_registry_tag_absent,
    digest_lookup: Callable[[str, str], str] = registry_digest,
    token: str, actor: str, images: tuple[str, str, str],
) -> dict[str, bool]:
    """Return existing exact image tags, including writes before a checkpoint."""
    version = tag.removeprefix("v")
    if not (
        re.fullmatch(r"[0-9a-f]{40}", source_sha)
        and re.fullmatch(r"[1-9][0-9]*", claim_run_id)
        and re.fullmatch(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", tag)
        and transaction.get("source_sha") == source_sha
        and transaction.get("claim_run_id") == claim_run_id
        and transaction.get("tag") == tag
        and transaction.get("version") == version
        and transaction.get("repository") == repository
        and transaction.get("image_uris") == dict(zip(
            ("ui", "services", "migrations"), images, strict=True,
        ))
    ):
        raise PrePromotionError("Qualified transaction differs from the exact claim")
    promoted = transaction.get("promoted_roles")
    if not isinstance(promoted, list) or any(
        not isinstance(role, str) or role not in ("ui", "services", "migrations")
        for role in promoted
    ) or len(promoted) != len(set(promoted)):
        raise PrePromotionError("Qualified transaction has invalid promotion state")
    fresh = len(promoted) == 0
    if promoted != list(("ui", "services", "migrations")[:len(promoted)]):
        raise PrePromotionError("Qualified transaction has invalid promotion order")
    state = transaction.get("state")
    if (fresh and state != "qualified") or (
        0 < len(promoted) < 3 and state != "promoting"
    ) or (len(promoted) == 3 and state != "promoted"):
        raise PrePromotionError("Qualified transaction has invalid promotion state")
    image_records = transaction.get("images")
    roles = ("ui", "services", "migrations")
    if not isinstance(image_records, dict) or set(image_records) != set(roles) or any(
        not isinstance(image_records[role], dict)
        or image_records[role].get("uri") != image
        or not isinstance(image_records[role].get("digest"), str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", image_records[role]["digest"]) is None
        for role, image in zip(roles, images, strict=True)
    ):
        raise PrePromotionError("Qualified image identities are invalid")

    if git_command("rev-parse", "HEAD^{commit}") != source_sha:
        raise PrePromotionError("Publication checkout differs from claimed source")
    git_command("fetch", "--no-tags", "origin", "+refs/heads/main:refs/remotes/origin/main")
    if git_command("rev-parse", "refs/remotes/origin/main^{commit}") != source_sha:
        raise PrePromotionError("Protected main moved after release qualification")

    if state != "promoted":
        if git_command("ls-remote", "--tags", "origin", f"refs/tags/{tag}", f"refs/tags/{tag}^{{}}"):
            raise PrePromotionError("Immutable release tag already exists")
        release_absent(repository, tag, token)
    existing: dict[str, bool] = {}
    for role, image in zip(roles, images, strict=True):
        if role in promoted:
            if digest_lookup(image, version) != image_records[role]["digest"]:
                raise PrePromotionError(f"Recorded {role} version tag differs from its qualified digest")
            existing[role] = True
        else:
            try:
                registry_absent(image, version, actor, token)
            except RegistryTagAlreadyExists:
                if digest_lookup(image, version) != image_records[role]["digest"]:
                    raise PrePromotionError(
                        f"Unrecorded {role} version tag differs from its qualified digest"
                    ) from None
                existing[role] = True
            else:
                existing[role] = False
    return existing


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--transaction", required=True, type=Path)
    parser.add_argument("--source-sha", default=os.environ.get("SOURCE_SHA", ""))
    parser.add_argument("--claim-run-id", default=os.environ.get("CLAIM_RUN_ID", ""))
    parser.add_argument("--tag", default=os.environ.get("TAG", ""))
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--image", action="append")
    parser.add_argument("--role", choices=("ui", "services", "migrations"))
    args = parser.parse_args()
    try:
        images = args.image or [os.environ.get(name, "") for name in (
            "IMAGE", "SERVICES_IMAGE", "MIGRATIONS_IMAGE",
        )]
        if len(images) != 3:
            raise PrePromotionError("Three release image coordinates are required")
        transaction = json.loads(args.transaction.read_text(encoding="utf-8"))
        if not isinstance(transaction, dict):
            raise PrePromotionError("Qualified transaction is invalid")
        existing = check(
            transaction, source_sha=args.source_sha, claim_run_id=args.claim_run_id,
            tag=args.tag, repository=args.repository,
            token=os.environ.get("GH_TOKEN", ""), actor=os.environ.get("GITHUB_ACTOR", ""),
            images=tuple(images),
        )
        if args.role:
            print("present" if existing[args.role] else "absent")
    except (
        OSError, ValueError, RegistryTagAlreadyExists, ReleaseAlreadyExists,
        ReleaseLookupError,
    ) as error:
        raise SystemExit(f"Pre-promotion release guard refused: {error}") from error


if __name__ == "__main__":
    main()
