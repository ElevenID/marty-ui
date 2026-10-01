#!/usr/bin/env python3
"""Recheck the claimed source and unused coordinates just before promotion."""

from __future__ import annotations

import argparse
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


def check(
    transaction: dict[str, object], *, source_sha: str, claim_run_id: str,
    tag: str, repository: str, git_command: Callable[..., str] = git,
    release_absent: Callable[[str, str, str], None] = ensure_release_absent,
    registry_absent: Callable[[str, str, str, str], None] = ensure_registry_tag_absent,
    token: str, actor: str, images: tuple[str, str, str],
) -> bool:
    """Return whether this transaction has not started public promotion."""
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
    if (fresh and transaction.get("state") != "qualified") or (
        not fresh and transaction.get("state") not in ("promoting", "promoted")
    ):
        raise PrePromotionError("Qualified transaction has invalid promotion state")

    if git_command("rev-parse", "HEAD^{commit}") != source_sha:
        raise PrePromotionError("Publication checkout differs from claimed source")
    git_command("fetch", "--no-tags", "origin", "+refs/heads/main:refs/remotes/origin/main")
    if git_command("rev-parse", "refs/remotes/origin/main^{commit}") != source_sha:
        raise PrePromotionError("Protected main moved after release qualification")

    if fresh:
        if git_command("ls-remote", "--tags", "origin", f"refs/tags/{tag}", f"refs/tags/{tag}^{{}}"):
            raise PrePromotionError("Immutable release tag already exists")
        release_absent(repository, tag, token)
        for image in images:
            registry_absent(image, version, actor, token)
    return fresh


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--transaction", required=True, type=Path)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--claim-run-id", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--image", action="append", required=True)
    args = parser.parse_args()
    try:
        if len(args.image) != 3:
            raise PrePromotionError("Three release image coordinates are required")
        transaction = json.loads(args.transaction.read_text(encoding="utf-8"))
        if not isinstance(transaction, dict):
            raise PrePromotionError("Qualified transaction is invalid")
        check(
            transaction, source_sha=args.source_sha, claim_run_id=args.claim_run_id,
            tag=args.tag, repository=args.repository,
            token=os.environ.get("GH_TOKEN", ""), actor=os.environ.get("GITHUB_ACTOR", ""),
            images=tuple(args.image),
        )
    except (
        OSError, ValueError, RegistryTagAlreadyExists, ReleaseAlreadyExists,
        ReleaseLookupError,
    ) as error:
        raise SystemExit(f"Pre-promotion release guard refused: {error}") from error


if __name__ == "__main__":
    main()
