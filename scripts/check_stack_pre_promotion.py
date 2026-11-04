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
    from .release_transaction import REQUIRED_IMAGE_ROLES
    from .release_review_main import gate_authority, require_review_only_history, strict_json
    from .check_release_absent import (
        RegistryTagAlreadyExists,
        ReleaseAlreadyExists,
        ReleaseLookupError,
        ensure_registry_tag_absent,
        ensure_release_absent,
    )
else:
    from release_transaction import REQUIRED_IMAGE_ROLES
    from release_review_main import gate_authority, require_review_only_history, strict_json
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


def protected_main_commit(repository: str) -> str:
    """Resolve authorization through the authenticated API, never a local ref."""
    try:
        result = subprocess.run(
            ["gh", "api", "--hostname", "github.com",
             f"repos/{repository}/branches/main"],
            check=True, capture_output=True, timeout=30,
        )
        if len(result.stdout) > 1024 * 1024:
            raise ValueError("oversized branch response")
        branch = strict_json(result.stdout)
        if not isinstance(branch, dict) or not isinstance(branch.get("commit"), dict):
            raise ValueError("invalid branch response")
        commit = branch["commit"].get("sha")
        if (branch.get("name") != "main" or branch.get("protected") is not True
                or not isinstance(commit, str)
                or re.fullmatch(r"[0-9a-f]{40}", commit) is None):
            raise ValueError("invalid protected main response")
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError):
        raise PrePromotionError("Could not authenticate protected main") from None
    return commit


def check(
    transaction: dict[str, object], *, source_sha: str, claim_run_id: str,
    tag: str, repository: str, git_command: Callable[..., str] = git,
    release_absent: Callable[[str, str, str], None] = ensure_release_absent,
    registry_absent: Callable[[str, str, str, str], None] = ensure_registry_tag_absent,
    digest_lookup: Callable[[str, str], str] = registry_digest,
    token: str, actor: str, images: tuple[str, ...],
    official_gate: bytes, run_id: int, current_attempt: int = 1,
    main_lookup: Callable[[str], str] = protected_main_commit,
    history_check: Callable[..., None] = require_review_only_history,
) -> dict[str, bool]:
    """Return existing exact image tags, including writes before a checkpoint."""
    roles = REQUIRED_IMAGE_ROLES
    if len(images) != len(roles):
        raise PrePromotionError("Every release image coordinate is required")
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
        and transaction.get("image_uris") == dict(zip(roles, images, strict=True))
    ):
        raise PrePromotionError("Qualified transaction differs from the exact claim")
    promoted = transaction.get("promoted_roles")
    if not isinstance(promoted, list) or any(
        not isinstance(role, str) or role not in roles
        for role in promoted
    ) or len(promoted) != len(set(promoted)):
        raise PrePromotionError("Qualified transaction has invalid promotion state")
    fresh = len(promoted) == 0
    if promoted != list(roles[:len(promoted)]):
        raise PrePromotionError("Qualified transaction has invalid promotion order")
    state = transaction.get("state")
    if (fresh and state != "qualified") or (
        0 < len(promoted) < len(roles) and state != "promoting"
    ) or (len(promoted) == len(roles) and state != "promoted"):
        raise PrePromotionError("Qualified transaction has invalid promotion state")
    image_records = transaction.get("images")
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
    try:
        authority = gate_authority(
            official_gate, transaction, run_id=run_id, current_attempt=current_attempt,
        )
    except (ValueError, KeyError, TypeError):
        raise PrePromotionError("Official gate differs from the qualified transaction") from None
    expected_main = authority["protected_main_commit"]
    if main_lookup(repository) != expected_main:
        raise PrePromotionError("Protected main changed after official qualification")
    git_command("fetch", "--no-tags", "origin", "+refs/heads/main:refs/remotes/origin/main")
    main_sha = git_command("rev-parse", "refs/remotes/origin/main^{commit}")
    if main_sha != expected_main:
        raise PrePromotionError("Fetched main differs from authenticated review authority")
    try:
        history_check(
            source_sha, main_sha, run_id, authority["origin_attempt"],
            authority["review_required"], record_sha256=authority["record_sha256"],
        )
    except (ValueError, OSError, subprocess.SubprocessError):
        raise PrePromotionError("Protected main is not the exact permitted review history") from None

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
    # Coordinate reads can take time. A later authorization commit is not an
    # invitation to refresh an already-qualified candidate's accepted main.
    if main_lookup(repository) != expected_main:
        raise PrePromotionError("Protected main changed during the pre-publication check")
    return existing


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--transaction", required=True, type=Path)
    parser.add_argument("--source-sha", default=os.environ.get("SOURCE_SHA", ""))
    parser.add_argument("--claim-run-id", default=os.environ.get("CLAIM_RUN_ID", ""))
    parser.add_argument("--tag", default=os.environ.get("TAG", ""))
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--official-gate", required=True, type=Path)
    parser.add_argument("--run-id", type=int, default=os.environ.get("GITHUB_RUN_ID", "0"))
    parser.add_argument("--current-attempt", type=int, default=os.environ.get("GITHUB_RUN_ATTEMPT", "0"))
    parser.add_argument("--image", action="append")
    parser.add_argument("--role", choices=REQUIRED_IMAGE_ROLES)
    args = parser.parse_args()
    try:
        images = args.image or [os.environ.get(name, "") for name in (
            "IMAGE", "SERVICES_IMAGE", "MIGRATIONS_IMAGE", "OPENBAO_DIDCOMM_IMAGE",
            "KEYCLOAK_IMAGE",
        )]
        if len(images) != len(REQUIRED_IMAGE_ROLES):
            raise PrePromotionError("Every release image coordinate is required")
        transaction = json.loads(args.transaction.read_text(encoding="utf-8"))
        if not isinstance(transaction, dict):
            raise PrePromotionError("Qualified transaction is invalid")
        if (args.official_gate.is_symlink() or not args.official_gate.is_file()
                or args.official_gate.stat().st_size > 8 * 1024 * 1024):
            raise PrePromotionError("Official gate must be a bounded regular file")
        official_gate = args.official_gate.read_bytes()
        if len(official_gate) > 8 * 1024 * 1024:
            raise PrePromotionError("Official gate exceeds its size bound")
        existing = check(
            transaction, source_sha=args.source_sha, claim_run_id=args.claim_run_id,
            tag=args.tag, repository=args.repository,
            token=os.environ.get("GH_TOKEN", ""), actor=os.environ.get("GITHUB_ACTOR", ""),
            images=tuple(images),
            official_gate=official_gate, run_id=args.run_id,
            current_attempt=args.current_attempt,
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
