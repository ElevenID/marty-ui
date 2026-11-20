#!/usr/bin/env python3
"""Select original releases from a reviewed protected-main push manifest.

This helper uses only the standard library and emits GitHub step outputs only
after validating the entire manifest, event identity, and checked-out source.
It does not fetch artifacts or change the original producer verification policy.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

MANIFEST_PATH = Path(".github/release-inputs/website-composition.json")
MAX_MANIFEST_BYTES = 4096
OUTPUT_FIELDS = ("website_repository", "website_run_id", "website_run_attempt",
                 "application_run_id", "application_run_attempt")
FIELDS = set(OUTPUT_FIELDS) | {"expected_parent_sha"}
RUN = re.compile(r"[1-9][0-9]{0,19}\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")
EVENT = {
    "GITHUB_EVENT_NAME": "push",
    "GITHUB_REPOSITORY": "ElevenID/marty-ui",
    "GITHUB_REPOSITORY_ID": "1140864197",
    "GITHUB_REF": "refs/heads/main",
    "GITHUB_REF_PROTECTED": "true",
    # The workflow supplies github.event.deleted explicitly; it is not a
    # built-in environment variable and omission must fail closed.
    "COMPOSITION_PUSH_DELETED": "false",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate manifest field")
        result[key] = value
    return result


def reject_constant(_value: str) -> None:
    raise ValueError("non-JSON manifest value")


def load_manifest(path: Path) -> tuple[dict, bytes]:
    # O_NOFOLLOW rejects a replaced final symlink. O_NONBLOCK ensures a FIFO
    # cannot hang validation before fstat rejects non-regular files.
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        require(stat.S_ISREG(metadata.st_mode), "manifest must be a regular file")
        require(0 < metadata.st_size <= MAX_MANIFEST_BYTES, "manifest size exceeds bounds")
        raw = stream.read(MAX_MANIFEST_BYTES + 1)
        require(0 < len(raw) <= MAX_MANIFEST_BYTES and len(raw) == metadata.st_size,
                "manifest size changed or exceeds bounds")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object, parse_constant=reject_constant)
    require(isinstance(value, dict) and set(value) == FIELDS, "manifest fields differ")
    require(value["website_repository"] == "ElevenID/website", "unexpected website repository")
    for field in OUTPUT_FIELDS[1:]:
        require(isinstance(value[field], str) and RUN.fullmatch(value[field]) is not None,
                "manifest invocation must be a canonical positive decimal of at most 20 digits")
    require(isinstance(value["expected_parent_sha"], str)
            and SHA.fullmatch(value["expected_parent_sha"]) is not None, "invalid expected parent SHA")
    return value, raw


def validate_environment(environment: dict[str, str]) -> str:
    require(all(environment.get(key) == value for key, value in EVENT.items()),
            "composition manifest requires a non-deleted push to the protected original main branch")
    source = environment.get("GITHUB_SHA", "")
    require(SHA.fullmatch(source) is not None, "invalid pushed source SHA")
    return source


def git(*arguments: str, timeout: int = 10) -> str:
    result = subprocess.run(["git", *arguments], capture_output=True, text=True, check=False, timeout=timeout)
    require(result.returncode == 0, "composition checkout identity could not be verified")
    return result.stdout.strip()


def manifest_path(path: Path) -> Path:
    root = Path(git("rev-parse", "--show-toplevel"))
    expected = root / MANIFEST_PATH
    require(Path(os.path.abspath(path)) == expected, "manifest must use its fixed checkout path")
    require(not expected.parent.is_symlink() and not expected.parent.parent.is_symlink(),
            "manifest parent directories must not be symlinks")
    return expected


def first_parent(source: str) -> str:
    # Reading the commit header also works at a shallow boundary, where
    # rev-parse HEAD^ cannot traverse to the recorded parent object.
    header = git("cat-file", "-p", source).split("\n\n", 1)[0]
    parents = [line.removeprefix("parent ") for line in header.splitlines() if line.startswith("parent ")]
    require(bool(parents) and SHA.fullmatch(parents[0]) is not None, "integration source lacks a valid first parent")
    return parents[0]


def validate_checkout(manifest: dict, source: str, raw: bytes, *, require_main_lineage: bool = True) -> None:
    require(git("rev-parse", "--verify", "HEAD^{commit}") == source, "checkout differs from pushed source")
    require(first_parent(source) == manifest["expected_parent_sha"],
            "composition manifest expected parent differs from the pushed commit's first parent")
    if require_main_lineage:
        git("merge-base", "--is-ancestor", source, "refs/remotes/origin/main")
    expected_blob = git("rev-parse", "--verify", f"{source}:{MANIFEST_PATH.as_posix()}")
    # Repository commit/object IDs use Git's SHA-1 format. Hash the already
    # bounded bytes rather than reading an unbounded blob or a later file view.
    actual_blob = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
    require(SHA.fullmatch(expected_blob) is not None and actual_blob == expected_blob,
            "manifest bytes differ from the reviewed source blob")


def require_integration_base(base: str) -> None:
    require(SHA.fullmatch(base) is not None, "invalid integration base SHA")
    present = subprocess.run(["git", "cat-file", "-e", f"{base}^{{commit}}"],
                             capture_output=True, text=True, check=False, timeout=10)
    if present.returncode != 0:
        # A merge queue batch may extend beyond checkout's two commits. Fetch
        # only the event's exact base for its tree; do not infer another base.
        git("fetch", "--no-tags", "--no-write-fetch-head", "--depth=1", "origin", base, timeout=60)
        git("cat-file", "-e", f"{base}^{{commit}}")


def check_integration(path: Path, environment: dict[str, str]) -> None:
    event = environment.get("GITHUB_EVENT_NAME", "")
    require(bool(event), "missing integration event")
    if event not in {"pull_request", "merge_group"}:
        return
    source = environment.get("GITHUB_SHA", "")
    require(SHA.fullmatch(source) is not None, "invalid integration source SHA")
    require(git("rev-parse", "--verify", "HEAD^{commit}") == source, "checkout differs from integration source")
    parent = first_parent(source)
    # PR event base.sha can lag behind the actual synthetic merge. A queue
    # batch needs its event base so an earlier manifest change is not missed.
    base = environment.get("COMPOSITION_INTEGRATION_BASE", "") if event == "merge_group" else parent
    require(base != source, "integration base cannot equal its source")
    require_integration_base(base)
    changed = git("diff", "--name-only", "--no-renames", "--no-ext-diff", "--no-textconv",
                  base, source, "--", MANIFEST_PATH.as_posix())
    if not changed:
        return
    value, raw = load_manifest(manifest_path(path))
    validate_checkout(value, source, raw, require_main_lineage=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    parser.add_argument("--check-integration", action="store_true",
                        help="validate a changed PR/merge-queue manifest without producing release selections")
    args = parser.parse_args()
    try:
        if args.check_integration:
            check_integration(args.manifest, os.environ)
            return 0
        source = validate_environment(os.environ)
        manifest, raw = load_manifest(manifest_path(args.manifest))
        validate_checkout(manifest, source, raw)
        outputs = "".join(f"{name}={manifest[name]}\n" for name in OUTPUT_FIELDS)
    except (ValueError, OSError, RecursionError, subprocess.SubprocessError):
        # Keep diagnostics bounded and never reflect arbitrary file contents,
        # environment values, or subprocess output into workflow commands.
        print("Composition manifest rejected: invalid manifest, event, or checkout identity.", file=sys.stderr)
        return 1
    sys.stdout.write(outputs)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
