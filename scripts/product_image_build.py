#!/usr/bin/env python3
"""Resolve one source-owned product image recipe for both existing producers.

This helper does not admit releases, sign artifacts, or choose credentials. The
caller retains those responsibilities; the shared action only builds its exact
source-derived row and retains the caller's existing cache authority.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from pathlib import Path

from product_package_plan import build_plan as product_plan
from nightly_release import base_version, build_plan as nightly_plan
from release_tag_handoff import decode

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = {"product": "product-packages.yml", "nightly": "nightly-release.yml"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def recipe(root: Path, *, producer: str, source_sha: str, row: object,
           product: str = "", version: str = "", private_forks: bool = False) -> dict[str, str]:
    require(producer in WORKFLOWS, "unknown image producer")
    require(isinstance(source_sha, str) and re.fullmatch(r"[0-9a-f]{40}", source_sha) is not None,
            "invalid image source")
    require(type(row) is dict and isinstance(row.get("role"), str), "invalid image row")
    if producer == "product":
        require(not version, "product version must come from its source")
        plan = product_plan(root, product, source_sha)
        rows = plan["images"]
    else:
        require(not product, "nightly is not an independent product identity")
        require(isinstance(version, str) and re.fullmatch(
            r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)-nightly\.[0-9]{8}\.[1-9][0-9]*", version) is not None,
            "invalid admitted nightly version")
        lock = decode((root / "release/stack-lock.json").read_bytes())
        require(lock.get("schema") == "marty.stack-lock/v1" and lock.get("release_state") == "eligible"
                and lock.get("release") == "marty-ui@" + base_version("v" + version),
                "nightly source lock is not eligible for this version")
        rows = nightly_plan({"source_sha": source_sha, "version": version}, lock)
    expected = [item for item in rows if item["role"] == row["role"]]
    require(len(expected) == 1 and row == expected[0], "image row differs from authoritative source plan")
    row = expected[0]
    args = row["build_args"]
    build_args = "\n".join(f"{key}={value}" for key, value in args.items()) if isinstance(args, dict) else args
    require(isinstance(build_args, str) and "\r" not in build_args
            and all(re.fullmatch(r"[A-Z][A-Z0-9_]*=[^\r\n]*", line) for line in build_args.splitlines()),
            "invalid source build arguments")
    if producer == "product":
        scope = "product-" + product + "-" + row["role"]
        cache_from, cache_to = "type=gha,scope=" + scope, "type=gha,mode=max,scope=" + scope
        labels = "io.elevenid.product=" + product + "\nio.elevenid.qualification=unqualified"
        secrets = ""
    else:
        cache_from, cache_to, labels = "type=gha,scope=marty-ui-public-services", "", ""
        secrets = "sccache_token=SCCACHE_GHA_RUNTIME_TOKEN\nsccache_url=SCCACHE_GHA_CACHE_URL\nsccache_mode=SCCACHE_GHA_RW_MODE"
    if private_forks:
        require(row["role"] in {"services", "migrations"},
                "Private fork access is only needed by native image roles")
        cache_from = cache_to = ""
        secrets = "private_forks_read_token=PRIVATE_FORKS_READ_TOKEN"
        build_args += "\nPRIVATE_FORKS_ENABLED=true"
    return {"context": row.get("context", "."), "dockerfile": row["dockerfile"],
            "target": row["target"], "platform": row.get("platform", "linux/amd64"),
            "image": row["image"], "build-args": build_args, "labels": labels,
            "cache-from": cache_from, "cache-to": cache_to, "secret-envs": secrets}


def trusted_checkout(root: Path, producer: str, source_sha: str, env: dict[str, str]) -> None:
    require(producer in WORKFLOWS, "unknown producer context")
    expected = "ElevenID/marty-ui/.github/workflows/" + WORKFLOWS[producer] + "@refs/heads/main"
    require(env.get("GITHUB_REPOSITORY") == "ElevenID/marty-ui"
            and env.get("GITHUB_REF") == "refs/heads/main"
            and env.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and env.get("GITHUB_WORKFLOW_REF") == expected
            and env.get("GITHUB_SHA") == source_sha, "image producer context differs")
    require(subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip() == source_sha,
            "image checkout differs from admitted source")
    require(subprocess.run(["git", "diff", "--quiet", "HEAD", "--"], cwd=root, check=False).returncode == 0,
            "image source contains tracked modifications")
    if producer == "nightly" and env.get("PRIVATE_FORKS_ENABLED") != "true":
        require(env.get("SCCACHE_GHA_RW_MODE") == "READ_ONLY", "nightly compiler cache must be read-only")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--producer", choices=WORKFLOWS, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--product", default="")
    parser.add_argument("--version", default="")
    args = parser.parse_args()
    try:
        trusted_checkout(ROOT, args.producer, args.source_sha, dict(os.environ))
        result = recipe(ROOT, producer=args.producer, source_sha=args.source_sha,
                        product=args.product, version=args.version,
                        row=decode(os.environ["IMAGE_PLAN"].encode()),
                        private_forks=os.environ.get("PRIVATE_FORKS_ENABLED") == "true")
        # All output values are regenerated from source. Bound the multiline
        # protocol as well, even if a source-owned input later changes.
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
            for name, value in result.items():
                delimiter = "MARTY_IMAGE_RECIPE_" + name.replace("-", "_").upper()
                require(delimiter not in value.splitlines(), "output delimiter collision")
                output.write(f"{name}<<{delimiter}\n{value}\n{delimiter}\n")
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"image recipe rejected: {error}\n")


if __name__ == "__main__":
    main()
