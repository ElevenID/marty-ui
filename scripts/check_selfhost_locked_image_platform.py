#!/usr/bin/env python3
"""Probe exact locked self-host images for Linux/amd64, without qualifying runtime."""

import argparse
import json
import subprocess
from pathlib import Path

from build_selfhost_image_lock import EXACT_IMAGE


def probe(lock_path: Path) -> dict:
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    if not isinstance(lock, dict) or lock.get("schema") != "marty.selfhost-image-lock/v1":
        raise ValueError("unsupported self-host image lock")
    services = lock.get("services")
    if not isinstance(services, dict) or not services:
        raise ValueError("self-host image lock has no services")
    if any(not isinstance(name, str) or not name or not isinstance(ref, str)
           or EXACT_IMAGE.fullmatch(ref) is None for name, ref in services.items()):
        raise ValueError("self-host image lock requires exact service digests")

    platforms = {}
    for ref in sorted(set(services.values())):
        try:
            subprocess.run(["docker", "pull", "--platform", "linux/amd64", ref],
                           check=True, capture_output=True, text=True)
            inspected = subprocess.run(
                ["docker", "image", "inspect", ref, "--format", "{{json .}}"],
                check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as error:
            raise ValueError(f"cannot anonymously pull or inspect locked image {ref}") from error
        entries = json.loads(inspected.stdout)
        if (not isinstance(entries, dict) or entries.get("Os") != "linux"
                or entries.get("Architecture") != "amd64"):
            raise ValueError(f"locked image is not Linux/amd64: {ref}")
        digests = entries.get("RepoDigests")
        if not isinstance(digests, list) or ref not in digests:
            raise ValueError(f"inspected image is not associated with locked digest: {ref}")
        platforms[ref] = "linux/amd64"
    return {"schema": "marty.selfhost-image-platform-preflight/v1",
            "qualification": "unqualified", "platform": "linux/amd64",
            "services": dict(sorted(services.items())), "images": platforms}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-lock", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = probe(args.image_lock)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
