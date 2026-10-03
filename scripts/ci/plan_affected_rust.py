"""Report conservative Rust package impact without changing CI execution."""

from __future__ import annotations

import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
from collections import defaultdict, deque


ROOT = Path(__file__).resolve().parents[2]
RUST = ROOT / "rust"


def changed_paths(base: str, head: str) -> list[str]:
    # Both move endpoints matter, including a deleted package that metadata no
    # longer describes. NUL delimiters preserve whitespace and Unicode names.
    result = subprocess.run(
        ["git", "diff", "--name-only", "-z", "--no-renames", base, head, "--"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return [path.decode("utf-8") for path in result.stdout.split(b"\0") if path]


def cargo_metadata() -> dict:
    result = subprocess.run(
        [
            "cargo",
            "metadata",
            "--locked",
            "--offline",
            "--no-deps",
            "--format-version",
            "1",
            "--manifest-path",
            str(RUST / "Cargo.toml"),
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return json.loads(result.stdout)


def plan(paths: list[str], metadata: dict, root: Path = ROOT) -> dict:
    members = set(metadata["workspace_members"])
    packages = [package for package in metadata["packages"] if package["id"] in members]
    if not packages:
        raise ValueError("Cargo metadata contains no workspace packages")
    names = {package["name"] for package in packages}
    roots = {
        package["name"]: PurePosixPath(
            Path(package["manifest_path"]).parent.relative_to(root).as_posix()
        )
        for package in packages
    }

    def full(reason: str) -> dict:
        return {"all": True, "packages": sorted(names), "reason": reason}

    direct: set[str] = set()
    for raw in paths:
        path = PurePosixPath(raw.replace("\\", "/"))
        if path == PurePosixPath("rust/Cargo.toml") or path == PurePosixPath(
            "rust/Cargo.lock"
        ):
            return full(f"workspace manifest or lock: {path}")
        if not path.parts or path.parts[0] != "rust":
            # Protocol corpora, workflows, Dockerfiles, scripts, release inputs,
            # and undeclared consumers are not represented by Cargo metadata.
            return full(f"external or unknown input: {path}")
        owners = [
            (len(owner.parts), name)
            for name, owner in roots.items()
            if path.is_relative_to(owner)
        ]
        if not owners:
            # Includes third_party, toolchain, .cargo, deleted packages, and
            # workspace-level inputs. The current graph cannot prove isolation.
            return full(f"unowned Rust input: {path}")
        direct.add(max(owners)[1])

    reverse: dict[str, set[str]] = defaultdict(set)
    for package in packages:
        for dependency in package["dependencies"]:
            name = dependency["name"]  # Canonical name, even with a local alias.
            if name in names:
                reverse[name].add(package["name"])

    affected = set(direct)
    queue = deque(direct)
    while queue:
        for consumer in reverse[queue.popleft()]:
            if consumer not in affected:
                affected.add(consumer)
                queue.append(consumer)
    return {
        "all": False,
        "packages": sorted(affected),
        "direct": sorted(direct),
        "reason": "workspace package inputs and reverse Cargo consumers",
    }


def main() -> int:
    base = os.environ.get("BASE_SHA", "")
    head = os.environ.get("HEAD_SHA", "")
    if not base or not head:
        result = {"all": True, "packages": ["*"], "reason": "missing base or head SHA"}
    else:
        try:
            subprocess.run(
                ["git", "fetch", "--no-tags", "--depth=1", "origin", base],
                cwd=ROOT,
                check=True,
                capture_output=True,
            )
            result = plan(changed_paths(base, head), cargo_metadata())
        except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
            result = {
                "all": True,
                "packages": ["*"],
                "reason": f"unable to prove affected packages: {type(error).__name__}",
            }
    print("affected-rust-shadow: " + json.dumps(result, sort_keys=True))
    # This remains observational. Existing full Rust lanes are authoritative.
    return 0


if __name__ == "__main__":
    sys.exit(main())
