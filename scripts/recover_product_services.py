#!/usr/bin/env python3
"""Recover selected product services without reconciling website-owned containers.

The Windows recovery wrapper passes its existing ordered Compose argument vector
after `--`. Profile selection stays with that invocation. The explicit nonempty
service list and --no-deps prevent a stale overlay from changing the edge or a
website slot while the independent website owner is deploying.
"""
from __future__ import annotations

import argparse
import re
import subprocess

WEBSITE_OWNERS = {"edge", "website-a", "website-b", "website-c"}
VALUE_FLAGS = {"--project-directory", "--project-name", "--env-file", "-f", "--file"}
SERVICE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*\Z")


def execute(command: list[str]) -> str:
    result = subprocess.run(command, capture_output=True, text=True, timeout=600, check=False)
    if result.returncode != 0 or len(result.stdout) > 1024 * 1024:
        raise ValueError("product recovery Compose command failed")
    return result.stdout


def recover(compose_args: list[str], *, runner=execute) -> list[str]:
    if not compose_args or len(compose_args) % 2 or not any(flag in {"-f", "--file"} for flag in compose_args[::2]):
        raise ValueError("explicit existing Compose files are required")
    for flag, value in zip(compose_args[::2], compose_args[1::2]):
        if flag not in VALUE_FLAGS or not value or value.startswith("-") or any(char in value for char in "\0\r\n"):
            raise ValueError("unexpected recovery Compose argument")
    command = ["docker", "compose", *compose_args]
    listed = runner([*command, "config", "--services"])
    if not isinstance(listed, str) or len(listed) > 65536:
        raise ValueError("invalid active service inventory")
    names = listed.splitlines()
    if not names or len(names) != len(set(names)) or not all(SERVICE.fullmatch(name) for name in names):
        raise ValueError("invalid or duplicate active service inventory")
    selected = sorted(name for name in names if name not in WEBSITE_OWNERS)
    if not selected:
        raise ValueError("no active product service remains after excluding website owners")
    runner([*command, "up", "-d", "--no-build", "--no-deps", "--wait", *selected])
    return selected


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("compose_args", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    values = args.compose_args[1:] if args.compose_args[:1] == ["--"] else args.compose_args
    selected = recover(values)
    print("Recovered product services: " + ", ".join(selected))


if __name__ == "__main__":
    main()
