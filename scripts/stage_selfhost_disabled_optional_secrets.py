#!/usr/bin/env python3
"""Stage only proven-disabled optional self-host Compose secret files."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

from run_selfhost_business_journey import (
    OPTIONAL_LOCAL_SECRET_NAMES, disabled_optional_secrets,
)


PROJECT = re.compile(r"marty-selfhost-qual-[0-9a-f]{16}\Z")


def render_model(install_root: Path, env_file: Path, project: str) -> dict:
    if (not install_root.is_absolute() or install_root.is_symlink()
            or not install_root.is_dir() or not env_file.is_absolute()
            or env_file.is_symlink() or not env_file.is_file()
            or env_file.stat().st_size > 65536 or not PROJECT.fullmatch(project)):
        raise ValueError("exact installed Compose inputs are invalid")
    compose = install_root / "docker-compose.yml"
    if compose.is_symlink() or not compose.is_file():
        raise ValueError("exact installed Compose file is missing")
    result = subprocess.run(
        ["docker", "compose", "--project-name", project, "--env-file", str(env_file),
         "-f", str(compose), "--profile", "*", "config", "--format", "json"],
        cwd=install_root, capture_output=True, text=True, timeout=45, check=False,
    )
    if result.returncode or len(result.stdout) > 4 * 1024 * 1024:
        raise RuntimeError("exact installed Compose render failed")
    model = json.loads(result.stdout)
    if not isinstance(model, dict) or model.get("name") != project:
        raise ValueError("rendered Compose project differs from requested install")
    return model


def stage(secret_root: Path, install_root: Path, env_file: Path, project: str) -> int:
    if os.name != "posix" or os.geteuid() == 0:
        raise ValueError("optional secret staging requires a non-root Linux operator")
    if (not secret_root.is_absolute() or secret_root.is_symlink()
            or not secret_root.is_dir() or secret_root.stat().st_uid != os.getuid()
            or stat.S_IMODE(secret_root.stat().st_mode) != 0o700):
        raise ValueError("optional secret root is not operator-owned and private")
    model = render_model(install_root, env_file, project)
    allowed = disabled_optional_secrets(model)
    if allowed != OPTIONAL_LOCAL_SECRET_NAMES or len(allowed) != 6:
        raise ValueError("not all optional integrations are proven disabled")
    if any((secret_root / name).exists() or (secret_root / name).is_symlink()
           for name in allowed):
        raise ValueError("optional secret staging would overwrite a file")
    created: list[Path] = []
    try:
        for name in sorted(allowed):
            path = secret_root / name
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                 os.O_NOFOLLOW, 0o600)
            created.append(path)
            with os.fdopen(descriptor, "wb") as stream:
                os.fchmod(stream.fileno(), 0o444)
        return len(created)
    except BaseException:
        for path in created:
            path.unlink(missing_ok=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--secret-root", required=True, type=Path)
    parser.add_argument("--install-root", required=True, type=Path)
    parser.add_argument("--env-file", required=True, type=Path)
    parser.add_argument("--project-name", required=True)
    args = parser.parse_args()
    try:
        count = stage(args.secret_root, args.install_root, args.env_file,
                      args.project_name)
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError,
            subprocess.SubprocessError) as error:
        print(f"optional secret staging failed: {type(error).__name__}", file=sys.stderr)
        return 2
    print(f"Staged {count} empty secrets for proven-disabled integrations")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
