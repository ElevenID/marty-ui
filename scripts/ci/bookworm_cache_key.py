#!/usr/bin/env python3
"""Key offline compiler objects by the exact container and compilation recipe."""
import hashlib
import os
from pathlib import Path
import platform
import re
import sys


def cache_key(root: Path, lane: str, arch: str) -> str:
    if lane not in {"canvas", "worker", "flow", "selfhost"} or arch not in {"x86_64", "aarch64"}:
        raise ValueError("unsupported offline compiler scope")
    builders = re.findall(r"^FROM (rust:1\.95-bookworm@sha256:[0-9a-f]{64}) AS rust-service-base$",
                          (root / "services/Dockerfile").read_text(), re.MULTILINE)
    if len(builders) != 1:
        raise ValueError("exact Bookworm compiler digest required")
    digest = hashlib.sha256()
    digest.update(f"sccache-0.16.0\0{builders[0]}\0{arch}\0".encode())
    paths = {"rust/Cargo.lock", ".github/workflows/ci.yml",
             "scripts/ci/bookworm_cache_key.py", "scripts/ci/bookworm-cache-env.sh",
             "scripts/ci/install-bookworm-sccache.sh"}
    paths.update(str(path.relative_to(root)) for path in (root / "rust").rglob("Cargo.toml")
                 if "target" not in path.relative_to(root / "rust").parts)
    paths.update(str(path.relative_to(root)) for path in (root / "rust/.cargo").glob("config*"))
    for name in sorted(paths):
        path = root / name
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"missing regular compiler input: {name}")
        digest.update(name.encode() + b"\0" + path.read_bytes() + b"\0")
    return f"bookworm-sccache-v1-{arch}-{digest.hexdigest()}"


if __name__ == "__main__":
    key = cache_key(Path.cwd(), os.environ["RUST_LANE"], platform.machine())
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as stream:
        stream.write(f"prefix={key}-\nkey={key}-{os.environ['GITHUB_RUN_ID']}-{os.environ['GITHUB_RUN_ATTEMPT']}\n")
    cache = Path(os.environ["RUNNER_TEMP"]) / "bookworm-sccache"
    (cache / "cache").mkdir(parents=True, exist_ok=True)
    with Path(os.environ["GITHUB_ENV"]).open("a") as stream:
        stream.write(f"BOOKWORM_CACHE_DIR={cache / 'cache'}\nBOOKWORM_SCCACHE_BIN={cache / 'sccache'}\n")
