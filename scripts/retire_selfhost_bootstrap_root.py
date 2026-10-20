#!/usr/bin/env python3
"""Retire a fresh self-host bootstrap root after the full KMS lineage audit.

The audit runs before and after revocation. An interrupted run can be repeated:
the revoked root remains denied, while the scoped identities still prove the
installation healthy. This command never handles the separately held unseal key.
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import zipfile
from pathlib import Path
from urllib.error import HTTPError

from check_selfhost_root_retirement import audit, build_parser
from selfhost_openbao_client import Bao


def root_token(path: Path, state_dir: Path) -> tuple[str, tuple[int, int]]:
    if (os.name != "posix" or not state_dir.is_absolute()
            or state_dir.resolve(strict=True) != state_dir
            or path != state_dir / "root.token" or path.is_symlink()):
        raise ValueError("bootstrap root path is outside owned OpenBao state")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) not in (0o400, 0o600)
                or not 20 <= metadata.st_size <= 4096):
            raise ValueError("bootstrap root file ownership or mode is invalid")
        value = os.read(descriptor, 4097).decode("ascii").strip()
        if not 20 <= len(value) <= 4096 or any(char.isspace() for char in value):
            raise ValueError("bootstrap root file content is invalid")
        return value, (metadata.st_dev, metadata.st_ino)
    finally:
        os.close(descriptor)


def denied(bao: Bao) -> bool:
    try:
        bao.request("GET", "auth/token/lookup-self")
    except HTTPError as error:
        if error.code == 403:
            return True
        raise
    return False


def retire(args) -> tuple[Path, Path]:
    before = audit(args)
    token_file = args.openbao_state_dir / "root.token"
    token, identity = root_token(token_file, args.openbao_state_dir)
    bao = Bao(args.bao_addr, args.bao_ca, token)
    if not denied(bao):
        lookup = bao.request("GET", "auth/token/lookup-self").get("data", {})
        if not isinstance(lookup, dict) or lookup.get("policies") != ["root"]:
            raise ValueError("bootstrap credential is not the initial root")
        bao.request("POST", "auth/token/revoke", {"token": token})
        if not denied(bao):
            raise RuntimeError("bootstrap root remains valid after revocation")
    after = audit(args)
    current = token_file.stat(follow_symlinks=False)
    if (not stat.S_ISREG(current.st_mode)
            or (current.st_dev, current.st_ino) != identity):
        raise RuntimeError("bootstrap root file changed during retirement")
    token_file.unlink()
    return before, after


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        before, after = retire(args)
    except (OSError, ValueError, RuntimeError, HTTPError, subprocess.SubprocessError,
            zipfile.BadZipFile) as error:
        print(f"self-host bootstrap root retirement failed: {type(error).__name__}",
              file=sys.stderr)
        return 2
    print(f"Bootstrap root retired; scoped snapshots: {before}, {after}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
