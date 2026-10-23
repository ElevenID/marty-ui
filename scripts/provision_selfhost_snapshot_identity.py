#!/usr/bin/env python3
"""Create and use a separate, snapshot-read-only self-host OpenBao AppRole."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
from urllib.error import HTTPError

sys.dont_write_bytecode = True
from selfhost_native_operator import approle_operation  # noqa: E402
from selfhost_operator_inputs import private_file  # noqa: E402
from selfhost_operator_inputs import snapshot_origin as snapshot_origin  # noqa: E402
from selfhost_openbao_client import Bao  # noqa: E402


AUTH_MOUNT = "selfhost-snapshot"
APPROLE = "raft-exporter"
POLICY = "selfhost-raft-snapshot-read"
ROLE_ID_FILE = "snapshot-role-id"
SECRET_ID_FILE = "snapshot-secret-id"
ACL = 'path "sys/storage/raft/snapshot" { capabilities = ["read"] }'




def bootstrap(bao: Bao, output: Path) -> None:
    approle_operation(bao, "bootstrap", "snapshot", output)


def checked_login(bao: Bao, identity: Path) -> str:
    return approle_operation(bao, "login", "snapshot", identity)["token"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bao-addr", required=True)
    parser.add_argument("--bao-ca", required=True, type=Path)
    parser.add_argument("--root-token-file", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        if (os.name != "posix"
                or not args.bao_ca.is_absolute() or args.bao_ca.is_symlink()
                or not args.bao_ca.is_file()):
            raise ValueError("snapshot OpenBao endpoint is invalid")
        snapshot_origin(args.bao_addr)
        root_token = private_file(args.root_token_file).strip()
        if len(root_token) < 20:
            raise ValueError("snapshot bootstrap root token is invalid")
        bootstrap(Bao(args.bao_addr, args.bao_ca, root_token), args.output)
    except (OSError, ValueError, RuntimeError, HTTPError) as error:
        print(f"self-host snapshot identity failed: {type(error).__name__}", file=sys.stderr)
        return 2
    print("Scoped self-host snapshot identity is ready")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
