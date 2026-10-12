#!/usr/bin/env python3
"""Check the Rust-owned Issuance database after a clean native migration."""

from __future__ import annotations

import argparse
import re
import subprocess

try:
    from .qualify_selfhost_migrations import PRIVATE_KEY_SCHEMA_QUERY
except ImportError:
    from qualify_selfhost_migrations import PRIVATE_KEY_SCHEMA_QUERY


CONTAINER = re.compile(r"[0-9a-f]{64}\Z")
DATABASE = re.compile(r"[a-z][a-z0-9_]*\Z")


def inspect(container: str, database: str) -> None:
    if not CONTAINER.fullmatch(container) or not DATABASE.fullmatch(database):
        raise ValueError("invalid disposable PostgreSQL target")

    def query(sql: str) -> str:
        result = subprocess.run(
            ["docker", "exec", container, "psql", "-X", "-v", "ON_ERROR_STOP=1",
             "-U", "postgres", "-d", database, "-At", "-c", sql],
            capture_output=True, text=True, check=False, timeout=60,
        )
        if result.returncode != 0:
            raise RuntimeError(f"fresh Issuance schema query failed: {result.stderr.strip()}")
        return result.stdout.strip()

    if query("SELECT to_regclass('issuance_service.alembic_version') IS NOT NULL") != "f":
        raise RuntimeError("fresh Issuance schema contains historical Alembic state")
    private_storage = query(PRIVATE_KEY_SCHEMA_QUERY)
    if private_storage:
        raise RuntimeError(f"fresh KMS database contains private-key storage: {private_storage}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container", required=True)
    parser.add_argument("--database", required=True)
    args = parser.parse_args()
    inspect(args.container, args.database)


if __name__ == "__main__":
    main()
