#!/usr/bin/env python3
"""Retired beta SQL handoff; retained only for closed historical imports."""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import NoReturn


NUMBER = re.compile(r"[1-9][0-9]*\Z")
CONTAINER_ID = re.compile(r"[0-9a-f]{64}\Z")


class NativeMigrationError(RuntimeError):
    """A historical fenced-beta receipt or SQL handoff is invalid."""


def checked_receipt(path: Path, source_commit: str) -> dict[str, str]:
    """Validate a historical receipt while its read-only consumers are retired."""
    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise NativeMigrationError("Fence installation receipt is unreadable") from exc
    if (not isinstance(receipt, dict)
            or receipt.get("schema") != "marty.passport-beta-fence-installation/v1"
            or receipt.get("source_commit") != source_commit):
        raise NativeMigrationError("Fence receipt is not bound to protected source")
    fence = receipt.get("fence")
    if (not isinstance(fence, dict)
            or fence.get("schema") != "marty.passport-beta-fence-verification/v1"
            or fence.get("phase") != "fully_fenced"):
        raise NativeMigrationError("Fence receipt lacks a full fence")
    system_id = str(receipt.get("postgres_system_identifier", ""))
    database_oid = str(receipt.get("database_oid", ""))
    epoch = str(fence.get("epoch", ""))
    container_id = str(receipt.get("postgres_container_id", ""))
    if (not all(NUMBER.fullmatch(value) is not None
                for value in (system_id, database_oid, epoch))
            or CONTAINER_ID.fullmatch(container_id) is None):
        raise NativeMigrationError("Fence receipt has invalid PostgreSQL or container identity")
    return {"system_id": system_id, "database_oid": database_oid,
            "fence_epoch": epoch, "container_id": container_id}


def prepare(*_args: object, **_kwargs: object) -> NoReturn:
    raise NativeMigrationError(
        "historical passport beta SQL handoff is retired; use fresh Rust migrations"
    )


if __name__ == "__main__":
    raise SystemExit(
        "Historical passport beta SQL handoff is retired; use fresh Rust migrations"
    )
