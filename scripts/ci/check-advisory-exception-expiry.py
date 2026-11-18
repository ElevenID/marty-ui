"""Fail closed when the approved chrono maintenance exception expires."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re
import sys
import tomllib

ADVISORY = "RUSTSEC-2026-0543"
EXPIRY = datetime(2026, 12, 1, tzinfo=timezone.utc)
CONFIGURATION = Path(__file__).resolve().parents[2] / "deny.toml"


def check(configuration: Path, now: datetime) -> None:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("An aware UTC comparison is required")
    with configuration.open("rb") as stream:
        data = tomllib.load(stream)
    advisories = data.get("advisories")
    if not isinstance(advisories, dict):
        raise ValueError("Missing advisory configuration")
    ignored = advisories.get("ignore")
    if not isinstance(ignored, list):
        raise ValueError("Advisory ignores must be a list")
    ids = set()
    for row in ignored:
        identifier = row.get("id") if isinstance(row, dict) else row
        if not isinstance(identifier, str) or not re.fullmatch(
            r"RUSTSEC-\d{4}-\d{4}", identifier
        ):
            raise ValueError("Invalid advisory ignore ID")
        if identifier in ids:
            raise ValueError("Duplicate advisory ignore ID")
        ids.add(identifier)
    if ADVISORY in ids and now.astimezone(timezone.utc) >= EXPIRY:
        raise ValueError(
            "The chrono maintenance exception expired at 2026-12-01 00:00 UTC"
        )


def main() -> int:
    if len(sys.argv) != 1:
        print("Advisory expiry checker accepts no arguments", file=sys.stderr)
        return 1
    try:
        check(CONFIGURATION, datetime.now(timezone.utc))
    except (OSError, ValueError) as error:
        print(f"Advisory exception policy refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
