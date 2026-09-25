#!/usr/bin/env python3
"""Require the reviewed Credentials schema release for native retention routes.

The issuance_event_owner migration is introduced at this exact source commit:
services/issuance/infrastructure/migrations/versions/
20260924_0100_add_issuance_event_owner.py. The shared DIDComm gate verifies the
same release's immutable image, digest, SBOM, and provenance binding.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.check_didcomm_native_credentials_release import (
    NativeDidcommReleaseError,
    validate_release_gate,
)


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_VERSION = "0.1.78"
REQUIRED_COMMIT = "efd5da1e2d41419ce93721f98d314c7b911e6b5e"
REQUIRED_REVISION = "issuance_event_owner"


def validate_retention_release(contract: dict, lock: dict) -> None:
    """Reject an image predating the tenant-owned issuance-events column."""
    validate_release_gate(contract, lock)
    release = contract["release_gate"]["qualified_release"]
    version = tuple(int(part) for part in release["version"].split("."))
    minimum = tuple(int(part) for part in REQUIRED_VERSION.split("."))
    if version < minimum or release["commit"] != REQUIRED_COMMIT:
        raise NativeDidcommReleaseError(
            f"Native retention requires Credentials {REQUIRED_VERSION} at "
            f"{REQUIRED_COMMIT} with migration {REQUIRED_REVISION}"
        )


def main() -> int:
    contract = json.loads(
        (ROOT / "contracts/didcomm-native-consumer-ownership.json").read_text(
            encoding="utf-8"
        )
    )
    lock = json.loads((ROOT / "release/stack-lock.json").read_text(encoding="utf-8"))
    try:
        validate_retention_release(contract, lock)
    except NativeDidcommReleaseError as exc:
        print(f"Native issuance retention release gate failed: {exc}")
        return 1
    print("Native issuance retention release gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
