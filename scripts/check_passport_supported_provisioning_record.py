#!/usr/bin/env python3
"""Read-only check of two protected artifacts and live disposable ownership."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path

if __package__:
    from .check_passport_supported_compose_ownership import OwnershipError
    from .passport_supported_provisioning_plan import PlanError, verify_record
else:
    from check_passport_supported_compose_ownership import OwnershipError
    from passport_supported_provisioning_plan import PlanError, verify_record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--record", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = verify_record(args.plan, args.record, datetime.now(timezone.utc))
    except (PlanError, OwnershipError, OSError, ValueError) as exc:
        report = {
            "schema": "marty.passport-supported-provisioning-record-check/v1",
            "status": "blocked", "blocker": str(exc),
        }
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    parser.exit(1, "Supported provisioning record remains blocked\n")


if __name__ == "__main__":
    raise SystemExit(main())
