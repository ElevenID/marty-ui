#!/usr/bin/env python3
"""Verify a future protected producer artifact before hosted attestation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

if __package__:
    from .passport_supported_provisioning_plan import PlanError, verify_handoff
else:
    from passport_supported_provisioning_plan import PlanError, verify_handoff


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--record", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--producer-run-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = verify_handoff(args.plan, args.record,
                                args.source_commit, args.producer_run_id)
    except (PlanError, OSError, ValueError) as exc:
        parser.exit(1, f"Protected resource handoff blocked: {exc}\n")
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
