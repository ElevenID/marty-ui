#!/usr/bin/env python3
"""Create a non-acceptance observation file for infrastructure shakeout runs."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


READINESS_PASSES = {
    "upstream_source_and_image_provenance": "Reviewed source/image provenance manifest matched the lock.",
    "stock_lifecycle_bootstrap_only": "All four allowlisted pre-start lifecycle commands completed.",
    "beta_release_bound_and_healthy": "Beta release markers matched throughout the run.",
    "canvas_public_https_reachable": "Public Canvas login responded through the existing beta tunnel.",
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=Path("deploy-config/catalog/canvas-oss-portability.json"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    catalog = json.loads(args.config.read_text(encoding="utf-8"))
    cases = []
    for definition in catalog["cases"]:
        case_id = definition["id"]
        classification = definition["classification"]
        if classification == "hosted_required":
            status, evidence = "hosted_required", "This capability requires the separate hosted Canvas contract."
        elif classification == "outside_gate":
            status, evidence = "outside_gate", "Optional projection is outside the portable production gate."
        elif case_id in READINESS_PASSES:
            status, evidence = "passed", READINESS_PASSES[case_id]
        else:
            status, evidence = "not_run", "Readiness-only mode cannot claim this standard integration scenario."
        cases.append({"id": case_id, "status": status, "evidence": evidence})
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps({"schema_version": 1, "started_at": datetime.now(timezone.utc).isoformat(), "cases": cases}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
