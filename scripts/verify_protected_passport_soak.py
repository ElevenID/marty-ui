#!/usr/bin/env python3
"""Authenticate each protected sample before verifying the passport beta soak."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

if __package__:
    from .read_protected_passport_artifact import read_artifact
    from .verify_passport_beta_soak_window import (
        WindowError, _timestamp, require, validate_observation, verify_rows,
    )
else:
    from read_protected_passport_artifact import read_artifact
    from verify_passport_beta_soak_window import (
        WindowError, _timestamp, require, validate_observation, verify_rows,
    )


def verify_protected(
    run_ids: list[int], *,
    as_of: datetime,
    reader: Callable[[str, int], dict[str, Any]] = read_artifact,
) -> dict[str, Any]:
    require(len(run_ids) >= 3 and all(type(run) is int and run > 0 for run in run_ids)
            and len(set(run_ids)) == len(run_ids),
            "Protected passport soak run IDs are incomplete or repeated")
    rows = []
    for run_id in run_ids:
        artifact = reader("soak", run_id)
        require(isinstance(artifact, dict)
                and artifact.get("kind") == "soak"
                and artifact.get("run_id") == run_id
                and artifact.get("artifact_name") == f"passport-beta-soak-{run_id}",
                "Protected passport soak artifact identity changed")
        row = validate_observation(artifact.get("value"),
                                   artifact.get("artifact_sha256"))
        observed = row[2]
        started = _timestamp(artifact.get("run_started_at_utc"))
        completed = _timestamp(artifact.get("run_completed_at_utc"))
        require(started <= observed <= completed
                and artifact.get("workflow_commit")
                    == row[0]["protected_run"]["workflow_commit"],
                "Protected passport observation is outside its successful run")
        rows.append((*row, f"{artifact['artifact_name']}.json"))
    result = verify_rows(rows, as_of=as_of)
    result["status"] = "protected_window_verified"
    result["provenance_pending"] = False
    result["protected_runs_verified"] = True
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-ids", type=int, nargs="+", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = verify_protected(args.run_ids, as_of=datetime.now(timezone.utc))
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                               encoding="utf-8")
    except (WindowError, OSError, ValueError) as exc:
        raise SystemExit(f"Protected passport beta soak blocked: {exc}") from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
