#!/usr/bin/env python3
"""Wait read-only for one admitted original CI/claim run; never adopt a rerun."""
from __future__ import annotations

import argparse
import time
from datetime import datetime, timedelta, timezone
from typing import Callable

if __package__:
    from . import release_tag_handoff as h
else:
    import release_tag_handoff as h

DEPENDENCIES = {
    "full-ci": (".github/workflows/prepare-stack-tag.yml", ".github/workflows/ci.yml"),
    "stable-claim": (".github/workflows/cd.yml", ".github/workflows/prepare-stack-tag.yml"),
}
ACTIVE = {"queued", "in_progress", "waiting", "pending", "requested"}
MAX_SECONDS = 330 * 60


def wait_for_original(github: h.GitHub, run_id: int, workflow: str, source: str, *,
                      deadline: datetime, now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
                      sleep: Callable[[float], None] = time.sleep) -> dict:
    h.require(h.positive(run_id) and workflow in {row[1] for row in DEPENDENCIES.values()}
              and isinstance(source, str) and h.SHA.fullmatch(source) is not None,
              "Original dependency identity is invalid")
    issued = now()
    h.require(deadline.tzinfo is not None and timedelta(0) < deadline - issued <= timedelta(seconds=MAX_SECONDS),
              "Original dependency deadline is invalid")
    github.deadline = deadline
    while True:
        h.require(now() < deadline, "Original dependency deadline expired")
        # GitHub.run verifies repository ID/name, exact workflow, main dispatch,
        # source SHA, run ID and first attempt on EVERY observation.
        run = github.run(run_id, workflow, source)
        created = h.timestamp(run["created_at"])
        h.require(issued - timedelta(seconds=MAX_SECONDS) <= created <= now(),
                  "Original dependency falls outside its admission window")
        if run.get("status") == "completed":
            h.require(run.get("conclusion") == "success", "Original dependency did not succeed")
            return run
        h.require(run.get("status") in ACTIVE and run.get("conclusion") is None,
                  "Original dependency state is unknown")
        sleep(min(15.0, max(0.0, (deadline - now()).total_seconds())))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dependency", choices=DEPENDENCIES)
    parser.add_argument("--run-id", type=int, required=True)
    args = parser.parse_args()
    try:
        owner, workflow = DEPENDENCIES[args.dependency]
        current_run, source = h.exact_context(owner)
        h.require(args.run_id != current_run, "A workflow cannot depend on itself")
        deadline = datetime.now(timezone.utc) + timedelta(seconds=MAX_SECONDS)
        wait_for_original(h.GitHub(deadline=deadline), args.run_id, workflow, source, deadline=deadline)
    except (OSError, ValueError, KeyError, TypeError):
        print("Original release dependency refused; no replacement or mutation was attempted.")
        return 1
    print("The exact original release dependency succeeded.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
