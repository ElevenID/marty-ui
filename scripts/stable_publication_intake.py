#!/usr/bin/env python3
"""Read-only event/API admission before entering per-tag publication concurrency."""
from __future__ import annotations

import argparse
import os
from pathlib import Path

import release_tag_handoff as h
import stable_publication_candidate as c
from stable_publication import publisher_context


def intake(github: h.GitHub, event: dict, environment: dict[str, str], manual_run: str = "") -> dict:
    publisher_context(environment)
    h.require(type(event) is dict and type(event.get("repository")) is dict
              and event["repository"].get("id") == h.REPOSITORY_ID
              and event["repository"].get("full_name") == h.REPOSITORY,
              "publisher event repository differs")
    automatic = environment["GITHUB_EVENT_NAME"] == "workflow_run"
    if automatic:
        run = event.get("workflow_run")
        h.require(type(run) is dict and h.positive(run.get("id"))
                  and type(run.get("run_attempt")) is int and run["run_attempt"] == 1
                  and run.get("event") == "workflow_dispatch" and run.get("head_branch") == "main"
                  and isinstance(run.get("head_sha"), str) and h.SHA.fullmatch(run["head_sha"])
                  and run.get("status") == "completed" and run.get("conclusion") == "success",
                  "automatic publication requires an original successful manual main CD run")
        run_id = run["id"]
    else:
        h.require(isinstance(manual_run, str) and c.cp.RUN.fullmatch(manual_run)
                  and h.positive(int(manual_run)), "candidate run ID must be a positive decimal integer")
        run_id = int(manual_run)
    found = c.find_artifact(github, run_id, allow_absent=automatic)
    if found is None:
        return {"eligible": "false"}
    original, artifact = found
    h.require(not automatic or original["head_sha"] == event["workflow_run"]["head_sha"],
              "event source differs from authenticated original CD run")
    tag = artifact["name"][len(f"stable-publication-candidate-v2-{run_id}-1-"):]
    return {"eligible": "true", "candidate_run_id": str(run_id), "tag": tag}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-run-id", default="")
    args = parser.parse_args()
    try:
        event = h.decode(h.bounded_file(Path(os.environ["GITHUB_EVENT_PATH"])))
        result = intake(h.GitHub(), event, dict(os.environ), args.candidate_run_id)
        with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
            for key, value in result.items():
                output.write(f"{key}={value}\n")
        return 0
    except (ValueError, KeyError, TypeError, OSError) as error:
        print(f"Publication intake refused: {error}", file=__import__("sys").stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
