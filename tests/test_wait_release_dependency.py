from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone

import pytest

from scripts import wait_release_dependency as module

SOURCE = "a" * 40
NOW = datetime(2026, 11, 12, tzinfo=timezone.utc)
WORKFLOW = module.DEPENDENCIES["full-ci"][1]


def run_record() -> dict:
    return {"id": 123, "path": WORKFLOW, "event": "workflow_dispatch", "head_branch": "main",
            "head_sha": SOURCE, "run_attempt": 1, "status": "completed", "conclusion": "success",
            "created_at": "2026-11-12T00:00:00Z",
            "repository": {"id": module.h.REPOSITORY_ID, "full_name": module.h.REPOSITORY}}


class GitHub(module.h.GitHub):
    def __init__(self, rows):
        super().__init__()
        self.rows = copy.deepcopy(rows)
        self.reads = []

    def json(self, path):
        self.reads.append(path)
        assert path == f"repos/{module.h.REPOSITORY}/actions/runs/123"
        return self.rows.pop(0)


def wait(github, sleep=lambda _: None):
    return module.wait_for_original(github, 123, WORKFLOW, SOURCE,
                                    deadline=NOW + timedelta(minutes=1), now=lambda: NOW, sleep=sleep)


def test_waits_only_for_the_definite_original_identity():
    pending = {**run_record(), "status": "in_progress", "conclusion": None}
    github = GitHub([pending, run_record()])
    delays = []
    assert wait(github, delays.append)["id"] == 123
    assert delays == [15.0] and len(github.reads) == 2
    assert github.mutations == []


@pytest.mark.parametrize("changes", [
    {"run_attempt": 2}, {"id": 124}, {"head_sha": "b" * 40}, {"head_branch": "other"},
    {"path": ".github/workflows/other.yml"}, {"event": "push"},
    {"repository": {"id": 1, "full_name": module.h.REPOSITORY}},
    {"status": "completed", "conclusion": "failure"}, {"status": "completed", "conclusion": "cancelled"},
    {"status": "queued", "conclusion": "success"}, {"status": "foreign", "conclusion": None},
    {"created_at": "2026-11-11T00:00:00Z"}, {"created_at": "2026-11-13T00:00:00Z"},
])
def test_refuses_identity_changes_failures_and_stale_dependencies(changes):
    github = GitHub([{**run_record(), **changes}, run_record()])
    with pytest.raises(module.h.HandoffError):
        wait(github)
    assert len(github.reads) == 1 and github.mutations == []


def test_stops_at_original_absolute_deadline_without_replacing_the_run():
    pending = {**run_record(), "status": "queued", "conclusion": None}
    github = GitHub([pending, run_record()])
    clock = [NOW]

    def sleep(seconds):
        clock[0] += timedelta(seconds=seconds)

    with pytest.raises(module.h.HandoffError, match="deadline expired"):
        module.wait_for_original(github, 123, WORKFLOW, SOURCE, deadline=NOW + timedelta(seconds=1),
                                 now=lambda: clock[0], sleep=sleep)
    assert len(github.reads) == 1 and github.mutations == []
