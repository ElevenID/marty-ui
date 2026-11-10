"""Initial child visibility through the real GitHub HTTP transport, without network I/O."""
from __future__ import annotations

import copy
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import release_pipeline as pipeline

SOURCE = "a" * 40
BASE = "repos/ElevenID/marty-ui"
CHILD = BASE + "/actions/runs/200"
MISSING = (404, {"message": "Not Found"})


class Clock:
    def __init__(self) -> None:
        self.value = datetime(2025, 1, 1, tzinfo=timezone.utc)
        self.sleeps: list[float] = []
        self.frozen = False

    def now(self, *_args) -> datetime:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += timedelta(seconds=seconds)

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        if not self.frozen:
            self.advance(seconds)


class HttpFixture:
    """Only the gh subprocess boundary is synthetic; HTTP parsing stays real."""
    def __init__(self, case: unittest.TestCase, clock: Clock, journal: Path) -> None:
        self.case, self.clock, self.journal = case, clock, journal
        self.github = pipeline.transport.GitHub()
        self.calls: list[dict] = []
        self.child_responses: list[tuple | Exception] = []
        self.default_child = None
        self.main_sha = SOURCE
        self.main_responses: list[tuple | Exception] = []
        self.overrides: dict[str, tuple | Exception] = {}
        self.after_main = None
        self.after_child = None
        self.post_error = None
        self.run = {
            "id": 200, "path": ".github/workflows/ci.yml", "event": "workflow_dispatch",
            "head_branch": "main", "head_sha": SOURCE, "run_attempt": 1,
            "status": "completed", "conclusion": "success",
            "created_at": "2025-01-01T00:00:00Z",
            "repository": {"id": pipeline.transport.REPOSITORY_ID, "full_name": "ElevenID/marty-ui"},
            "display_title": "synthetic",
        }

    @property
    def posts(self) -> list[dict]:
        return [call for call in self.calls if call["method"] == "POST"]

    @property
    def child_reads(self) -> list[dict]:
        return [call for call in self.calls if call["method"] == "GET" and call["path"] == CHILD]

    def command(self, arguments, *, input_bytes=None, timeout, **_kwargs):
        index = arguments.index("--method")
        method, path = arguments[index + 1:index + 3]
        self.case.assertEqual(arguments[:5], ["gh", "api", "--hostname", "github.com", "--include"])
        self.case.assertIn("X-GitHub-Api-Version: 2026-03-10", arguments)
        call = {"method": method, "path": path, "timeout": timeout,
                "at": self.clock.now(), "deadline": self.github.deadline}
        self.calls.append(call)
        if method == "POST":
            self.case.assertEqual(path, BASE + "/actions/workflows/ci.yml/dispatches")
            self.case.assertEqual(json.loads(input_bytes),
                                  {"ref": "main", "inputs": {"canvas_migrated_base_pilot": False}})
            self.case.assertEqual(json.loads(self.journal.read_bytes())["steps"][0]["outcome"], "unknown")
            if self.post_error:
                raise self.post_error
            result = (200, {"workflow_run_id": 200,
                            "run_url": "https://api.github.com/" + CHILD,
                            "html_url": "https://github.com/ElevenID/marty-ui/actions/runs/200"})
        else:
            self.case.assertEqual(method, "GET")
            self.case.assertIsNone(input_bytes)
            if path in self.overrides:
                result = self.overrides[path]
            elif path == BASE + "/branches/main":
                result = self.main_responses.pop(0) if self.main_responses else (
                    200, {"name": "main", "protected": True, "commit": {"sha": self.main_sha}})
                if self.after_main:
                    self.after_main(call)
            elif path == CHILD:
                call["journal"] = json.loads(self.journal.read_bytes())
                result = self.child_responses.pop(0) if self.child_responses else (
                    self.default_child or (200, copy.deepcopy(self.run)))
                if self.after_child:
                    self.after_child(call)
            elif path == CHILD + "/attempts/1/jobs?per_page=100&page=1":
                result = (200, {"total_count": 1, "jobs": [{
                    "id": 1000, "name": "CI Gate", "run_id": 200, "run_attempt": 1,
                    "head_sha": SOURCE, "status": "completed", "conclusion": "success",
                }]})
            else:
                raise AssertionError("Unexpected synthetic endpoint: " + path)
        if isinstance(result, Exception):
            raise result
        status, value = result
        body = value if isinstance(value, bytes) else pipeline.transport.encoded(value)
        return (0 if status < 400 else 1), (
            f"HTTP/2 {status}\r\nContent-Type: application/json\r\n\r\n".encode() + body)


class InitialVisibilityTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.case_number = 0
        self.journal = self.root / "journal.json"
        self.clock = Clock()
        self.http = HttpFixture(self, self.clock, self.journal)
        command = mock.patch.object(pipeline.transport, "command",
                                    side_effect=lambda *args, **kwargs: self.http.command(*args, **kwargs))
        command.start()
        self.addCleanup(command.stop)
        dates = mock.patch.object(pipeline.transport, "datetime", wraps=datetime)
        dates.start().now.side_effect = lambda *args: self.clock.now(*args)
        self.addCleanup(dates.stop)
        self.synced: list[dict] = []
        actual_fsync = pipeline.os.fsync

        def fsync(fd):
            actual_fsync(fd)
            self.synced.append(json.loads(self.journal.read_bytes()))

        sync = mock.patch.object(pipeline.os, "fsync", side_effect=fsync)
        sync.start()
        self.addCleanup(sync.stop)
        self.fresh_case()
        self.addCleanup(lambda: None if self.driver.stream.closed else self.driver.stream.close())

    def fresh_case(self) -> None:
        """Separate synthetic invocations for each response vector."""
        if hasattr(self, "driver"):
            self.driver.stream.close()
        self.case_number += 1
        self.journal = self.root / f"journal-{self.case_number}.json"
        self.clock = Clock()
        self.http = HttpFixture(self, self.clock, self.journal)
        self.synced.clear()
        self.driver = pipeline.Pipeline(
            "qualify", 123, SOURCE, "2025-01-01T00:00:00Z", "v1.2.3",
            {"channel": "stable", "profile": "full", "production_web": False, "external_images": "{}"},
            self.journal, github=self.http.github, now=self.clock.now, sleep=self.clock.sleep)
        self.output = io.StringIO()

    def execute(self):
        with redirect_stdout(self.output):
            return self.driver.execute()

    def test_current_child_completes_with_one_post(self) -> None:
        self.assertEqual(self.execute(), {"ci_run_id": 200, "stable_tag": "v1.2.3"})
        self.assertEqual(len(self.http.posts), 1)
        self.assertEqual(len(self.http.child_reads), 1)
        self.assertEqual(self.clock.sleeps, [])
        self.assertEqual(json.loads(self.journal.read_bytes())["steps"][0]["outcome"], "success")

    def test_initial_404s_follow_only_the_durably_acknowledged_child(self) -> None:
        self.http.child_responses = [MISSING, MISSING]
        self.assertEqual(self.execute(), {"ci_run_id": 200, "stable_tag": "v1.2.3"})
        self.assertEqual(len(self.http.posts), 1)
        self.assertEqual(self.clock.sleeps, [5.0, 5.0])
        for call in self.http.child_reads:
            step = call["journal"]["steps"][0]
            self.assertEqual((step["outcome"], step["run_id"], step["run_attempt"]),
                             ("dispatch_confirmed", 200, 1))
        self.assertTrue(any(item["steps"] and item["steps"][0]["outcome"] == "dispatch_confirmed"
                            for item in self.synced))
        self.assertFalse(any("/runs?" in call["path"] for call in self.http.calls))

    def test_unknown_post_remains_consumed_without_a_child_read(self) -> None:
        self.http.post_error = TimeoutError("synthetic lost acknowledgement")
        with self.assertRaises(TimeoutError):
            self.execute()
        with self.assertRaisesRegex(ValueError, "already consumed"):
            self.execute()
        self.assertEqual(len(self.http.posts), 1)
        self.assertEqual(self.http.child_reads, [])
        self.assertEqual(self.clock.sleeps, [])
        self.assertEqual(json.loads(self.journal.read_bytes())["steps"][0]["outcome"], "unknown")

    def test_permanent_absence_has_one_fixed_minute_and_preserves_the_consumed_dispatch(self) -> None:
        self.http.default_child = MISSING
        started, prior_deadline = self.clock.now(), self.http.github.deadline
        with self.assertRaises(pipeline.PipelineError) as caught:
            self.execute()
        self.assertEqual(caught.exception.code, "child_visibility_unavailable")
        self.assertEqual((self.clock.now() - started).total_seconds(), 60)
        self.assertEqual(self.clock.sleeps, [5.0] * 12)
        self.assertEqual(len(self.http.child_reads), 12)
        self.assertEqual(self.http.github.deadline, prior_deadline)
        with self.assertRaisesRegex(ValueError, "already consumed"):
            self.execute()
        with self.assertRaises(FileExistsError):
            pipeline.Pipeline("qualify", 123, SOURCE, "2025-01-01T00:00:00Z", "v1.2.3",
                              self.driver.plan, self.journal, github=self.http.github, now=self.clock.now)
        with redirect_stdout(self.output):
            self.driver.stop(caught.exception)
        saved = json.loads(self.journal.read_bytes())
        self.assertEqual(saved["steps"][0]["run_id"], 200)
        self.assertEqual(saved["steps"][0]["outcome"], "dispatch_confirmed")
        self.assertEqual(saved["steps"][0]["initial_visibility"]["http_statuses"], [404] * 12)
        self.assertEqual(saved["failure"]["code"], "child_visibility_unavailable")
        self.assertEqual(saved["status"], "stopped")
        self.assertEqual(len(self.http.posts), 1)

    def test_frozen_clock_still_has_a_finite_observation_cap(self) -> None:
        self.clock.frozen = True
        self.http.default_child = MISSING
        with self.assertRaises(pipeline.PipelineError) as caught:
            self.execute()
        self.assertEqual(caught.exception.code, "child_visibility_unavailable")
        self.assertEqual(len(self.http.child_reads), 13)
        self.assertEqual(len(self.clock.sleeps), 12)
        self.assertEqual(len(self.http.posts), 1)

    def test_stage_and_preexisting_transport_deadlines_are_not_extended(self) -> None:
        for kind in ("stage", "transport"):
            with self.subTest(kind=kind):
                self.fresh_case()
                bound = self.clock.now() + timedelta(seconds=7)
                if kind == "stage":
                    self.driver.deadline = bound
                else:
                    self.http.github.deadline = bound
                previous = self.http.github.deadline
                self.http.default_child = MISSING
                with self.assertRaises(pipeline.PipelineError) as caught:
                    self.execute()
                self.assertEqual(caught.exception.code, "child_visibility_unavailable")
                self.assertEqual(self.clock.now(), bound)
                self.assertEqual(self.clock.sleeps, [5.0, 2.0])
                self.assertEqual(len(self.http.child_reads), 2)
                self.assertEqual(self.http.github.deadline, previous)
                post_index = self.http.calls.index(self.http.posts[0])
                for call in self.http.calls[post_index + 1:]:
                    self.assertEqual(call["deadline"], bound)
                    self.assertEqual(call["timeout"], (bound - call["at"]).total_seconds())
                self.assertEqual(len(self.http.posts), 1)

    def test_visibility_transport_deadline_covers_main_and_child_then_is_restored(self) -> None:
        self.http.child_responses = [MISSING]
        started, original = self.clock.now(), self.http.github.deadline
        self.execute()
        post_index = self.http.calls.index(self.http.posts[0])
        initial = self.http.calls[post_index + 1:post_index + 5]
        self.assertEqual([call["path"] for call in initial],
                         [BASE + "/branches/main", CHILD, BASE + "/branches/main", CHILD])
        for call in initial:
            self.assertEqual(call["deadline"], started + timedelta(seconds=60))
            self.assertEqual(call["timeout"], 60 - (call["at"] - started).total_seconds())
        self.assertEqual(self.http.github.deadline, original)
        self.assertEqual(self.http.calls[-1]["path"], CHILD + "/attempts/1/jobs?per_page=100&page=1")
        self.assertEqual(self.http.calls[-1]["deadline"], original)
        saved = json.loads(self.journal.read_bytes())["steps"][0]["initial_visibility"]
        self.assertEqual(saved, {"not_after": "2025-01-01T00:01:00Z",
                                 "status": "visible", "http_statuses": [404, 200]})

    def test_main_or_child_read_time_consumes_the_same_bound(self) -> None:
        for kind in ("main", "child"):
            with self.subTest(kind=kind):
                self.fresh_case()
                original = self.http.github.deadline

                def exhaust(_call):
                    if self.http.posts:
                        self.clock.advance(60)

                if kind == "main":
                    self.http.after_main = exhaust
                else:
                    self.http.after_child = exhaust
                with self.assertRaises(pipeline.PipelineError) as caught:
                    self.execute()
                self.assertEqual(caught.exception.code, "child_visibility_unavailable")
                self.assertEqual(len(self.http.child_reads), 0 if kind == "main" else 1)
                self.assertEqual(self.clock.sleeps, [])
                self.assertEqual(self.http.github.deadline, original)
                self.assertEqual(len(self.http.posts), 1)

    def test_slow_main_reads_leave_only_the_remaining_transport_budget(self) -> None:
        self.http.child_responses = [MISSING]

        def slow_main(_call):
            if self.http.posts and len(self.http.child_reads) < 2:
                self.clock.advance(4)

        self.http.after_main = slow_main
        self.execute()
        self.assertEqual([call["timeout"] for call in self.http.child_reads[:2]], [56, 47])
        self.assertEqual(self.clock.sleeps, [5.0])

    def test_main_change_during_absence_stops_before_another_child_read(self) -> None:
        self.http.default_child = MISSING
        sleep = self.clock.sleep

        def change_main(seconds):
            sleep(seconds)
            self.http.main_sha = "b" * 40

        self.driver.sleep = change_main
        with self.assertRaises(pipeline.PipelineError) as caught:
            self.execute()
        self.assertEqual(caught.exception.code, "source_changed")
        self.assertEqual(self.driver.observed_main_sha, "b" * 40)
        self.assertEqual(len(self.http.child_reads), 1)
        self.assertEqual(len(self.http.posts), 1)
        self.assertEqual(self.clock.sleeps, [5.0])

    def test_other_http_errors_and_timeouts_never_receive_an_allowance(self) -> None:
        for response in [(status, {"message": "private synthetic response"}) for status in
                         (401, 403, 429, 500, 502, 503)] + [TimeoutError("private synthetic timeout")]:
            with self.subTest(response=response):
                self.fresh_case()
                self.http.child_responses = [response]
                previous = self.http.github.deadline
                with self.assertRaises((pipeline.transport.HandoffError, TimeoutError)) as caught:
                    self.execute()
                self.assertEqual(len(self.http.child_reads), 1)
                self.assertEqual(len(self.http.posts), 1)
                self.assertEqual(self.clock.sleeps, [])
                self.assertEqual(self.http.github.deadline, previous)
                diagnostic = pipeline.stop_diagnostic(caught.exception, "qualify", self.driver.operation,
                                                      child_run_id=200)
                if isinstance(response, tuple):
                    self.assertEqual(diagnostic["http_status"], response[0])
                    self.assertEqual(diagnostic["message"], "GitHub read failed; no dispatch was retried")
                else:
                    self.assertEqual(diagnostic["code"], "io_timeout")
                self.assertNotIn("private synthetic", json.dumps(diagnostic))

    def test_only_bounded_well_formed_not_found_responses_can_wait(self) -> None:
        responses = (None, [], {}, {"message": "Forbidden"}, b"not json",
                     b'{"message":"Not Found","message":"Not Found"}',
                     b'{"message":"Not Found","extra":NaN}',
                     b"x" * (pipeline.transport.MAX_JSON + 1))
        for value in responses:
            with self.subTest(kind=type(value).__name__, size=len(value) if hasattr(value, "__len__") else 0):
                self.fresh_case()
                self.http.child_responses = [(404, value)]
                with self.assertRaises(pipeline.transport.HandoffError):
                    self.execute()
                self.assertEqual(len(self.http.child_reads), 1)
                self.assertEqual(self.clock.sleeps, [])
                self.assertEqual(len(self.http.posts), 1)

    def test_success_status_with_null_or_other_invalid_json_is_never_absence(self) -> None:
        for prefix in ([], [MISSING]):
            for value in (None, [], {}, b"not json", b'{"id":200,"id":200}'):
                with self.subTest(prefix=bool(prefix), value=value):
                    self.fresh_case()
                    self.http.child_responses = [*prefix, (200, value)]
                    with self.assertRaises(ValueError):
                        self.execute()
                    self.assertEqual(len(self.http.child_reads), len(prefix) + 1)
                    self.assertEqual(self.clock.sleeps, [5.0] * len(prefix))
                    self.assertEqual(len(self.http.posts), 1)

    def test_first_visible_run_must_pass_every_existing_identity_check(self) -> None:
        changes = ({"id": 201}, {"id": True}, {"path": ".github/workflows/cd.yml"},
                   {"event": "push"}, {"head_branch": "foreign"}, {"head_sha": "b" * 40},
                   {"run_attempt": 2}, {"run_attempt": True}, {"repository": None},
                   {"repository": []}, {"repository": {"id": 1, "full_name": "ElevenID/marty-ui"}},
                   {"repository": {"id": pipeline.transport.REPOSITORY_ID, "full_name": "other/repo"}},
                   {"created_at": "2024-12-31T23:59:59Z"}, {"created_at": "2025-01-02T00:00:00Z"},
                   {"created_at": "not a timestamp"})
        for change in changes:
            with self.subTest(change=change):
                self.fresh_case()
                value = copy.deepcopy(self.http.run)
                value.update(change)
                self.http.child_responses = [MISSING, (200, value)]
                with self.assertRaises(ValueError):
                    self.execute()
                self.assertEqual(len(self.http.child_reads), 2)
                self.assertEqual(self.clock.sleeps, [5.0])
                self.assertEqual(len(self.http.posts), 1)

    def test_first_visible_failure_or_invalid_state_cannot_be_replaced_by_a_later_success(self) -> None:
        changes = (({"conclusion": "failure"}, "child_workflow_failed", None),
                   ({"conclusion": "cancelled"}, "child_workflow_failed", None),
                   ({"status": "unrecognized"}, "child_state_unknown", None),
                   ({"status": "in_progress", "conclusion": "failure"}, "child_state_unknown", None),
                   ({"display_title": "wrong title"}, "child_title_mismatch", "synthetic"))
        for prefix in ([], [MISSING]):
            for change, code, title in changes:
                with self.subTest(prefix=bool(prefix), change=change):
                    self.fresh_case()
                    first = copy.deepcopy(self.http.run)
                    first.update(change)
                    self.http.child_responses = [*prefix, (200, first)]
                    # Any next GET would expose a valid successful run. The
                    # first visible response must itself receive every check.
                    with redirect_stdout(self.output), self.assertRaises(pipeline.PipelineError) as caught:
                        self.driver.dispatch("full-ci", {"canvas_migrated_base_pilot": False}, title=title)
                    self.assertEqual(caught.exception.code, code)
                    self.assertEqual(len(self.http.child_reads), len(prefix) + 1)
                    self.assertEqual(self.clock.sleeps, [5.0] * len(prefix))
                    self.assertEqual(len(self.http.posts), 1)

    def test_a_later_404_does_not_reopen_initial_visibility(self) -> None:
        active = copy.deepcopy(self.http.run)
        active.update(status="in_progress", conclusion=None)
        self.http.child_responses = [(200, active), MISSING]
        with self.assertRaisesRegex(pipeline.transport.HandoffError, "HTTP 404"):
            self.execute()
        self.assertEqual(len(self.http.child_reads), 2)
        self.assertEqual(self.clock.sleeps, [15.0])
        self.assertEqual(len(self.http.posts), 1)
        step = self.driver.record["steps"][0]
        self.assertEqual(step["initial_visibility"]["status"], "visible")
        with self.assertRaisesRegex(ValueError, "already consumed"):
            self.driver._wait_dispatched_visibility(step)
        self.assertEqual(len(self.http.child_reads), 2)

    def test_inherited_child_prior_stage_and_publisher_reads_remain_strict(self) -> None:
        for kind in ("direct", "prior-stage", "publisher"):
            with self.subTest(kind=kind):
                self.fresh_case()
                self.http.default_child = MISSING
                with self.assertRaisesRegex(pipeline.transport.HandoffError, "HTTP 404"):
                    if kind == "direct":
                        self.driver.wait(200, ".github/workflows/ci.yml", {"CI Gate"})
                    elif kind == "prior-stage":
                        self.driver.phase = "stable"
                        self.driver.execute(ci_run_id=200)
                    else:
                        self.driver.wait_publisher(200, 150)
                self.assertEqual(len(self.http.child_reads), 1)
                self.assertEqual(self.clock.sleeps, [])
                self.assertEqual(self.http.posts, [])
                self.assertEqual(self.driver.record["steps"], [])

    def test_main_and_job_reads_remain_strict(self) -> None:
        for kind in ("main", "jobs"):
            with self.subTest(kind=kind):
                self.fresh_case()
                if kind == "main":
                    self.http.main_responses = [(200, {"name": "main", "protected": True,
                                                       "commit": {"sha": SOURCE}}), MISSING]
                else:
                    self.http.overrides[CHILD + "/attempts/1/jobs?per_page=100&page=1"] = MISSING
                with self.assertRaisesRegex(pipeline.transport.HandoffError, "HTTP 404"):
                    self.execute()
                self.assertEqual(self.clock.sleeps, [])
                self.assertEqual(len(self.http.posts), 1)
                self.assertEqual(len(self.http.child_reads), 0 if kind == "main" else 1)

    def test_automatic_publisher_listing_and_observed_run_have_no_allowance(self) -> None:
        listing = BASE + "/actions/workflows/publish-stable-candidate.yml/runs"
        listing += f"?event=workflow_run&head_sha={SOURCE}&branch=main&per_page=100"
        for kind in ("listing", "observed-run"):
            with self.subTest(kind=kind):
                self.fresh_case()
                candidate = copy.deepcopy(self.http.run)
                candidate.update(id=150, path=".github/workflows/cd.yml")
                self.http.overrides[BASE + "/actions/runs/150"] = (200, candidate)
                self.http.overrides[BASE + "/actions/runs/150/attempts/1/jobs?per_page=100&page=1"] = (
                    200, {"total_count": 3, "jobs": [
                        {"id": 1000 + index, "name": name, "run_id": 150, "run_attempt": 1,
                         "head_sha": SOURCE, "status": "completed", "conclusion": "success"}
                        for index, name in enumerate(("official-gate-evidence", "qualify-release", "publish-manifest"))]})
                self.http.overrides[listing] = MISSING if kind == "listing" else (
                    200, {"total_count": 1, "workflow_runs": [
                        {"id": 200, "display_title": "Publish stable candidate 150"}]})
                self.http.default_child = MISSING
                with self.assertRaisesRegex(pipeline.transport.HandoffError, "HTTP 404"):
                    self.driver.stable_publisher(150)
                self.assertEqual(self.clock.sleeps, [])
                self.assertEqual(self.http.posts, [])
                self.assertEqual(len(self.http.child_reads), 0 if kind == "listing" else 1)
                if kind == "observed-run":
                    self.assertEqual(self.driver.record["steps"][0]["outcome"], "observed")
                    self.assertNotIn("initial_visibility", self.driver.record["steps"][0])

    def test_acknowledgment_must_be_fsynced_before_any_visibility_read(self) -> None:
        def refuse_ack(_fd):
            if self.driver.operation == "record_dispatch_acknowledgment":
                raise OSError("synthetic fsync failure")

        with mock.patch.object(pipeline.os, "fsync", side_effect=refuse_ack):
            with self.assertRaises(OSError):
                self.execute()
        self.assertEqual(len(self.http.posts), 1)
        self.assertEqual(self.http.child_reads, [])
        self.assertEqual(self.clock.sleeps, [])
        with self.assertRaisesRegex(ValueError, "already consumed"):
            self.execute()
        self.assertEqual(len(self.http.posts), 1)

    def test_failed_visibility_journal_write_restores_transport_and_cannot_dispatch_again(self) -> None:
        original = self.http.github.deadline
        persist = self.driver.persist

        def fail_visibility():
            if self.driver.operation == "record_child_visibility":
                raise OSError("synthetic visibility journal failure")
            persist()

        with mock.patch.object(self.driver, "persist", side_effect=fail_visibility):
            with self.assertRaises(OSError):
                self.execute()
        self.assertEqual(len(self.http.posts), 1)
        self.assertEqual(self.http.child_reads, [])
        self.assertEqual(self.http.github.deadline, original)
        with self.assertRaisesRegex(ValueError, "already consumed"):
            self.execute()
        self.assertEqual(len(self.http.posts), 1)

    def test_visibility_failure_keeps_a_bounded_diagnostic_when_finalization_fails(self) -> None:
        self.http.child_responses = [(404, {"message": "private-token\n::error::injected"})]
        with self.assertRaises(ValueError) as caught:
            self.execute()
        with redirect_stdout(self.output), mock.patch.object(
                self.driver, "finish", side_effect=OSError("private-token")):
            self.driver.stop(caught.exception)
        text = self.output.getvalue()
        self.assertNotIn("private-token", text)
        self.assertNotIn("Traceback", text)
        self.assertIn("Release pipeline journal incomplete", text)
        self.assertLess(len(text), 1500)
        self.assertEqual(len(self.http.posts), 1)
        saved = json.loads(self.journal.read_bytes())["steps"][0]
        self.assertEqual((saved["outcome"], saved["run_id"]), ("dispatch_confirmed", 200))


if __name__ == "__main__":
    unittest.main()
