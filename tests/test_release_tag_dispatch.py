"""Offline controls for the publisher's single independent-operator dispatch."""
from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import release_tag_handoff as handoff
from scripts import release_review_main, stable_publication_checkpoint

SOURCE = "a" * 40
MAIN = "b" * 40
TAG_OBJECT = "c" * 40
INTENT_OBJECT = "d" * 40


class OperatorDispatchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.start = datetime.now(timezone.utc).replace(microsecond=0)
        self.deadline = self.start + timedelta(seconds=900)
        self.request = {
            "tag": "v1.2.3", "tag_handoff_contract": handoff.TAG_HANDOFF_CONTRACT,
            "transaction_id": "synthetic-transaction", "claim_run_id": "456",
            "source_sha": SOURCE, "run_id": 123, "protected_main_commit": MAIN,
            "created_at": self.start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "not_after": self.deadline.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        self.request_sha = "sha256:" + "e" * 64
        self.artifact = {"id": 11, "digest": "sha256:" + "f" * 64}
        self.endpoint = "repos/ElevenID/marty-ui/actions/workflows/release-tag-handoff.yml/dispatches"
        self.details = {"workflow_run_id": 789,
                        "run_url": "https://api.github.com/repos/ElevenID/marty-ui/actions/runs/789",
                        "html_url": "https://github.com/ElevenID/marty-ui/actions/runs/789"}
        self.run = {"id": 789, "path": handoff.OPERATOR_WORKFLOW, "event": "workflow_dispatch",
                    "head_branch": "main", "head_sha": MAIN, "run_attempt": 1,
                    "repository": {"id": handoff.REPOSITORY_ID, "full_name": handoff.REPOSITORY},
                    "status": "queued", "conclusion": None, "created_at": self.request["created_at"]}
        self.main = {"name": "main", "protected": True, "commit": {"sha": MAIN}}

    def response(self, path: str, *, method: str = "GET", payload=None):
        if path == self.endpoint and method == "POST":
            self.assertEqual(payload, {"ref": "main", "inputs": {
                "mode": "create-qualified-tag", "promotion_run_id": "123", "claim_run_id": "456"}})
            return 200, handoff.encoded(self.details)
        self.assertEqual(method, "GET")
        if path == "repos/ElevenID/marty-ui/actions/runs/789":
            return 200, handoff.encoded(self.run)
        if path == "repos/ElevenID/marty-ui/branches/main":
            return 200, handoff.encoded(self.main)
        raise AssertionError("Unexpected GitHub operation: " + path)

    def dispatch(self, github: handoff.GitHub, path: Path) -> int:
        return handoff.dispatch_operator_once(github, self.request, self.request_sha, self.artifact, path)

    def test_single_post_uses_current_documented_api_and_authenticates_exact_run(self) -> None:
        github = handoff.GitHub(deadline=self.deadline)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "dispatch.json"

            def transport(arguments, **kwargs):
                method = arguments[arguments.index("--method") + 1]
                endpoint = arguments[arguments.index("--method") + 2]
                self.assertIn("X-GitHub-Api-Version: 2026-03-10", arguments)
                payload = json.loads(kwargs["input_bytes"]) if kwargs.get("input_bytes") else None
                if method == "POST":
                    before = json.loads(path.read_bytes())
                    self.assertEqual(before["outcome"], "unknown")
                    self.assertFalse(before["run_identity_verified"])
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                status, body = self.response(endpoint, method=method, payload=payload)
                return 0, b"HTTP/2.0 " + str(status).encode() + b" OK\r\n\r\n" + body

            with mock.patch.object(handoff, "command", side_effect=transport) as command:
                self.assertEqual(self.dispatch(github, path), 789)
            posts = [call for call in command.call_args_list if "POST" in call.args[0]]
            self.assertEqual(len(posts), 1)
            receipt = json.loads(path.read_bytes())
            self.assertEqual(receipt["operator_run_id"], 789)
            self.assertEqual(receipt["http_status"], 200)
            self.assertEqual(receipt["outcome"], "dispatch_confirmed")
            self.assertTrue(receipt["run_identity_verified"])
            self.assertEqual(receipt["not_after"], self.request["not_after"])
            self.assertNotIn("return_run_details", receipt["request"])

    def test_lost_response_and_permission_refusal_never_retry_even_in_new_process(self) -> None:
        for failure in (TimeoutError("synthetic lost response"), (403, b'{"message":"Forbidden"}'),
                        (204, b""), (500, b"{}")):
            with self.subTest(failure=type(failure).__name__), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "dispatch.json"
                github = handoff.GitHub(deadline=self.deadline)
                response = mock.Mock(side_effect=failure) if isinstance(failure, Exception) else mock.Mock(return_value=failure)
                with mock.patch.object(github, "response", response):
                    with self.assertRaises((TimeoutError, handoff.HandoffError)):
                        self.dispatch(github, path)
                self.assertEqual(response.call_count, 1)
                receipt = json.loads(path.read_bytes())
                self.assertFalse(receipt["run_identity_verified"])
                self.assertNotIn("operator_run_id", receipt)
                second = handoff.GitHub(deadline=self.deadline)
                with mock.patch.object(second, "response") as second_response:
                    with self.assertRaises(FileExistsError):
                        self.dispatch(second, path)
                second_response.assert_not_called()

    def test_malformed_acknowledgement_never_searches_for_or_adopts_another_run(self) -> None:
        invalid = [b"not-json", b"{}", b"null", b"[]", b'{"workflow_run_id":789,"workflow_run_id":790}',
                   handoff.encoded({**self.details, "workflow_run_id": True}),
                   handoff.encoded({**self.details, "workflow_run_id": 789.0}),
                   handoff.encoded({**self.details, "workflow_run_id": 0}),
                   handoff.encoded({**self.details, "run_url": "https://example.org/789"}),
                   handoff.encoded({**self.details, "html_url": self.details["html_url"] + "?other=1"})]
        for body in invalid:
            with self.subTest(body=body), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "dispatch.json"
                github = handoff.GitHub(deadline=self.deadline)
                with mock.patch.object(github, "response", return_value=(200, body)) as response:
                    with self.assertRaises(handoff.HandoffError):
                        self.dispatch(github, path)
                self.assertEqual(response.call_count, 1)
                self.assertFalse(json.loads(path.read_bytes())["run_identity_verified"])

    def test_returned_run_must_match_original_workflow_source_attempt_and_window(self) -> None:
        mutations = [{"id": 790}, {"path": handoff.CD_WORKFLOW}, {"event": "push"},
                     {"head_branch": "feature"}, {"head_sha": SOURCE}, {"run_attempt": 2},
                     {"run_attempt": True}, {"repository": {"id": 9, "full_name": handoff.REPOSITORY}},
                     {"status": "completed", "conclusion": "failure"},
                     {"created_at": (self.start - timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")},
                     {"created_at": (self.deadline + timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")}]
        original = copy.deepcopy(self.run)
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "dispatch.json"
                github = handoff.GitHub(deadline=self.deadline)
                self.run = {**original, **mutation}
                with mock.patch.object(github, "response", side_effect=self.response) as response:
                    with self.assertRaises(handoff.HandoffError):
                        self.dispatch(github, path)
                posts = [call for call in response.call_args_list if call.kwargs.get("method") == "POST"]
                self.assertEqual(len(posts), 1)
                receipt = json.loads(path.read_bytes())
                self.assertEqual(receipt["operator_run_id"], 789)
                self.assertFalse(receipt["run_identity_verified"])
        self.run = original

    def test_deadline_and_journal_failure_prevent_a_dispatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "dispatch.json"
            github = handoff.GitHub(deadline=self.deadline)
            with mock.patch.object(github, "response") as response:
                with self.assertRaises(handoff.HandoffError):
                    handoff.dispatch_operator_once(github, self.request, self.request_sha, self.artifact,
                                                   path, now=lambda: self.deadline)
                response.assert_not_called()
                self.assertFalse(path.exists())
                with mock.patch.object(handoff.os, "fsync", side_effect=OSError("synthetic disk failure")):
                    with self.assertRaises(OSError):
                        self.dispatch(github, path)
                response.assert_not_called()
                self.assertTrue(path.exists())

    def test_wait_step_api_lag_only_repeats_reads_within_original_deadline(self) -> None:
        github = handoff.GitHub(deadline=self.deadline)
        job = {"id": 99, "name": "publish-manifest", "run_id": 123, "run_attempt": 1,
               "head_sha": SOURCE, "status": "in_progress", "conclusion": None,
               "steps": [{"name": handoff.WAIT_STEP, "status": "queued", "conclusion": None}]}
        ready = copy.deepcopy(job)
        ready["steps"][0]["status"] = "in_progress"
        with mock.patch.object(github, "run", return_value={"status": "in_progress"}), \
             mock.patch.object(github, "main", return_value=self.main), \
             mock.patch.object(github, "pages", side_effect=[[job], [ready]]) as pages, \
             mock.patch.object(github, "response") as response:
            sleep = mock.Mock()
            handoff.wait_for_dispatch_step(github, self.request, sleep=sleep)
            sleep.assert_called_once_with(2.0)
            self.assertEqual(pages.call_count, 2)
            response.assert_not_called()
        with mock.patch.object(github, "response") as response, self.assertRaises(handoff.HandoffError):
            handoff.wait_for_dispatch_step(github, self.request, now=lambda: self.deadline)
        response.assert_not_called()

    def test_publisher_wait_accepts_only_the_run_it_dispatched_and_retains_admission_contract(self) -> None:
        for actual_operator in (789, 790):
            with self.subTest(actual_operator=actual_operator), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                checkpoint = root / "checkpoint"
                (checkpoint / "assets").mkdir(parents=True)
                (checkpoint / "request.json").write_bytes(handoff.encoded(self.request))
                (checkpoint / "assets/release-transaction.json").write_bytes(b"{}")
                (checkpoint / "official-interoperability.json").write_bytes(b"{}")
                request_sha = handoff.file_digest(checkpoint / "request.json")
                output = root / "admission.json"
                dispatch_receipt = root / "dispatch.json"
                tag = {"sha": TAG_OBJECT, "object": {"sha": SOURCE}, "message": handoff.tag_message(
                    self.request, request_sha, self.artifact, actual_operator, intent_object_sha=INTENT_OBJECT)}
                github = handoff.GitHub()

                def run(run_id, workflow, source):
                    if run_id == 123:
                        return {"status": "in_progress"}
                    self.assertEqual((run_id, workflow, source), (789, handoff.OPERATOR_WORKFLOW, MAIN))
                    return {"status": "completed", "conclusion": "success"}

                with ExitStack() as held:
                    held.enter_context(mock.patch.object(stable_publication_checkpoint, "load_checkpoint", return_value=self.request))
                    held.enter_context(mock.patch.object(release_review_main, "gate_authority", return_value={"review_required": False, "record_sha256": None}))
                    held.enter_context(mock.patch.object(release_review_main, "require_review_only_history"))
                    held.enter_context(mock.patch.object(handoff, "exact_context", return_value=(123, SOURCE)))
                    held.enter_context(mock.patch.object(handoff, "git"))
                    held.enter_context(mock.patch.object(github, "artifact", return_value=self.artifact))
                    held.enter_context(mock.patch.object(github, "main", return_value=self.main))
                    held.enter_context(mock.patch.object(github, "run", side_effect=run))
                    held.enter_context(mock.patch.object(handoff, "wait_for_dispatch_step"))
                    dispatch = held.enter_context(mock.patch.object(handoff, "dispatch_operator_once", return_value=789))
                    held.enter_context(mock.patch.object(handoff, "annotated_tag", side_effect=[None, None, tag, tag]))
                    held.enter_context(mock.patch.object(handoff, "owned_intent", return_value={"sha": INTENT_OBJECT}))
                    admitted = {"schema": handoff.TAG_ADMISSION_SCHEMA, "operator_run_id": 789}
                    result = held.enter_context(mock.patch.object(handoff, "successful_result", return_value=admitted))
                    if actual_operator == 789:
                        self.assertEqual(handoff.wait_for_operator(checkpoint, 11, self.artifact["digest"], output,
                                                                   dispatch_receipt=dispatch_receipt, github=github), admitted)
                        self.assertEqual(json.loads(output.read_bytes()), admitted)
                    else:
                        with self.assertRaisesRegex(handoff.HandoffError, "other than the exact dispatched"):
                            handoff.wait_for_operator(checkpoint, 11, self.artifact["digest"], output,
                                                      dispatch_receipt=dispatch_receipt, github=github)
                        result.assert_not_called()
                        self.assertFalse(output.exists())
                    dispatch.assert_called_once_with(github, self.request, request_sha, self.artifact,
                                                     dispatch_receipt, now=mock.ANY)


if __name__ == "__main__":
    unittest.main()
