"""Bounded local transport/receipt tests; no network or release payload execution."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
import sys
import tempfile
import time
import unittest
import warnings
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import release_tag_handoff as handoff

SOURCE = "a" * 40
MAIN = "b" * 40
TAG_OBJECT = "c" * 40


class BoundedTransportTests(unittest.TestCase):
    def test_json_duplicate_keys_and_nonfinite_numbers_are_rejected(self) -> None:
        for value in (b'{"a":1,"a":2}', b'{"value":NaN}', b'{"value":Infinity}'):
            with self.subTest(value=value), self.assertRaises(handoff.HandoffError):
                handoff.decode(value)

    def test_real_http_status_is_required_for_absence(self) -> None:
        self.assertEqual(handoff.parse_http(b'HTTP/2.0 404 Not Found\r\nX-Test: x\r\n\r\n{"message":"Not Found"}')[0], 404)
        with self.assertRaises(handoff.HandoffError):
            handoff.parse_http(b'{"message":"Not Found"}')
        github = handoff.GitHub()
        with mock.patch.object(github, "response", return_value=(404, b'{"message":"Not Found"}')):
            self.assertIsNone(github.json("repos/ElevenID/marty-ui/example", absent=True))
        for status in (401, 403, 429, 500):
            with self.subTest(status=status), mock.patch.object(github, "response", return_value=(status, b'{}')):
                with self.assertRaises(handoff.HandoffError):
                    github.json("repos/ElevenID/marty-ui/example", absent=True)

    def test_commands_stop_at_stdout_bound_and_do_not_return_stderr(self) -> None:
        with self.assertRaises(handoff.HandoffError):
            handoff.command([sys.executable, "-c", "print('x'*100000)"], maximum=64)
        code, output = handoff.command([sys.executable, "-c", "import sys;sys.stderr.write('synthetic-secret');print('ok')"])
        self.assertEqual((code, output), (0, b"ok\n"))

    def test_timeout_kills_the_entire_local_synthetic_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "child-ran"
            child = "import pathlib,time;time.sleep(0.7);pathlib.Path(" + repr(str(marker)) + ").write_text('bad')"
            parent = "import subprocess,sys,time;subprocess.Popen([sys.executable,'-c'," + repr(child) + "]);time.sleep(4)"
            with self.assertRaises(handoff.HandoffError):
                handoff.command([sys.executable, "-c", parent], timeout=0.15)
            time.sleep(0.8)
            self.assertFalse(marker.exists())

    def test_deadline_caps_the_timeout_and_expiry_refuses(self) -> None:
        deadline = datetime.now(timezone.utc) + timedelta(seconds=2)
        self.assertGreater(handoff.remaining(deadline), 0)
        self.assertLessEqual(handoff.remaining(deadline), 2)
        with self.assertRaises(handoff.HandoffError):
            handoff.remaining(datetime.now(timezone.utc) - timedelta(seconds=1))

    def test_complete_unique_id_pagination_is_required(self) -> None:
        github = handoff.GitHub()
        page1 = {"total_count": 101, "artifacts": [{"id": n} for n in range(1, 101)]}
        page2 = {"total_count": 101, "artifacts": [{"id": 101}]}
        with mock.patch.object(github, "json", side_effect=[page1, page2]):
            self.assertEqual(len(github.pages("repos/ElevenID/marty-ui/list", "artifacts")), 101)
        for bad in ({"total_count": 101, "artifacts": [{"id": 1}]},
                    {"total_count": 102, "artifacts": [{"id": 101}]},
                    {"total_count": 101, "artifacts": []}):
            with self.subTest(bad=bad), mock.patch.object(github, "json", side_effect=[page1, bad]):
                with self.assertRaises(handoff.HandoffError):
                    github.pages("repos/ElevenID/marty-ui/list", "artifacts")

    def test_unknown_mutation_outcome_is_journaled_without_retry(self) -> None:
        github = handoff.GitHub()
        with mock.patch.object(handoff, "command", side_effect=handoff.HandoffError("timeout")) as invoke:
            with self.assertRaises(handoff.HandoffError):
                github.response("graphql", method="POST", payload={"public": "request"})
        self.assertEqual(invoke.call_count, 1)
        self.assertEqual(github.mutations[0]["outcome"], "unknown")
        self.assertNotIn("Authorization", json.dumps(github.mutations))

    def test_authenticated_run_and_artifact_attempts_reject_boolean_one(self) -> None:
        github = handoff.GitHub()
        run = {"id": 1, "path": handoff.CD_WORKFLOW, "event": "workflow_dispatch", "head_branch": "main",
               "head_sha": SOURCE, "run_attempt": 1,
               "repository": {"id": handoff.REPOSITORY_ID, "full_name": handoff.REPOSITORY}}
        for key in ("id", "run_attempt"):
            with self.subTest(key=key), mock.patch.object(github, "json", return_value={**run, key: True}):
                with self.assertRaises(handoff.HandoffError):
                    github.run(1, handoff.CD_WORKFLOW, SOURCE)
        artifact = {"id": 2, "name": "synthetic", "expired": False, "size_in_bytes": 20,
                    "digest": "sha256:" + "d" * 64,
                    "workflow_run": {"id": 1, "head_sha": SOURCE, "head_branch": "main", "run_attempt": 1}}
        for key in ("id", "run_attempt"):
            changed = copy.deepcopy(artifact)
            changed["workflow_run"][key] = True
            with self.subTest(artifact_key=key), mock.patch.object(github, "artifacts", return_value=[changed]):
                with self.assertRaises(handoff.HandoffError):
                    github.artifact(1, "synthetic", SOURCE)


class ArtifactAdmissionTests(unittest.TestCase):
    def test_exact_zip_members_are_written_private_and_nonexecutable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "ok.zip"
            with zipfile.ZipFile(archive, "w") as output:
                info = zipfile.ZipInfo("assets/payload")
                info.external_attr = (stat.S_IFREG | 0o755) << 16
                output.writestr(info, b"public synthetic data")
            handoff.extract_archive(archive, root / "held", {"assets/payload"}, limits={"assets/payload": 64})
            path = root / "held/assets/payload"
            self.assertEqual(path.read_bytes(), b"public synthetic data")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)

    def test_missing_duplicate_extra_link_and_oversized_members_refuse(self) -> None:
        for kind in ("missing", "duplicate", "extra", "link", "large"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                archive = root / "bad.zip"
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    with zipfile.ZipFile(archive, "w") as output:
                        if kind != "missing":
                            info = zipfile.ZipInfo("record")
                            if kind == "link":
                                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                            output.writestr(info, b"x" * (100 if kind == "large" else 1))
                        if kind in {"duplicate", "extra"}:
                            output.writestr("record" if kind == "duplicate" else "../foreign", b"x")
                with self.assertRaises(handoff.HandoffError):
                    handoff.extract_archive(archive, root / "held", {"record"}, limits={"record": 10})
                self.assertFalse((root / "held").exists())

    def test_artifact_download_checks_exact_api_zip_digest(self) -> None:
        github = handoff.GitHub()
        raw = b"synthetic ZIP bytes"
        artifact = {"id": 77, "size_in_bytes": len(raw), "digest": handoff.sha256(raw)}
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "archive.zip"

            def download(arguments, **kwargs):
                kwargs["destination"].write_bytes(raw)
                return 0, b""

            with mock.patch.object(handoff, "command", side_effect=download):
                github.download(artifact, path)
            self.assertEqual(path.read_bytes(), raw)
            path.unlink()
            with mock.patch.object(handoff, "command", side_effect=download), self.assertRaises(handoff.HandoffError):
                github.download({**artifact, "digest": "sha256:" + "0" * 64}, path)


class OperatorReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        start = datetime.now(timezone.utc).replace(microsecond=0)
        self.request = {"tag": "v1.2.3", "transaction_id": "synthetic-transaction", "claim_run_id": "456",
                        "source_sha": SOURCE, "run_id": 123, "protected_main_commit": MAIN,
                        "created_at": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "not_after": (start + timedelta(seconds=900)).strftime("%Y-%m-%dT%H:%M:%SZ")}
        self.request_sha = "sha256:" + "d" * 64
        self.checkpoint = {"id": 11, "digest": "sha256:" + "e" * 64}
        self.tag = {"sha": TAG_OBJECT}

    def result(self) -> dict:
        return {"schema": "marty.release-tag-handoff-result/v1", "status": "success", "mode": "create-qualified-tag",
                "repository": handoff.REPOSITORY, "operator_run_id": 789, "operator_run_attempt": 1,
                "operator_source_sha": MAIN, "source_sha": SOURCE, "candidate_run_id": 123,
                "candidate_run_attempt": 1, "claim_run_id": "456", "tag": "v1.2.3", "protected_main_commit": MAIN,
                "request_sha256": self.request_sha, "checkpoint_artifact_id": 11,
                "checkpoint_artifact_sha256": self.checkpoint["digest"], "tag_object_sha": TAG_OBJECT,
                "tag_commit_sha": SOURCE, "completed_at": self.request["created_at"], "crypto_verified": True,
                "main_before_sha": MAIN, "main_after_sha": MAIN}

    def test_tag_without_successful_operator_completion_is_insufficient(self) -> None:
        github = handoff.GitHub()
        run = {"status": "in_progress", "created_at": self.request["created_at"]}
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(github, "run", return_value=run), mock.patch.object(github, "artifact") as artifact:
            self.assertIsNone(handoff.successful_result(github, 789, self.request, self.request_sha,
                                                       self.checkpoint, self.tag, Path(temporary)))
            artifact.assert_not_called()
        run.update(status="completed", conclusion="failure")
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(github, "run", return_value=run):
            with self.assertRaises(handoff.HandoffError):
                handoff.successful_result(github, 789, self.request, self.request_sha,
                                          self.checkpoint, self.tag, Path(temporary))

    def test_exact_api_digested_bound_result_is_required(self) -> None:
        for mutation in (None, "source_sha", "candidate_run_attempt", "crypto_verified", "checkpoint_artifact_sha256", "extra",
                         "boolean:operator_run_id", "boolean:operator_run_attempt", "boolean:candidate_run_id",
                         "boolean:candidate_run_attempt", "boolean:checkpoint_artifact_id"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                value = self.result()
                if mutation == "extra":
                    value["extra"] = "not admitted"
                elif mutation is not None and mutation.startswith("boolean:"):
                    value[mutation.split(":", 1)[1]] = True
                elif mutation is not None:
                    value[mutation] = False if mutation == "crypto_verified" else "foreign"
                original = root / "original.zip"
                with zipfile.ZipFile(original, "w") as output:
                    output.writestr("tag-handoff-result.json", handoff.encoded(value))
                artifact = {"id": 99, "size_in_bytes": original.stat().st_size,
                            "digest": handoff.file_digest(original)}
                github = handoff.GitHub()
                run = {"status": "completed", "conclusion": "success", "created_at": self.request["created_at"]}

                def download(arguments, **kwargs):
                    kwargs["destination"].write_bytes(original.read_bytes())
                    return 0, b""

                with mock.patch.object(github, "run", return_value=run), mock.patch.object(github, "artifact", return_value=artifact), mock.patch.object(handoff, "command", side_effect=download):
                    if mutation is None:
                        admitted = handoff.successful_result(github, 789, self.request, self.request_sha,
                                                             self.checkpoint, self.tag, root)
                        self.assertEqual(admitted["result_artifact_sha256"], artifact["digest"])
                    else:
                        with self.assertRaises(handoff.HandoffError):
                            handoff.successful_result(github, 789, self.request, self.request_sha,
                                                      self.checkpoint, self.tag, root)

    def test_annotation_has_noncyclic_request_and_actual_operator_identity(self) -> None:
        message = handoff.tag_message(self.request, self.request_sha, self.checkpoint, 789)
        self.assertEqual(handoff.operator_from_message(message), 789)
        self.assertIn("Handoff-Request: " + self.request_sha, message)
        self.assertNotIn("result_sha", message)
        with self.assertRaises(handoff.HandoffError):
            handoff.operator_from_message(message + "Operator-Run: 790\n")


if __name__ == "__main__":
    unittest.main()
