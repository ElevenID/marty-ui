"""Transport and history controls; unchanged Rust owns official qualification."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import official_review_gate as gate

LANES = ["oid4vci-issuer", "oid4vp-final", "oid4vp-url-query", "oid4vp-mdoc", "haip", "w3c-v2", "eudi"]
RUN = 17
HARNESS = "b" * 40
RECORD = b'{\r\n  "transport_fixture_only": true\r\n}\r\n'


def encoded(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class Clock:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        assert 0 < seconds <= gate.REVIEW_POLL_SECONDS
        self.sleeps.append(seconds)
        self.now += seconds


class FakeGitHub:
    """No network: local real Git objects back the mocked API identities."""

    def __init__(self, source: str) -> None:
        self.source = source
        self.mains = [source]
        self.calls: list[tuple] = []
        self.record: bytes | None = None
        self.branch_error: Exception | None = None
        self.record_error: Exception | None = None
        self.branch_mutator = lambda value: None

    def api(self, path: str) -> bytes:
        assert path == "branches/main"
        self.calls.append(("branch",))
        if self.branch_error is not None:
            raise self.branch_error
        main = self.mains.pop(0) if len(self.mains) > 1 else self.mains[0]
        value = {"name": "main", "protected": True, "commit": {"sha": main}}
        self.branch_mutator(value)
        return encoded(value)

    def fetch_main(self, commit: str, repository: Path) -> None:
        self.calls.append(("fetch", commit, repository))

    def review_record(self, run_id: int, attempt: int, commit: str) -> bytes | None:
        assert (run_id, attempt) == (RUN, 1)
        self.calls.append(("record", commit))
        if self.record_error is not None:
            raise self.record_error
        return None if commit == self.source else self.record


class TestBoundedReviewWait(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="official-review-wait-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.repo = self.directory / "repository"
        self.repo.mkdir()
        self.git_env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": self.temp.name,
                        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                        "GIT_AUTHOR_NAME": "Unit Fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
                        "GIT_COMMITTER_NAME": "Unit Fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid"}
        self.git("init", "-q", "--initial-branch=main")
        (self.repo / "product.txt").write_bytes(b"original\n")
        self.source = self.commit("candidate")
        self.args = argparse.Namespace(
            validator=Path("validator-unit-fixture"), manifest=self.directory / "manifest.json",
            snapshot=self.directory / "snapshot", authorization=self.directory / "authorization",
            output=self.directory / "gate.json", source=self.source, harness=HARNESS,
            run_id=RUN, current_attempt=1, repository=self.repo,
        )
        self.args.manifest.write_bytes(b"transport-unit-fixture-manifest\n")
        self.args.snapshot.mkdir()
        (self.args.snapshot / "stack-manifest.json").write_bytes(self.args.manifest.read_bytes())
        (self.args.snapshot / "origin-attempt.txt").write_bytes(b"1\n")
        self.set_plan(False)
        self.clock = Clock()
        self.github = FakeGitHub(self.source)
        self.accepted_main = self.source
        self.validator_calls: list[tuple[list[str], dict]] = []
        self.validator_error: Exception | None = None
        self.after_validation = lambda: None
        self.gate_mutator = lambda value: None
        self.addCleanup(mock.patch.stopall)
        mock.patch.dict(os.environ, {
            "GITHUB_REPOSITORY": gate.REPOSITORY, "GITHUB_REPOSITORY_ID": gate.REPOSITORY_ID,
            "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": self.source,
            "GITHUB_RUN_ID": str(RUN), "GITHUB_RUN_ATTEMPT": "1", "GITHUB_EVENT_NAME": "workflow_dispatch",
        }).start()
        mock.patch.object(gate, "command", side_effect=self.validator).start()

    def git(self, *args: str) -> str:
        return subprocess.run(
            ["git", "--no-replace-objects", "-c", "protocol.allow=never", *args], cwd=self.repo,
            env=self.git_env, capture_output=True, text=True, timeout=10, check=True,
        ).stdout.strip()

    def commit(self, message: str) -> str:
        self.git("add", "--all")
        self.git("-c", f"core.hooksPath={os.devnull}", "commit", "-qm", message, "--no-gpg-sign")
        return self.git("rev-parse", "HEAD")

    def set_plan(self, pending: bool) -> None:
        self.plan = encoded({"pending": ["transport-unit-fixture-only"] if pending else [],
                             "release_qualified": False})
        (self.args.snapshot / "review-request.json").write_bytes(self.plan)

    def add_review(self) -> str:
        self.set_plan(True)
        path = self.repo / gate.review_path(RUN)
        path.parent.mkdir(parents=True)
        path.write_bytes(RECORD)
        self.accepted_main = self.commit("review disposition fixture")
        self.github.record = RECORD
        return self.accepted_main

    def result(self) -> bytes:
        value = {"schema": "marty.official-release-gate/v1", "source_sha": self.source,
                 "harness_sha": HARNESS, "manifest_sha256": digest(self.args.manifest.read_bytes()),
                 "run_id": RUN, "qualification_context": "PRE_PUBLICATION_CANDIDATE",
                 "lanes": [{"lane": lane, "summary_sha256": "sha256:" + "e" * 64} for lane in LANES]}
        if json.loads(self.plan)["pending"]:
            value["review_disposition"] = {
                "schema": "marty.accepted-official-review/v1", "protected_main_commit": self.accepted_main,
                "record_sha256": digest(RECORD), "request_sha256": digest(self.plan), "evidence_run_attempt": 1,
                "reviewer": {"kind": "delegated_codex", "github_login": "reviewer"}, "reviewed_cases": 1,
                "original_official_results_unchanged": True,
            }
        self.gate_mutator(value)
        return encoded(value)

    def validator(self, arguments: list[str], **kwargs) -> bytes:
        self.validator_calls.append((arguments, kwargs))
        assert arguments[0] == "validator-unit-fixture"
        assert arguments[-2:] == ["1", str(self.args.snapshot / "official-summaries")]
        assert 0 < kwargs["timeout"] <= min(120, gate.REVIEW_WAIT_SECONDS - self.clock.now)
        if arguments[1] == "--prepare-review":
            return self.plan
        if self.validator_error is not None:
            raise self.validator_error
        self.after_validation()
        return self.result()

    def qualify(self) -> None:
        gate.qualify(self.args, self.github, clock=self.clock, sleeper=self.clock.sleep)

    def test_all_pass_retains_original_main_without_any_review_lookup(self) -> None:
        self.qualify()
        self.assertEqual(self.args.output.read_bytes(), self.result())
        self.assertFalse(self.args.authorization.exists())
        self.assertEqual([call[0] for call in self.github.calls], ["branch", "fetch", "branch"])
        self.assertEqual(len(self.validator_calls), 2)
        self.assertEqual(self.clock.sleeps, [])

    def test_wait_accepts_only_exact_review_descendant_in_original_attempt(self) -> None:
        main = self.add_review()
        self.github.mains = [self.source, self.source, main, main]
        self.qualify()
        self.assertEqual(self.clock.sleeps, [60, 60])
        self.assertEqual([call for call in self.github.calls if call[0] == "record"],
                         [("record", self.source), ("record", main)])
        self.assertEqual(len(self.validator_calls), 2)
        self.assertEqual(self.validator_calls[-1][0][1:4],
                         ["--with-main-review", str(self.args.authorization / "record.json"), main])
        self.assertEqual((self.args.authorization / "record.json").read_bytes(), RECORD)
        self.assertEqual(self.args.authorization.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.args.authorization / "record.json").stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.args.output.stat().st_mode & 0o777, 0o600)
        receipt = json.loads(self.args.output.read_bytes())
        self.assertEqual(receipt["source_sha"], self.source)
        self.assertEqual(receipt["review_disposition"]["protected_main_commit"], main)
        self.assertEqual({lane["lane"] for lane in receipt["lanes"]}, set(LANES))

    def test_absent_review_expires_at_fixed_bound_without_revalidating_or_downloading(self) -> None:
        self.set_plan(True)
        with self.assertRaisesRegex(ValueError, "deadline expired"):
            self.qualify()
        self.assertEqual(self.clock.now, 3600)
        self.assertEqual(len(self.clock.sleeps), 60)
        self.assertEqual([call for call in self.github.calls if call[0] == "record"], [("record", self.source)])
        self.assertEqual(len(self.validator_calls), 1)
        self.assertFalse(self.args.output.exists())
        self.assertFalse(self.args.authorization.exists())

    def test_transport_failures_do_not_become_pending_review(self) -> None:
        self.set_plan(True)
        self.github.record_error = ValueError("transport refused")
        with self.assertRaisesRegex(ValueError, "transport refused"):
            self.qualify()
        self.assertEqual(self.clock.sleeps, [])
        self.assertFalse(self.args.output.exists())

    def test_unprotected_main_fails_before_git_or_record_access(self) -> None:
        self.github.branch_mutator = lambda value: value.update(protected=False)
        with self.assertRaisesRegex(ValueError, "protected main"):
            self.qualify()
        self.assertEqual(self.github.calls, [("branch",)])

    def test_unrelated_intervening_change_fails_before_record_access(self) -> None:
        self.add_review()
        (self.repo / "product.txt").write_bytes(b"unrelated\n")
        self.github.mains = [self.commit("unrelated product mutation")]
        with self.assertRaisesRegex(ValueError, "outside the exact"):
            self.qualify()
        self.assertFalse(any(call[0] == "record" for call in self.github.calls))
        self.assertFalse(self.args.output.exists())

    def test_api_absence_cannot_hide_a_record_in_advanced_main(self) -> None:
        self.github.mains = [self.add_review()]
        self.github.record = None
        with self.assertRaisesRegex(ValueError, "absence contradicts"):
            self.qualify()
        self.assertEqual(self.clock.sleeps, [])

    def test_api_record_must_match_the_immutable_git_blob(self) -> None:
        self.github.mains = [self.add_review()]
        self.github.record = RECORD.replace(b"true", b"false")
        with self.assertRaisesRegex(ValueError, "differs from the accepted"):
            self.qualify()
        self.assertEqual(len(self.validator_calls), 1)
        self.assertFalse(self.args.authorization.exists())

    def test_rust_rejection_cannot_produce_gate_output(self) -> None:
        self.github.mains = [self.add_review()]
        self.validator_error = ValueError("unchanged Rust refused")
        with self.assertRaisesRegex(ValueError, "unchanged Rust refused"):
            self.qualify()
        self.assertFalse(self.args.output.exists())

    def test_main_movement_after_validation_refuses_output(self) -> None:
        main = self.add_review()
        self.github.mains = [main, self.source]
        with self.assertRaisesRegex(ValueError, "changed after"):
            self.qualify()
        self.assertFalse(self.args.output.exists())

    def test_expiration_during_validation_refuses_output_and_final_api(self) -> None:
        self.github.mains = [self.add_review()]
        self.after_validation = lambda: setattr(self.clock, "now", 3601)
        with self.assertRaisesRegex(ValueError, "deadline expired"):
            self.qualify()
        self.assertFalse(self.args.output.exists())
        self.assertEqual(len([call for call in self.github.calls if call[0] == "branch"]), 1)

    def test_second_attempt_refuses_before_any_api_or_validation(self) -> None:
        self.args.current_attempt = 2
        with mock.patch.dict(os.environ, {"GITHUB_RUN_ATTEMPT": "2"}):
            with self.assertRaisesRegex(ValueError, "original protected-main dispatch attempt"):
                self.qualify()
        self.assertEqual(self.github.calls, [])
        self.assertEqual(self.validator_calls, [])

    def test_foreign_dispatch_context_refuses_before_work(self) -> None:
        changes = {"GITHUB_EVENT_NAME": "push", "GITHUB_SHA": "a" * 40,
                   "GITHUB_REPOSITORY_ID": "1", "GITHUB_REF": "refs/heads/feature"}
        for key, value in changes.items():
            with self.subTest(key=key), mock.patch.dict(os.environ, {key: value}):
                with self.assertRaises(ValueError):
                    self.qualify()
        self.assertEqual(self.github.calls, [])
        self.assertEqual(self.validator_calls, [])

    def test_preexisting_authorization_and_output_are_never_overwritten(self) -> None:
        self.args.authorization.mkdir()
        record = self.args.authorization / "record.json"
        record.write_bytes(b"forged-local-record")
        with self.assertRaises(FileExistsError):
            self.qualify()
        self.assertEqual(record.read_bytes(), b"forged-local-record")
        self.args.output.write_bytes(b"existing-output")
        with self.assertRaisesRegex(ValueError, "output already exists"):
            self.qualify()
        self.assertEqual(self.args.output.read_bytes(), b"existing-output")
        self.assertEqual(self.validator_calls, [])

    def test_wrong_returned_candidate_or_request_is_not_an_authorization(self) -> None:
        main = self.add_review()
        mutations = [lambda value: value.update(harness_sha="a" * 40),
                     lambda value: value.update(manifest_sha256="sha256:" + "a" * 64),
                     lambda value: value["review_disposition"].update(request_sha256="sha256:" + "a" * 64),
                     lambda value: value["review_disposition"].update(evidence_run_attempt=2),
                     lambda value: value.update(source_sha="a" * 40),
                     lambda value: value.update(run_id=RUN + 1)]
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                self.args.authorization = self.directory / f"authorization-{index}"
                self.github.mains = [main]
                self.gate_mutator = mutate
                with self.assertRaises(ValueError):
                    self.qualify()
                self.assertFalse(self.args.output.exists())


class TestReviewRecordTransport(unittest.TestCase):
    def envelope(self, raw: bytes = RECORD) -> dict:
        path = gate.review_path(RUN)
        return {"type": "file", "path": path, "name": path.rsplit("/", 1)[1], "size": len(raw),
                "encoding": "base64", "content": base64.b64encode(raw).decode() + "\n",
                "sha": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()}

    def response(self, body: object, *, status: int = 200, newline: bytes = b"\r\n", rc: int = 0):
        raw = newline.join([f"HTTP/2.0 {status} Fixture".encode(), b"Content-Type: application/json; charset=utf-8",
                            b"X-GitHub-Request-Id: public-unit-fixture", b"", encoded(body)])
        return subprocess.CompletedProcess(["fixture"], rc, stdout=raw, stderr=b"")

    def read(self, response):
        with mock.patch.object(gate, "completed", return_value=response) as process:
            result = gate.GitHub().review_record(RUN, 1, "a" * 40)
        self.assertEqual(process.call_args.args[0][-1],
                         "repos/ElevenID/marty-ui/contents/release/official-reviews/17-1.json?ref=" + "a" * 40)
        self.assertEqual(process.call_args.args[0][:5], ["gh", "api", "--hostname", "github.com", "--include"])
        return result

    def test_record_bytes_including_crlf_survive_both_supported_header_styles(self) -> None:
        for newline in (b"\r\n", b"\n"):
            with self.subTest(newline=newline):
                self.assertEqual(self.read(self.response(self.envelope(), newline=newline)), RECORD)

    def test_lf_header_separator_is_not_confused_with_crlf_in_json_whitespace(self) -> None:
        raw = b'HTTP/2.0 200 OK\nContent-Type: application/json\n\n{\r\n\r\n"message":"fixture"}\r\n'
        self.assertEqual(gate.http_json_response(raw), (200, {"message": "fixture"}))

    def test_only_explicit_not_found_with_matching_process_status_is_absence(self) -> None:
        self.assertIsNone(self.read(self.response({"message": "Not Found"}, status=404, rc=1)))
        cases = [(404, 0, "Not Found"), (404, 1, "Resource not accessible by integration"),
                 (403, 1, "Not Found"), (500, 1, "Not Found"), (200, 1, "Not Found")]
        for status, rc, message in cases:
            with self.subTest(status=status, rc=rc, message=message), self.assertRaises(ValueError):
                self.read(self.response({"message": message}, status=status, rc=rc))

    def test_wrong_path_type_encoding_size_and_blob_are_refused(self) -> None:
        changes = [("path", "release/official-reviews/18-1.json"), ("name", "18-1.json"),
                   ("type", "symlink"), ("encoding", "none"), ("size", True),
                   ("size", 0), ("size", gate.MAX_RECORD_BYTES + 1), ("size", len(RECORD) + 1),
                   ("sha", "0" * 40), ("content", "!!!"), ("content", "\N{SNOWMAN}"),
                   ("content", "A" * (2 * gate.MAX_RECORD_BYTES + 1))]
        for key, value in changes:
            envelope = self.envelope(); envelope[key] = value
            with self.subTest(field=key, value_type=type(value).__name__), self.assertRaises(ValueError):
                self.read(self.response(envelope))

    def test_malformed_or_ambiguous_response_headers_and_bodies_are_refused(self) -> None:
        responses = [b'{"message":"Not Found"}',
                     b'HTTP/2.0 404 Not Found\r\nContent-Type: text/html\r\n\r\n{}',
                     b'HTTP/2.0 404 Not Found\r\nContent-Type: application/json\r\n\r\n[]',
                     b'HTTP/2.0 404 Not Found\r\nContent-Type: application/json\r\n\r\n{"message":"Not Found","message":"Not Found"}',
                     b'HTTP/2.0 404 Not Found\r\nContent-Type: application/json\r\nContent-Type: application/json\r\n\r\n{}',
                     b'HTTP/2.0 404 Not Found\r\nnot a header\r\n\r\n{}',
                     b'HTTP/2.0 404 Not Found\r\nContent-Type: application/json\r\n\r\nnot-json']
        for index, raw in enumerate(responses):
            with self.subTest(response=index), self.assertRaises(ValueError):
                self.read(subprocess.CompletedProcess(["fixture"], 1, stdout=raw, stderr=b"private-error-marker"))

    def test_record_transport_cannot_start_after_deadline(self) -> None:
        github = gate.GitHub(); github.deadline = 10; github.clock = lambda: 11
        with mock.patch.object(gate, "completed") as process:
            with self.assertRaisesRegex(ValueError, "deadline expired"):
                github.review_record(RUN, 1, "a" * 40)
            process.assert_not_called()

    def test_remaining_time_caps_each_transport_command(self) -> None:
        github = gate.GitHub(); github.deadline = 10; github.clock = lambda: 8.5
        with mock.patch.object(gate, "completed", return_value=self.response(self.envelope())) as process:
            self.assertEqual(github.review_record(RUN, 1, "a" * 40), RECORD)
            self.assertEqual(process.call_args.kwargs["timeout"], 1.5)
        with mock.patch.object(gate, "command", return_value=b"{}") as command:
            github.api("branches/main")
            self.assertEqual(command.call_args.kwargs["timeout"], 1.5)

    def test_process_error_details_are_not_exposed(self) -> None:
        response = subprocess.CompletedProcess(["fixture"], 1, stdout=b"private-output-marker", stderr=b"private-error-marker")
        with mock.patch.object(gate.subprocess, "run", return_value=response):
            with self.assertRaisesRegex(ValueError, "transport or Rust validation failed") as error:
                gate.command(["fixture"])
        self.assertNotIn("private", str(error.exception))

    def test_expired_nonfinite_and_boolean_command_timeouts_refuse_before_spawn(self) -> None:
        for timeout in (0, -1, True, float("nan"), float("inf"), 121):
            with self.subTest(timeout=timeout), mock.patch.object(gate.subprocess, "run") as process:
                with self.assertRaises(ValueError):
                    gate.completed(["fixture"], timeout=timeout)
                process.assert_not_called()


if __name__ == "__main__":
    unittest.main()
