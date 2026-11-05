"""Synthetic HTTP controls and real local receive-pack transactions; no network."""
from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import release_git_atomic as atomic
from scripts import release_tag_handoff as handoff
from scripts import push_promoted_release_tag as operator

R = "b" * 40
G = "a" * 40
A = "c" * 40
TAG = "v-release-capability-123-1"

# Exact public Git response from run 41792570662, artifact 13304121134.
# The artifact ZIP SHA-256 was verified against authenticated GitHub metadata:
# af9c4f376e5109581e9f09c192f810dd215c94cec52e5d98d5fcc606d5104736.
# This historical failed capability run is a parser fixture, not qualification.
GITHUB_RULE_REFUSAL = (
    b"0006\2\0"
    b"0013\1" b"000eunpack ok\n"
    b"010c\2error: GH013: Repository rule violations found for refs/heads/main.\n"
    b"Review all repository rules at https://github.com/ElevenID/marty-ui/rules?ref=refs%2Fheads%2Fmain\n"
    b"\n- Changes must be made through the merge queue\n"
    b"\n- Changes must be made through a pull request.\n\n"
    b"004c\1" b"0047ng refs/heads/main push declined due to repository rule violations\n"
    b"0053\1" b"004eng refs/tags/v-release-capability-41792570662-1 atomic transaction failed\n"
    b"0009\1" b"00000000"
)
# Corrected A -> A request's response from run 41894878943, artifact
# 13355352570. Authenticated ZIP SHA-256:
# 9bc1ca672f57127b5bfde8c47475d7d5f54a9c7c3af31553014b2280c2f1a67f.
# This also remains a failed historical run: it never sent a positive request.
GITHUB_STALE_NOOP_POLICY_REFUSAL = GITHUB_RULE_REFUSAL.replace(b"41792570662", b"41894878943")


def spec(negative: bool = False) -> dict:
    return atomic.transaction_spec(G if negative else R, R, TAG, A,
                                   "capability-negative-123-1" if negative else "capability-positive-123-1")


def http_result(body: bytes, method: str) -> dict:
    return {"http_status": 200, "headers": {
        "content-type": "application/x-git-receive-pack-" + ("advertisement" if method == "GET" else "result"),
        "content-length": str(len(body)),
    }, "body_base64": base64.b64encode(body).decode()}


def advertisement(main: str = R, caps: tuple = atomic.CAPABILITIES, extra: bytes = b"") -> bytes:
    return (atomic.pkt(b"# service=git-receive-pack\n") + b"0000"
            + atomic.pkt((main + " HEAD\0" + " ".join(caps) + "\n").encode())
            + atomic.pkt((main + " refs/heads/main\n").encode()) + extra + b"0000")


def report(request: dict, outcomes: tuple = ("ok", "ok"), diagnostic: bytes = b"") -> bytes:
    body = atomic.pkt(b"unpack ok\n")
    for command, status in zip(request["commands"], outcomes):
        line = status + " " + command["ref"] + (" atomic transaction failed" if status == "ng" else "")
        body += atomic.pkt((line + "\n").encode())
    body += b"0000"
    return atomic.pkt(b"\1" + body) + (atomic.pkt(b"\2" + diagnostic) if diagnostic else b"") + b"0000"


class LocalReceivePackTests(unittest.TestCase):
    """The sender under test talks to stock Git through local pipes only."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="native-git-atomic-fixture-")
        self.directory = Path(self.temporary.name)
        self.repo = self.directory / "receiver.git"
        self.environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(self.directory),
                            "LANG": "C", "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1",
                            "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull,
                            "GIT_TERMINAL_PROMPT": "0", "GIT_NO_LAZY_FETCH": "1",
                            "GIT_AUTHOR_NAME": "Synthetic", "GIT_AUTHOR_EMAIL": "synthetic@example.invalid",
                            "GIT_COMMITTER_NAME": "Synthetic", "GIT_COMMITTER_EMAIL": "synthetic@example.invalid",
                            "GIT_AUTHOR_DATE": "2001-01-01T00:00:00Z", "GIT_COMMITTER_DATE": "2001-01-01T00:00:00Z"}
        self.git = shutil.which("git")
        self.assertIsNotNone(self.git, "The meaningful local protocol tests require Git")
        self.run_git("init", "--bare", "--object-format=sha1", str(self.repo))
        tree = self.object_git("hash-object", "-w", "-t", "tree", "--stdin", data=b"").strip().decode()
        self.ancestor = self.object_git("commit-tree", tree, data=b"Synthetic ancestor\n").strip().decode()
        self.main = self.object_git("commit-tree", tree, "-p", self.ancestor, data=b"Synthetic main\n").strip().decode()
        self.later = self.object_git("commit-tree", tree, "-p", self.main, data=b"Synthetic later\n").strip().decode()
        self.object_git("update-ref", "refs/heads/main", self.main)
        self.object_git("symbolic-ref", "HEAD", "refs/heads/main")
        tag = (f"object {self.ancestor}\ntype commit\ntag {TAG}\n"
               "tagger Synthetic <synthetic@example.invalid> 978307200 +0000\n\nSynthetic audit only\n").encode()
        self.tag_object = self.object_git("mktag", data=tag).strip().decode()
        hook = self.repo / "hooks/pre-receive"
        hook.write_text("#!/bin/sh\ncat > received.commands\n")
        hook.chmod(0o700)
        self.http_calls = []
        self.saved = []
        self.before_post = None
        self.after_post = None
        self.native = atomic.NativeGit(runner=lambda *a, **k: self.fail("No HTTPS worker may run in local fixtures"),
                                      deadline=lambda: datetime.now(timezone.utc) + timedelta(seconds=15),
                                      persist=lambda: self.saved.append(copy.deepcopy(self.native.transactions)),
                                      http=self.local_http)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_git(self, *arguments: str, data: bytes | None = None) -> bytes:
        process = subprocess.run([self.git, "--no-replace-objects", "-c", "protocol.allow=never",
                                  "-c", "commit.gpgsign=false", *arguments], input=data, cwd=self.directory,
                                 env=self.environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        self.assertEqual(process.returncode, 0, process.stderr.decode(errors="replace"))
        self.assertLessEqual(len(process.stdout) + len(process.stderr), 65536)
        return process.stdout

    def object_git(self, *arguments: str, data: bytes | None = None) -> bytes:
        return self.run_git("--git-dir=" + str(self.repo), *arguments, data=data)

    def local_spec(self, negative: bool = False) -> dict:
        return atomic.transaction_spec(self.ancestor if negative else self.main, self.main, TAG,
                                       self.tag_object, "capability-negative-123-1" if negative else "capability-positive-123-1")

    def local_http(self, method: str, body: bytes | None) -> dict:
        self.http_calls.append((method, body))
        if method == "GET":
            raw = self.run_git("receive-pack", "--stateless-rpc", "--advertise-refs", str(self.repo))
            return http_result(atomic.pkt(b"# service=git-receive-pack\n") + b"0000" + raw, method)
        self.assertIsNotNone(body)
        self.assertEqual(self.saved[-1][-1]["mutation"]["outcome"], "unknown")
        self.assertEqual(self.saved[-1][-1]["mutation"]["body_sha256"], atomic.digest(body))
        if self.before_post:
            self.before_post()
        raw = self.run_git("receive-pack", "--stateless-rpc", str(self.repo), data=body)
        if self.after_post:
            return self.after_post(raw)
        return http_result(raw, method)

    def assert_tag_absent(self) -> None:
        names = self.object_git("for-each-ref", "--format=%(refname)", "refs/tags/").decode().splitlines()
        self.assertNotIn("refs/tags/" + TAG, names)

    def assert_main(self, expected: str) -> None:
        self.assertEqual(self.object_git("rev-parse", "refs/heads/main").strip().decode(), expected)

    def test_positive_retains_noop_main_command_and_creates_actual_annotated_tag(self) -> None:
        value = self.native.exchange(self.local_spec())
        self.assertEqual(value["decision"], "confirmed_success")
        self.assert_main(self.main)
        self.assertEqual(self.object_git("cat-file", "-t", "refs/tags/" + TAG).strip(), b"tag")
        self.assertEqual(self.object_git("rev-parse", "refs/tags/" + TAG + "^{}").strip().decode(), self.ancestor)
        self.assertEqual((self.repo / "received.commands").read_text().splitlines(), [
            f"{self.main} {self.main} refs/heads/main", f"{atomic.ZERO} {self.tag_object} refs/tags/{TAG}"])

    def test_real_stale_main_atomic_refusal_contains_attributable_sideband_diagnostic(self) -> None:
        value = self.native.exchange(self.local_spec(True))
        self.assertEqual(value["decision"], "confirmed_stale_main_refusal")
        diagnostic = value["mutation"]["report"]["diagnostic"]
        self.assertIn(f"is at {self.main} but expected {self.ancestor}", diagnostic)
        self.assertTrue(all(row["status"] == "ng" for row in value["mutation"]["report"]["refs"]))
        self.assertEqual(value["request"]["observed_main_oid"], self.main)
        self.assertEqual((self.repo / "received.commands").read_text().splitlines(), [
            f"{self.ancestor} {self.ancestor} refs/heads/main",
            f"{atomic.ZERO} {self.tag_object} refs/tags/{TAG}"])
        self.assert_main(self.main)
        self.assert_tag_absent()

    def test_stale_and_current_noops_pass_a_hook_that_prohibits_main_updates(self) -> None:
        # This local hook represents the branch-update distinction, not
        # GitHub's implementation. Stock Git still performs the actual CAS.
        hook = self.repo / "hooks/pre-receive"
        hook.write_text("#!/bin/sh\n"
                        "while read old new ref; do\n"
                        '  if [ "$ref" = refs/heads/main ] && [ "$old" != "$new" ]; then\n'
                        "    printf 'error: main updates require a pull request\\n' >&2\n"
                        "    exit 1\n"
                        "  fi\n"
                        "done\n")
        negative = self.native.exchange(self.local_spec(True))
        self.assertEqual(negative["decision"], "confirmed_stale_main_refusal")
        self.assert_main(self.main)
        self.assert_tag_absent()
        positive = self.native.exchange(self.local_spec())
        self.assertEqual(positive["decision"], "confirmed_success")
        self.assert_main(self.main)
        self.assertEqual(self.object_git("rev-parse", "refs/tags/" + TAG).strip().decode(), self.tag_object)

    def test_negative_then_positive_is_two_distinct_admitted_attempts(self) -> None:
        self.native.exchange(self.local_spec(True))
        self.assert_tag_absent()
        self.native.exchange(self.local_spec())
        self.assertEqual([method for method, _ in self.http_calls], ["GET", "POST", "GET", "POST"])
        self.assertEqual(len(self.native.transactions), 2)

    def test_main_changed_after_discovery_prevents_tag_creation(self) -> None:
        self.before_post = lambda: self.object_git("update-ref", "refs/heads/main", self.later, self.main)
        with self.assertRaises(atomic.AtomicGitError):
            self.native.exchange(self.local_spec())
        self.assert_main(self.later)
        self.assert_tag_absent()
        self.assertTrue(self.native.poisoned)

    def test_negative_current_main_must_match_discovery_before_post(self) -> None:
        self.object_git("update-ref", "refs/heads/main", self.later, self.main)
        with self.assertRaises(atomic.AtomicGitError):
            self.native.exchange(self.local_spec(True))
        self.assertEqual([method for method, _ in self.http_calls], ["GET"])
        self.assert_main(self.later)
        self.assert_tag_absent()

    def test_negative_main_race_cannot_be_mistaken_for_the_admitted_stale_proof(self) -> None:
        self.before_post = lambda: self.object_git("update-ref", "refs/heads/main", self.later, self.main)
        with self.assertRaises(atomic.AtomicGitError):
            self.native.exchange(self.local_spec(True))
        value = self.native.transactions[-1]
        self.assertIn(f"is at {self.later} but expected {self.ancestor}", value["mutation"]["report"]["diagnostic"])
        self.assertEqual(value["mutation"]["outcome"], "unknown")
        self.assertEqual(value["decision"], "unadmitted")
        self.assert_main(self.later)
        self.assert_tag_absent()
        with self.assertRaises(atomic.AtomicGitError):
            self.native.exchange(self.local_spec())
        self.assertEqual([method for method, _ in self.http_calls].count("POST"), 1)

    def test_progress_keepalive_preserves_real_ref_results_and_raw_receipts(self) -> None:
        self.after_post = lambda raw: http_result(b"0006\2\0" + raw, "POST")
        for request in (self.local_spec(True), self.local_spec()):
            value = self.native.exchange(request)
            parsed = value["mutation"]["report"]
            raw = base64.b64decode(value["mutation"]["https"]["body_base64"], validate=True)
            self.assertTrue(raw.startswith(b"0006\2\0"))
            self.assertEqual(parsed["keepalive_packets"], 1)
            self.assertEqual(parsed["body_sha256"], atomic.digest(raw))
            self.assertNotIn("\0", parsed["diagnostic"])
        self.assert_main(self.main)
        self.assertEqual(self.object_git("rev-parse", "refs/tags/" + TAG).strip().decode(), self.tag_object)

    def test_tag_collision_after_discovery_rolls_back_whole_transaction(self) -> None:
        self.before_post = lambda: self.object_git("update-ref", "refs/tags/" + TAG, self.ancestor)
        with self.assertRaises(atomic.AtomicGitError):
            self.native.exchange(self.local_spec())
        self.assert_main(self.main)
        self.assertEqual(self.object_git("rev-parse", "refs/tags/" + TAG).strip().decode(), self.ancestor)
        self.assertEqual(self.native.transactions[-1]["mutation"]["outcome"], "unknown")

    def test_unknown_response_after_real_commit_never_replays(self) -> None:
        def lose_response(_: bytes) -> dict:
            raise TimeoutError("synthetic lost acknowledgement")
        self.after_post = lose_response
        with self.assertRaises(TimeoutError):
            self.native.exchange(self.local_spec())
        self.assertEqual(self.object_git("rev-parse", "refs/tags/" + TAG).strip().decode(), self.tag_object)
        for request in (self.local_spec(), self.local_spec(True)):
            with self.assertRaises(atomic.AtomicGitError):
                self.native.exchange(request)
        self.assertEqual([method for method, _ in self.http_calls].count("POST"), 1)
        self.assertEqual(self.native.transactions[-1]["mutation"]["outcome"], "unknown")

    def test_truncated_ack_after_real_commit_is_unknown_and_consumed(self) -> None:
        self.after_post = lambda raw: http_result(raw[:-3], "POST")
        with self.assertRaises(atomic.AtomicGitError):
            self.native.exchange(self.local_spec())
        with self.assertRaises(atomic.AtomicGitError):
            self.native.exchange(self.local_spec())
        self.assertEqual([method for method, _ in self.http_calls].count("POST"), 1)

    def test_existing_advertised_tag_is_refused_before_any_post(self) -> None:
        self.object_git("update-ref", "refs/tags/" + TAG, self.tag_object)
        with self.assertRaises(atomic.AtomicGitError):
            self.native.exchange(self.local_spec())
        self.assertEqual([method for method, _ in self.http_calls], ["GET"])

    def test_outcome_persistence_failure_after_real_commit_never_replays(self) -> None:
        def persist() -> None:
            self.saved.append(copy.deepcopy(self.native.transactions))
            if self.native.transactions[-1]["decision"] == "confirmed_success":
                raise OSError("synthetic outcome persistence outage")
        self.native.persist = persist
        with self.assertRaises(OSError): self.native.exchange(self.local_spec())
        with self.assertRaises(atomic.AtomicGitError): self.native.exchange(self.local_spec())
        self.assertEqual(self.object_git("rev-parse", "refs/tags/" + TAG).strip().decode(), self.tag_object)
        self.assertEqual([method for method, _ in self.http_calls].count("POST"), 1)

    def test_report_persistence_failure_after_real_commit_never_replays(self) -> None:
        def persist() -> None:
            self.saved.append(copy.deepcopy(self.native.transactions))
            value = self.native.transactions[-1]
            if value["mutation"] and "report" in value["mutation"]:
                self.assertEqual(value["mutation"]["outcome"], "unknown")
                raise OSError("synthetic decoded-report persistence outage")
        self.native.persist = persist
        with self.assertRaises(OSError):
            self.native.exchange(self.local_spec())
        with self.assertRaises(atomic.AtomicGitError):
            self.native.exchange(self.local_spec())
        self.assertEqual(self.object_git("rev-parse", "refs/tags/" + TAG).strip().decode(), self.tag_object)
        self.assertEqual([method for method, _ in self.http_calls].count("POST"), 1)
        self.assertEqual(self.native.transactions[-1]["decision"], "unadmitted")


class ProtocolRefusalTests(unittest.TestCase):
    def test_supported_advertisement_binds_exact_main_tag_absence_and_capabilities(self) -> None:
        value = atomic.parse_advertisement(advertisement(), spec())
        self.assertEqual(value["main_oid"], R)
        self.assertIs(value["tag_absent"], True)
        self.assertEqual(value["object_format"], "sha1")

    def test_negative_discovery_binds_current_separately_from_the_stale_noop(self) -> None:
        request = spec(True)
        value = atomic.parse_advertisement(advertisement(), request)
        self.assertEqual(value["main_oid"], R)
        frames = atomic.packets(atomic.request_bytes(request)[:-32], 2048)
        self.assertIn((G + " " + G + " refs/heads/main").encode(), frames[0])
        for wrong in (G, A):
            with self.subTest(observed=wrong), self.assertRaises(atomic.AtomicGitError):
                atomic.parse_advertisement(advertisement(main=wrong), request)

    def test_negative_current_binding_cannot_be_missing_equal_malformed_or_used_on_other_operations(self) -> None:
        invalid = []
        missing = spec(True)
        del missing["observed_main_oid"]
        invalid.append(missing)
        for observed in (G, atomic.ZERO, True, None, "not-an-object", "A" * 40):
            invalid.append({**spec(True), "observed_main_oid": observed})
        for current in (spec(), atomic.transaction_spec(R, R, "v1.2.3", A, "release-tag-123-1")):
            invalid.append({**current, "observed_main_oid": R})
        invalid.append({**spec(True), "unbound_current_oid": R})
        for request in invalid:
            with self.subTest(request=request), self.assertRaises(atomic.AtomicGitError):
                atomic.request_bytes(request)

    def test_negative_main_command_cannot_propose_current_or_any_other_new_value(self) -> None:
        for proposed in (R, A, atomic.ZERO):
            request = spec(True)
            request["commands"][0]["new_oid"] = proposed
            with self.subTest(proposed=proposed), self.assertRaises(atomic.AtomicGitError):
                atomic.request_bytes(request)

    def test_missing_atomic_status_or_sideband_refuses_before_mutation(self) -> None:
        for capability in atomic.CAPABILITIES:
            with self.subTest(capability=capability), self.assertRaises(atomic.AtomicGitError):
                atomic.parse_advertisement(advertisement(caps=tuple(x for x in atomic.CAPABILITIES if x != capability)), spec())

    def test_foreign_main_peeled_tag_duplicate_ref_and_format_refuse(self) -> None:
        cases = [advertisement(main=G), advertisement(caps=(*atomic.CAPABILITIES, "object-format=sha256")),
                 advertisement(extra=atomic.pkt((A + " refs/tags/" + TAG + "^{}\n").encode())),
                 advertisement(extra=atomic.pkt((R + " refs/heads/main\n").encode())),
                 advertisement(caps=(*atomic.CAPABILITIES, "atomic"))]
        for raw in cases:
            with self.subTest(raw=raw[:20]), self.assertRaises(atomic.AtomicGitError):
                atomic.parse_advertisement(raw, spec())

    def test_truncated_trailing_control_or_split_advertisement_refuses(self) -> None:
        raw = advertisement()
        for candidate in (raw[:-1], raw + b"0000", b"0001", b"0002", b"0004", b"ffffx", raw.replace(b"refs/heads/main", b"refs/heads/ma\nin")):
            with self.subTest(raw=candidate[:20]), self.assertRaises(atomic.AtomicGitError):
                atomic.parse_advertisement(candidate, spec())

    def test_partial_foreign_reordered_fatal_or_trailing_status_is_never_success(self) -> None:
        raw = report(spec())
        inner = atomic.pkt(b"unpack ok\n") + atomic.pkt(b"ok refs/heads/main\n") + b"0000"
        cases = [raw[:-1], raw + b"0000", atomic.pkt(b"\1" + inner) + b"0000", atomic.pkt(b"\3fatal") + b"0000",
                 raw.replace(b"refs/heads/main", b"refs/heads/evil")]
        for refs in [("refs/tags/" + TAG, "refs/heads/main"), ("refs/heads/main", "refs/heads/main")]:
            payload = atomic.pkt(b"unpack ok\n") + b"".join(atomic.pkt(("ok " + ref + "\n").encode()) for ref in refs) + b"0000"
            cases.append(atomic.pkt(b"\1" + payload) + b"0000")
        for candidate in cases:
            with self.subTest(raw=candidate[:20]), self.assertRaises(atomic.AtomicGitError):
                atomic.parse_report(candidate, spec())

    def test_only_the_exact_standalone_progress_nul_is_ignored(self) -> None:
        raw = b"0006\2\0" + report(spec())[:-4] + b"0006\2\0" + b"0000"
        parsed = atomic.parse_report(raw, spec())
        self.assertEqual(parsed["keepalive_packets"], 2)
        self.assertEqual(parsed["diagnostic"], "")
        self.assertEqual(parsed["body_sha256"], atomic.digest(raw))
        self.assertEqual(atomic.admit_report(spec(), parsed), "confirmed_success")
        for payload in (b"\2\0\0", b"\2text\0", b"\2\0text", b"\2\1", b"\2\7",
                        b"\2\177", b"\2\377", b"\1\0", b"\3\0", b"\1", b"\2"):
            with self.subTest(payload=payload), self.assertRaises(atomic.AtomicGitError):
                atomic.parse_report(atomic.pkt(payload) + report(spec()), spec())
        with self.assertRaises(atomic.AtomicGitError):
            atomic.parse_report(b"0006\2\0" + b"0000", spec())

    def test_progress_keepalives_do_not_bypass_packet_or_byte_limits(self) -> None:
        for raw in (b"0006\2\0" * 20000 + report(spec()),
                    b"0006\2\0" * (atomic.MAX_STATUS // 6 + 1)):
            with self.subTest(size=len(raw)), self.assertRaises(atomic.AtomicGitError):
                atomic.parse_report(raw, spec())

    def test_partial_ok_ng_and_generic_errors_cannot_prove_stale_cas(self) -> None:
        before = spec(True)
        diagnostic = f"error: cannot lock ref 'refs/heads/main': is at {R} but expected {G}\n".encode()
        accepted = atomic.parse_report(report(before, ("ng", "ng"), diagnostic), before)
        self.assertEqual(atomic.admit_report(before, accepted), "confirmed_stale_main_refusal")
        for outcomes, reason in [(("ok", "ng"), diagnostic), (("ng", "ok"), diagnostic), (("ok", "ok"), diagnostic),
                                 (("ng", "ng"), b"error: main requires a pull request\n"),
                                 (("ng", "ng"), diagnostic.replace(G.encode(), A.encode())),
                                 (("ng", "ng"), diagnostic.replace(R.encode(), A.encode())),
                                 (("ng", "ng"), diagnostic + diagnostic)]:
            with self.subTest(reason=reason[:40]), self.assertRaises(atomic.AtomicGitError):
                atomic.admit_report(before, atomic.parse_report(report(before, outcomes, reason), before))

    def test_command_aliases_and_mutating_positive_main_are_refused(self) -> None:
        for tag, operation, before in [("main", "release-tag-123-1", R), (TAG, "capability-positive-124-1", R),
                                       ("v1.2.3", "release-tag-123-1", G), (TAG, "capability-negative-123-1", R)]:
            with self.subTest(tag=tag, operation=operation), self.assertRaises(atomic.AtomicGitError):
                atomic.transaction_spec(before, R, tag, A, operation)
        value = spec()
        value["commands"][1]["old_oid"] = A
        with self.assertRaises(atomic.AtomicGitError):
            atomic.request_bytes(value)

    def test_http_redirect_encoding_length_type_and_boolean_status_refuse(self) -> None:
        for mutation in ("redirect", "encoding", "length", "transfer", "type", "boolean", "extra"):
            value = http_result(advertisement(), "GET")
            if mutation == "redirect": value["http_status"] = 307
            elif mutation == "encoding": value["headers"]["content-encoding"] = "gzip"
            elif mutation == "length": value["headers"]["content-length"] = "1"
            elif mutation == "transfer": value["headers"]["transfer-encoding"] = "chunked"
            elif mutation == "type": value["headers"]["content-type"] = "text/html"
            elif mutation == "boolean": value["http_status"] = True
            else: value["redirected"] = True
            with self.subTest(mutation=mutation), self.assertRaises(atomic.AtomicGitError):
                atomic.validate_http(value, method="GET")

    def test_empty_pack_is_valid_git_object_transfer_framing(self) -> None:
        body = atomic.request_bytes(spec())
        pack = body[-32:]
        self.assertEqual(pack[:12], b"PACK\0\0\0\2\0\0\0\0")
        self.assertEqual(pack[12:], hashlib.sha1(pack[:12]).digest())
        frames = atomic.packets(body[:-32], 2048)
        self.assertIn((R + " " + R + " refs/heads/main").encode(), frames[0])
        self.assertEqual(frames[-1], None)

    def test_conflicting_ref_reason_or_diagnostic_cannot_count_as_stale_proof(self) -> None:
        before = spec(True)
        reason = f"error: cannot lock ref 'refs/heads/main': is at {R} but expected {G}\n".encode()
        parsed = atomic.parse_report(report(before, ("ng", "ng"), reason), before)
        parsed["refs"][0]["reason"] = "protected branch hook declined"
        with self.assertRaises(atomic.AtomicGitError): atomic.admit_report(before, parsed)
        parsed = atomic.parse_report(report(before, ("ng", "ng"), reason + b"error: permission denied\n"), before)
        with self.assertRaises(atomic.AtomicGitError): atomic.admit_report(before, parsed)

    def test_only_the_exact_main_policy_refusal_has_a_distinct_negative_classification(self) -> None:
        before = spec(True)
        parsed = atomic.parse_report(report(before, ("ng", "ng"), atomic.GITHUB_MAIN_POLICY_REFUSAL.encode()), before)
        parsed["refs"][0]["reason"] = "push declined due to repository rule violations"
        self.assertEqual(atomic.admit_report(before, parsed), "confirmed_main_policy_refusal")
        invalid = []
        for index in (0, 1):
            for key, value in (("status", "ok"), ("reason", "generic policy refusal"), ("ref", "refs/heads/other")):
                changed = copy.deepcopy(parsed)
                changed["refs"][index][key] = value
                invalid.append(changed)
        for diagnostic in ("GH013", parsed["diagnostic"] + "Bypassed rules\n",
                           parsed["diagnostic"].replace("merge queue", "review"),
                           parsed["diagnostic"].replace("refs/heads/main", "refs/heads/other"),
                           parsed["diagnostic"].replace("ElevenID/marty-ui", "another/repository")):
            invalid.append({**parsed, "diagnostic": diagnostic})
        for changed in invalid:
            with self.subTest(report=changed), self.assertRaises(atomic.AtomicGitError):
                atomic.admit_report(before, changed)
        for request in (spec(), atomic.transaction_spec(R, R, "v1.2.3", A, "release-tag-123-1")):
            for outcomes in (("ng", "ng"), ("ok", "ok")):
                with self.subTest(request=request, outcomes=outcomes), self.assertRaises(atomic.AtomicGitError):
                    atomic.admit_report(request, atomic.parse_report(
                        report(request, outcomes, atomic.GITHUB_MAIN_POLICY_REFUSAL.encode()), request))
    def test_reported_protection_bypass_cannot_count_as_positive_proof(self) -> None:
        parsed = atomic.parse_report(report(spec(), diagnostic=b"Bypassed rule violations for refs/heads/main\n"), spec())
        with self.assertRaises(atomic.AtomicGitError): atomic.admit_report(spec(), parsed)


class HTTPSWorkerTests(unittest.TestCase):
    TOKEN = "ghs_" + "SYNTHETIC" * 4

    def setUp(self) -> None:
        # Production calls this in a disposable process; direct mocked tests
        # must restore the standard-library limits before other CI tests run.
        for name in ("_MAXLINE", "_MAXHEADERS"):
            patch = mock.patch.object(atomic.http.client, name, getattr(atomic.http.client, name))
            patch.start()
            self.addCleanup(patch.stop)

    def request(self, method: str = "GET") -> dict:
        return {"method": method, "path": atomic.DISCOVERY_PATH if method == "GET" else atomic.RECEIVE_PATH,
                "body_base64": "" if method == "GET" else base64.b64encode(atomic.request_bytes(spec())).decode(),
                "token": self.TOKEN, "timeout_seconds": 2}

    def fake(self, body: bytes | None = None, headers: list | None = None, status: int = 200):
        body = advertisement() if body is None else body
        response = mock.Mock()
        response.status = status
        response.getheaders.return_value = headers if headers is not None else [
            ("Content-Type", "application/x-git-receive-pack-advertisement"), ("Content-Length", str(len(body)))]
        response.read.return_value = body
        connection = mock.Mock()
        connection.getresponse.return_value = response
        return connection, response

    def test_canonical_tls_connection_and_token_only_in_authorization_header(self) -> None:
        connection, response = self.fake()
        with mock.patch.object(atomic.http.client, "HTTPSConnection", return_value=connection) as make:
            value = atomic.https_once(self.request())
        args, kwargs = make.call_args
        self.assertEqual(args, ("github.com", 443))
        self.assertTrue(kwargs["context"].check_hostname)
        self.assertEqual(kwargs["context"].verify_mode, atomic.ssl.CERT_REQUIRED)
        self.assertEqual(connection.connect.call_count, 1)
        self.assertEqual(connection.request.call_count, 1)
        self.assertEqual(connection.request.call_args.args[:2], ("GET", atomic.DISCOVERY_PATH))
        self.assertNotIn(self.TOKEN, json.dumps(value))
        response.close.assert_called_once()
        connection.close.assert_called_once()

    def test_redirect_is_not_followed_and_parent_refuses_it(self) -> None:
        connection, _ = self.fake(status=307)
        with mock.patch.object(atomic.http.client, "HTTPSConnection", return_value=connection):
            value = atomic.https_once(self.request())
        with self.assertRaises(atomic.AtomicGitError): atomic.validate_http(value, method="GET")
        self.assertEqual(connection.request.call_count, 1)

    def test_duplicate_or_conflicting_headers_and_encoded_body_refuse(self) -> None:
        for headers in [
            [("Content-Length", "1"), ("content-length", "1")],
            [("Content-Length", "1"), ("Transfer-Encoding", "chunked")],
            [("Content-Encoding", "gzip")], [("Content-Length", "999999999999")],
            [("Content-Type", "text/plain\r\nmalformed")],
        ]:
            connection, _ = self.fake(headers=headers)
            with self.subTest(headers=headers), mock.patch.object(atomic.http.client, "HTTPSConnection", return_value=connection), \
                 self.assertRaises(atomic.AtomicGitError):
                atomic.https_once(self.request())
            connection.close.assert_called_once()

    def test_credentials_echoed_in_body_or_headers_are_never_returned(self) -> None:
        encoded_token = base64.b64encode(("x-access-token:" + self.TOKEN).encode())
        for body, headers in [(self.TOKEN.encode(), []), (encoded_token, []),
                              (b"public", [("Set-Cookie", self.TOKEN)])]:
            connection, _ = self.fake(body=body, headers=headers)
            with mock.patch.object(atomic.http.client, "HTTPSConnection", return_value=connection), \
                 self.assertRaises(atomic.AtomicGitError):
                atomic.https_once(self.request())

    def test_worker_fixed_error_hides_raw_exceptions_and_never_retries(self) -> None:
        connection, _ = self.fake()
        connection.request.side_effect = RuntimeError("synthetic raw secret " + self.TOKEN)
        stdin = mock.Mock(buffer=io.BytesIO(atomic.encoded(self.request())))
        stdout = mock.Mock(buffer=io.BytesIO())
        with mock.patch.object(atomic.sys, "argv", ["worker", "--https-worker"]), \
             mock.patch.object(atomic.sys, "stdin", stdin), mock.patch.object(atomic.sys, "stdout", stdout), \
             mock.patch.object(atomic.http.client, "HTTPSConnection", return_value=connection):
            self.assertEqual(atomic.worker_main(), 1)
        self.assertEqual(stdout.buffer.getvalue(), b'{"status":"transport_refused"}\n')
        self.assertEqual(connection.request.call_count, 1)

    def test_arbitrary_host_path_method_or_input_shape_cannot_launch_http(self) -> None:
        for field, value in [("path", "/other.git/git-receive-pack"), ("method", "PATCH"), ("timeout_seconds", True),
                             ("timeout_seconds", 31), ("body_base64", "!!!")]:
            request = self.request()
            request[field] = value
            with self.subTest(field=field, value=value), mock.patch.object(atomic.http.client, "HTTPSConnection") as make, \
                 self.assertRaises(atomic.AtomicGitError):
                atomic.https_once(request)
            make.assert_not_called()


class ExecutionCustodyTests(unittest.TestCase):
    def setUp(self) -> None:
        # The local suite must never read a connected job's credential value.
        patch = mock.patch.dict(os.environ, {}, clear=True)
        patch.start()
        self.addCleanup(patch.stop)

    def test_actual_corrected_github_negative_is_policy_evidence_but_positive_refusal_still_poisons(self) -> None:
        current = "f1266b3d87476ea8332b1b45a21e77939246d84a"
        ancestor = "c9ee1a764f15d6a4625110d886792a6f247be5f1"
        tag_object = "80cd1f8f38123f0e67db1ec7e5d7206b80444a4e"
        audit_tag = "v-release-capability-41894878943-1"
        request = atomic.transaction_spec(ancestor, current, audit_tag, tag_object,
                                          "capability-negative-41894878943-1")
        raw = GITHUB_STALE_NOOP_POLICY_REFUSAL
        self.assertEqual(len(raw), 465)
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
                         "58e146df0ead6e0cbaf62d0642bbbc8d2bca8e009ea3a67016b057092ff7a7fb")
        calls = []
        saved = []
        def http(method, body):
            calls.append(method)
            return http_result(advertisement(main=current) if method == "GET" else raw, method)
        native = atomic.NativeGit(runner=mock.Mock(), deadline=lambda: datetime.now(timezone.utc) + timedelta(seconds=10),
                                  persist=lambda: saved.append(copy.deepcopy(native.transactions)), http=http)
        result = native.exchange(request)
        self.assertEqual(result["decision"], "confirmed_main_policy_refusal")
        value = saved[-1][-1]
        parsed = value["mutation"]["report"]
        self.assertEqual(parsed["keepalive_packets"], 1)
        self.assertIn("GH013", parsed["diagnostic"])
        self.assertIn("Changes must be made through the merge queue", parsed["diagnostic"])
        self.assertEqual(parsed["refs"], [
            {"ref": "refs/heads/main", "status": "ng", "reason": "push declined due to repository rule violations"},
            {"ref": "refs/tags/" + audit_tag, "status": "ng", "reason": "atomic transaction failed"}])
        self.assertEqual(parsed["body_sha256"], atomic.digest(raw))
        self.assertEqual(base64.b64decode(value["mutation"]["https"]["body_base64"]), raw)
        self.assertEqual(value["mutation"]["outcome"], "confirmed_main_policy_refusal")
        self.assertFalse(native.poisoned)
        positive = atomic.transaction_spec(current, current, audit_tag, tag_object,
                                           "capability-positive-41894878943-1")
        with self.assertRaises(atomic.AtomicGitError):
            native.exchange(positive)
        self.assertTrue(native.poisoned)
        self.assertEqual(saved[-1][-1]["decision"], "unadmitted")
        self.assertEqual(saved[-1][-1]["mutation"]["outcome"], "unknown")
        for retry in (request, positive):
            with self.assertRaises(atomic.AtomicGitError):
                native.exchange(retry)
        self.assertEqual(calls, ["GET", "POST", "GET", "POST"])

    def test_historical_main_update_request_is_never_reclassified_as_a_noop_probe(self) -> None:
        request = atomic.transaction_spec("4882496b125a3df4d639c94f471880b66c51a9d4",
                                          "296917da3baf572e5fbc425e6f3e86392bdba698",
                                          "v-release-capability-41792570662-1",
                                          "53c73031586843e81ad65c9b3e1f2e8e27d88e8f",
                                          "capability-negative-41792570662-1")
        self.assertEqual(hashlib.sha256(GITHUB_RULE_REFUSAL).hexdigest(),
                         "a1e03714848c99445adfe85976ac18ccf37ed7a24ded7bb7764e68ca3ac6ae59")
        self.assertEqual(atomic.parse_report(GITHUB_RULE_REFUSAL, request)["keepalive_packets"], 1)
        request["commands"][0]["new_oid"] = request["observed_main_oid"]
        http = mock.Mock()
        native = atomic.NativeGit(runner=mock.Mock(), deadline=lambda: datetime.now(timezone.utc) + timedelta(seconds=10),
                                  persist=mock.Mock(), http=http)
        with self.assertRaises(atomic.AtomicGitError):
            native.exchange(request)
        http.assert_not_called()
        self.assertEqual(native.transactions, [])

    def test_a_main_movement_cannot_start_discovery_or_write_an_intent(self) -> None:
        request = spec(True)
        request["commands"][0]["new_oid"] = R
        http = mock.Mock()
        persist = mock.Mock()
        native = atomic.NativeGit(runner=mock.Mock(), deadline=lambda: datetime.now(timezone.utc) + timedelta(seconds=10),
                                  persist=persist, http=http)
        with self.assertRaises(atomic.AtomicGitError):
            native.exchange(request)
        http.assert_not_called()
        persist.assert_not_called()
        self.assertEqual(native.transactions, [])

    def test_expired_deadline_cannot_start_discovery_or_read_credentials(self) -> None:
        http = mock.Mock()
        native = atomic.NativeGit(runner=mock.Mock(), deadline=lambda: datetime.now(timezone.utc) - timedelta(seconds=1),
                                  persist=lambda: None, http=http)
        with self.assertRaises(atomic.AtomicGitError): native.exchange(spec())
        http.assert_not_called()

    def test_intent_write_failure_prevents_post_and_consumes_attempt(self) -> None:
        calls = []
        saved = []
        native = None
        def persist() -> None:
            saved.append(copy.deepcopy(native.transactions))
            if native.transactions[-1]["mutation"] is not None: raise OSError("synthetic journal outage")
        def http(method, body):
            calls.append(method)
            return http_result(advertisement(), method)
        native = atomic.NativeGit(runner=mock.Mock(), deadline=lambda: datetime.now(timezone.utc) + timedelta(seconds=10),
                                  persist=persist, http=http)
        with self.assertRaises(OSError): native.exchange(spec())
        with self.assertRaises(atomic.AtomicGitError): native.exchange(spec())
        self.assertEqual(calls, ["GET"])
        self.assertEqual(saved[-1][-1]["mutation"]["outcome"], "unknown")

    def test_worker_input_is_small_private_and_clean_environment_has_no_token(self) -> None:
        token = "ghs_" + "SYNTHETIC" * 5
        deadline = datetime.now(timezone.utc) + timedelta(seconds=9)
        runner = mock.Mock(return_value=(0, atomic.encoded(http_result(advertisement(), "GET"))))
        native = atomic.NativeGit(runner=runner, deadline=lambda: deadline, persist=lambda: None)
        with mock.patch.dict(os.environ, {"GH_TOKEN": token, "HTTPS_PROXY": "synthetic://unused"}, clear=True):
            native._https("GET", None)
        args, options = runner.call_args
        self.assertEqual(args[0][1:4], ["-I", "-S", "-B"])
        self.assertNotIn(token, " ".join(args[0]))
        self.assertLessEqual(len(options["input_bytes"]), 4096)
        self.assertEqual(set(options["environment"]), {"PATH", "LANG", "LC_ALL"})
        self.assertLessEqual(options["timeout"], 9)
        self.assertEqual(json.loads(options["input_bytes"])["token"], token)

    def test_later_provider_value_never_refreshes_the_original_deadline(self) -> None:
        now = datetime.now(timezone.utc)
        provided = [now + timedelta(seconds=20)]
        native = atomic.NativeGit(runner=mock.Mock(), deadline=lambda: provided[0], persist=lambda: None)
        original = native.not_after
        provided[0] = now + timedelta(hours=1)
        self.assertLessEqual(native._remaining(), 20)
        self.assertEqual(native.not_after, original)
        provided[0] = now - timedelta(seconds=1)
        with self.assertRaises(atomic.AtomicGitError): native._remaining()
        provided[0] = now + timedelta(hours=1)
        with self.assertRaises(atomic.AtomicGitError): native._remaining()

    def test_maximum_synthetic_token_and_post_still_fit_private_pipe_bound(self) -> None:
        runner = mock.Mock(return_value=(0, atomic.encoded(http_result(report(spec()), "POST"))))
        native = atomic.NativeGit(runner=runner, deadline=lambda: datetime.now(timezone.utc) + timedelta(seconds=10),
                                  persist=lambda: None)
        with mock.patch.dict(os.environ, {"GH_TOKEN": "S" * 2048}, clear=True):
            native._https("POST", atomic.request_bytes(spec()))
        self.assertLessEqual(len(runner.call_args.kwargs["input_bytes"]), 4096)

    def test_unknown_worker_return_does_not_retry(self) -> None:
        runner = mock.Mock(side_effect=TimeoutError("synthetic"))
        native = atomic.NativeGit(runner=runner, deadline=lambda: datetime.now(timezone.utc) + timedelta(seconds=9), persist=lambda: None)
        with mock.patch.dict(os.environ, {"GH_TOKEN": "ghs_" + "X" * 30}, clear=True):
            with self.assertRaises(TimeoutError): native._https("GET", None)
        self.assertEqual(runner.call_count, 1)

    def test_audit_snapshots_are_exclusive_private_durable_and_detect_path_swap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "operator-api-receipt.json"
            journal = operator.ObservationJournal(path)
            try:
                with mock.patch.object(os, "fsync", wraps=os.fsync) as fsync:
                    journal.write({"outcome": "unknown", "kind": "synthetic"})
                    self.assertGreaterEqual(fsync.call_count, 2)
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                with self.assertRaises(FileExistsError): operator.ObservationJournal(path)
                original = path.read_bytes()
                path.rename(path.with_suffix(".preserved"))
                path.write_bytes(b"{}\n")
                with self.assertRaises(handoff.HandoffError): journal.write({"outcome": "success"})
                self.assertEqual(path.read_bytes(), b"{}\n")
                self.assertEqual(path.with_suffix(".preserved").read_bytes(), original)
            finally:
                journal.close()

    def test_audit_symlink_hardlink_and_credential_echo_refuse(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            target.write_bytes(b"unchanged")
            link = root / "audit"
            link.symlink_to(target)
            with self.assertRaises(OSError): operator.ObservationJournal(link)
            self.assertEqual(target.read_bytes(), b"unchanged")
            path = root / "real"
            journal = operator.ObservationJournal(path)
            try:
                token = "ghs_" + "SYNTHETIC" * 4
                with mock.patch.dict(os.environ, {"GH_TOKEN": token}, clear=True):
                    with self.assertRaises(handoff.HandoffError): journal.write({"secret": token})
                os.link(path, root / "alias")
                with self.assertRaises(handoff.HandoffError): journal.write({"public": True})
            finally:
                journal.close()


if __name__ == "__main__":
    unittest.main()
