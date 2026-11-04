from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("release_review_main", ROOT / "scripts/release_review_main.py")
assert SPEC and SPEC.loader
policy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(policy)
SOURCE = "a" * 40
MAIN = "b" * 40
RUN = 17


def gate_fixture(review: bool = False) -> dict:
    # Binding/transport fixtures only; unchanged Rust tests own actual official
    # module, pixel and disposition qualification.
    value = {"schema": "marty.official-release-gate/v1", "source_sha": SOURCE,
             "harness_sha": "c" * 40, "manifest_sha256": "sha256:" + "d" * 64,
             "run_id": RUN, "qualification_context": "PRE_PUBLICATION_CANDIDATE",
             "lanes": [{"lane": lane, "summary_sha256": "sha256:" + "e" * 64}
                       for lane in sorted(policy.LANES)]}
    if review:
        value["review_disposition"] = {
            "schema": "marty.accepted-official-review/v1", "protected_main_commit": MAIN,
            "record_sha256": "sha256:" + "f" * 64, "request_sha256": "sha256:" + "1" * 64,
            "evidence_run_attempt": 1, "reviewer": {"kind": "delegated_codex", "github_login": "reviewer"},
            "reviewed_cases": 13, "original_official_results_unchanged": True,
        }
    return value


def transaction_for(raw: bytes) -> dict:
    return {"repository": policy.REPOSITORY, "source_sha": SOURCE,
            "gates": {"official_interoperability": {"run_id": str(RUN),
                       "evidence_sha256": "sha256:" + hashlib.sha256(raw).hexdigest()}}}


class TestGateAuthority(unittest.TestCase):
    def authority(self, gate: dict, **kwargs) -> dict:
        raw = json.dumps(gate, separators=(",", ":")).encode()
        return policy.gate_authority(raw, transaction_for(raw), run_id=RUN, **kwargs)

    def test_all_pass_keeps_candidate_main(self) -> None:
        value = self.authority(gate_fixture())
        assert value["protected_main_commit"] == SOURCE
        assert value["review_required"] is False and value["record_sha256"] is None
        assert value["origin_attempt"] == 1

    def test_review_keeps_candidate_and_authorization_identities_separate(self) -> None:
        value = self.authority(gate_fixture(True))
        assert value["source_sha"] == SOURCE and value["protected_main_commit"] == MAIN
        assert value["review_required"] is True
        assert value["record_sha256"] == "sha256:" + "f" * 64

    def test_changed_gate_bytes_cannot_use_the_old_transaction_binding(self) -> None:
        raw = json.dumps(gate_fixture()).encode()
        with self.assertRaisesRegex(policy.ReviewMainError, "transaction binding"):
            policy.gate_authority(raw + b"\n", transaction_for(raw), run_id=RUN)

    def test_wrong_source_run_context_or_lane_inventory_fails(self) -> None:
        mutations = [lambda d: d.update(source_sha=MAIN), lambda d: d.update(run_id=RUN + 1),
                     lambda d: d.update(run_id=True), lambda d: d.update(qualification_context="PUBLISHED"),
                     lambda d: d.update(extra=True), lambda d: d["lanes"].pop(),
                     lambda d: d["lanes"].__setitem__(0, d["lanes"][1])]
        for mutate in mutations:
            with self.subTest(mutation=mutations.index(mutate)):
                value = gate_fixture(); mutate(value)
                with self.assertRaises(policy.ReviewMainError):
                    self.authority(value)

    def test_second_or_boolean_attempt_fails(self) -> None:
        for attempt in (2, True, "1"):
            with self.subTest(attempt=attempt), self.assertRaises(policy.ReviewMainError):
                self.authority(gate_fixture(), current_attempt=attempt)

    def test_duplicate_json_keys_fail_even_with_a_matching_byte_digest(self) -> None:
        raw = json.dumps(gate_fixture(), separators=(",", ":")).encode()
        raw = raw.replace(b'"run_id":17', b'"run_id":17,"run_id":17')
        with self.assertRaisesRegex(policy.ReviewMainError, "duplicate"):
            policy.gate_authority(raw, transaction_for(raw), run_id=RUN)

    def test_deeply_nested_json_refuses_with_the_same_contract_error(self) -> None:
        raw = b'{"nested":' + b"[" * 2000 + b"0" + b"]" * 2000 + b"}"
        # Some JSON implementations parse this iteratively; either parser or
        # closed-schema rejection must still use the public contract error.
        with self.assertRaises(policy.ReviewMainError):
            policy.gate_authority(raw, transaction_for(raw), run_id=RUN)
        with mock.patch.object(policy.json, "loads", side_effect=RecursionError):
            with self.assertRaisesRegex(policy.ReviewMainError, "malformed"):
                policy.gate_authority(raw, transaction_for(raw), run_id=RUN)

    def test_unaccepted_or_foreign_review_metadata_fails(self) -> None:
        changes = [("protected_main_commit", SOURCE), ("evidence_run_attempt", 2),
                   ("evidence_run_attempt", True), ("original_official_results_unchanged", False),
                   ("original_official_results_unchanged", 1), ("reviewed_cases", 0),
                   ("record_sha256", None), ("reviewer", {"kind": [], "github_login": "reviewer"})]
        for key, value in changes:
            with self.subTest(field=key, value=value):
                gate = gate_fixture(True); gate["review_disposition"][key] = value
                with self.assertRaises(policy.ReviewMainError):
                    self.authority(gate)


class TestReviewHistory(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="release-review-history-")
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / "repository"
        self.repo.mkdir()
        self.env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": self.temp.name,
                    "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                    "GIT_AUTHOR_NAME": "Unit Fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
                    "GIT_COMMITTER_NAME": "Unit Fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid"}
        self.git("init", "-q", "--initial-branch=main")
        (self.repo / "product.txt").write_text("original product\n")
        self.source = self.commit("candidate")
        self.record = self.repo / policy.review_path(RUN)

    def git(self, *args: str) -> str:
        result = subprocess.run(["git", "--no-replace-objects", "-c", "protocol.allow=never", *args],
                                cwd=self.repo, env=self.env, capture_output=True, text=True, timeout=10, check=True)
        return result.stdout.strip()

    def commit(self, message: str) -> str:
        self.git("add", "--all")
        self.git("-c", f"core.hooksPath={os.devnull}", "commit", "-qm", message, "--no-gpg-sign")
        return self.git("rev-parse", "HEAD")

    def add_record(self, content: bytes = b'{"transport_fixture_only":true}\n') -> str:
        self.record.parent.mkdir(parents=True, exist_ok=True)
        self.record.write_bytes(content)
        return self.commit("exact review record")

    def check(self, main: str, review: bool = True, digest: str | None = None) -> None:
        policy.require_review_only_history(self.source, main, RUN, 1, review,
                                           repository=self.repo, record_sha256=digest)

    def test_unchanged_all_pass_and_pending_main_are_allowed(self) -> None:
        self.check(self.source, False)
        self.check(self.source, True)

    def test_exact_new_record_and_matching_digest_are_allowed(self) -> None:
        main = self.add_record()
        self.check(main, digest="sha256:" + hashlib.sha256(self.record.read_bytes()).hexdigest())

    def test_all_pass_cannot_use_a_descendant(self) -> None:
        with self.assertRaisesRegex(policy.ReviewMainError, "unchanged"):
            self.check(self.add_record(), False)

    def test_changed_then_reverted_product_cannot_hide_in_history(self) -> None:
        product = self.repo / "product.txt"
        product.write_text("unrelated change\n"); self.commit("unrelated")
        product.write_text("original product\n"); self.commit("revert unrelated")
        with self.assertRaisesRegex(policy.ReviewMainError, "outside"):
            self.check(self.add_record())

    def test_foreign_review_record_is_not_an_allowed_path(self) -> None:
        self.add_record()
        (self.record.parent / "18-1.json").write_text("{}\n")
        with self.assertRaisesRegex(policy.ReviewMainError, "outside"):
            self.check(self.commit("foreign record"))

    def test_an_unrelated_root_is_not_an_ancestor(self) -> None:
        tree = self.git("rev-parse", "HEAD^{tree}")
        other = self.git("commit-tree", tree, "-m", "unrelated root")
        with self.assertRaises(policy.ReviewMainError):
            self.check(other)

    def test_symlink_and_executable_record_fail(self) -> None:
        self.record.parent.mkdir(parents=True)
        self.record.symlink_to("../../product.txt")
        with self.assertRaisesRegex(policy.ReviewMainError, "ordinary"):
            self.check(self.commit("symlink"))
        self.git("reset", "--hard", self.source)
        self.record.parent.mkdir(parents=True, exist_ok=True)
        self.record.write_text("{}\n"); self.record.chmod(0o755)
        with self.assertRaisesRegex(policy.ReviewMainError, "ordinary"):
            self.check(self.commit("executable record"))

    def test_candidate_cannot_supply_its_own_future_record(self) -> None:
        self.source = self.add_record()
        with self.assertRaisesRegex(policy.ReviewMainError, "already contains"):
            self.check(self.source)

    def test_record_deletion_cannot_hide_behind_readdition(self) -> None:
        self.add_record()
        self.record.unlink(); self.commit("delete record")
        with self.assertRaisesRegex(policy.ReviewMainError, "deletes"):
            self.check(self.add_record())

    def test_changed_record_bytes_fail_the_accepted_hash(self) -> None:
        with self.assertRaisesRegex(policy.ReviewMainError, "differs"):
            self.check(self.add_record(), digest="sha256:" + "0" * 64)

    def test_accepted_hash_cannot_point_at_still_pending_main(self) -> None:
        with self.assertRaisesRegex(policy.ReviewMainError, "absent"):
            self.check(self.source, digest="sha256:" + "0" * 64)

    def test_shallow_replace_and_graft_histories_fail(self) -> None:
        main = self.add_record()
        shallow = self.repo / ".git/shallow"; shallow.write_text(self.source + "\n")
        with self.assertRaisesRegex(policy.ReviewMainError, "shallow"):
            self.check(main)
        shallow.unlink()
        self.git("replace", self.source, main)
        with self.assertRaisesRegex(policy.ReviewMainError, "replace"):
            self.check(main)
        self.git("replace", "-d", self.source)
        graft = self.repo / ".git/info/grafts"; graft.write_text("")
        with self.assertRaisesRegex(policy.ReviewMainError, "grafts"):
            self.check(main)

    def test_history_and_record_limits_fail_closed(self) -> None:
        self.add_record()
        main = self.add_record(b'{"transport_fixture_only":"revised"}\n')
        with mock.patch.object(policy, "MAX_HISTORY_COMMITS", 1):
            with self.assertRaisesRegex(policy.ReviewMainError, "complete bound"):
                self.check(main)
        with mock.patch.object(policy, "MAX_RECORD_BYTES", 1):
            with self.assertRaisesRegex(policy.ReviewMainError, "size bound"):
                self.check(main)

    def test_history_verification_has_one_absolute_deadline(self) -> None:
        with mock.patch.object(policy.time, "monotonic", side_effect=[0, 31]):
            with self.assertRaisesRegex(policy.ReviewMainError, "exceeded"):
                self.check(self.source)

    def test_caller_remaining_time_caps_the_entire_history_check(self) -> None:
        with mock.patch.object(policy.time, "monotonic", side_effect=[10, 12]):
            with self.assertRaisesRegex(policy.ReviewMainError, "exceeded"):
                policy.require_review_only_history(self.source, self.source, RUN, 1, False,
                                                   repository=self.repo, timeout_seconds=1)
        with mock.patch.object(policy.time, "monotonic", return_value=10):
            self.assertEqual(policy._Git(self.repo, 300).deadline, 40)
            self.assertEqual(policy._Git(self.repo, 2.5).deadline, 12.5)

    def test_invalid_caller_deadlines_fail_before_git(self) -> None:
        for value in (0, -1, True, "1", float("nan"), float("inf")):
            with self.subTest(value=value), mock.patch.object(policy.subprocess, "run") as process:
                with self.assertRaisesRegex(policy.ReviewMainError, "positive and finite"):
                    policy.require_review_only_history(self.source, self.source, RUN, 1, False,
                                                       repository=self.repo, timeout_seconds=value)
                process.assert_not_called()


if __name__ == "__main__":
    unittest.main()
