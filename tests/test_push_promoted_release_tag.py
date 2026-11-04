"""Offline controls for the native tag operator; these are not API capability proof."""
from __future__ import annotations

import copy
import io
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import push_promoted_release_tag as operator
from scripts import release_tag_handoff as handoff

SOURCE = "a" * 40
MAIN = "b" * 40
OBJECT = "c" * 40

# Names are from actual public CD41726515793 attempt1. IDs, lifecycle states and
# step records below are explicitly synthetic; none is release qualification.
ACTUAL_JOB_NAMES = (
    "resolve-transaction", "release-environment-preflight / validate", "validate-stack",
    "build-openbao-didcomm", "build-operator-catalog (ubuntu-24.04-arm, arm64, AArch64, aarch64-unknown-linux-musl)",
    "build-services", "build-operator-catalog (ubuntu-24.04, amd64, Advanced Micro Devices X86-64, x86_64-unknown-linux-...",
    "build-keycloak", "build-ui", "record-digests", "public-stack-smoke", "keycloak-kms-image-qualification",
    "prepare-official-candidate", "verifier-differential", "didcomm-plugin-image-qualification",
    "native-schema-image-qualification", "Collect seven official candidate lanes / oid4vp-final",
    "Collect seven official candidate lanes / oid4vp-mdoc", "Collect seven official candidate lanes / oid4vci-issuer",
    "Collect seven official candidate lanes / haip", "Collect seven official candidate lanes / w3c-v2",
    "Collect seven official candidate lanes / eudi", "Collect seven official candidate lanes / oid4vp-url-query",
    "official-gate-evidence", "build-selfhost-lock-roles", "preflight-selfhost-prepared-consumer",
    "prepare-selfhost-image-lock", "prepare-installer-inputs", "qualify-release", "publish-manifest",
    "publish-cloudflare-addon",
)


def jobs_fixture() -> list[dict]:
    jobs = [{"id": index + 1, "name": name, "run_id": 123, "run_attempt": 1, "head_sha": SOURCE,
             "status": "completed", "conclusion": "success"} for index, name in enumerate(ACTUAL_JOB_NAMES)]
    publisher = next(job for job in jobs if job["name"] == "publish-manifest")
    before = sorted(operator.MANDATORY_PUBLISH_STEPS)
    publisher.update(status="in_progress", conclusion=None, steps=[
        {"number": index + 1, "name": name, "status": "completed", "conclusion": "success"}
        for index, name in enumerate(before)
    ] + [{"number": len(before) + 1, "name": handoff.WAIT_STEP, "status": "in_progress", "conclusion": None},
         {"number": len(before) + 2, "name": "Publish the qualified GitHub release and exact assets",
          "status": "pending", "conclusion": None}])
    jobs[-1].update(status="queued", conclusion=None)
    return jobs


class OperatorStateTests(unittest.TestCase):
    def test_actual_matrix_and_reusable_job_names_admit_only_completed_prerequisites(self) -> None:
        operator.validate_waiting_jobs(jobs_fixture(), 123, SOURCE)

    def test_optional_downstream_can_be_skipped_or_waiting_but_cannot_already_run(self) -> None:
        for status, conclusion, accepted in (
            ("completed", "skipped", True), ("waiting", None, True),
            ("in_progress", None, False), ("completed", "failure", False),
        ):
            with self.subTest(status=status, conclusion=conclusion):
                jobs = jobs_fixture()
                jobs[-1].update(status=status, conclusion=conclusion)
                if accepted:
                    operator.validate_waiting_jobs(jobs, 123, SOURCE)
                else:
                    with self.assertRaises(handoff.HandoffError):
                        operator.validate_waiting_jobs(jobs, 123, SOURCE)

    def test_missing_failed_skipped_foreign_and_later_prerequisites_refuse(self) -> None:
        for mutation in ("missing_lane", "failed", "skipped", "attempt", "source", "future_step", "skipped_crypto"):
            with self.subTest(mutation=mutation):
                jobs = jobs_fixture()
                if mutation == "missing_lane":
                    jobs = [job for job in jobs if not job["name"].endswith(" / haip")]
                elif mutation in {"failed", "skipped"}:
                    jobs[4]["conclusion"] = "failure" if mutation == "failed" else "skipped"
                elif mutation == "attempt":
                    jobs[0]["run_attempt"] = 2
                elif mutation == "source":
                    jobs[0]["head_sha"] = MAIN
                else:
                    publisher = next(job for job in jobs if job["name"] == "publish-manifest")
                    step = publisher["steps"][-1] if mutation == "future_step" else publisher["steps"][0]
                    step.update(status="in_progress", conclusion=None) if mutation == "future_step" else step.update(conclusion="skipped")
                with self.assertRaises(handoff.HandoffError):
                    operator.validate_waiting_jobs(jobs, 123, SOURCE)

    def test_wait_step_must_be_unique_and_actually_in_progress(self) -> None:
        for mutation in ("duplicate", "completed", "absent"):
            with self.subTest(mutation=mutation):
                jobs = jobs_fixture()
                publisher = next(job for job in jobs if job["name"] == "publish-manifest")
                wait = next(step for step in publisher["steps"] if step["name"] == handoff.WAIT_STEP)
                if mutation == "duplicate":
                    publisher["steps"].append({**wait, "number": 99})
                elif mutation == "completed":
                    wait.update(status="completed", conclusion="success")
                else:
                    publisher["steps"].remove(wait)
                with self.assertRaises(handoff.HandoffError):
                    operator.validate_waiting_jobs(jobs, 123, SOURCE)

    def test_boolean_job_attempt_and_numeric_ids_are_not_integers(self) -> None:
        for field in ("id", "run_id", "run_attempt"):
            with self.subTest(field=field):
                jobs = jobs_fixture()
                jobs[0][field] = True
                with self.assertRaises(handoff.HandoffError):
                    operator.validate_waiting_jobs(jobs, 123, SOURCE)


class AtomicContractTests(unittest.TestCase):
    def setUp(self) -> None:
        patch = mock.patch.dict(operator.os.environ, {}, clear=True)
        patch.start()
        self.addCleanup(patch.stop)

    @staticmethod
    def native_receipt(request: dict) -> dict:
        negative = request["operation_id"].startswith("capability-negative-")
        outcome = "confirmed_stale_main_refusal" if negative else "confirmed_success"
        return {"transport": operator.atomic.TRANSPORT, "request": request,
                "not_after": "2026-01-01T00:10:00Z",
                "discovery": {"admitted": {"main_oid": MAIN, "tag_absent": True,
                                           "body_sha256": "sha256:" + "d" * 64}},
                "mutation": {"method": "POST", "path": operator.atomic.RECEIVE_PATH,
                             "requested_at": "2026-01-01T00:00:00Z", "body_sha256": "sha256:" + "e" * 64,
                             "body_bytes": 400, "outcome": outcome,
                             "report": {"unpack": "ok", "refs": [], "diagnostic": "synthetic caller fixture"}},
                "decision": outcome}

    def capability_fixture(self, changed_rules: bool = False):
        github = mock.Mock()
        github.deadline = datetime.now(timezone.utc) + timedelta(seconds=30)
        github.main.return_value = {"commit": {"sha": MAIN}}
        github.json.return_value = None
        native = mock.Mock()
        native.exchange.side_effect = self.native_receipt
        inspection = {"rulesets_sha256": "sha256:" + "f" * 64, "rulesets": []}
        final = {**inspection, "rulesets": [{"id": 1}]} if changed_rules else inspection
        return github, native, inspection, final

    def test_capability_preserves_stale_before_only_then_noop_and_ancestor_tag_target(self) -> None:
        github, native, inspection, final = self.capability_fixture()
        with mock.patch.object(handoff, "git", side_effect=[SOURCE, "", ""]), \
             mock.patch.object(operator, "create_tag_object", return_value={"sha": OBJECT}) as create, \
             mock.patch.object(operator, "read_exact_tag") as read, \
             mock.patch.object(operator, "inspect_repository", return_value=(123, MAIN, final)):
            result = operator.qualify_capability(github, native, 123, MAIN, inspection)
        requests = [call.args[0] for call in native.exchange.call_args_list]
        self.assertEqual(len(requests), 2)
        self.assertEqual(requests[0]["commands"][0], {"ref": "refs/heads/main", "old_oid": SOURCE, "new_oid": MAIN})
        self.assertEqual(requests[1]["commands"][0], {"ref": "refs/heads/main", "old_oid": MAIN, "new_oid": MAIN})
        self.assertEqual(create.call_args.args[2], SOURCE)
        self.assertEqual(read.call_args.args[3], SOURCE)
        self.assertEqual(result["schema"], "marty.release-tag-capability/v2")
        self.assertEqual(result["transport"], operator.atomic.TRANSPORT)
        self.assertIn("negative_transaction", result)
        self.assertNotIn("negative_response", result)
        self.assertNotIn("graphql", str(native.mock_calls))

    def test_capability_final_rule_drift_is_not_accepted(self) -> None:
        github, native, inspection, final = self.capability_fixture(changed_rules=True)
        with mock.patch.object(handoff, "git", side_effect=[SOURCE, "", ""]), \
             mock.patch.object(operator, "create_tag_object", return_value={"sha": OBJECT}), \
             mock.patch.object(operator, "read_exact_tag"), \
             mock.patch.object(operator, "inspect_repository", return_value=(123, MAIN, final)), \
             self.assertRaises(handoff.HandoffError):
            operator.qualify_capability(github, native, 123, MAIN, inspection)
        self.assertEqual(native.exchange.call_count, 2)

    def test_unattributed_negative_prevents_positive_dispatch(self) -> None:
        github, native, inspection, _ = self.capability_fixture()
        native.exchange.side_effect = operator.atomic.AtomicGitError("synthetic generic refusal")
        with mock.patch.object(handoff, "git", side_effect=[SOURCE, "", ""]), \
             mock.patch.object(operator, "create_tag_object", return_value={"sha": OBJECT}), \
             mock.patch.object(operator, "read_exact_tag") as read, \
             self.assertRaises(operator.atomic.AtomicGitError):
            operator.qualify_capability(github, native, 123, MAIN, inspection)
        self.assertEqual(native.exchange.call_count, 1)
        read.assert_not_called()

    def test_changed_workflows_prevent_any_capability_object_or_native_write(self) -> None:
        github, native, inspection, _ = self.capability_fixture()
        with mock.patch.object(handoff, "git", side_effect=[SOURCE, "", ".github/workflows/changed.yml"]), \
             mock.patch.object(operator, "create_tag_object") as create, self.assertRaises(handoff.HandoffError):
            operator.qualify_capability(github, native, 123, MAIN, inspection)
        create.assert_not_called()
        native.exchange.assert_not_called()

    def test_rest_intent_persistence_failure_prevents_subprocess_dispatch(self) -> None:
        github = handoff.GitHub(observer=mock.Mock(side_effect=OSError("synthetic audit outage")))
        with mock.patch.object(handoff, "command") as command, self.assertRaises(OSError):
            github.response("repos/ElevenID/marty-ui/git/tags", method="POST", payload={"synthetic": True})
        command.assert_not_called()
        self.assertEqual(len(github.mutations), 1)
        self.assertEqual(github.mutations[0]["outcome"], "unknown")

    def test_rest_transport_timeout_retains_consumed_intent_without_retry(self) -> None:
        persisted = []
        github = handoff.GitHub(observer=lambda: persisted.append(copy.deepcopy(github.mutations)))
        with mock.patch.object(handoff, "command", side_effect=TimeoutError("synthetic")) as command, \
             self.assertRaises(TimeoutError):
            github.response("repos/ElevenID/marty-ui/git/tags", method="POST", payload={"synthetic": True})
        self.assertEqual(command.call_count, 1)
        self.assertEqual(persisted[0][0]["outcome"], "unknown")

    def test_inspect_entry_writes_distinct_v2_observation_without_any_git_transport(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "tag-handoff-result.json"
            args = ["operator", "--mode", "inspect", "--output", str(output)]
            with mock.patch.object(operator.sys, "argv", args), \
                 mock.patch.object(operator, "inspect_repository", return_value=(123, MAIN, {"rulesets": []})), \
                 mock.patch.object(operator.atomic.NativeGit, "exchange") as exchange:
                self.assertEqual(operator.main(), 0)
            exchange.assert_not_called()
            self.assertEqual(json.loads(output.read_bytes())["status"], "inspected")
            audit = json.loads(output.with_name("operator-api-receipt.json").read_bytes())
            self.assertEqual(audit["schema"], "marty.release-tag-operator-observations/v2")
            self.assertEqual(audit["rest_api_mutations"], [])
            self.assertEqual(audit["git_transactions"], [])

    def test_unknown_entry_outcome_preserves_intent_and_only_fixed_error_output(self) -> None:
        def lose_result(github, *args):
            github.mutations.append({"outcome": "unknown", "request": {"synthetic": True}})
            github.observer()
            raise TimeoutError("synthetic private transport detail")
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "tag-handoff-result.json"
            args = ["operator", "--mode", "qualify-capability", "--output", str(output)]
            stdout = io.StringIO()
            with mock.patch.object(operator.sys, "argv", args), mock.patch.object(operator.sys, "stdout", stdout), \
                 mock.patch.object(operator, "inspect_repository", return_value=(123, MAIN, {"rulesets": []})), \
                 mock.patch.object(operator, "qualify_capability", side_effect=lose_result) as qualify:
                self.assertEqual(operator.main(), 1)
            self.assertEqual(qualify.call_count, 1)
            self.assertNotIn("private transport detail", stdout.getvalue())
            self.assertEqual(json.loads(output.read_bytes())["status"], "refused")
            audit = json.loads(output.with_name("operator-api-receipt.json").read_bytes())
            self.assertEqual(audit["rest_api_mutations"][0]["outcome"], "unknown")
            self.assertIs(audit["automatic_retry_or_cleanup_performed"], False)


class CryptoDelegationTests(unittest.TestCase):
    def test_every_subject_delegates_to_original_exact_attempt_verifier(self) -> None:
        from scripts import verify_installer_provenance as provenance
        subjects = ["subject-" + str(index) for index in range(13)]
        calls = []

        def command(arguments, **kwargs):
            self.assertLessEqual(kwargs["timeout"], 45)
            calls.append(arguments)
            return 0, (("\n".join(subjects) + "\n").encode() if arguments[0] == "bash" else b"")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            request = {"source_sha": SOURCE, "run_id": 123, "tag": "v1.2.3"}
            deadline = datetime.now(timezone.utc) + timedelta(seconds=45)
            with mock.patch.object(handoff, "command", side_effect=command), mock.patch.object(provenance, "verify_subject") as verify:
                operator.verify_crypto(root, request, root / "gh", root / "cosign", deadline)
            self.assertEqual(verify.call_count, 13)
            for call, name in zip(verify.call_args_list, subjects):
                self.assertEqual(call.args, (root / name, root / "install.sh.provenance.jsonl"))
                self.assertEqual(call.kwargs["source_sha"], SOURCE)
                self.assertEqual(call.kwargs["run_id"], 123)
                self.assertEqual(call.kwargs["run_attempt"], 1)
                self.assertEqual(call.kwargs["signature_bundle"], root / (name + ".sigstore.json"))
            self.assertIn(str(ROOT / "scripts/stable_installer_assets.py"), calls[-1])
            self.assertIn("verify-published", calls[-1])


if __name__ == "__main__":
    unittest.main()
