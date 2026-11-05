"""Offline controls for the native tag operator; these are not API capability proof."""
from __future__ import annotations

import copy
import hashlib
import io
import json
import sys
import tempfile
import unittest
import zipfile
from contextlib import ExitStack
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


class ReservationContractTests(unittest.TestCase):
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
        github.create_tag_ref.side_effect = handoff.tag_ref_creation
        native = mock.Mock()
        native.exchange.side_effect = self.native_receipt
        inspection = {"rulesets_sha256": "sha256:" + "f" * 64, "rulesets": [{
            "id": 1, "target": "branch", "enforcement": "active", "bypass_actors": [],
            "source_type": "Repository", "source": "ElevenID/marty-ui",
            "current_user_can_bypass": "never", "rules": [{"type": "merge_queue"}],
            "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
        }]}
        final = {**inspection, "rulesets": [{"id": 1}]} if changed_rules else inspection
        return github, native, inspection, final

    def test_capability_preserves_native_negative_then_reserves_only_the_ancestor_tag(self) -> None:
        github, native, inspection, final = self.capability_fixture()
        with mock.patch.object(handoff, "git", side_effect=[SOURCE, "", ""]), \
             mock.patch.object(operator, "create_tag_object", return_value={"sha": OBJECT}) as create, \
             mock.patch.object(operator, "read_exact_tag") as read, \
             mock.patch.object(operator, "inspect_repository", return_value=(123, MAIN, final)):
            result = operator.qualify_capability(github, native, 123, MAIN, inspection)
        requests = [call.args[0] for call in native.exchange.call_args_list]
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0]["commands"][0], {"ref": "refs/heads/main", "old_oid": SOURCE, "new_oid": SOURCE})
        self.assertEqual(requests[0]["observed_main_oid"], MAIN)
        self.assertEqual(github.create_tag_ref.call_args_list, [
            mock.call("v-release-capability-intent-123-1", OBJECT), mock.call("v-release-capability-123-1", OBJECT)])
        self.assertEqual(create.call_args.args[2], SOURCE)
        self.assertEqual(read.call_args.args[3], SOURCE)
        self.assertEqual(result["schema"], "marty.release-tag-capability/v5")
        self.assertEqual(result["tag_handoff_contract"], handoff.TAG_HANDOFF_CONTRACT)
        self.assertEqual(result["ref_creation_scope"], "absent_tag_only")
        self.assertEqual(result["main_check_scope"], "before_after_observation")
        self.assertIs(result["tag_alone_authorizes_publication"], False)
        self.assertEqual(result["main_protection_ruleset_ids"], [1])
        self.assertEqual(result["main_protection_scope"], "current_workflow_credential")
        self.assertEqual(result["main_protection_observations"], [{"ruleset_id": 1,
                         "current_user_can_bypass": "never", "bypass_actor_inventory_visibility": "observed_empty"}])
        self.assertEqual(result["negative_probe_scope"], "stale_or_policy_refusal_only")
        self.assertEqual(result["positive_ref_creation"], handoff.tag_ref_creation("v-release-capability-123-1", OBJECT))
        self.assertEqual(result["intent_ref_creation"], handoff.tag_ref_creation("v-release-capability-intent-123-1", OBJECT))
        self.assertNotIn("positive_transaction", result)
        self.assertIn("negative_transaction", result)
        self.assertNotIn("negative_response", result)
        self.assertNotIn("graphql", str(native.mock_calls))

    def test_capability_final_rule_drift_is_not_accepted(self) -> None:
        github, native, inspection, final = self.capability_fixture(changed_rules=True)
        with mock.patch.object(handoff, "git", side_effect=[SOURCE, "", ""]), \
             mock.patch.object(operator, "create_tag_object", return_value={"sha": OBJECT}), \
             mock.patch.object(operator, "read_exact_tag"), \
             mock.patch.object(operator, "inspect_repository", side_effect=[(123, MAIN, inspection),
                                                                           (123, MAIN, inspection), (123, MAIN, final)]), \
             self.assertRaises(handoff.HandoffError):
            operator.qualify_capability(github, native, 123, MAIN, inspection)
        self.assertEqual(native.exchange.call_count, 1)
        self.assertEqual(github.create_tag_ref.call_count, 2)

    def test_policy_negative_requires_successful_positive_and_preserves_distinct_evidence(self) -> None:
        for positive in ("confirmed_created", "refused", "unknown"):
            github, native, inspection, _ = self.capability_fixture()
            def receipt(request):
                result = self.native_receipt(request)
                decision = "confirmed_main_policy_refusal"
                result["decision"] = result["mutation"]["outcome"] = decision
                return result
            native.exchange.side_effect = receipt
            def reserve(tag, object_sha):
                if tag == "v-release-capability-123-1" and positive != "confirmed_created":
                    raise handoff.HandoffError(positive)
                return handoff.tag_ref_creation(tag, object_sha)
            github.create_tag_ref.side_effect = reserve
            with self.subTest(positive=positive), \
                 mock.patch.object(handoff, "git", side_effect=[SOURCE, "", ""]), \
                 mock.patch.object(operator, "create_tag_object", return_value={"sha": OBJECT}), \
                 mock.patch.object(operator, "read_exact_tag") as read, \
                 mock.patch.object(operator, "inspect_repository", return_value=(123, MAIN, inspection)) as inspect:
                if positive == "confirmed_created":
                    result = operator.qualify_capability(github, native, 123, MAIN, inspection)
                    self.assertEqual(result["negative_transaction"]["decision"], "confirmed_main_policy_refusal")
                    self.assertEqual(result["positive_ref_creation"]["decision"], "confirmed_created")
                    self.assertEqual(inspect.call_count, 3)
                    self.assertEqual(read.call_count, 4)
                else:
                    with self.assertRaises(handoff.HandoffError):
                        operator.qualify_capability(github, native, 123, MAIN, inspection)
                    self.assertEqual(read.call_count, 2)
                    self.assertEqual(read.call_args.args[1], "v-release-capability-intent-123-1")
                self.assertEqual(native.exchange.call_count, 1)
                self.assertEqual(github.create_tag_ref.call_count, 2)

    def test_rule_drift_after_negative_prevents_positive_dispatch(self) -> None:
        github, native, inspection, final = self.capability_fixture(changed_rules=True)
        with mock.patch.object(handoff, "git", side_effect=[SOURCE, "", ""]), \
             mock.patch.object(operator, "create_tag_object", return_value={"sha": OBJECT}), \
             mock.patch.object(operator, "read_exact_tag") as read, \
             mock.patch.object(operator, "inspect_repository", return_value=(123, MAIN, final)), \
             self.assertRaises(handoff.HandoffError):
            operator.qualify_capability(github, native, 123, MAIN, inspection)
        self.assertEqual(native.exchange.call_count, 1)
        github.create_tag_ref.assert_not_called()
        read.assert_not_called()

    def test_effective_current_credential_main_queue_is_required_before_any_write(self) -> None:
        cases = [
            ("id", True), ("target", "tag"), ("enforcement", "evaluate"),
            ("source_type", "Organization"), ("source", "another/repository"),
            ("bypass_actors", [{"actor_id": 1, "bypass_mode": "always"}]),
            ("bypass_actors", None), ("bypass_actors", {}), ("bypass_actors", ""),
            ("bypass_actors", False), ("bypass_actors", ()), ("current_user_can_bypass", "always"),
            ("current_user_can_bypass", "pull_requests_only"), ("current_user_can_bypass", None),
            ("current_user_can_bypass", ""), ("current_user_can_bypass", True),
            ("rules", [{"type": "pull_request"}]),
            ("rules", None), ("conditions", None),
            ("conditions", {"ref_name": {"include": ["refs/heads/other"], "exclude": []}}),
            ("conditions", {"ref_name": {"include": ["~ALL"], "exclude": []}}),
            ("conditions", {"ref_name": {"include": ["refs/heads/main"], "exclude": ["refs/heads/main"]}}),
            ("conditions", {"ref_name": {"include": ["refs/heads/main"], "exclude": []},
                            "repository_name": {"include": ["another"], "exclude": []}}),
        ]
        for field, value in cases:
            github, native, inspection, _ = self.capability_fixture()
            inspection["rulesets"][0][field] = value
            with self.subTest(field=field, value=value), \
                 mock.patch.object(operator, "create_tag_object") as create, self.assertRaises(handoff.HandoffError):
                operator.qualify_capability(github, native, 123, MAIN, inspection)
            create.assert_not_called()
            native.exchange.assert_not_called()
            github.create_tag_ref.assert_not_called()

    @staticmethod
    def actual_runner_inspection() -> dict:
        # Unchanged public read-only result from run 41791774863 attempt 1,
        # artifact 13303856131. Its ZIP digest is retained in the gate runbook.
        # This authentic visibility fixture is not a successful capability run.
        raw = (ROOT / "tests/fixtures/release-tag-inspection-41791774863.json").read_bytes()
        if hashlib.sha256(raw).hexdigest() != "e6c95215e27066bb7ada10df8263764546fd22bbb2a3a8893071851f19cf9e57":
            raise AssertionError("Original runner inspection fixture changed")
        packet = json.loads(raw)
        # The saved inspect-mode envelope contains its own run/schema fields.
        # inspect_repository returns only these original snapshot fields.
        return {key: packet[key] for key in ("repository_id", "repository_node_id", "rulesets", "rulesets_sha256")}

    def test_actual_runner_omission_preserves_unknown_inventory_and_requires_confirmed_reservation(self) -> None:
        inspection = self.actual_runner_inspection()
        original = copy.deepcopy(inspection)
        for positive in ("confirmed_created", "refused", "unknown"):
            github, native, _, _ = self.capability_fixture()
            def receipt(request):
                result = self.native_receipt(request)
                decision = "confirmed_main_policy_refusal"
                result["decision"] = result["mutation"]["outcome"] = decision
                return result
            native.exchange.side_effect = receipt
            def reserve(tag, object_sha):
                if tag == "v-release-capability-123-1" and positive != "confirmed_created":
                    raise handoff.HandoffError(positive)
                return handoff.tag_ref_creation(tag, object_sha)
            github.create_tag_ref.side_effect = reserve
            with self.subTest(positive=positive), \
                 mock.patch.object(handoff, "git", side_effect=[SOURCE, "", ""]), \
                 mock.patch.object(operator, "create_tag_object", return_value={"sha": OBJECT}), \
                 mock.patch.object(operator, "read_exact_tag") as read, \
                 mock.patch.object(operator, "inspect_repository", return_value=(123, MAIN, inspection)):
                if positive == "confirmed_created":
                    result = operator.qualify_capability(github, native, 123, MAIN, inspection)
                    self.assertEqual(result["schema"], "marty.release-tag-capability/v5")
                    self.assertEqual(result["main_protection_scope"], "current_workflow_credential")
                    self.assertEqual(result["main_protection_observations"], [{"ruleset_id": 20775473,
                        "current_user_can_bypass": "never", "bypass_actor_inventory_visibility": "not_disclosed"}])
                    self.assertEqual(result["rulesets"], original["rulesets"])
                    self.assertEqual(result["rulesets_sha256"], original["rulesets_sha256"])
                    self.assertTrue(all("bypass_actors" not in rule for rule in result["rulesets"]))
                    self.assertEqual(read.call_count, 4)
                else:
                    with self.assertRaises(handoff.HandoffError):
                        operator.qualify_capability(github, native, 123, MAIN, inspection)
                    self.assertEqual(read.call_count, 2)
                    self.assertEqual(read.call_args.args[1], "v-release-capability-intent-123-1")
            self.assertEqual(native.exchange.call_count, 1)
            self.assertEqual(github.create_tag_ref.call_args_list, [
                mock.call("v-release-capability-intent-123-1", OBJECT), mock.call("v-release-capability-123-1", OBJECT)])
            requests = [call.args[0] for call in native.exchange.call_args_list]
            self.assertEqual(requests[0]["commands"][0]["old_oid"], SOURCE)
            self.assertEqual(requests[0]["commands"][0]["new_oid"], SOURCE)
            self.assertEqual(inspection, original)

    def test_omitted_current_actor_capability_never_infers_authority_from_inventory(self) -> None:
        for inventory in ("not_disclosed", "observed_empty"):
            inspection = self.actual_runner_inspection()
            for rule in inspection["rulesets"]:
                rule.pop("current_user_can_bypass")
                if inventory == "observed_empty":
                    rule["bypass_actors"] = []
            github, native, _, _ = self.capability_fixture()
            with self.subTest(inventory=inventory), \
                 mock.patch.object(operator, "create_tag_object") as create, \
                 self.assertRaises(operator.OperatorRefusal) as refusal:
                operator.qualify_capability(github, native, 123, MAIN, inspection)
            self.assertEqual(refusal.exception.reason, "capability_current_credential_not_protected")
            create.assert_not_called()
            native.exchange.assert_not_called()

    def test_visible_actor_capability_or_inventory_visibility_drift_prevents_positive(self) -> None:
        for field, value in (("current_user_can_bypass", "always"), ("bypass_actors", [])):
            inspection = self.actual_runner_inspection()
            changed = copy.deepcopy(inspection)
            changed["rulesets"][0][field] = value
            github, native, _, _ = self.capability_fixture()
            with self.subTest(field=field), \
                 mock.patch.object(handoff, "git", side_effect=[SOURCE, "", ""]), \
                 mock.patch.object(operator, "create_tag_object", return_value={"sha": OBJECT}), \
                 mock.patch.object(operator, "inspect_repository", return_value=(123, MAIN, changed)), \
                 mock.patch.object(operator, "read_exact_tag") as read, \
                 self.assertRaises(handoff.HandoffError):
                operator.qualify_capability(github, native, 123, MAIN, inspection)
            self.assertEqual(native.exchange.call_count, 1)
            read.assert_not_called()

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

    def test_negative_readback_drift_prevents_positive_dispatch(self) -> None:
        for changed in ("main", "tag"):
            with self.subTest(changed=changed):
                github, native, inspection, _ = self.capability_fixture()
                github.main.side_effect = [{"commit": {"sha": MAIN}},
                                           {"commit": {"sha": OBJECT if changed == "main" else MAIN}}]
                github.json.side_effect = [None, None, {"object": {"sha": OBJECT}} if changed == "tag" else None]
                with mock.patch.object(handoff, "git", side_effect=[SOURCE, "", ""]), \
                     mock.patch.object(operator, "create_tag_object", return_value={"sha": OBJECT}), \
                     mock.patch.object(operator, "read_exact_tag") as read, \
                     self.assertRaises(handoff.HandoffError):
                    operator.qualify_capability(github, native, 123, MAIN, inspection)
                self.assertEqual(native.exchange.call_count, 1)
                read.assert_not_called()

    def test_missing_multiple_or_invalid_parents_prevent_any_capability_write(self) -> None:
        for parents in ("", SOURCE + " " + OBJECT, "not-a-commit"):
            with self.subTest(parents=parents):
                github, native, inspection, _ = self.capability_fixture()
                with mock.patch.object(handoff, "git", return_value=parents), \
                     mock.patch.object(operator, "create_tag_object") as create, self.assertRaises(handoff.HandoffError):
                    operator.qualify_capability(github, native, 123, MAIN, inspection)
                create.assert_not_called()
                native.exchange.assert_not_called()

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

    def test_inspect_entry_writes_distinct_v3_observation_without_any_git_transport(self) -> None:
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
            self.assertEqual(audit["schema"], "marty.release-tag-operator-observations/v3")
            self.assertEqual(audit["tag_handoff_contract"], handoff.TAG_HANDOFF_CONTRACT)
            self.assertEqual(audit["main_check_scope"], "before_after_observation")
            self.assertEqual(audit["rest_api_mutations"], [])
            self.assertEqual(audit["git_transactions"], [])

    def test_unknown_entry_outcome_preserves_intent_and_only_fixed_error_output(self) -> None:
        def lose_result(github, *args, **kwargs):
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

    def test_refusal_diagnostics_expose_only_static_stage_and_reason(self) -> None:
        secret = "private-token-and-redirect-https://example.invalid/?signed=secret"
        for failure, expected_stage, expected_reason in (
            ("inspection", "repository_inspection", "handoff_validation_refused"),
            ("protection", "capability_protection", "capability_current_credential_not_protected"),
            ("negative", "capability_negative", "atomic_git_validation_refused"),
        ):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / "tag-handoff-result.json"
                stdout = io.StringIO()
                inspection = self.actual_runner_inspection()
                if failure == "protection":
                    inspection["rulesets"][0].pop("current_user_can_bypass")
                with mock.patch.object(operator.sys, "argv", ["operator", "--mode", "qualify-capability",
                                                               "--output", str(output)]), \
                     mock.patch.object(operator.sys, "stdout", stdout), \
                     mock.patch.object(operator, "inspect_repository", return_value=(123, MAIN, inspection)) as inspect, \
                     mock.patch.object(handoff, "git", side_effect=[SOURCE, "", ""]), \
                     mock.patch.object(operator, "create_tag_object", return_value={"sha": OBJECT}), \
                     mock.patch.object(handoff.GitHub, "json", return_value=None), \
                     mock.patch.object(handoff.GitHub, "main", return_value={"commit": {"sha": MAIN}}), \
                     mock.patch.object(operator.atomic.NativeGit, "exchange",
                                       side_effect=operator.atomic.AtomicGitError(secret)) as exchange:
                    if failure == "inspection":
                        inspect.side_effect = handoff.HandoffError(secret)
                    self.assertEqual(operator.main(), 1)
                result = json.loads(output.read_bytes())
                self.assertEqual(result["status"], "refused")
                self.assertEqual(result["refusal_stage"], expected_stage)
                self.assertEqual(result["refusal_reason"], expected_reason)
                self.assertNotIn(secret, stdout.getvalue() + output.read_text()
                                 + output.with_name("operator-api-receipt.json").read_text())
                self.assertEqual(exchange.call_count, 1 if failure == "negative" else 0)
                self.assertIs(result["automatic_retry_or_cleanup_performed"], False)


class ProductionReservationTests(unittest.TestCase):
    """Real checkpoint/claim/readback gates over a local stateful API model.

    Cryptographic verifiers and review history are explicit boundary doubles;
    these fixtures never claim that synthetic signatures qualify a release.
    """

    def setUp(self) -> None:
        from tests import test_stable_publication_checkpoint as fixtures
        self.fixtures = fixtures
        self.fixture = fixtures.CheckpointTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.make_fixture()
        self.request = self.fixture.prepare(now=datetime.now(timezone.utc))
        self.source_root = self.fixture.base / "source"
        (self.source_root / "release").mkdir(parents=True)
        (self.source_root / "release/stack-lock.json").write_bytes((self.fixture.control / "stack-lock.json").read_bytes())
        claim = fixtures.transaction.create_claim(repository=handoff.REPOSITORY, tag=fixtures.TAG,
            source_sha=SOURCE, stack_lock=self.fixture.control / "stack-lock.json", claim_run_id=fixtures.CLAIM,
            image_uris=fixtures.transaction.IMAGE_URIS, tag_absent=True, release_absent=True,
            version_tags_absent={role: True for role in fixtures.transaction.REQUIRED_IMAGE_ROLES})
        payloads = [{str(path.relative_to(self.fixture.output)): path.read_bytes()
                     for path in self.fixture.output.rglob("*") if path.is_file()},
                    {"release-transaction.json": handoff.encoded(claim), "stack-tag-evidence.json": b"{}"}]
        self.archives, self.artifacts = {}, {}
        for index, (run, name, files) in enumerate(zip(
                (fixtures.RUN, int(fixtures.CLAIM)),
                (f"stack-release-publication-inputs-{fixtures.RUN}-1", "stack-release-claim-v1.2.3"), payloads), 1):
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, "w") as archive:
                for path, raw in files.items():
                    archive.writestr(path, raw)
            self.archives[index] = stream.getvalue()
            self.artifacts[run] = {"id": index, "name": name, "expired": False,
                "digest": handoff.sha256(stream.getvalue()), "size_in_bytes": len(stream.getvalue()),
                "workflow_run": {"id": run, "head_sha": SOURCE, "head_branch": "main", "run_attempt": 1}}
        self.refs, self.objects, self.writes, self.gates = {}, {}, [], []
        self.main_sha = SOURCE
        self.failure = None
        self.cd_status, self.cd_attempt, self.claim_conclusion = "in_progress", 1, "success"
        self.inspection = ReservationContractTests().capability_fixture()[2]
        self.native = mock.Mock()

    def json(self, path, *, absent=False):
        prefix = "repos/ElevenID/marty-ui/"
        if path == prefix + "branches/main":
            return {"name": "main", "protected": True, "commit": {"sha": self.main_sha}}
        if path.startswith(prefix + "actions/runs/"):
            run = int(path.rsplit("/", 1)[1])
            candidate = run == self.fixtures.RUN
            return {"id": run, "run_attempt": self.cd_attempt if candidate else 1,
                    "path": handoff.CD_WORKFLOW if candidate else ".github/workflows/prepare-stack-tag.yml",
                    "event": "workflow_dispatch", "head_branch": "main", "head_sha": SOURCE,
                    "repository": {"id": handoff.REPOSITORY_ID, "full_name": handoff.REPOSITORY},
                    "status": self.cd_status if candidate else "completed",
                    "conclusion": None if candidate and self.cd_status == "in_progress" else self.claim_conclusion}
        if path.startswith(prefix + "git/ref/tags/"):
            ref = "refs/tags/" + path.removeprefix(prefix + "git/ref/tags/")
            value = self.refs.get(ref)
            if value is None and not absent:
                raise handoff.HandoffError("Synthetic reference is absent")
            return copy.deepcopy(value)
        if path.startswith(prefix + "git/tags/"):
            return copy.deepcopy(self.objects[path.rsplit("/", 1)[1]])
        if path == prefix + "releases/tags/v1.2.3":
            return None
        raise AssertionError("Unexpected read: " + path)

    def response(self, github, path, *, method="GET", payload=None):
        self.assertEqual(method, "POST")
        self.assertTrue({"review", "crypto", "digests"} <= set(self.gates), "Every original proof gate must precede writes")
        self.writes.append((method, path, copy.deepcopy(payload)))
        if path == "repos/ElevenID/marty-ui/git/tags":
            self.assertEqual(payload["object"], SOURCE)
            sha = hashlib.sha1(handoff.encoded(payload)).hexdigest()
            value = {"sha": sha, "tag": payload["tag"], "message": payload["message"],
                     "object": {"type": "commit", "sha": payload["object"]}}
            self.objects[sha] = value
            return 201, handoff.encoded(value)
        self.assertEqual(path, "repos/ElevenID/marty-ui/git/refs")
        self.assertEqual(set(payload), {"ref", "sha"})
        self.assertIn(payload["ref"], {"refs/tags/v-release-intent-1.2.3", "refs/tags/v1.2.3"})
        stage = "intent" if payload["ref"] == "refs/tags/v-release-intent-1.2.3" else "production"
        if payload["ref"] in self.refs or self.failure == stage + "-collision":
            return 422, b'{"message":"Reference already exists"}'
        if self.failure == stage + "-timeout-before":
            raise TimeoutError("Synthetic unknown outcome before visible creation")
        self.refs[payload["ref"]] = {"ref": payload["ref"], "object": {"type": "tag", "sha": payload["sha"]}}
        if self.failure == stage + "-timeout-after":
            raise TimeoutError("Synthetic lost acknowledgement after creation")
        if self.failure == stage + "-malformed":
            return 201, b"{}"
        acknowledged = copy.deepcopy(self.refs[payload["ref"]])
        if self.failure == stage + "-ref-drift":
            self.refs[payload["ref"]]["object"]["sha"] = "e" * 40
        if self.failure == stage + "-main-drift":
            self.main_sha = OBJECT
        if self.failure == stage + "-rules-drift":
            self.inspection = {**self.inspection, "rulesets_sha256": "sha256:" + "1" * 64}
        if self.failure == stage + "-cd-stopped":
            self.cd_status = "completed"
        if self.failure == stage + "-expired":
            github.deadline = datetime.now(timezone.utc) - timedelta(seconds=1)
        return 201, handoff.encoded(acknowledged)

    def invoke(self, operator_run=789):
        github = handoff.GitHub(deadline=datetime.now(timezone.utc) + timedelta(seconds=60))
        inspection = copy.deepcopy(self.inspection)
        jobs = jobs_fixture()
        for job in jobs:
            job["run_id"] = self.fixtures.RUN

        def gate(name):
            def verify(*args, **kwargs):
                if self.failure == name:
                    raise handoff.HandoffError("Synthetic refused independent " + name)
                if name == "crypto":
                    self.assertEqual(args[1], self.request)
                    self.assertEqual({path.name for path in args[0].iterdir()}, self.fixtures.checkpoint.ASSET_NAMES)
                self.gates.append(name)
            return verify

        with ExitStack() as held:
            held.enter_context(mock.patch.object(github, "json", side_effect=self.json))
            held.enter_context(mock.patch.object(github, "pages", return_value=jobs))
            held.enter_context(mock.patch.object(github, "artifacts", side_effect=lambda run: [self.artifacts[run]]))
            held.enter_context(mock.patch.object(github, "download", side_effect=lambda artifact, path: path.write_bytes(self.archives[artifact["id"]])))
            held.enter_context(mock.patch.object(github, "response", side_effect=lambda path, **kw: self.response(github, path, **kw)))
            held.enter_context(mock.patch.object(operator, "ROOT", self.source_root))
            held.enter_context(mock.patch.object(handoff, "git", return_value=""))
            held.enter_context(mock.patch.object(operator, "require_review_only_history", side_effect=gate("review")))
            held.enter_context(mock.patch.object(operator, "verify_crypto", side_effect=gate("crypto")))
            held.enter_context(mock.patch.object(operator, "promoted_digests", side_effect=gate("digests")))
            held.enter_context(mock.patch.object(operator, "inspect_repository", side_effect=lambda _: (operator_run, SOURCE, self.inspection)))
            return operator.create_qualified_tag(github, self.native, operator_run, SOURCE, self.fixtures.RUN,
                self.fixtures.CLAIM, self.fixture.base / "gh", self.fixture.base / "cosign", inspection)

    def ref_writes(self):
        return [payload["ref"] for _, path, payload in self.writes if path.endswith("/git/refs")]

    def test_success_requires_retained_original_owner_before_the_exact_production_tag(self) -> None:
        result = self.invoke()
        self.native.exchange.assert_not_called()
        self.assertEqual(self.ref_writes(), ["refs/tags/v-release-intent-1.2.3", "refs/tags/v1.2.3"])
        self.assertEqual(result["schema"], handoff.TAG_RESULT_SCHEMA)
        self.assertIs(result["tag_alone_authorizes_publication"], False)
        intent = self.objects[result["intent_object_sha"]]
        tag = self.objects[result["tag_object_sha"]]
        self.assertIn("Operator-Run: 789", intent["message"])
        self.assertIn("Intent-Object: " + intent["sha"], tag["message"])
        self.assertEqual((intent["object"]["sha"], tag["object"]["sha"]), (SOURCE, SOURCE))
        self.assertEqual(result["intent_ref_creation"], handoff.tag_ref_creation(result["intent_tag"], intent["sha"]))

    def test_all_independent_original_proof_gates_still_precede_any_object_or_ref_write(self) -> None:
        for stage in ("review", "crypto", "digests"):
            with self.subTest(stage=stage):
                self.failure = stage
                with self.assertRaises(handoff.HandoffError):
                    self.invoke()
                self.assertEqual(self.writes, [])
        self.failure = None
        for status, attempt, conclusion in (("completed", 1, "success"), ("in_progress", 2, "success"),
                                             ("in_progress", 1, "failure")):
            with self.subTest(status=status, attempt=attempt, claim=conclusion):
                self.cd_status, self.cd_attempt, self.claim_conclusion = status, attempt, conclusion
                with self.assertRaises(handoff.HandoffError):
                    self.invoke()
                self.assertEqual(self.writes, [])

    def test_unknown_or_refused_production_write_is_fenced_across_new_operator_instances(self) -> None:
        for failure in ("production-timeout-before", "production-timeout-after", "production-malformed", "production-collision"):
            with self.subTest(failure=failure):
                self.refs.clear(); self.objects.clear(); self.writes.clear()
                self.failure = failure
                with self.assertRaises((handoff.HandoffError, TimeoutError)):
                    self.invoke()
                before = copy.deepcopy(self.writes)
                self.assertEqual(self.ref_writes(), ["refs/tags/v-release-intent-1.2.3", "refs/tags/v1.2.3"])
                self.assertIn("refs/tags/v-release-intent-1.2.3", self.refs)
                self.failure = None
                for operator_run in (789, 790):
                    with self.assertRaisesRegex(handoff.HandoffError, "already owns"):
                        self.invoke(operator_run=operator_run)
                self.assertEqual(self.writes, before)

    def test_unknown_ownership_cannot_reach_a_production_reference_request(self) -> None:
        for failure in ("intent-timeout-before", "intent-timeout-after", "intent-malformed", "intent-collision"):
            with self.subTest(failure=failure):
                self.refs.clear(); self.objects.clear(); self.writes.clear()
                self.failure = failure
                with self.assertRaises((handoff.HandoffError, TimeoutError)):
                    self.invoke()
                self.assertEqual(self.ref_writes(), ["refs/tags/v-release-intent-1.2.3"])
                self.assertNotIn("refs/tags/v1.2.3", self.refs)

    def test_ownership_unknown_across_instances_has_only_the_explicit_two_safe_outcomes(self) -> None:
        for committed in (False, True):
            with self.subTest(committed=committed):
                self.refs.clear(); self.objects.clear(); self.writes.clear()
                self.failure = "intent-timeout-after" if committed else "intent-timeout-before"
                with self.assertRaises(TimeoutError):
                    self.invoke()
                self.assertEqual(self.ref_writes(), ["refs/tags/v-release-intent-1.2.3"])
                self.assertNotIn("refs/tags/v1.2.3", self.refs)
                self.failure = None
                if committed:
                    before = copy.deepcopy(self.writes)
                    with self.assertRaisesRegex(handoff.HandoffError, "already owns"):
                        self.invoke(operator_run=790)
                    self.assertEqual(self.writes, before)
                else:
                    # No earlier production write existed to replay. A new
                    # original operator must acquire the still-absent owner.
                    result = self.invoke(operator_run=790)
                    self.assertEqual(result["operator_run_id"], 790)
                    self.assertEqual(self.ref_writes(), ["refs/tags/v-release-intent-1.2.3",
                        "refs/tags/v-release-intent-1.2.3", "refs/tags/v1.2.3"])
                    self.assertIn("Operator-Run: 790", self.objects[result["intent_object_sha"]]["message"])

    def test_post201_main_rules_deadline_or_original_cd_drift_cannot_issue_a_success_receipt(self) -> None:
        for stage in ("intent", "production"):
            for changed in ("main-drift", "rules-drift", "expired", "cd-stopped", "ref-drift"):
                with self.subTest(stage=stage, changed=changed):
                    self.refs.clear(); self.objects.clear(); self.writes.clear()
                    self.main_sha, self.cd_status = SOURCE, "in_progress"
                    self.inspection = ReservationContractTests().capability_fixture()[2]
                    self.failure = stage + "-" + changed
                    with self.assertRaises(handoff.HandoffError):
                        self.invoke()
                    expected = ["refs/tags/v-release-intent-1.2.3"]
                    if stage == "production":
                        expected.append("refs/tags/v1.2.3")
                    self.assertEqual(self.ref_writes(), expected)
                    self.assertIn("refs/tags/v-release-intent-1.2.3", self.refs)


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
