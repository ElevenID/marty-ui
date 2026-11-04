"""Offline controls for the native tag operator; these are not API capability proof."""
from __future__ import annotations

import copy
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
    def test_atomic_mutation_asserts_main_and_absent_tag_without_force(self) -> None:
        request = operator.atomic_request(MAIN, MAIN, "v1.2.3", OBJECT, "synthetic")
        self.assertIn("updateRefs", request["query"])
        refs = request["variables"]["input"]["refUpdates"]
        self.assertEqual(refs, [
            {"name": "refs/heads/main", "beforeOid": MAIN, "afterOid": MAIN, "force": False},
            {"name": "refs/tags/v1.2.3", "beforeOid": "0" * 40, "afterOid": OBJECT, "force": False},
        ])

    def test_capability_negative_differs_only_in_stale_precondition(self) -> None:
        negative = operator.atomic_request(SOURCE, MAIN, "v-release-capability-123-1", OBJECT, "same")
        positive = operator.atomic_request(MAIN, MAIN, "v-release-capability-123-1", OBJECT, "same")
        negative["variables"]["input"]["refUpdates"][0]["beforeOid"] = MAIN
        self.assertEqual(negative, positive)

    def test_arbitrary_refs_and_unqualified_names_refuse(self) -> None:
        for name in ("main", "v1.2.3/other", "v1.2.3;echo x", "v-release-capability-123-2", "nightly"):
            with self.subTest(name=name), self.assertRaises(handoff.HandoffError):
                operator.atomic_request(MAIN, MAIN, name, OBJECT, "test")

    def test_only_attributable_stale_main_error_is_capability_evidence(self) -> None:
        accepted = {"data": {"updateRefs": None}, "errors": [{
            "message": "Reference refs/heads/main before OID does not match the expected value"}]}
        self.assertTrue(operator.stale_main_rejection(200, accepted, SOURCE, MAIN))
        for message in ("Resource not accessible by integration", "Non-fast-forward update refused",
                        "Could not resolve node", "main requires merge queue", "Network timeout"):
            with self.subTest(message=message):
                value = {"data": {"updateRefs": None}, "errors": [{"message": message}]}
                self.assertFalse(operator.stale_main_rejection(200, value, SOURCE, MAIN))
        self.assertFalse(operator.stale_main_rejection(403, accepted, SOURCE, MAIN))

    def test_graphql_null_partial_and_unknown_results_refuse_safely(self) -> None:
        for value in ({}, {"data": None}, {"data": {"updateRefs": None}},
                      {"data": {"updateRefs": {"clientMutationId": "foreign"}}},
                      {"data": {"updateRefs": {"clientMutationId": "expected"}}, "errors": [{"message": "failed"}]}):
            with self.subTest(value=value), self.assertRaises(handoff.HandoffError):
                operator.require_graph_success(200, value, "expected")
        operator.require_graph_success(200, {"data": {"updateRefs": {"clientMutationId": "expected"}}}, "expected")

    def test_noop_cas_model_has_no_partial_change_on_stale_before(self) -> None:
        # A synthetic server model checks the documented all-or-nothing request
        # contract. Only the prospective native capability run proves GitHub.
        current = {"refs/heads/main": MAIN}
        request = operator.atomic_request(SOURCE, MAIN, "v-release-capability-123-1", OBJECT, "test")
        updates = request["variables"]["input"]["refUpdates"]
        before = copy.deepcopy(current)
        admitted = all(current.get(item["name"], operator.ZERO) == item["beforeOid"] for item in updates)
        if admitted:
            current.update({item["name"]: item["afterOid"] for item in updates})
        self.assertFalse(admitted)
        self.assertEqual(current, before)


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
