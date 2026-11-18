"""Pure selection/ownership controls: never starts Docker, KMS or a listener."""
import json
import subprocess
import unittest
import uuid
from unittest.mock import patch

from scripts import probe_signing_keys_openbao_policy as probe


def completed(stdout, code=0):
    return subprocess.CompletedProcess([], code, stdout, "")


class MdocFixtureProbeTests(unittest.TestCase):
    def test_contact_is_truthful_and_crl_is_explicitly_unpublished(self):
        nonce = uuid.uuid4().hex
        status, contact = probe.mdoc_contact_response("/contact", nonce)
        self.assertEqual(status, 200)
        self.assertEqual(contact["owner"], probe.MDOC_FIXTURE_OWNER)
        self.assertEqual(contact["nonce"], nonce)
        self.assertFalse(contact["crl_published"])
        for path in ["/mdoc.crl", "/unknown", "/contact?other=1"]:
            status, value = probe.mdoc_contact_response(path, nonce)
            self.assertEqual(status, 404)
            self.assertFalse(value["crl_published"])

    def test_discovery_requires_exact_single_owned_case(self):
        exact = f"{probe.MDOC_TEST_CASE}: test\n\n1 test, 0 benchmarks\n"
        self.assertTrue(probe.mdoc_test_discovered(completed(exact)))
        for output in ["0 tests, 0 benchmarks", exact.replace(probe.MDOC_TEST_CASE, "wrong_case"),
                       exact + "another_case: test\n", exact.replace("1 test", "2 tests")]:
            self.assertFalse(probe.mdoc_test_discovered(completed(output)))
        self.assertFalse(probe.mdoc_test_discovered(completed(exact, 1)))
        command = probe.mdoc_test_command(discovery=True)
        self.assertIn("--list", command)
        self.assertIn("--ignored", command)
        self.assertIn("--exact", command)
        self.assertNotIn("--list", probe.mdoc_test_command())

    def test_zero_selected_or_ignored_tests_cannot_qualify(self):
        exact = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s"
        self.assertTrue(probe.mdoc_test_succeeded(completed(exact)))
        for output in [exact.replace("1 passed", "0 passed"), exact.replace("0 ignored", "1 ignored"),
                       exact.replace("0 filtered", "1 filtered"), ""]:
            self.assertFalse(probe.mdoc_test_succeeded(completed(output)))
        self.assertFalse(probe.mdoc_test_succeeded(completed(exact, 101)))

    def test_missing_discovery_stops_before_backend_creation(self):
        with patch.object(probe, "pull_pinned_openbao") as pull, patch.object(probe, "docker") as docker:
            with self.assertRaises(RuntimeError):
                probe.qualify(managed_mdoc=True, mdoc_runner=lambda *_args, **_kwargs: completed("0 tests, 0 benchmarks"))
            pull.assert_not_called()
            docker.assert_not_called()

    def test_conflicting_mode_fails_before_any_backend_or_cargo(self):
        with patch.object(probe, "pull_pinned_openbao") as pull, patch.object(probe, "docker") as docker:
            with self.assertRaises(RuntimeError):
                probe.qualify(rust_adapter=True, managed_mdoc=True)
            pull.assert_not_called()
            docker.assert_not_called()

    def test_cleanup_refuses_foreign_owner_or_rebound_identity(self):
        cid = "a" * 64
        correct = {"Id": cid, "Name": "/owned", "Config": {"Labels": {
            "codex.owner": probe.MDOC_FIXTURE_OWNER, "codex.purpose": "mdoc-certificate-fixture"}}}
        for mutate in [lambda row: row.update(Id="b" * 64),
                       lambda row: row["Config"]["Labels"].update({"codex.owner": "other"}),
                       lambda row: row.update(Name="/rebound")]:
            row = json.loads(json.dumps(correct))
            mutate(row)
            calls = []
            def fake(*args, **_kwargs):
                calls.append(args)
                return cid if args[0] == "ps" else json.dumps([row])
            with patch.object(probe, "require_docker", side_effect=fake):
                with self.assertRaises(RuntimeError):
                    probe.remove_owned_mdoc_backend("owned", cid)
            self.assertFalse(any(call[0] == "rm" for call in calls))

    def test_cleanup_uses_exact_owned_id_and_verifies_absence(self):
        cid = "a" * 64
        row = {"Id": cid, "Name": "/owned", "Config": {"Labels": {
            "codex.owner": probe.MDOC_FIXTURE_OWNER, "codex.purpose": "mdoc-certificate-fixture"}}}
        with patch.object(probe, "require_docker", side_effect=[cid, json.dumps([row]), cid, ""]) as docker:
            probe.remove_owned_mdoc_backend("owned", cid)
            self.assertEqual(docker.call_args_list[2].args, ("rm", "-f", "-v", cid))
        with patch.object(probe, "require_docker", side_effect=[cid, json.dumps([row]), cid, cid]):
            with self.assertRaises(RuntimeError):
                probe.remove_owned_mdoc_backend("owned", cid)
        with patch.object(probe, "require_docker", return_value="") as docker:
            probe.remove_owned_mdoc_backend("owned", cid)
            self.assertEqual(docker.call_count, 1)


if __name__ == "__main__":
    unittest.main()
