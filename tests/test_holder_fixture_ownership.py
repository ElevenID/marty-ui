"""Ownership/discovery regressions; never starts Docker or reads credentials."""
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from scripts import probe_signing_keys_openbao_policy as probe


class HolderFixtureOwnershipTests(unittest.TestCase):
    def test_cleanup_refuses_any_changed_container_identity_or_label(self):
        cid = "a" * 64
        for field, value in [("Id", "b" * 64), ("Name", "/another-fixture"),
                ("purpose", "another-task"), ("marker", "another-purpose")]:
            with self.subTest(field=field):
                metadata = {"Id": cid, "Name": "/owned-holder", "Config": {"Labels": {
                    "codex.purpose": "holder-lifecycle-fixture", "marty.disposable": "kms-signing-policy"}}}
                if field == "purpose":
                    metadata["Config"]["Labels"]["codex.purpose"] = value
                elif field == "marker":
                    metadata["Config"]["Labels"]["marty.disposable"] = value
                else:
                    metadata[field] = value
                calls = []

                def docker(*args):
                    calls.append(args)
                    return json.dumps([metadata]) if args[0] == "inspect" else cid

                with patch.object(probe, "require_docker", side_effect=docker):
                    with self.assertRaises(RuntimeError):
                        probe.remove_owned_holder_backend("owned-holder", cid)
                self.assertFalse(any(call[0] == "rm" for call in calls))

    def test_owned_removal_uses_exact_id_and_verifies_absence(self):
        cid = "a" * 64
        metadata = {"Id": cid, "Name": "/owned-holder", "Config": {"Labels": {
            "codex.purpose": "holder-lifecycle-fixture", "marty.disposable": "kms-signing-policy"}}}
        with patch.object(probe, "require_docker", side_effect=[cid, json.dumps([metadata]), "", ""]) as docker:
            probe.remove_owned_holder_backend("owned-holder", cid)
        self.assertIn(unittest.mock.call("rm", "-f", "-v", cid), docker.call_args_list)
        self.assertEqual(docker.call_args_list[-1], unittest.mock.call("ps", "-aq", "--filter", f"id={cid}"))

    def test_missing_native_artifact_fails_before_backend_admission(self):
        with patch.object(probe, "pull_pinned_openbao") as pull:
            with self.assertRaises(FileNotFoundError):
                probe.qualify(holder_test_binary=Path("missing-owned-native-artifact"))
        pull.assert_not_called()
