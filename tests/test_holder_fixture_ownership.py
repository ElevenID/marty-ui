"""Ownership/discovery regressions; never starts Docker or reads credentials."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from unittest.mock import Mock

from scripts import probe_signing_keys_openbao_policy as probe
from scripts import selfhost_openbao_client, with_disposable_policy_owner_kms, with_disposable_event_stream_kms


class HolderFixtureOwnershipTests(unittest.TestCase):
    def test_owner_fixture_rejects_nonlocal_or_plaintext_provider_before_contact(self):
        for endpoint in ("http://127.0.0.1:8200", "https://provider.example:8200", "https://u:p@127.0.0.1:8200",
                         "https://127.0.0.1:8200/v1?token=bad", "https://127.0.0.1:8200/other"):
            with self.subTest(endpoint=endpoint), patch.object(selfhost_openbao_client, "Bao") as connect:
                with self.assertRaises(RuntimeError), probe.holder_issuer_tls("a" * 32, endpoint, Path("unused-public-ca"), "unused-root"):
                    self.fail("unowned provider was admitted")
                connect.assert_not_called()

    def test_owner_fixture_checks_marker_before_any_tls_provisioning(self):
        client = Mock()
        client.request.return_value = {"data": {"data": {"nonce": "foreign"}}}
        with patch.object(selfhost_openbao_client, "Bao", return_value=client), \
                patch.object(with_disposable_policy_owner_kms, "owner_environment") as provision:
            with self.assertRaisesRegex(RuntimeError, "unmarked"), probe.holder_issuer_tls(
                    "a" * 32, "https://127.0.0.1:8200/v1", Path("unused-public-ca"), "unused-root"):
                self.fail("foreign marker admitted")
            provision.assert_not_called()

    def test_existing_transit_mount_reuse_refuses_unknown_type_before_writes(self):
        for mounts in ({}, {"transit/": {"type": "kv"}}):
            client = Mock()
            client.request.return_value = {"data": mounts}
            with self.subTest(mounts=mounts), self.assertRaisesRegex(RuntimeError, "mount type mismatch"):
                with_disposable_event_stream_kms.provision_server_identity(client, Path("unused"), "signing-keys", reuse_transit=True)
            client.request.assert_called_once_with("GET", "sys/mounts")

    def test_owner_certificate_operations_stay_in_the_new_fixture_pki(self):
        mount = "holder-owner-pki-0123456789abcdef"
        client = Mock()
        client.request.return_value = {"data": {"type": "ecdsa-p256", "latest_version": 2,
            "exportable": False, "allow_plaintext_backup": False}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            identity = {"key_name": "owned-tls-key", "cert": str(root / "leaf.pem"),
                "token_file": str(root / "scoped-token"), "workload_ca": str(root / "public-ca.pem")}
            with patch.object(with_disposable_policy_owner_kms, "provision_server_identity", return_value=identity) as provision, \
                    patch.object(with_disposable_policy_owner_kms, "public_certificate", return_value="public-certificate") as certificate:
                with_disposable_policy_owner_kms.owner_environment(client, root, "https://127.0.0.1:8200",
                    reuse_transit=True, pki_mount=mount)
            provision.assert_called_once_with(client, root, "signing-keys", reuse_transit=True, pki_mount=mount)
            self.assertEqual(certificate.call_count, 3)
            self.assertTrue(all(call.kwargs["pki_mount"] == mount for call in certificate.call_args_list))
            paths = [call.args[1] for call in client.request.call_args_list]
            self.assertIn(f"{mount}/roles/signing-keys", paths)
            self.assertIn(f"{mount}/roles/w05-wrong-dns", paths)
            self.assertFalse(any(path.startswith("pki/") or path.startswith("sys/mounts/") for path in paths))

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
