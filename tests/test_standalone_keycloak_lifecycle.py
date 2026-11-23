import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import standalone_keycloak_lifecycle as lifecycle


def names():
    return {file: "selfhost-keycloak-" + scope + "-0123456789ab"
            for file, scope in lifecycle.LEAF_FILES.items()}


class Boundaries(unittest.TestCase):
    def test_renewal_has_no_key_or_policy_mutation_or_wildcards(self):
        paths = json.loads(lifecycle.renewal_policy(names()))["path"]
        self.assertFalse(any("*" in path or "+" in path for path in paths))
        self.assertFalse(any("export" in path or "rotate" in path for path in paths))
        self.assertNotIn("auth/token/create", paths)
        self.assertNotIn("transit/keys/foreign-keycloak-selfhost", paths)
        self.assertNotIn("sys/mounts/keycloak-pki", paths)
        for path, rule in paths.items():
            if path.startswith("sys/policies/acl/"):
                self.assertEqual(rule["capabilities"], ["read"])
        mint = paths[lifecycle.LEAF_PATH]
        self.assertEqual(set(mint["required_parameters"]),
                         {"policies", "ttl", "explicit_max_ttl", "no_default_policy"})
        self.assertEqual(mint["allowed_parameters"]["ttl"], ["8h"])
        self.assertEqual(mint["allowed_parameters"]["explicit_max_ttl"], ["8h"])
        self.assertEqual(mint["allowed_parameters"]["policies"], [])
        self.assertEqual(set(mint["allowed_parameters"]), set(mint["required_parameters"]))

    def test_foreign_or_combined_policy_cannot_be_enrolled(self):
        for value in ["root", "default", "selfhost-keycloak-sign-0123456789ab/other",
                      "selfhost-keycloak-master-cookie-0123456789ab"]:
            changed = names()
            changed["keycloak_signing_kms_token"] = value
            with self.subTest(policy=value), self.assertRaises(ValueError):
                lifecycle.renewal_policy(changed)
        changed = names()
        changed["unrelated_workload_token"] = "arbitrary"
        with self.assertRaises(ValueError):
            lifecycle.renewal_policy(changed)

    def test_returned_leaf_must_be_independent_and_actually_hard_capped(self):
        valid = {"policies": ["purpose"], "orphan": True, "type": "service",
                 "num_uses": 0, "explicit_max_ttl": 28800, "ttl": 28000,
                 "creation_ttl": 28800, "path": lifecycle.LEAF_PATH}
        lifecycle.leaf_valid(valid, "purpose")
        attacks = [("orphan", False), ("explicit_max_ttl", 0), ("explicit_max_ttl", 86400),
                   ("ttl", 28801), ("ttl", 0), ("creation_ttl", 86400),
                   ("policies", ["purpose", "root"]), ("policies", ["purpose", "other-purpose"]),
                   ("period", 28800),
                   ("token_period", 28800), ("identity_policies", ["extra"]),
                   ("token_policies", ["extra"]), ("type", "batch"), ("num_uses", 1),
                   ("path", "auth/token/create")]
        for field, value in attacks:
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                lifecycle.leaf_valid({**valid, field: value}, "purpose")
        with self.assertRaises(ValueError):
            lifecycle.leaf_valid({**valid, "ttl": lifecycle.MINIMUM_PUBLICATION_TTL - 1},
                                 "purpose", minimum=lifecycle.MINIMUM_PUBLICATION_TTL)


@unittest.skipUnless(os.name == "posix", "POSIX private projection contract")
class PrivatePublication(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        for path in self.root.rglob("*"):
            if path.is_dir():
                path.chmod(0o700)
        self.temp.cleanup()

    def test_secret_reader_rejects_links_and_shared_files(self):
        path = self.root / "secret"
        lifecycle.write_file(path, b"owner-private")
        self.assertEqual(lifecycle.read_file(path), b"owner-private")
        (self.root / "alias").symlink_to(path)
        with self.assertRaises(OSError):
            lifecycle.read_file(self.root / "alias")
        os.link(path, self.root / "hardlink")
        with self.assertRaises(ValueError):
            lifecycle.read_file(path)

    def test_interrupted_projection_resumes_without_minting_another_generation(self):
        worker = lifecycle.Lifecycle.__new__(lifecycle.Lifecycle)
        worker.root, worker.runtime = self.root, self.root / "runtime"
        worker.state = self.root / "renewal"
        worker.state.mkdir(mode=0o700)
        worker.runtime.mkdir(mode=0o700)
        outputs = {name: "new-" + name for name in lifecycle.OUTPUTS}
        projection = dict(outputs)
        for realm in ("master", "11id"):
            projection[f"keycloak-{realm}-rs256.crt"] = outputs[f"keycloak_{realm}_rs256_cert"]
            for purpose in ("cookie", "ciba"):
                projection[f"{realm}-{purpose}.token"] = outputs[f"keycloak_{realm}_{purpose}_token"]
        for name in projection:
            lifecycle.write_file(worker.runtime / name, b"previous-valid-leaf", mode=0o444)
        worker.runtime.chmod(0o555)
        bao = Mock()
        worker.login = Mock(return_value=(bao, {"policies": names()}))
        worker.close = Mock()
        worker.validate_outputs = Mock()
        worker.native_json = Mock(return_value=outputs)
        worker.endpoint, worker.ca = "https://localhost:8200", self.root / "ca.crt"
        worker.config = {"operator_source_sha": "a" * 40}
        real_write = lifecycle.write_file
        published = []

        def interrupt(path, data, *args, **kwargs):
            if path.parent == worker.runtime:
                if len(published) == 2:
                    raise OSError("simulated interruption")
                published.append(path)
            return real_write(path, data, *args, **kwargs)

        with patch.object(lifecycle, "write_file", side_effect=interrupt):
            with self.assertRaises(OSError):
                worker.renew()
        self.assertEqual(worker.runtime.stat().st_mode & 0o777, 0o555)
        pending = json.loads((worker.state / "generation-pending.json").read_text())
        self.assertEqual(pending["phase"], "staged")
        self.assertFalse((worker.state / "last-renewal.json").exists())
        worker.native_json.assert_called_once()
        with self.assertRaises(ValueError):
            worker.renew()  # A timer cannot silently mint over a pending generation.
        worker.native_json.reset_mock()
        receipt = worker.renew(resume=True)
        worker.native_json.assert_not_called()
        self.assertTrue(receipt["passed"])
        self.assertFalse((worker.state / "generation-pending.json").exists())
        self.assertTrue(all((worker.runtime / name).read_text() == value
                            for name, value in projection.items()))
        self.assertEqual(worker.close.call_count, 2)

    def test_secret_rotation_resumes_after_publication_and_retirement_without_new_mint(self):
        worker = lifecycle.Lifecycle.__new__(lifecycle.Lifecycle)
        worker.state = self.root
        previous = {"role_id": "same-role", "secret_id": "previous-secret",
                    "accessor": "previous-accessor", "policies": names(), "acl_sha256": "hash"}
        candidate = {**previous, "secret_id": "replacement-secret", "accessor": "new-accessor"}
        lifecycle.save(self.root / "authority.json", candidate)
        lifecycle.save(self.root / "rotation-pending.json", {"previous": previous, "candidate": candidate})
        bao = Mock()
        worker.login = Mock(return_value=(bao, candidate))
        worker.close = Mock()
        worker.old_identity_denied = Mock(return_value=True)
        worker.resume_rotation()
        worker.login.assert_called_once_with(candidate)
        bao.request.assert_not_called()
        self.assertFalse((self.root / "rotation-pending.json").exists())
        self.assertTrue(json.loads((self.root / "last-rotation.json").read_text())["passed"])

    def test_rotation_recovery_refuses_to_replace_an_unrelated_active_identity(self):
        worker = lifecycle.Lifecycle.__new__(lifecycle.Lifecycle)
        worker.state = self.root
        previous = {"role_id": "same-role", "secret_id": "previous-secret",
                    "accessor": "old", "policies": names(), "acl_sha256": "hash"}
        candidate = {**previous, "secret_id": "new", "accessor": "new"}
        lifecycle.save(self.root / "authority.json", {**candidate, "secret_id": "another-writer"})
        worker.login = Mock()
        with self.assertRaises(ValueError):
            worker.finish_rotation(previous, candidate)
        worker.login.assert_not_called()


if __name__ == "__main__":
    unittest.main()
