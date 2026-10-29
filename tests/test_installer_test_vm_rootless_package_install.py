"""Synthetic, unprivileged contracts for the dormant offline installer."""
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import uuid

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import installer_test_vm_rootless_package_admission as archive  # noqa: E402
import installer_test_vm_rootless_package_install as install  # noqa: E402


VM = "70573b98-a002-468c-a932-f27c1ca20440"
ENGINE = "6c3ab358-4b21-4979-b2ff-916bbd32d891"
BOOT = "376c3c9f-f782-4e8d-9703-2697d80c7b5c"


def status(*packages):
    entries = [("docker.io", "29.1.3-0ubuntu3~24.04.2"), *packages]
    return "".join(f"Package: {name}\nStatus: install ok installed\n"
                   f"Version: {version}\n\n" for name, version in entries).encode()


class ContractTests(unittest.TestCase):
    def test_plan_binds_current_status_checkpoint_archive_and_actions(self):
        files = [{"package": "uidmap", "relative": "pool/u/uidmap.deb",
                  "sha256": "a" * 64, "size": 3}]
        actions = [{"package": "uidmap", "version": "v"}]
        args = dict(vm_id=VM, engine_id=ENGINE, checkpoint_sha256="b" * 64,
                    admission_sha256="c" * 64, status_sha256="d" * 64,
                    package_files=files, archive_metadata={"releases": [], "indexes": []},
                    actions=actions)
        first = install.plan_bytes(**args)
        self.assertEqual(first, install.canonical(json.loads(first)))
        for key in ("checkpoint_sha256", "admission_sha256", "status_sha256"):
            altered = {**args, key: "e" * 64}
            self.assertNotEqual(hashlib.sha256(first).digest(),
                                hashlib.sha256(install.plan_bytes(**altered)).digest())
        self.assertFalse(json.loads(first)["automatic_rollback"])

    def test_confirmation_requires_exact_tuple_and_literal(self):
        record = {"schema": install.CONFIRMATION_SCHEMA, "vm_id": VM,
                  "engine_id": ENGINE, "checkpoint_sha256": "a" * 64,
                  "plan_sha256": "b" * 64,
                  "nonce": "ca5d5ac8-a47e-4709-a1b5-58878086db11",
                  "phrase": install.CONFIRM_LITERAL}
        install._confirm(record, VM, ENGINE, "a" * 64, "b" * 64)
        for change in ({"vm_id": str(uuid.uuid4())},
                       {"checkpoint_sha256": "c" * 64},
                       {"plan_sha256": "c" * 64},
                       {"phrase": "yes"}, {"unexpected": True}):
            with self.subTest(change=change), self.assertRaises(install.Refused):
                install._confirm({**record, **change}, VM, ENGINE,
                                 "a" * 64, "b" * 64)

    def test_external_checkpoint_is_strict_stopped_identity_only(self):
        record = {"schema": install.CHECKPOINT_SCHEMA, "vm_id": VM,
                  "controller_boot_id": BOOT, "stopped_pid": 1135,
                  "stopped_start_ticks": "91460346", "disk_device": 2128,
                  "disk_inode": 111, "disk_sha256": "a" * 64,
                  "snapshot_sha256": "b" * 64, "snapshot_bytes": 1024,
                  "rollback_test_sha256": "c" * 64,
                  "created_at": 1793200000, "stopped": True}
        raw = install.canonical(record)
        self.assertEqual(install._checkpoint(raw, record, VM), archive.sha(raw))
        for change in ({"stopped": False}, {"disk_inode": 0},
                       {"vm_id": str(uuid.uuid4())},
                       {"snapshot_sha256": "bad"}, {"extra": 1}):
            with self.subTest(change=change), self.assertRaises(install.Refused):
                install._checkpoint(raw, {**record, **change}, VM)

    @unittest.skipUnless(os.name == "posix", "Linux directory descriptor test")
    def test_repo_copies_only_fixed_signed_locations(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            source = root / "bundle"
            source.mkdir()
            for pocket in archive.POCKETS:
                (source / f"{pocket}.inrelease").write_bytes(b"signed")
                for component in archive.COMPONENTS:
                    (source / f"{pocket}.{component}.packages.xz").write_bytes(b"index")
            files = []
            for package in archive.TARGETS:
                (source / f"{package}.deb").write_bytes(package.encode())
                files.append({"package": package,
                              "relative": f"pool/main/{package[0]}/{package}/{package}_1_amd64.deb",
                              "sha256": archive.sha(package.encode()),
                              "size": len(package)})
            dest = root / "transaction"
            dest.mkdir()
            with mock.patch.object(archive, "private_file",
                                   side_effect=lambda path, *_args, **_kw: path.read_bytes()):
                repo = install._repo(dest, source, files)
                config = install._config(dest, repo)
            for item in files:
                self.assertEqual((repo / item["relative"]).read_bytes(),
                                 item["package"].encode())
            cfg = config.read_text()
            self.assertIn("file://", cfg)
            self.assertIn('APT::Sandbox::User "root"', cfg)
            self.assertIn('Dir::State::status "/var/lib/dpkg/status"', cfg)
            self.assertNotIn("archive.ubuntu.com", cfg)


@unittest.skipUnless(os.name == "posix", "Linux one-shot descriptor test")
class OneShotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.parent = Path(self.temp.name)
        self.root = self.parent / VM
        self.root.mkdir()
        self.bundle = self.root / "bundle"
        self.bundle.mkdir()
        self.private = self.root / "transaction"
        self.private.mkdir()
        self.current = self.root / "status"
        self.before = status()
        self.current.write_bytes(self.before)
        self.actions = [{"package": "uidmap", "version": archive.EXPECTED_VERSIONS["uidmap"]},
                        {"package": "rootlesskit", "version": archive.EXPECTED_VERSIONS["rootlesskit"]}]
        self.rows = {name: {"package": name, "version": archive.EXPECTED_VERSIONS[name],
                            "sha256": archive.sha(name.encode()), "size": len(name),
                            "pocket": "noble", "component": "main"}
                     for name in archive.TARGETS}
        self.files = [{"package": name, "relative": f"pool/{name}.deb",
                       "sha256": row["sha256"], "size": row["size"]}
                      for name, row in self.rows.items()]
        self.metadata = {"releases": [{"pocket": pocket,
                                       "inrelease_sha256": "a" * 64,
                                       "keyring_sha256": "b" * 64}
                                      for pocket in archive.POCKETS], "indexes": []}
        for name in self.rows:
            (self.bundle / f"{name}.deb").write_bytes(name.encode())
        self.admission = {"schema": "elevenid.installer-only-vm-rootless-package-admission/v1",
                          "phase": "observed", "vm_id": VM, "engine_id": ENGINE,
                          "dpkg_status_sha256": archive.sha(self.before),
                          "transaction_simulated": True,
                          "rootful_docker_package_simulated_change": False,
                          "package_actions_authorized": False,
                          "installation_authorized": False,
                          "intent_sha256": "d" * 64,
                          "module_sha256": "e" * 64,
                          "controller_sha256": "f" * 64,
                          "packages": list(self.rows.values()),
                          "archive_releases": [],
                          "new_package_actions": self.actions}
        self.checkpoint = {"schema": install.CHECKPOINT_SCHEMA, "vm_id": VM,
                           "controller_boot_id": BOOT, "stopped_pid": 1135,
                           "stopped_start_ticks": "91460346", "disk_device": 2128,
                           "disk_inode": 111, "disk_sha256": "a" * 64,
                           "snapshot_sha256": "b" * 64, "snapshot_bytes": 1024,
                           "rollback_test_sha256": "c" * 64,
                           "created_at": 1793200000, "stopped": True}
        checkpoint_raw = install.canonical(self.checkpoint)
        plan = install.plan_bytes(vm_id=VM, engine_id=ENGINE,
                                  checkpoint_sha256=archive.sha(checkpoint_raw),
                                  admission_sha256=archive.sha(install.canonical(self.admission)),
                                  status_sha256=archive.sha(self.before),
                                  package_files=sorted(self.files, key=lambda x: x["package"]),
                                  archive_metadata=self.metadata,
                                  actions=self.actions)
        self.confirmation = {"schema": install.CONFIRMATION_SCHEMA,
                             "vm_id": VM, "engine_id": ENGINE,
                             "checkpoint_sha256": archive.sha(checkpoint_raw),
                             "plan_sha256": archive.sha(plan),
                             "nonce": "ca5d5ac8-a47e-4709-a1b5-58878086db11",
                             "phrase": install.CONFIRM_LITERAL}
        self.admission_path = self.root / "admission.json"
        self.checkpoint_path = self.root / "checkpoint.json"
        self.confirmation_path = self.root / "confirmation.json"
        self.manifest_path = self.root / "bundle-manifest.json"
        self._records()
        self.verified_admission = install.VerifiedAdmission(
            VM, archive.sha(install.canonical(self.admission)), "d" * 64,
            "e" * 64, "f" * 64, ENGINE, archive.sha(self.before))
        self.verified_checkpoint = install.VerifiedStoppedCheckpoint(
            VM, archive.sha(checkpoint_raw), "a" * 64, "b" * 64, "c" * 64)
        self.patches = [
            mock.patch.object(install.os, "geteuid", return_value=0),
            mock.patch.object(install.os, "getegid", return_value=0),
            mock.patch.object(install, "private_root"),
            mock.patch.object(install, "CUSTODY_PARENT", self.parent),
            mock.patch.object(install, "STATUS", self.current),
            mock.patch.object(install, "_engine_id", return_value=ENGINE),
            mock.patch.object(install, "_bundle", return_value=(
                sorted(self.files, key=lambda x: x["package"]), self.rows,
                self.metadata)),
            mock.patch.object(install, "_repo", return_value=self.root / "repo"),
            mock.patch.object(install, "_config", return_value=self.root / "apt.conf"),
            mock.patch.object(install, "_recheck_repo"),
            mock.patch.object(archive, "private_file",
                              side_effect=lambda path, *_args, **_kw: Path(path).read_bytes()),
            mock.patch.object(archive, "inspect_simulation", return_value=self.actions),
        ]
        for patch in self.patches:
            patch.start()
            self.addCleanup(patch.stop)

    def _records(self):
        for path, value in ((self.admission_path, self.admission),
                            (self.checkpoint_path, self.checkpoint),
                            (self.confirmation_path, self.confirmation),
                            (self.manifest_path, {"packages": list(self.rows.values())})):
            path.write_bytes(install.canonical(value))

    def run_install(self, apt):
        with mock.patch.object(install, "_apt", side_effect=apt) as calls:
            result = install.install_once(
                vm_id=VM, root_dir=self.root,
                verified_admission=self.verified_admission,
                verified_checkpoint=self.verified_checkpoint)
        return result, calls

    def test_exact_confirmation_refusal_before_intent_or_apt(self):
        self.confirmation["plan_sha256"] = "0" * 64
        self._records()
        with mock.patch.object(install, "_apt") as apt:
            with self.assertRaises(install.Refused):
                install.install_once(vm_id=VM, root_dir=self.root,
                    verified_admission=self.verified_admission,
                    verified_checkpoint=self.verified_checkpoint)
        apt.assert_not_called()
        self.assertEqual(list(self.private.iterdir()), [])

    def test_unverified_or_mismatched_capability_refuses_before_intent(self):
        original = self.verified_admission
        self.verified_admission = install.VerifiedAdmission(
            VM, "0" * 64, original.intent_sha256, original.module_sha256,
            original.controller_sha256, ENGINE, original.status_sha256)
        with mock.patch.object(install, "_apt") as apt:
            with self.assertRaises(install.Refused):
                install.install_once(vm_id=VM, root_dir=self.root,
                    verified_admission=self.verified_admission,
                    verified_checkpoint=self.verified_checkpoint)
        apt.assert_not_called()
        self.assertEqual(list(self.private.iterdir()), [])

    def test_success_rechecks_then_records_no_rootless_authority(self):
        def apt(args, _config):
            if args[0] == "--yes":
                self.current.write_bytes(status(
                    ("uidmap", archive.EXPECTED_VERSIONS["uidmap"]),
                    ("rootlesskit", archive.EXPECTED_VERSIONS["rootlesskit"])))
            return b"simulation" if args[0] == "--simulate" else b""
        result, calls = self.run_install(apt)
        self.assertEqual(result["phase"], "observed-installed")
        self.assertFalse(result["rootless_ready"])
        self.assertEqual([call.args[0][0] for call in calls.call_args_list],
                         ["update", "--simulate", "--yes"])
        self.assertEqual(json.loads((self.private / "result.json").read_bytes()), result)
        with self.assertRaises(install.Refused):
            self.run_install(apt)

    def test_simulation_drift_never_reaches_package_action(self):
        with mock.patch.object(archive, "inspect_simulation", return_value=[]):
            with self.assertRaises(install.Refused):
                self.run_install(lambda _args, _config: b"simulation")
        result = json.loads((self.private / "result.json").read_bytes())
        self.assertEqual(result["phase"], "uncertain")
        self.assertEqual(result["last_stage"], "simulating")

    def test_install_failure_records_uncertain_and_refuses_retry(self):
        def apt(args, _config):
            if args[0] == "--yes":
                raise install.Refused("offline APT transaction refused")
            return b"simulation" if args[0] == "--simulate" else b""
        with self.assertRaises(install.Refused):
            self.run_install(apt)
        result = json.loads((self.private / "result.json").read_bytes())
        self.assertEqual(result["phase"], "uncertain")
        self.assertEqual(result["last_stage"], "installing")
        self.assertTrue(result["manual_checkpoint_recovery_required"])
        with self.assertRaises(install.Refused):
            self.run_install(apt)

    def test_unplanned_new_package_after_apt_is_uncertain(self):
        def apt(args, _config):
            if args[0] == "--yes":
                self.current.write_bytes(status(
                    ("uidmap", archive.EXPECTED_VERSIONS["uidmap"]),
                    ("rootlesskit", archive.EXPECTED_VERSIONS["rootlesskit"]),
                    ("surprise", "1")))
            return b"simulation" if args[0] == "--simulate" else b""
        with self.assertRaises(install.Refused):
            self.run_install(apt)
        result = json.loads((self.private / "result.json").read_bytes())
        self.assertEqual(result["phase"], "uncertain")
        self.assertEqual(result["last_stage"], "verifying")
        self.assertTrue(result["manual_checkpoint_recovery_required"])
        with self.assertRaises(install.Refused):
            self.run_install(apt)


if __name__ == "__main__":
    unittest.main()
