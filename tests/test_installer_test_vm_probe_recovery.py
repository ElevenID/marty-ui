"""Synthetic, non-VM tests for explicit staged installer probe recovery."""
from __future__ import annotations

import os
import hashlib
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

if sys.platform != "linux":
    raise unittest.SkipTest("Linux VM controller tests")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import installer_test_vm_probe_recovery as recovery

VM = "70573b98-a002-468c-a932-f27c1ca20440"
PROBE = "49ade74d-d979-425f-9c98-67452ed11f4d"
RECOVERY = "53195b07-62bf-4f64-bf6a-97023af2ce20"


class Recovery(unittest.TestCase):
    @unittest.skipUnless(os.geteuid() == 0, "root-owned source admission fixture")
    def test_admission_binds_root_owned_module_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scripts = root / "scripts"
            scripts.mkdir(mode=0o700)
            module = scripts / "installer_test_vm_probe_recovery.py"
            module.write_bytes(Path(recovery.__file__).read_bytes())
            module.chmod(0o600)
            admission = root / "admission.json"
            sha = hashlib.sha256(module.read_bytes()).hexdigest()
            record = {"schema": recovery.ADMISSION_SCHEMA,
                      "original_controller_sha": recovery.ORIGINAL_CONTROLLER_SHA,
                      "original_failure": recovery.ORIGINAL_FAILURE,
                      "classified_stage": recovery.STAGE,
                      "source_sha": "9" * 40, "module_sha256": sha,
                      "vm_id": VM, "probe_id": PROBE,
                      "original_intent_sha256": "7" * 64,
                      "readiness_sha256": "e" * 64,
                      "directory_device": 10, "directory_inode": 20,
                      "operator_device": 10, "operator_inode": 21,
                      "operator_sha256": "a" * 64,
                      "operator_bytes": 42, "operator_mode": 600}
            admission.write_bytes(recovery.release.encode(record))
            admission.chmod(0o600)
            with mock.patch.object(recovery, "__file__", str(module)):
                self.assertEqual(recovery._admitted_controller(admission), record)
                module.write_bytes(module.read_bytes() + b"\n")
                with self.assertRaisesRegex(ValueError, "source admission differs"):
                    recovery._admitted_controller(admission)

    def test_held_fchmod_changes_only_exact_inode_and_refuses_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "marty-deploy"
            target.write_bytes(b"synthetic-public-operator")
            target.chmod(0o600)
            before = target.stat()
            old = (before.st_dev, before.st_ino, before.st_uid, 600, 1, before.st_size)
            expected = {"binary_bytes": before.st_size}
            binding = {"guest_uid": before.st_uid}
            def local(_binding, script, **_kwargs):
                run = subprocess.run(shlex.split(script), capture_output=True, timeout=5)
                if run.returncode:
                    raise ValueError("held fchmod refused")
                return run.stdout
            with mock.patch.object(recovery.probe, "_ssh", side_effect=local):
                recovery._held_chmod(binding, str(target), expected, old)
            self.assertEqual(target.stat().st_ino, old[1])
            self.assertEqual(target.stat().st_mode & 0o777, 0o700)

            target.chmod(0o600)
            replacement = Path(directory) / "replacement"
            replacement.write_bytes(b"different public bytes")
            replacement.chmod(0o600)
            def competing(_binding, script, **_kwargs):
                argv = shlex.split(script)
                marker = "os.fchmod(r,0o700);"
                self.assertIn(marker, argv[4])
                argv[4] = argv[4].replace(marker,
                    "os.replace(" + repr(str(replacement)) + ",p);" + marker)
                run = subprocess.run(argv, capture_output=True, timeout=5)
                self.assertNotEqual(run.returncode, 0)
                raise ValueError("held fchmod refused")
            with mock.patch.object(recovery.probe, "_ssh", side_effect=competing):
                with self.assertRaisesRegex(ValueError, "held fchmod refused"):
                    recovery._held_chmod(binding, str(target), expected, old)
            self.assertEqual(target.read_bytes(), b"different public bytes")
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_exact_staged_recovery_intent_precedes_chmod_and_never_retries(self):
        with tempfile.TemporaryDirectory() as directory:
            registry = Path(directory)
            expected = {"binary": Path("/private/operator"), "binary_sha256": "a" * 64,
                        "binary_bytes": 42, "source_sha": "b" * 40,
                        "release_tag": "v1.1.263-nightly.20261027.40597099479",
                        "build_run_id": 40597188642, "build_run_attempt": 1,
                        "inventory_sha256": "c" * 64, "acquisition_sha256": "d" * 64}
            home = (10, 11, 1000, 700, "directory")
            binding = {"readiness_sha256": "e" * 64, "pid": 1135,
                       "start_ticks": "91460346", "boot_id": "f" * 36,
                       "disk_device": 2128, "disk_inode": 33597607,
                       "engine_id": "engine-705", "guest_uid": 1000,
                       "home_stamp": home}
            original = {"schema": recovery.probe.SCHEMA, "phase": "intent",
                        "vm_id": VM, "probe_id": PROBE,
                        "restart_readiness_sha256": binding["readiness_sha256"],
                        "restart_pid": binding["pid"],
                        "restart_start_ticks": binding["start_ticks"],
                        "controller_boot_id": binding["boot_id"],
                        "disk_device": binding["disk_device"],
                        "disk_inode": binding["disk_inode"],
                        "engine_id": binding["engine_id"],
                        "guest_uid": binding["guest_uid"],
                        "operator_sha256": expected["binary_sha256"],
                        "operator_bytes": expected["binary_bytes"],
                        "source_sha": expected["source_sha"],
                        "release_tag": expected["release_tag"],
                        "build_run_id": expected["build_run_id"],
                        "build_run_attempt": expected["build_run_attempt"],
                        "inventory_sha256": expected["inventory_sha256"],
                        "acquisition_sha256": expected["acquisition_sha256"],
                        "guest_directory": recovery.probe._guest_dir(PROBE),
                        "allowlist": ["--build-identity", "--help"],
                        "qualified": False, "dispatch_authorized": False,
                        "application_deployment_authorized": False,
                        "started_at": 100}
            self.assertEqual(set(original), recovery.ORIGINAL_FIELDS)
            original_raw = recovery.release.encode(original)
            original_sha = recovery.release.digest(original_raw)
            original_name = VM + ".installer-only-probe-intent.json"
            (registry / original_name).write_bytes(original_raw)
            staged = (10, 21, 1000, 600, 1, 42)
            executable = (10, 21, 1000, 700, 1, 42)
            directory_stamp = (10, 20, 1000, 700, "directory", 2)
            current_mode = [600]
            class Lease:
                def __init__(self, _registry):
                    self.parent = os.open(registry, os.O_RDONLY | os.O_DIRECTORY)
                def __enter__(self):
                    return self
                def __exit__(self, *_args):
                    os.close(self.parent)
            def write(parent, name, record):
                raw = recovery.release.encode(record)
                fd = os.open(name, os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                             0o600, dir_fd=parent)
                try:
                    os.write(fd, raw)
                    os.fsync(fd)
                    os.fsync(parent)
                finally:
                    os.close(fd)
                return raw
            def read(parent, name):
                fd = os.open(name, os.O_RDONLY, dir_fd=parent)
                try:
                    raw = os.read(fd, 65537)
                finally:
                    os.close(fd)
                return raw, recovery.release.decode(raw)
            def observe(_binding, _target, _expected, mode=700):
                if mode != current_mode[0]:
                    raise ValueError("staged file mode differs")
                return staged if mode == 600 else executable
            def chmod(_binding, _target, _expected, _old):
                self.assertTrue((registry / (VM + ".installer-only-probe-recovery-intent.json")).is_file())
                current_mode[0] = 700
            kwargs = dict(source=Path("/source"), registry=registry,
                          runtime_parent=Path("/runtime"), vm_id=VM,
                          probe_id=PROBE, recovery_id=RECOVERY,
                          original_intent_sha256=original_sha,
                          controller_admission=Path("/admission.json"),
                          assets=Path("/assets"), gh=Path("/gh"),
                          cosign=Path("/cosign"), client=None)
            admission = {"schema": recovery.ADMISSION_SCHEMA,
                         "original_controller_sha": recovery.ORIGINAL_CONTROLLER_SHA,
                         "original_failure": recovery.ORIGINAL_FAILURE,
                         "classified_stage": recovery.STAGE,
                         "source_sha": "9" * 40, "module_sha256": "8" * 64,
                         "vm_id": VM, "probe_id": PROBE,
                         "original_intent_sha256": original_sha,
                         "readiness_sha256": binding["readiness_sha256"],
                         "directory_device": directory_stamp[0],
                         "directory_inode": directory_stamp[1],
                         "operator_device": staged[0], "operator_inode": staged[1],
                         "operator_sha256": expected["binary_sha256"],
                         "operator_bytes": expected["binary_bytes"],
                         "operator_mode": 600}
            with mock.patch.object(recovery.os, "geteuid", return_value=0), \
                 mock.patch.object(recovery, "_admitted_controller",
                                   return_value=admission), \
                 mock.patch.object(recovery, "ControllerLease", Lease), \
                 mock.patch.object(recovery, "_read_record", side_effect=read), \
                 mock.patch.object(recovery, "_write", side_effect=write), \
                 mock.patch.object(recovery.probe, "_verified_assets", return_value=expected), \
                 mock.patch.object(recovery.probe, "_bound_vm", return_value=binding), \
                 mock.patch.object(recovery.probe, "_guest_home_stamp", return_value=home), \
                 mock.patch.object(recovery.probe, "_guest_stamp", return_value=directory_stamp), \
                 mock.patch.object(recovery.probe, "_guest_operator", side_effect=observe), \
                 mock.patch.object(recovery.probe, "_ssh", return_value=b"marty-deploy\n") as names, \
                 mock.patch.object(recovery, "_held_chmod", side_effect=chmod), \
                 mock.patch.object(recovery.probe, "_execute_sealed",
                                   side_effect=lambda *_a: {"matched": True,
                                       "output_sha256": "f" * 64, "output_bytes": 100}) as run:
                with self.assertRaisesRegex(ValueError, "not the admitted interruption"):
                    recovery.recover(**dict(kwargs, original_intent_sha256="0" * 64))
                with self.assertRaisesRegex(ValueError, "not the admitted interruption"):
                    recovery.recover(**dict(kwargs, probe_id=RECOVERY))
                with self.assertRaisesRegex(ValueError, "not the admitted interruption"):
                    recovery.recover(**dict(kwargs, vm_id=RECOVERY))
                with self.assertRaisesRegex(ValueError, "binding differs"):
                    original["engine_id"] = "different-engine"
                    (registry / original_name).write_bytes(recovery.release.encode(original))
                    changed_sha = recovery.release.digest(recovery.release.encode(original))
                    with mock.patch.dict(admission, {"original_intent_sha256": changed_sha}):
                        recovery.recover(**dict(kwargs, original_intent_sha256=changed_sha))
                original["engine_id"] = binding["engine_id"]
                (registry / original_name).write_bytes(original_raw)
                with mock.patch.dict(admission, {"operator_inode": 99}):
                    with self.assertRaisesRegex(ValueError, "admitted staging differs"):
                        recovery.recover(**kwargs)
                names.return_value = b"unexpected-new-file\n"
                with self.assertRaisesRegex(ValueError, "directory content differs"):
                    recovery.recover(**kwargs)
                self.assertFalse((registry / (VM + ".installer-only-probe-recovery-intent.json")).exists())
                names.return_value = b"marty-deploy\n"
                result = recovery.recover(**kwargs)
                self.assertEqual(result["intent_sha256"], original_sha)
                self.assertEqual(result["recovery_controller_source_sha"], "9" * 40)
                self.assertEqual(run.call_count, 2)
                self.assertEqual((registry / original_name).read_bytes(), original_raw)
                with self.assertRaisesRegex(ValueError, "already exists"):
                    recovery.recover(**kwargs)

                (registry / (VM + ".installer-only-probe-result.json")).unlink()
                with self.assertRaisesRegex(ValueError, "already exists"):
                    recovery.recover(**kwargs)

                (registry / (VM + ".installer-only-probe-recovery-intent.json")).unlink()
                names.return_value = b"unexpected-new-file\n"
                with self.assertRaisesRegex(ValueError, "directory content differs"):
                    recovery.recover(**kwargs)


if __name__ == "__main__":
    unittest.main()
