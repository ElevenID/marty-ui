"""Synthetic, non-VM checks for the closed rootless prerequisite observation."""
from __future__ import annotations

import os
from pathlib import Path
import shlex
import sys
import tempfile
import unittest
from unittest import mock

if sys.platform != "linux":
    raise unittest.SkipTest("Linux controller tests")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import installer_test_vm_rootless_prerequisites as subject


VM = "70573b98-a002-468c-a932-f27c1ca20440"
OBSERVATION = "acc531dd-5697-47c1-bfe0-43e4cc152b5e"


def guest() -> dict:
    return {"schema": subject.GUEST_SCHEMA, "uid": 1000, "gid": 1000,
            "docker_group": True, "sudo_group": True,
            "sudo_policy_known": False,
            "binaries": {name: {"kind": "missing", "root_owned": False,
                                "not_writable": False, "setuid": False}
                         for name in subject.BINARY_NAMES},
            "subuid": {"status": "observed", "account_entries": 1,
                       "sufficient_65536": True},
            "subgid": {"status": "unknown", "account_entries": 0,
                       "sufficient_65536": False},
            "userns_clone": 1, "max_user_namespaces": 10000,
            "cgroup_v2_controllers": {"cpu": True, "memory": True, "pids": True},
            "mem_available_kib": 1200000, "home_available_bytes": 4000000000,
            "home_total_bytes": 8000000000, "daemon_started": False,
            "rootless_ready": False}


class RootlessPrerequisites(unittest.TestCase):
    def test_fixed_guest_command_and_sanitized_schema(self):
        argv = shlex.split(subject._guest_command())
        self.assertEqual(argv[:5], ["/usr/bin/python3", "-E", "-I", "-B", "-c"])
        self.assertEqual(argv[5], subject.GUEST_SCRIPT)
        for forbidden in ("dockerd-rootless-setuptool.sh --check", "sudo -", "unshare ",
                          "docker info", "docker ps", "systemctl --user start"):
            self.assertNotIn(forbidden, subject.GUEST_SCRIPT)
        self.assertEqual(subject._decode_guest(subject.release.encode(guest()), 1000),
                         guest())
        for bad in (dict(guest(), uid=0), dict(guest(), rootless_ready=True),
                    dict(guest(), unrelated_secret="canary"),
                    dict(guest(), subuid={"status": "observed", "account_entries": 1,
                                          "sufficient_65536": True,
                                          "raw_line": "foreign:1:2"})):
            with self.assertRaises(ValueError):
                subject._decode_guest(subject.release.encode(bad), 1000)

    def test_systemd_user_only_fixed_fields_and_expected_runtime_path(self):
        self.assertEqual(subject._systemd_user(
            b"Linger=no\nState=active\nRuntimePath=/run/user/1000\n", 1000),
            {"status": "observed", "linger": False, "state": "active",
             "runtime_path_expected": True})
        for raw in (None, b"Linger=yes\nState=active\nEnvironment=secret\n",
                    b"Linger=yes\nState=custom\nRuntimePath=/run/user/1000\n"):
            self.assertEqual(subject._systemd_user(raw, 1000)["status"], "unknown")

    def test_one_shot_result_requires_same_live_vm_before_private_write(self):
        with tempfile.TemporaryDirectory() as temporary:
            registry = Path(temporary)
            binding = {"guest_uid": 1000, "readiness_sha256": "a" * 64,
                       "pid": 1135, "start_ticks": "91460346", "engine_id": "engine-705"}
            class Lease:
                def __init__(self, _registry):
                    self.parent = os.open(registry, os.O_RDONLY | os.O_DIRECTORY)
                def __enter__(self):
                    return self
                def __exit__(self, *_):
                    os.close(self.parent)
            def write(parent, name, record):
                fd = os.open(name, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600,
                             dir_fd=parent)
                try:
                    os.write(fd, subject.release.encode(record))
                    os.fsync(fd)
                    os.fsync(parent)
                finally:
                    os.close(fd)
            kwargs = {"source": Path("/source"), "registry": registry,
                      "runtime_parent": Path("/runtime"), "vm_id": VM,
                      "observation_id": OBSERVATION}
            with mock.patch.object(subject.os, "geteuid", return_value=0), \
                 mock.patch.object(subject, "ControllerLease", Lease), \
                 mock.patch.object(subject.probe, "_bound_vm", return_value=binding) as bound, \
                 mock.patch.object(subject.probe, "_ssh", side_effect=[
                     subject.release.encode(guest()),
                     b"Linger=no\nState=active\nRuntimePath=/run/user/1000\n"]) as ssh, \
                 mock.patch.object(subject, "_write", side_effect=write):
                result = subject.observe(**kwargs)
                self.assertEqual(bound.call_count, 2)
                self.assertEqual(ssh.call_count, 2)
                self.assertEqual(ssh.call_args_list[0].args[1], subject._guest_command())
                self.assertEqual(ssh.call_args_list[1].args[1], subject.LOGINCTL_COMMAND)
                self.assertFalse(result["rootless_ready"])
                self.assertFalse(result["installation_authorized"])
                self.assertTrue((registry / (VM + subject.RESULT_SUFFIX)).is_file())
                with self.assertRaisesRegex(ValueError, "already recorded"):
                    subject.observe(**kwargs)

            (registry / (VM + subject.RESULT_SUFFIX)).unlink()
            changed = dict(binding, engine_id="replacement")
            with mock.patch.object(subject.os, "geteuid", return_value=0), \
                 mock.patch.object(subject, "ControllerLease", Lease), \
                 mock.patch.object(subject.probe, "_bound_vm", side_effect=[binding, changed]), \
                 mock.patch.object(subject.probe, "_ssh", side_effect=[
                     subject.release.encode(guest()), b""]), \
                 mock.patch.object(subject, "_write", side_effect=write) as writing:
                with self.assertRaisesRegex(ValueError, "live binding changed"):
                    subject.observe(**kwargs)
                writing.assert_not_called()


if __name__ == "__main__":
    unittest.main()
