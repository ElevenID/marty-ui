"""Synthetic tests only: no VM, package, account, or Docker mutation."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import installer_candidate_vm_seed as seed  # noqa: E402
import installer_candidate_vm_launch as launch  # noqa: E402
import installer_test_vm_rootless_fixture as fixture  # noqa: E402
import installer_release as release  # noqa: E402


class FixtureTests(unittest.TestCase):
    VM_ID = "85c24c93-54bf-4450-ae24-a1156b918e26"

    def test_rootless_seed_has_no_sudo_docker_group_or_daemon_start(self):
        key = "ssh-ed25519 " + "A" * 44
        host = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + "A" * 120 + "\n-----END OPENSSH PRIVATE KEY-----\n"
        raw = seed._cloud_config(key, key, host, seed.ROOTLESS_FIXTURE_PROFILE)
        self.assertIn(b"sudo: false", raw)
        self.assertIn(b"groups: installer", raw)
        self.assertIn(b"openssh-server", raw)
        installer_block = raw.split(b"  - name: installer\n", 1)[1].split(
            b"  - name: fixture-admin\n", 1)[0]
        self.assertNotIn(b"NOPASSWD", installer_block)
        self.assertIn(b"  - name: fixture-admin", raw)
        for forbidden in (b"groups: docker", b"docker.io",
                          b"enable, --now, docker", b"rootlesskit", b"uidmap"):
            self.assertNotIn(forbidden, raw)

    def test_rootless_seed_cloud_init_schema_when_tool_available(self):
        tool = shutil.which("cloud-init")
        if tool is None:
            self.skipTest("cloud-init absent")
        key = "ssh-ed25519 " + "A" * 44
        host = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + "A" * 120 + "\n-----END OPENSSH PRIVATE KEY-----\n"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "user-data"
            path.write_bytes(seed._cloud_config(key, key, host,
                                                seed.ROOTLESS_FIXTURE_PROFILE))
            result = subprocess.run([tool, "schema", "--config-file", str(path)],
                                    capture_output=True, timeout=20, check=False)
            self.assertEqual(result.returncode, 0, result.stderr[:1024])

    def test_legacy_seed_policy_remains_exact(self):
        key = "ssh-ed25519 " + "A" * 44
        host = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + "A" * 120 + "\n-----END OPENSSH PRIVATE KEY-----\n"
        raw = seed._cloud_config(key, key, host)
        self.assertIn(b"sudo: ALL=(ALL) NOPASSWD:ALL", raw)
        self.assertIn(b"groups: docker", raw)
        self.assertIn(b"enable, --now, docker", raw)
        self.assertIn(b"docker.io", raw)

    def test_fresh_fixture_memory_changes_only_qemu_memory_argument(self):
        with mock.patch.object(launch, "_safe_runtime_path"):
            old = launch._arguments(Path("/tmp/fixture") / self.VM_ID,
                                    self.VM_ID, 22024)
            new = launch._arguments(Path("/tmp/fixture") / self.VM_ID,
                                    self.VM_ID, 22024,
                                    launch.ROOTLESS_FIXTURE_MEMORY_MIB)
        position = old.index("-m") + 1
        self.assertEqual(old[position], "4096")
        self.assertEqual(new[position], "2048")
        self.assertEqual(new[:position] + new[position + 1:],
                         old[:position] + old[position + 1:])
        with self.assertRaises(ValueError):
            launch._arguments(Path("/tmp/fixture") / self.VM_ID,
                              self.VM_ID, 22024, 1024)

    def test_bad_identity_refuses_before_source_or_disk(self):
        with mock.patch.object(fixture.create, "verify_source") as source, \
             mock.patch.object(fixture.create, "create_overlay") as disk, \
             mock.patch.object(fixture.os, "geteuid", return_value=0):
            with self.assertRaises(ValueError):
                fixture.prepare_fixture(source=Path("/source"), registry=Path("/registry"),
                                        vm_parent=Path("/vm"), runtime_parent=Path("/run"),
                                        vm_id=str(uuid.uuid4()), runtime_uid=0,
                                        runtime_gid=987, ssh_port=22024)
            source.assert_not_called()
            disk.assert_not_called()

    def test_durable_intent_precedes_disk_and_failure_never_starts_seed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            registry, vm_parent, runtime_parent = (root / name for name in
                                                   ("registry", "vm", "runtime"))
            for path in (registry, vm_parent, runtime_parent):
                path.mkdir()
            events: list[str] = []
            records: dict[str, tuple[bytes, dict]] = {}
            class Lease:
                def __enter__(self):
                    self.parent = os.open(registry, os.O_RDONLY)
                    return self
                def __exit__(self, *_):
                    os.close(self.parent)
            def write(_fd, name, value):
                events.append("intent")
                raw = release.encode(value)
                records[name] = (raw, value)
                return raw
            def disk(*args, **kwargs):
                events.append("disk")
                raise RuntimeError("synthetic interrupted create")
            provenance = {key: "a" * 64 for key in
                          ("image_sha256", "manifest_sha256", "signature_sha256",
                           "keyring_sha256")}
            with mock.patch.object(fixture.os, "geteuid", return_value=0), \
                 mock.patch.object(fixture, "ControllerLease", return_value=Lease()), \
                 mock.patch.object(fixture, "_directory",
                                   side_effect=lambda p: os.open(p, os.O_RDONLY)), \
                 mock.patch.object(fixture.create, "verify_source", return_value=provenance), \
                 mock.patch.object(fixture.create, "_rebind_directory"), \
                 mock.patch.object(fixture.runtime, "_same_path"), \
                 mock.patch.object(fixture.runtime, "_runtime_parent",
                                   side_effect=lambda p: os.open(p, os.O_RDONLY)), \
                 mock.patch.object(fixture.create, "_write", side_effect=write), \
                 mock.patch.object(fixture.create, "create_overlay", side_effect=disk), \
                 mock.patch.object(fixture.runtime, "transfer") as transfer, \
                 mock.patch.object(fixture.seed, "prepare") as seed_prepare:
                with self.assertRaisesRegex(RuntimeError, "interrupted create"):
                    fixture.prepare_fixture(source=root / "source", registry=registry,
                                            vm_parent=vm_parent, runtime_parent=runtime_parent,
                                            vm_id=self.VM_ID, runtime_uid=994,
                                            runtime_gid=987, ssh_port=22024)
                self.assertEqual(events, ["intent", "disk"])
                self.assertEqual(records[self.VM_ID + fixture.RECORD_SUFFIX][1]
                                 ["guest_profile"], seed.ROOTLESS_FIXTURE_PROFILE)
                transfer.assert_not_called()
                seed_prepare.assert_not_called()


if __name__ == "__main__":
    unittest.main()
