"""Unprivileged tests for the closed root qualification launcher's ELF gate."""

import importlib.util
import hashlib
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "installer_reader_foreign_owner_root_qualification.py"
spec = importlib.util.spec_from_file_location("reader_root_qualification", SCRIPT)
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)


def elf(*, segment=1, tags=(0,), size=None):
    raw = bytearray(120 + 16 * len(tags))
    raw[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<HH", raw, 16, 3, 62)
    struct.pack_into("<Q", raw, 32, 64)
    struct.pack_into("<HH", raw, 54, 56, 1)
    struct.pack_into("<IIQQQQQQ", raw, 64, segment, 0, 120 if segment == 2 else 0,
                     0, 0, 16 * len(tags) if segment == 2 else 0, 0, 0)
    for index, tag in enumerate(tags):
        struct.pack_into("<qQ", raw, 120 + index * 16, tag, 0)
    if size is not None:
        raw = raw[:size]
    return raw


class ElfGateTests(unittest.TestCase):
    def check(self, data, accepted):
        with tempfile.TemporaryFile() as target:
            target.write(data)
            target.flush()
            with self.subTest(accepted=accepted):
                if accepted:
                    launcher.require_static_elf(target.fileno(), len(data))
                else:
                    with self.assertRaises(RuntimeError):
                        launcher.require_static_elf(target.fileno(), len(data))

    def test_static_and_static_pie_metadata(self):
        self.check(elf(), True)
        self.check(elf(segment=2, tags=(7, 0)), True)

    def test_loader_library_and_search_paths_refused(self):
        self.check(elf(segment=3), False)
        for tag in (1, 15, 29):
            self.check(elf(segment=2, tags=(tag, 0)), False)

    def test_malformed_or_unterminated_tables_refused(self):
        self.check(elf(segment=2, tags=(7,)), False)
        self.check(elf(segment=2, tags=(0,), size=100), False)

    def test_fixed_single_test_invocation(self):
        self.assertEqual(launcher.ARGV,
                         (launcher.TEST, "--exact", "--ignored", "--test-threads=1"))
        self.assertEqual(launcher.SOURCE_SHA256,
                         "5d71767dd8b523efc01161ecf9938a8dcf7f4b5180cc80a142162a1835bf2510")
        self.assertEqual(os.path.basename(launcher.STAGED_SCRIPT),
                         "installer-reader-foreign-owner-root-qualification.py")

    def test_exact_engineering_elf_if_present(self):
        artifact = Path(launcher.SOURCE)
        if not artifact.exists():
            self.skipTest("local engineering ELF is absent")
        self.assertEqual(artifact.stat().st_size, launcher.SOURCE_SIZE)
        digest = hashlib.sha256()
        with artifact.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
            launcher.require_static_elf(source.fileno(), launcher.SOURCE_SIZE)
        self.assertEqual(digest.hexdigest(), launcher.SOURCE_SHA256)

    def test_named_replacement_is_preserved(self):
        with tempfile.TemporaryDirectory() as root:
            parent_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            os.mkdir("fixture", dir_fd=parent_fd)
            held_fd = os.open("fixture", os.O_RDONLY | os.O_DIRECTORY,
                              dir_fd=parent_fd)
            original = os.fstat(held_fd)
            os.rename("fixture", "saved", src_dir_fd=parent_fd,
                      dst_dir_fd=parent_fd)
            os.mkdir("fixture", dir_fd=parent_fd)
            with self.assertRaisesRegex(RuntimeError, "named directory"):
                launcher.require_named_directory(parent_fd, "fixture", original)
            self.assertTrue((Path(root) / "fixture").is_dir())
            self.assertTrue((Path(root) / "saved").is_dir())
            os.close(held_fd)
            os.close(parent_fd)

    def test_empty_fixture_parent_rebind_after_child_removal(self):
        with tempfile.TemporaryDirectory() as root:
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            os.mkdir("parent", dir_fd=root_fd)
            parent_fd = os.open("parent", os.O_RDONLY | os.O_DIRECTORY,
                                dir_fd=root_fd)
            os.mkdir("fixture", dir_fd=parent_fd)
            parent_before = os.fstat(parent_fd)
            launcher.require_named_directory(root_fd, "parent", parent_before)
            os.rmdir("fixture", dir_fd=parent_fd)
            parent_after = os.fstat(parent_fd)
            self.assertEqual(parent_after.st_nlink + 1, parent_before.st_nlink)
            launcher.require_named_directory(root_fd, "parent", parent_after)
            launcher.require_empty_directory(parent_fd)
            os.close(parent_fd)
            os.close(root_fd)

    def test_unknown_fixture_entry_refuses_without_removal(self):
        with tempfile.TemporaryDirectory() as root:
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            foreign = Path(root) / "canary"
            foreign.write_text("preserve")
            with self.assertRaisesRegex(RuntimeError, "not empty"):
                launcher.require_empty_directory(fd)
            self.assertEqual(foreign.read_text(), "preserve")
            os.close(fd)

    def test_root_copy_rehash_refuses_changed_or_replaced_name(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / "qualified-test-elf"
            target.write_bytes(b"abc")
            parent_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            copied_fd = os.open(target, os.O_RDONLY)
            copied_stat = os.fstat(copied_fd)
            expected = hashlib.sha256(b"abc").hexdigest()
            with mock.patch.object(launcher, "SOURCE_SIZE", 3), mock.patch.object(
                    launcher, "SOURCE_SHA256", expected):
                launcher.require_root_copy(parent_fd, copied_fd, copied_stat)
                target.write_bytes(b"abd")
                with self.assertRaisesRegex(RuntimeError, "drift"):
                    launcher.require_root_copy(parent_fd, copied_fd, copied_stat)
                target.write_bytes(b"abc")
                os.rename(target, Path(root) / "saved")
                copied_stat = os.fstat(copied_fd)
                target.write_bytes(b"abc")
                with self.assertRaisesRegex(RuntimeError, "identity drift"):
                    launcher.require_root_copy(parent_fd, copied_fd, copied_stat)
                self.assertEqual(target.read_bytes(), b"abc")
            os.close(copied_fd)
            os.close(parent_fd)

    def test_nonzero_leader_remains_waitable_until_group_kill(self):
        proc = subprocess.Popen((sys.executable, "-c", "raise SystemExit(7)"),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=True, close_fds=True)
        real_killpg = os.killpg
        seen = []

        def check_before_kill(pid, sig):
            status = os.waitid(os.P_PID, pid,
                               os.WEXITED | os.WNOHANG | os.WNOWAIT)
            self.assertIsNotNone(status)
            self.assertIsNone(proc.returncode)
            seen.append((pid, sig))
            return real_killpg(pid, sig)

        with mock.patch.object(launcher.os, "killpg", side_effect=check_before_kill):
            with self.assertRaisesRegex(RuntimeError, "test process failed"):
                launcher.collect_owned_process(proc, None, 3, 1024)
        self.assertEqual(seen, [(proc.pid, launcher.signal.SIGKILL)])
        self.assertEqual(proc.returncode, 7)

    def test_timeout_kills_owned_group_before_reap(self):
        proc = subprocess.Popen((sys.executable, "-c", "import time; time.sleep(30)"),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=True, close_fds=True)
        start = time.monotonic()
        with self.assertRaisesRegex(RuntimeError, "timed out"):
            launcher.collect_owned_process(proc, None, 0.2, 1024)
        self.assertLess(time.monotonic() - start, 5)
        self.assertEqual(proc.returncode, -launcher.signal.SIGKILL)

    def test_success_kills_closed_pipe_descendant(self):
        with tempfile.TemporaryDirectory() as root:
            pidfile = Path(root) / "child.pid"
            code = ("import os,time; p=os.fork(); "
                    "exec('if p == 0:\\n os.close(1); os.close(2); "
                    "time.sleep(30); os._exit(0)'); "
                    f"open({str(pidfile)!r},'w').write(str(p)); os._exit(0)")
            proc = subprocess.Popen((sys.executable, "-c", code),
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    start_new_session=True, close_fds=True)
            self.assertEqual(launcher.collect_owned_process(proc, None, 3, 1024), b"")
            self.assertEqual(proc.returncode, 0)
            child = int(pidfile.read_text())
            for _ in range(30):
                stat_path = Path(f"/proc/{child}/stat")
                if not stat_path.exists() or stat_path.read_text().split()[2] == "Z":
                    break
                time.sleep(0.05)
            else:
                self.fail("closed-pipe descendant survived group cleanup")


if __name__ == "__main__":
    unittest.main()
