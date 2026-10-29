"""No daemon, container, privilege, or network use in these source tests."""

import importlib.util
import hashlib
from pathlib import Path
import subprocess
import sys
import threading
import tempfile
import unittest
from datetime import datetime, timezone
from email.utils import format_datetime
from unittest import mock


SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "installer_rootless_host_custody_fixture.py"
SPEC = importlib.util.spec_from_file_location("rootless_fixture", SOURCE)
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)
sys.path.insert(0, str(SOURCE.parent))
ADMISSION_SPEC = importlib.util.spec_from_file_location(
    "rootless_admission", SOURCE.parent / "installer_rootless_tool_admission.py")
admission = importlib.util.module_from_spec(ADMISSION_SPEC)
ADMISSION_SPEC.loader.exec_module(admission)


class RootlessHostCustodyFixtureTests(unittest.TestCase):
    def test_exact_mapping_for_root_and_openbao_user(self):
        mapping = "         0       1000          1\n         1     231072      65536\n"
        self.assertEqual(fixture.mapped(mapping, 0), 1000)
        self.assertEqual(fixture.mapped(mapping, 100), 231171)

    def test_mapping_refuses_missing_duplicate_and_malformed_ranges(self):
        for mapping in ("1 231072 65536\n", "0 1000 1\n0 2000 1\n", "0 -1 1\n"):
            with self.subTest(mapping=mapping), self.assertRaises(RuntimeError):
                fixture.mapped(mapping, 0)

    def test_unsigned_or_different_inventory_bytes_refuse(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "installer-inventory.json"
            path.write_text('{"images":{"openbao_didcomm_image":"other"}}')
            with self.assertRaisesRegex(RuntimeError, "authenticated inventory bytes differ"):
                fixture.authenticated_image(path)

    def test_bounded_regular_output_and_wrong_owner_refuse(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "output"
            path.write_bytes(fixture.CANARY)
            path.chmod(0o444)
            self.assertEqual(fixture.inspect_owner(path, __import__('os').geteuid(), 0o444).st_size,
                             len(fixture.CANARY))
            with self.assertRaises(RuntimeError):
                fixture.inspect_owner(path, __import__('os').geteuid() + 1, 0o444)
            path.chmod(0o644)
            with self.assertRaises(RuntimeError):
                fixture.inspect_owner(path, __import__('os').geteuid(), 0o444)

    def test_client_exec_sets_no_new_privileges_and_bounds_output(self):
        env = {"PATH": "/usr/bin:/bin"}
        output = fixture.run(["/bin/sh", "-c", "grep '^NoNewPrivs:' /proc/self/status"], env)
        self.assertEqual(output.split()[-1], "1")
        with self.assertRaisesRegex(RuntimeError, "bounded command output exceeded"):
            fixture.run(["/usr/bin/python3", "-c", "import os;os.write(1,b'x'*70000)"], env)

    def test_no_new_privileges_exec_is_bounded_while_log_thread_is_live(self):
        release = threading.Event()
        worker = threading.Thread(target=lambda: release.wait(2), daemon=True)
        worker.start()
        try:
            self.assertTrue(worker.is_alive())
            output = fixture.run(["/bin/sh", "-c", "grep '^NoNewPrivs:' /proc/self/status"],
                                 {"PATH": "/usr/bin:/bin"}, timeout=2)
            self.assertEqual(output.split()[-1], "1")
        finally:
            release.set()
            worker.join(timeout=2)

    def test_client_timeout_kills_only_its_process_group(self):
        with self.assertRaisesRegex(RuntimeError, "bounded command timeout"):
            fixture.run(["/bin/sh", "-c", "sleep 3"], {"PATH": "/usr/bin:/bin"}, timeout=0.1)

    def test_binary_tool_output_is_bounded_without_reaping_before_cleanup(self):
        result = fixture.run(["/usr/bin/python3", "-c", "import os;os.write(1,b'x'*70000)"],
                             {"PATH": "/usr/bin:/bin"}, output_limit=70000, binary=True)
        self.assertEqual(result, b"x" * 70000)

    def test_signed_index_package_selection_accepts_exact_docker_epoch(self):
        record = ("Package: docker-ce-rootless-extras\n"
                  "Version: 5:28.0.4-1~ubuntu.24.04~noble\n"
                  "Architecture: amd64\n"
                  "Filename: dists/noble/pool/stable/amd64/"
                  "docker-ce-rootless-extras_28.0.4-1~ubuntu.24.04~noble_amd64.deb\n"
                  "SHA256: " + "a" * 64 + "\nSize: 6092294\n")
        selected = admission.package_record(record, "28.0.4")
        self.assertEqual(selected["Version"], "5:28.0.4-1~ubuntu.24.04~noble")
        for changed in (record.replace("amd64\n", "arm64\n", 1),
                        record.replace("28.0.4", "29.0.4"), record + "\n" + record):
            with self.subTest(changed=changed[-80:]), self.assertRaises(RuntimeError):
                admission.package_record(changed, "28.0.4")

    def test_owned_daemon_group_stops_before_leader_reap(self):
        with tempfile.TemporaryDirectory() as temp:
            proc = subprocess.Popen(["/bin/sleep", "30"], start_new_session=True)
            fixture.stop_daemon(proc, fixture.proc_stamp(proc.pid),
                                Path(temp) / "missing.sock", None, Path(temp))
            self.assertIsNotNone(proc.returncode)

    def test_signed_index_requires_identity_fresh_date_and_exact_packages_hash(self):
        packages = b"Package: docker-ce-rootless-extras\n\n"
        date = format_datetime(datetime.now(timezone.utc))
        index = ("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n"
                 "Architectures: amd64 arm64\nComponents: stable edge\n"
                 f"Date: {date}\nLabel: Docker CE\nOrigin: Docker\nSuite: noble\n"
                 "SHA256:\n " + hashlib.sha256(packages).hexdigest() + " "
                 + str(len(packages)) + " stable/binary-amd64/Packages\n").encode()
        def fetch(relative, _limit):
            return {"gpg": b"key", "dists/noble/InRelease": index,
                    "dists/noble/stable/binary-amd64/Packages": packages}[relative]
        def verify(argv, _env):
            if "--show-keys" in argv:
                return "pub:::::::::\nfpr:::::::::" + admission.FINGERPRINT + ":\n"
            if "--status-fd" in argv:
                return "[GNUPG:] VALIDSIG " + admission.FINGERPRINT + " 0 0 0 0 0 0 0 0 " + admission.FINGERPRINT
            return ""
        with tempfile.TemporaryDirectory() as temp, \
             mock.patch.object(admission, "bounded_get", side_effect=fetch), \
             mock.patch.object(admission.fixture, "run", side_effect=verify):
            self.assertEqual(admission.signed_index(Path(temp))[0].encode(), packages)


if __name__ == "__main__":
    unittest.main()
