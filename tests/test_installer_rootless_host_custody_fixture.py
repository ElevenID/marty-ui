"""No daemon, container, privilege, or network use in these source tests."""

import importlib.util
from pathlib import Path
import tempfile
import unittest


SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "installer_rootless_host_custody_fixture.py"
SPEC = importlib.util.spec_from_file_location("rootless_fixture", SOURCE)
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


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

    def test_client_timeout_kills_only_its_process_group(self):
        with self.assertRaisesRegex(RuntimeError, "bounded command timeout"):
            fixture.run(["/bin/sh", "-c", "sleep 3"], {"PATH": "/usr/bin:/bin"}, timeout=0.1)


if __name__ == "__main__":
    unittest.main()
