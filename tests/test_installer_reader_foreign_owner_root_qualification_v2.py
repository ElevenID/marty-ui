"""Unprivileged POSIX access regression for the distinct v2 qualification fixture."""

import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "installer_reader_foreign_owner_root_qualification_v2.py"
spec = importlib.util.spec_from_file_location("reader_root_qualification_v2", SCRIPT)
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)


@unittest.skipUnless(os.name == "posix", "requires POSIX directory access")
class FixtureAccessTests(unittest.TestCase):
    def test_exact_v2_staged_path_and_root_parent_mode(self):
        self.assertEqual(
            launcher.STAGED_SCRIPT,
            "/root/installer-reader-foreign-owner-root-qualification-v2.py",
        )
        self.assertEqual(launcher.FIXTURE_PARENT_MODE, 0o755)
        self.assertFalse(launcher.FIXTURE_PARENT_MODE & 0o022)

    @unittest.skipIf(os.geteuid() == 0, "test must use an unprivileged EUID")
    def test_traverse_only_ancestor_refuses_read_open_then_0755_allows(self):
        with tempfile.TemporaryDirectory() as root:
            parent = Path(root) / "parent"
            parent.mkdir(mode=0o700)
            child = parent / "fixture"
            child.mkdir(mode=0o700)
            parent.chmod(0o111)
            try:
                self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o111)
                held = os.open(parent, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW)
                os.close(held)
                with self.assertRaises(PermissionError):
                    os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                parent.chmod(launcher.FIXTURE_PARENT_MODE)
                readable = os.open(
                    parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                )
                os.close(readable)
                self.assertEqual(stat.S_IMODE(child.stat().st_mode), 0o700)
            finally:
                parent.chmod(0o700)


if __name__ == "__main__":
    unittest.main()
