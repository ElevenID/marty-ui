"""Exercise the canonical shell contract without compiling anything."""
import os
from pathlib import Path
import subprocess
import shutil
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/build-rust-service-binaries.sh"
SHELL = Path(shutil.which("sh") or "C:/Program Files/Git/usr/bin/sh.exe")


@unittest.skipUnless(SHELL.is_file(), "A POSIX shell is required for this local contract")
class CanonicalNativeBuildOptionsTests(unittest.TestCase):
    def invoke(self, *args):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stub = root / "cargo"
            capture = root / "capture.txt"
            stub.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$CAPTURE"\n', encoding="utf-8")
            stub.chmod(0o700)
            environment = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"],
                               CAPTURE=str(capture))
            result = subprocess.run([str(SHELL), str(SCRIPT), *args], env=environment,
                                    capture_output=True, text=True)
            return result.returncode, capture.read_text().splitlines() if capture.exists() else []

    def test_default_forwards_only_safe_offline_telemetry_options(self):
        code, arguments = self.invoke("default", "--offline", "-j1", "--message-format=json")
        self.assertEqual(code, 0)
        self.assertEqual(arguments[:5], ["build", "--locked", "--release", "--offline", "-j1"])
        self.assertIn("--message-format=json", arguments)
        self.assertEqual(arguments.count("--bin"), 30)

    def test_default_without_options_still_builds_same_set(self):
        code, arguments = self.invoke("default")
        self.assertEqual(code, 0)
        self.assertEqual(arguments[:3], ["build", "--locked", "--release"])
        self.assertEqual(arguments.count("--bin"), 30)

    def test_feature_package_and_profile_overrides_are_rejected_before_cargo(self):
        for option in ("--features=local-key-operations", "--no-default-features", "-p", "--debug"):
            with self.subTest(option=option):
                code, arguments = self.invoke("default", option)
                self.assertEqual(code, 2)
                self.assertFalse(arguments)


if __name__ == "__main__":
    unittest.main()
