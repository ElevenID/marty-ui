"""Exact Linux subprocess checks, runnable without third-party dependencies."""
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import installer_host_probe as probe


@unittest.skipUnless(sys.platform == "linux", "Linux process and filesystem boundaries")
class HostProbeLinux(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="host-probe-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.env = {"PATH": probe.SAFE_PATH, "LANG": "C", "HOME": str(self.root)}

    def test_process_bounds_redaction_env_and_private_config(self):
        with mock.patch.dict(probe.os.environ, {"GH_TOKEN": "never-inherited"}):
            result = probe.command([sys.executable, "-c", "import os;print(os.getenv('GH_TOKEN','absent'))"], env=self.env)
        self.assertEqual(result, b"absent\n")
        for code, kwargs in [("import time;time.sleep(10)", {"timeout": 0.1}),
                             ("import sys;sys.stderr.write('secret'*10000)", {"limit": 128}),
                             ("import sys;print('secret');sys.exit(1)", {})]:
            with self.subTest(code=code), self.assertRaisesRegex(ValueError, "^host command observation failed$"):
                probe.command([sys.executable, "-c", code], env=self.env, **kwargs)
        private = self.root / "config"
        private.mkdir(mode=0o700)
        probe.Filesystem().config(private)
        (private / "config.json").write_text("do-not-read")
        with self.assertRaises(ValueError):
            probe.Filesystem().config(private)

    def assert_not_running(self, pid):
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                state = Path(f"/proc/{pid}/stat").read_text().split(") ", 1)[1].split()[0]
            except FileNotFoundError:
                return
            if state == "Z":
                return
            time.sleep(0.01)
        self.fail("owned descendant remains running")

    def test_success_cancels_descendants_with_closed_pipes(self):
        code = """import os,subprocess,sys
assert os.getcwd() == os.environ['HOME']
p = subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'],
                     stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
open('child.pid','w').write(str(p.pid))
print('observed')
"""
        self.assertEqual(probe.command([sys.executable, "-c", code], env=self.env), b"observed\n")
        self.assert_not_running(int((self.root / "child.pid").read_text()))

    def test_interrupt_cancels_and_reaps_owned_process(self):
        original = probe.selectors.DefaultSelector
        root = self.root
        for interruption in (KeyboardInterrupt, SystemExit):
            with self.subTest(interruption=interruption):
                pid_name = interruption.__name__ + ".pid"
                pid_path = root / pid_name
                class InterruptedSelector(original):
                    def select(self, timeout=None):
                        deadline = time.monotonic() + 2
                        while not pid_path.exists():
                            if time.monotonic() >= deadline:
                                raise AssertionError("owned process did not start")
                            time.sleep(0.01)
                        raise interruption()
                with mock.patch.object(probe.selectors, "DefaultSelector", InterruptedSelector):
                    with self.assertRaises(interruption):
                        # Publish only after the PID bytes have been closed;
                        # existence must not expose an empty, newly opened file.
                        code = (
                            "import os,time\n"
                            f"with open({pid_name + '.pending'!r}, 'w') as stream:\n"
                            "    stream.write(str(os.getpid()))\n"
                            f"os.replace({pid_name + '.pending'!r}, {pid_name!r})\n"
                            "time.sleep(30)\n"
                        )
                        probe.command([sys.executable, "-c",
                                       code],
                                      env=self.env)
                pid = int(pid_path.read_text())
                self.assertFalse(Path(f"/proc/{pid}").exists())
                pid_path.unlink()


if __name__ == "__main__":
    unittest.main()
