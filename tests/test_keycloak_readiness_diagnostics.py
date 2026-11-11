"""Bounded Keycloak diagnostics and shared subprocess isolation controls."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError

source = Path(__file__).resolve().parents[1] / "scripts/probe_keycloak_remote_rs256.py"
spec = importlib.util.spec_from_file_location("probe_keycloak_diagnostic", source)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class Clock:
    def __init__(self):
        self.now = 0
    def monotonic(self):
        self.now += 0.5
        return self.now
    def sleep(self, _):
        pass


class ReadinessDiagnostics(unittest.TestCase):
    def test_http_timeout_keeps_status_without_changing_failure(self):
        with patch.object(probe, "time", Clock()), patch.object(probe, "http_json",
                side_effect=HTTPError("http://127.0.0.1", 503, "unready", {}, None)), patch.object(probe, "run", return_value="true"):
            with self.assertRaisesRegex(RuntimeError, "last=http_503"):
                probe.wait_for_keycloak("http://127.0.0.1", "disposable", seconds=1)

    def test_network_timeout_retains_class_without_error_text(self):
        with patch.object(probe, "time", Clock()), patch.object(probe, "http_json",
                side_effect=URLError(ConnectionRefusedError("secret-in-error"))), patch.object(probe, "run", return_value="true"):
            with self.assertRaises(RuntimeError) as caught:
                probe.wait_for_keycloak("http://127.0.0.1", "disposable", seconds=1)
            self.assertIn("network_ConnectionRefusedError", str(caught.exception))
            self.assertNotIn("secret-in-error", str(caught.exception))

    def test_success_does_not_inspect_or_change_readiness(self):
        with patch.object(probe, "time", Clock()), patch.object(probe, "http_json", return_value={"issuer": "synthetic"}), patch.object(probe, "run") as docker:
            self.assertIsNone(probe.wait_for_keycloak("http://127.0.0.1", "disposable", seconds=35))
            docker.assert_not_called()

    def test_startup_evidence_is_bounded_and_secret_free(self):
        original = subprocess.run
        def fake(argv, **kwargs):
            if argv[1] == "inspect":
                return SimpleNamespace(returncode=0, stdout=json.dumps({"Status": "running", "Running": True,
                    "ExitCode": 0, "OOMKilled": False, "Health": {"Status": "starting"}, "Error": "Bearer hvs.must-not-print"}), stderr="")
            return SimpleNamespace(returncode=0, stdout="INFO Keycloak boot\nWARN Postgres waiting\nERROR OpenBao Bearer hvs.must-not-print token=secret-value\n", stderr="")
        with patch.object(probe.subprocess, "run", side_effect=fake) as child:
            result = probe.keycloak_startup_diagnostics("disposable")
            self.assertEqual(result["container"], {"inspectExitCode": 0, "status": "running", "running": True,
                "exitCode": 0, "oomKilled": False, "healthStatus": "starting"})
            self.assertEqual(result["startupTail"][-1], {"level": "error", "phase": "kms_provider"})
            self.assertNotIn("hvs.must-not-print", json.dumps(result))
            self.assertNotIn("secret-value", json.dumps(result))
            self.assertEqual([call.args[0][1] for call in child.call_args_list], ["inspect", "logs"])
        self.assertIs(subprocess.run, original)
        with patch.object(probe.subprocess, "run", side_effect=TimeoutError("secret-in-error")):
            self.assertEqual(probe.keycloak_startup_diagnostics("disposable"), {"inspectFailureClass": "TimeoutError"})
        self.assertIs(subprocess.run, original)

    def test_z_real_subprocess_and_timeout_after_diagnostic(self):
        result = subprocess.run([sys.executable, "-c", "print('owned-control-ok')"], capture_output=True, text=True, timeout=5, check=True)
        self.assertEqual(result.stdout.strip(), "owned-control-ok")
        with self.assertRaises(subprocess.TimeoutExpired):
            subprocess.run([sys.executable, "-c", "import time; time.sleep(1)"], capture_output=True, timeout=0.05)


if __name__ == "__main__":
    unittest.main()
