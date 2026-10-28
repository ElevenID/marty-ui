"""Pure controls for bounded Keycloak readiness failure diagnostics."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
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

probe.time = Clock()
probe.http_json = lambda _: (_ for _ in ()).throw(HTTPError("http://127.0.0.1", 503, "unready", {}, None))
probe.run = lambda *args: "true"
try:
    probe.wait_for_keycloak("http://127.0.0.1", "disposable", seconds=1)
except RuntimeError as error:
    assert "last=http_503" in str(error)
else:
    raise AssertionError("timeout did not fail closed")

probe.time = Clock()
probe.http_json = lambda _: (_ for _ in ()).throw(URLError(ConnectionRefusedError("secret-in-error")))
try:
    probe.wait_for_keycloak("http://127.0.0.1", "disposable", seconds=1)
except RuntimeError as error:
    assert "network_ConnectionRefusedError" in str(error)
    assert "secret-in-error" not in str(error)
else:
    raise AssertionError("network timeout did not fail closed")

probe.time = Clock()
probe.http_json = lambda _: {"issuer": "synthetic"}
probe.run = lambda *args: (_ for _ in ()).throw(AssertionError("Docker inspect on successful readiness"))
assert probe.wait_for_keycloak("http://127.0.0.1", "disposable", seconds=35) is None

calls = []
def fake_subprocess(argv, **kwargs):
    calls.append(argv)
    if argv[1] == "inspect":
        return SimpleNamespace(returncode=0, stdout=json.dumps({
            "Status": "running", "Running": True, "ExitCode": 0,
            "OOMKilled": False, "Health": {"Status": "starting"},
            "Error": "Bearer hvs.must-not-print", "Pid": 12345,
        }), stderr="")
    return SimpleNamespace(returncode=0, stdout=(
        "INFO Keycloak boot\nWARN Postgres waiting\n"
        "ERROR OpenBao Bearer hvs.must-not-print token=secret-value\n"), stderr="")

probe.subprocess.run = fake_subprocess
result = probe.keycloak_startup_diagnostics("disposable")
rendered = json.dumps(result)
assert result["container"] == {"inspectExitCode": 0, "status": "running", "running": True,
                               "exitCode": 0, "oomKilled": False, "healthStatus": "starting"}
assert result["startupTail"][-1] == {"level": "error", "phase": "kms_provider"}
assert "hvs.must-not-print" not in rendered and "secret-value" not in rendered
assert [call[1] for call in calls] == ["inspect", "logs"]
probe.subprocess.run = lambda *args, **kwargs: (_ for _ in ()).throw(TimeoutError("secret-in-error"))
assert probe.keycloak_startup_diagnostics("disposable") == {"inspectFailureClass": "TimeoutError"}
print("PASS: readiness outcome unchanged; status/class and bounded secret-free startup evidence")
