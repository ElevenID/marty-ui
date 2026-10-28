"""Nonprivileged source tests for the fixed package admission controller."""
import json
from pathlib import Path
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import installer_test_vm_rootless_package_admission_controller as controller


def _result():
    return {"schema": "elevenid.installer-only-rootless-package-child/v1",
            "packages": [{"package": name, "version": version, "sha256": "a" * 64,
                          "size": 12, "pocket": "noble-updates", "component": "main"}
                         for name, version in controller.admission.EXPECTED_VERSIONS.items()],
            "archive_releases": [{"pocket": pocket, "base_url": base,
                                  "inrelease_sha256": "c" * 64,
                                  "keyring_sha256": "d" * 64,
                                  "signer_fingerprint": controller.admission.ARCHIVE_FINGERPRINT,
                                  "date": "2026-10-28T00:00:00+00:00", "valid_until": None}
                                 for pocket, base in controller.admission.POCKETS.items()],
            "status_sha256": "b" * 64,
            "installed_docker_io_version": "29.1.3-0ubuntu3~24.04.2",
            "new_package_actions": [{"package": name,
                                     "version": controller.admission.EXPECTED_VERSIONS[name]}
                                    for name in controller.admission.REQUIRED],
            "transaction_simulated": True,
            "rootful_docker_package_simulated_change": False,
            "package_actions_authorized": False,
            "installation_authorized": False, "rootless_ready": False}


def test_child_uses_fixed_nonroot_clean_exec(monkeypatch, tmp_path):
    observed = {}
    monkeypatch.setattr(controller.admission, "trusted_tool", lambda path: (1, 2, 3, 4))
    class Completed:
        returncode = 0
        stderr = b""
        stdout = json.dumps(_result()).encode()
    def run(args, **kwargs):
        observed.update({"args": args, "kwargs": kwargs})
        return Completed()
    monkeypatch.setattr(controller.admission, "run_bounded", run)
    assert controller._child(b"verified code", tmp_path / "bundle",
                             tmp_path / "status")["transaction_simulated"] is True
    args = observed["args"]
    assert args[:8] == ["/usr/bin/setpriv", "--reuid=65534", "--regid=65534",
                        "--clear-groups", "--no-new-privs", "--bounding-set=-all",
                        "--inh-caps=-all", "--ambient-caps=-all"]
    assert args[8:11] == ["/usr/bin/python3", "-I", "-B"]
    assert observed["kwargs"]["stdout_limit"] == 65536
    assert observed["kwargs"]["stderr_limit"] == 4096
    assert observed["kwargs"]["env"] == {"PATH": "/usr/bin", "HOME": "/nonexistent",
                                            "LC_ALL": "C"}
    assert observed["kwargs"]["input_bytes"] == b"verified code"


def test_child_refuses_nonzero_or_authorizing_result(monkeypatch, tmp_path):
    monkeypatch.setattr(controller.admission, "trusted_tool", lambda path: (1, 2, 3, 4))
    for exit_code, payload in ((1, b"{}"),
                               (0, json.dumps({**_result(),
                                               "package_actions_authorized": True}).encode()),
                               (0, b"not-json")):
        def run(*args, **kwargs):
            return subprocess.CompletedProcess(args, exit_code, payload, b"")
        with monkeypatch.context() as patch:
            patch.setattr(controller.admission, "run_bounded", run)
            with pytest.raises(ValueError):
                controller._child(b"verified code", tmp_path / "bundle", tmp_path / "status")
