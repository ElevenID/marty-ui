"""The native batch preflight must stay inside its owned disposable project."""

from datetime import datetime, timezone
from pathlib import Path
import subprocess
import sys

import pytest

from scripts import passport_supported_native_batch_preflight as preflight


NOW = datetime(2026, 9, 30, tzinfo=timezone.utc)
PROJECT = "marty-passport-acceptance-base-abcdef"
NATIVE_ID = "a" * 64


def test_preflight_script_mode_imports_from_protected_workflow(tmp_path: Path) -> None:
    result = subprocess.run(
        [sys.executable, str(Path(preflight.__file__))], cwd=tmp_path,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")


def staged(tmp_path: Path, monkeypatch) -> dict:
    monkeypatch.setattr(preflight.tempfile, "gettempdir", lambda: str(tmp_path))
    root = tmp_path / PROJECT
    secrets = root / "secrets"
    secrets.mkdir(parents=True)
    (secrets / "grpc_service_token").write_text("1" * 64, encoding="ascii")
    (secrets / "passport_beta_reconciliation_operator_token").write_text(
        "2" * 64, encoding="ascii")
    return {"project": PROJECT, "disposable_root": str(root),
            "containers": {"issuance-native": NATIVE_ID}}


def test_preflight_uses_owned_native_and_local_docker(tmp_path: Path, monkeypatch) -> None:
    record = staged(tmp_path, monkeypatch)
    calls = []

    def run(command, *, input, stdout, stderr, check, timeout, env):
        calls.append((command, input))
        assert command == ["docker", "exec", "-i", NATIVE_ID, "curl", "--config", "-"]
        assert env["DOCKER_HOST"] == "unix:///var/run/docker.sock"
        assert "DOCKER_CONTEXT" not in env
        assert stdout == subprocess.PIPE and stderr == subprocess.DEVNULL
        assert check is False and timeout == 70
        return subprocess.CompletedProcess(command, 0, (
            b'{"ready":true,"provider_profile_id":"passport-beta-bureau",'
            b'"issuer_mode":"managed-issuer-profile","artifact_custody":"kms"}\n200'))

    monkeypatch.setenv("DOCKER_CONTEXT", "remote-host")
    result = preflight.preflight_owned_native(
        record, "base", inspector=lambda args: "",
        ownership=lambda *args: {"live_ownership_verified": True},
        run=run, clock=lambda: NOW)
    assert result == {"native_container_id": NATIVE_ID,
                      "native_batch_preflight_verified": True}
    assert len(calls) == 1
    assert b"1" * 64 in calls[0][1] and b"2" * 64 in calls[0][1]
    assert "1" * 64 not in str(result) and "2" * 64 not in str(result)


def test_preflight_fails_if_ownership_changes_before_private_call(
    tmp_path: Path, monkeypatch,
) -> None:
    record = staged(tmp_path, monkeypatch)
    checks = []

    def ownership(*args):
        checks.append(True)
        return {"live_ownership_verified": len(checks) == 1}

    with pytest.raises(preflight.DisposableBatchPreflightError,
                       match="ownership changed"):
        preflight.preflight_owned_native(
            record, "base", inspector=lambda args: "",
            ownership=ownership,
            run=lambda *args, **kwargs: pytest.fail("private call escaped ownership"),
            clock=lambda: NOW)


def test_preflight_rejects_shared_operator_token(tmp_path: Path, monkeypatch) -> None:
    record = staged(tmp_path, monkeypatch)
    root = Path(record["disposable_root"])
    (root / "secrets/passport_beta_reconciliation_operator_token").write_text(
        "1" * 64, encoding="ascii")
    with pytest.raises(preflight.DisposableBatchPreflightError,
                       match="not distinct"):
        preflight.preflight_owned_native(
            record, "base", inspector=lambda args: "",
            ownership=lambda *args: {"live_ownership_verified": True},
            clock=lambda: NOW)
