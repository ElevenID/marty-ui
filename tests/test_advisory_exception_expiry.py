"""The maintenance exception must expire through the ordinary audit entrypoint."""

from datetime import datetime, timedelta, timezone
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "advisory_exception_expiry", ROOT / "scripts/ci/check-advisory-exception-expiry.py"
)
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


def configuration(tmp_path, ignores):
    path = tmp_path / "deny.toml"
    path.write_text("[advisories]\nignore = " + ignores + "\n", encoding="utf-8")
    return path


@pytest.mark.parametrize(
    "row",
    [
        '"RUSTSEC-2026-0543"',
        '{id="RUSTSEC-2026-0543", reason="temporary maintenance exception"}',
    ],
)
def test_both_cargo_deny_ignore_forms_expire(tmp_path, row):
    path = configuration(tmp_path, "[" + row + "]")
    policy.check(path, policy.EXPIRY - timedelta(microseconds=1))
    for now in (policy.EXPIRY, policy.EXPIRY + timedelta(days=1)):
        with pytest.raises(ValueError, match="expired"):
            policy.check(path, now)


def test_expiry_uses_utc_instead_of_local_calendar(tmp_path):
    path = configuration(tmp_path, '["RUSTSEC-2026-0543"]')
    with pytest.raises(ValueError, match="expired"):
        policy.check(
            path, datetime(2026, 11, 30, 17, tzinfo=timezone(timedelta(hours=-7)))
        )


def test_removing_exception_allows_normal_audit_after_deadline(tmp_path):
    path = configuration(tmp_path, '["RUSTSEC-2023-0071"]')
    policy.check(path, policy.EXPIRY + timedelta(days=90))


@pytest.mark.parametrize(
    "ignores",
    [
        '["RUSTSEC-2026-0543", {id="RUSTSEC-2026-0543"}]',
        '[{reason="missing ID"}]',
        "[false]",
        "[1]",
        '["all"]',
        '"RUSTSEC-2026-0543"',
    ],
)
def test_malformed_and_duplicate_ignores_fail_closed(tmp_path, ignores):
    with pytest.raises(ValueError):
        policy.check(
            configuration(tmp_path, ignores), policy.EXPIRY - timedelta(days=1)
        )


@pytest.mark.parametrize(
    "body", ["", "[advisories]\n", "advisories = []", "broken = ["]
)
def test_missing_or_malformed_configuration_fails_closed(tmp_path, body):
    path = tmp_path / "deny.toml"
    path.write_text(body, encoding="utf-8")
    with pytest.raises(ValueError):
        policy.check(path, policy.EXPIRY - timedelta(days=1))


def test_missing_file_and_naive_clock_fail_closed(tmp_path):
    with pytest.raises(OSError):
        policy.check(tmp_path / "absent.toml", policy.EXPIRY)
    with pytest.raises(ValueError, match="aware"):
        policy.check(configuration(tmp_path, "[]"), datetime(2026, 11, 30))


def test_runtime_has_no_clock_or_configuration_argument_override(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["checker", "--date=2026-11-01"])
    assert policy.main() == 1
    assert "no arguments" in capsys.readouterr().err


def test_runtime_checks_actual_repository_config(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["checker"])
    assert policy.main() == 0


def test_runtime_refuses_expired_policy_despite_environment_clock_values(
    tmp_path, monkeypatch
):
    class Clock:
        @staticmethod
        def now(tz):
            assert tz is timezone.utc
            return policy.EXPIRY

    monkeypatch.setattr(policy, "datetime", Clock)
    monkeypatch.setattr(
        policy, "CONFIGURATION", configuration(tmp_path, '["RUSTSEC-2026-0543"]')
    )
    monkeypatch.setattr(sys, "argv", ["checker"])
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "0")
    monkeypatch.setenv("FAKE_NOW", "2026-01-01")
    assert policy.main() == 1


def test_runtime_refuses_missing_configuration(tmp_path, monkeypatch):
    monkeypatch.setattr(policy, "CONFIGURATION", tmp_path / "absent.toml")
    monkeypatch.setattr(sys, "argv", ["checker"])
    assert policy.main() == 1


def test_shell_stops_before_download_when_policy_checker_refuses(tmp_path):
    bash = shutil.which("bash")
    if os.name == "nt":
        git = shutil.which("git")
        candidate = Path(git).resolve().parents[1] / "bin/bash.exe" if git else None
        bash = str(candidate) if candidate and candidate.is_file() else None
    if not bash:
        pytest.skip("POSIX shell integration requires Bash")
    entrypoint = tmp_path / "audit entrypoint.sh"
    shutil.copyfile(ROOT / "scripts/ci/run-cargo-deny.sh", entrypoint)
    tools = tmp_path / "tools"
    tools.mkdir()
    for name, body in (
        ("python3", "printf checked > guard-ran\nexit 73\n"),
        ("curl", "printf unexpected > download-ran\nexit 1\n"),
    ):
        tool = tools / name
        tool.write_text("#!/bin/sh\n" + body, encoding="utf-8")
        tool.chmod(0o755)
    environment = dict(
        os.environ, PATH=str(tools) + os.pathsep + os.environ.get("PATH", "")
    )
    result = subprocess.run(
        [bash, entrypoint.as_posix()],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        timeout=15,
    )
    assert result.returncode == 73, result.stderr.decode(errors="replace")
    assert (tmp_path / "guard-ran").read_text() == "checked"
    assert not (tmp_path / "download-ran").exists()
