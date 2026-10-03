"""The one-job runner must not admit work onto an orphaned passport host."""

import json
import os
from pathlib import Path
import subprocess

import pytest

from scripts.check_canvas_oss_runner import (
    check_passport_host_quarantine, check_runner_process_quiescence, docker,
    runner_process_inventory,
)


COMMANDS = {
    "containers": ("ps", "-a", "--format", "{{json .}}"),
    "networks": ("network", "ls", "--format", "{{json .}}"),
    "volumes": ("volume", "ls", "--format", "{{json .}}"),
}
NAME_KEY = {"containers": "Names", "networks": "Name", "volumes": "Name"}


def inventory_runner(rows: dict[str, list[dict]]):
    def run(*args: str) -> str:
        kind = next(kind for kind, command in COMMANDS.items() if args == command)
        return "\n".join(json.dumps(row) for row in rows.get(kind, []))

    return run


def test_quarantine_allows_unrelated_beta_resources(tmp_path: Path) -> None:
    rows = {
        kind: [{key: f"elevenid-beta-{kind}", "Labels": (
            "com.docker.compose.project=elevenid-beta,") }]
        for kind, key in NAME_KEY.items()
    }
    check_passport_host_quarantine(inventory_runner(rows), tmp_path)


@pytest.mark.parametrize("kind", list(COMMANDS))
@pytest.mark.parametrize("identity", ["name", "owner_label", "project_label"])
def test_quarantine_detects_passport_docker_resources(
    tmp_path: Path, kind: str, identity: str,
) -> None:
    name = ("marty-passport-acceptance-base-123456abcdef"
            if identity == "name" else "unexpected-resource-name")
    labels = {
        "name": "",
        "owner_label": "com.marty.passport.acceptance.owner=supported-consumer",
        "project_label": (
            "com.docker.compose.project=marty-passport-acceptance-selfhost-123456abcdef"),
    }[identity]
    rows = {kind: [{NAME_KEY[kind]: name, "Labels": labels}]}
    with pytest.raises(RuntimeError, match=f"{kind}=1"):
        check_passport_host_quarantine(inventory_runner(rows), tmp_path)


def test_quarantine_detects_staged_secret_path_without_reading_it(tmp_path: Path) -> None:
    (tmp_path / "marty-passport-acceptance-base-malformed").write_text(
        "do-not-read", encoding="ascii")
    with pytest.raises(RuntimeError, match="staged_paths=1"):
        check_passport_host_quarantine(inventory_runner({}), tmp_path)


def test_quarantine_fails_closed_on_docker_inventory_error(tmp_path: Path) -> None:
    def fail(*args: str) -> str:
        raise OSError("Docker daemon unavailable")

    with pytest.raises(OSError, match="Docker daemon unavailable"):
        check_passport_host_quarantine(fail, tmp_path)


def test_docker_inventory_forces_local_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DOCKER_HOST", "tcp://other-daemon:2376")
    monkeypatch.setenv("DOCKER_CONTEXT", "other-daemon")
    monkeypatch.setenv("DOCKER_TLS_VERIFY", "1")
    monkeypatch.setenv("DOCKER_CERT_PATH", "/other/certs")
    observed = {}

    def run(*args, **kwargs):
        observed.update(kwargs)
        return subprocess.CompletedProcess(args[0], 0, "", "")

    monkeypatch.setattr(subprocess, "run", run)
    docker("ps", "-a")
    environment = observed["env"]
    assert environment["DOCKER_HOST"] == "unix:///var/run/docker.sock"
    assert all(name not in environment for name in (
        "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"))
    assert os.environ["DOCKER_HOST"] == "tcp://other-daemon:2376"


@pytest.mark.parametrize("process", [
    "Runner.Listener ./bin/Runner.Listener run",
    "Runner.Worker ./bin/Runner.Worker spawnclient",
    "python3 python3 scripts/passport_supported_infra_rehearsal.py --plan plan",
    "timeout timeout 1200s python3 scripts/passport_supported_infra_rehearsal.py",
    "bash bash -c python3 scripts/passport_supported_infra_rehearsal.py",
    "python3 python3 scripts/passport_supported_certificate_rehearsal.py --plan plan",
    "timeout timeout 1200s python3 scripts/passport_supported_certificate_rehearsal.py",
    "bash bash -c python3 scripts/passport_supported_certificate_rehearsal.py",
    "docker docker compose --project-name marty-passport-acceptance-base-123456abcdef up",
])
def test_quarantine_rejects_orphaned_runner_process(process: str) -> None:
    with pytest.raises(RuntimeError, match="still active"):
        check_runner_process_quiescence(lambda: process)


def test_quarantine_process_inventory_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*args, **kwargs):
        raise subprocess.CalledProcessError(1, args[0])

    monkeypatch.setattr(subprocess, "run", fail)
    with pytest.raises(subprocess.CalledProcessError):
        check_runner_process_quiescence(runner_process_inventory)


def test_quarantine_allows_unrelated_processes() -> None:
    check_runner_process_quiescence(lambda: "docker docker ps -a\n"
                                           "python3 python3 unrelated.py\n"
                                           "kworker\n")


def test_quarantine_runs_before_registration_token() -> None:
    root = Path(__file__).resolve().parents[1]
    script = (root / "scripts/register-canvas-oss-runner.ps1").read_text(
        encoding="utf-8")
    gate = "Invoke-WslBash $preflight"
    assert script.count(gate) == 3
    assert script[:script.index('actions/runners/registration-token')].count(gate) == 2
    assert script[script.index('exec ./run.sh'):].count(gate) == 1
    assert r'Global\ElevenIDMartyDockerRunner' in script
    assert script.index('$hostMutex.WaitOne(0)') < script.index('actions/runners/remove-token')
    assert script.index('if (Test-Path -LiteralPath $markerPath)') < script.index(
        'actions/runners/registration-token')
    assert script.index('$existingRunners = @(Get-RepositoryRunners)') < script.index(
        'actions/runners/registration-token')
    assert 'Assert-ExistingRunnerRouting $existingRunners $runnerLabel' in script
    assert 'Assert-NewRunnerRouting $registered $runnerLabel' in script
    assert 'runner-routing-label-policy.ps1' in script
    assert script.index('[System.IO.FileMode]::CreateNew') < script.index('exec ./run.sh')
    assert script.index('exec ./run.sh') < script.index('$hostMutex.ReleaseMutex()')
    assert script.index('exec ./run.sh') < script.index('Remove-Item -LiteralPath $markerPath')
    assert script.index('Assert-NewRunnerRouting $registered $runnerLabel') < script.index('exec ./run.sh')
    assert script.index('$registrationAttempted = $true') < script.index(
        "./config.sh --url '$repoUrl'")
    assert 'if ($registrationAttempted -and -not $markerCreated)' in script
    assert "if test -f '$wslRunnerDirectory/.runner'" in script
    assert 'Could not obtain rejected runner removal token' in script
