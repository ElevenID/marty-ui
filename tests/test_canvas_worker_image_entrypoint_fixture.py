"""Packaging fixture ownership tests, not application runtime qualification."""

import importlib
from pathlib import Path
import subprocess

import pytest


@pytest.fixture
def entrypoint(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    return importlib.import_module("test_canvas_worker_image_entrypoint")


@pytest.mark.parametrize("failure", [None, "start", "wait", "logs", "assertion"])
def test_every_created_container_is_reaped(entrypoint, monkeypatch, tmp_path, failure):
    owned_id = "a" * 64
    calls = []

    def docker(*arguments, **kwargs):
        calls.append((arguments, kwargs))
        operation = arguments[0]
        if operation == failure:
            raise subprocess.TimeoutExpired(["docker", operation], 15)
        if operation == "create":
            return owned_id
        if operation == "wait":
            return "0" if failure == "assertion" else "1"
        if operation == "logs":
            return (
                "Starting canonical Rust service: canvas-sync-worker\n"
                "INTEGRATION_SECRET_MASTER_KEY source is required"
            )
        return ""

    monkeypatch.setattr(entrypoint, "docker", docker)
    if failure:
        with pytest.raises((subprocess.TimeoutExpired, AssertionError)):
            entrypoint.exercise_case("synthetic-image", entrypoint.CASES[0], tmp_path)
    else:
        entrypoint.exercise_case("synthetic-image", entrypoint.CASES[0], tmp_path)
    assert calls[-1][0] == ("rm", "--force", owned_id)
    assert sum(call[0][0] == "rm" for call in calls) == 1
    arguments = calls[0][0]
    assert arguments[arguments.index("--network") + 1] == "none"
    assert "--read-only" in arguments
    assert "--publish" not in arguments
    if failure not in {"start"}:
        assert next(options for args, options in calls if args[0] == "wait") == {
            "timeout": 15
        }


def test_create_failure_does_not_remove_unowned_container(
    entrypoint, monkeypatch, tmp_path
):
    calls = []

    def docker(*arguments, **kwargs):
        calls.append(arguments)
        raise subprocess.CalledProcessError(1, ["docker", "create"])

    monkeypatch.setattr(entrypoint, "docker", docker)
    with pytest.raises(subprocess.CalledProcessError):
        entrypoint.exercise_case("synthetic-image", entrypoint.CASES[0], tmp_path)
    assert len(calls) == 1
    assert calls[0][0] == "create"


def test_docker_logs_include_stderr_diagnostics(entrypoint, monkeypatch):
    def run(command, **options):
        assert options["check"]
        assert options["timeout"] == 30
        return subprocess.CompletedProcess(
            command, 0, stdout="launch\n", stderr="error\n"
        )

    monkeypatch.setattr(entrypoint.subprocess, "run", run)
    assert entrypoint.docker("logs", "a" * 64) == "launch\nerror"
    assert entrypoint.docker("create", "synthetic-image") == "launch"


def test_outer_container_cleanup_survives_inner_cleanup_failure(
    entrypoint, monkeypatch
):
    identities = iter(["a" * 64, "b" * 64])
    removed = []

    def docker(*arguments, **options):
        if arguments[0] == "create":
            return next(identities)
        assert arguments[:2] == ("rm", "--force")
        removed.append(arguments[2])
        if arguments[2] == "b" * 64:
            raise subprocess.CalledProcessError(1, ["docker", "rm"])
        return ""

    monkeypatch.setattr(entrypoint, "docker", docker)
    with pytest.raises(subprocess.CalledProcessError):
        with entrypoint.owned_container("synthetic-postgres"):
            with entrypoint.owned_container("synthetic-worker"):
                pass
    assert removed == ["b" * 64, "a" * 64]


def test_ci_executes_packaged_worker_and_preserves_api_default():
    root = Path(__file__).resolve().parents[1]
    dockerfile = (root / "rust/services/Dockerfile.ci").read_text(encoding="utf-8")
    issuance = dockerfile.split("FROM runtime AS issuance\n", 1)[1].split(
        "FROM runtime AS gateway\n", 1
    )[0]
    assert "ENV SERVICE_NAME=issuance_native" in issuance
    assert 'ENTRYPOINT ["/app/services/entrypoint.sh"]' in issuance
    assert (
        "COPY --chmod=755 services/entrypoint.sh /app/services/entrypoint.sh"
        in issuance
    )
    assert (
        "COPY --chown=10001:10001 scripts/load-secrets-env.sh /usr/local/bin/load-secrets-env.sh"
        in issuance
    )
    entrypoint = (root / "services/entrypoint.sh").read_text(encoding="utf-8")
    assert entrypoint.index(". /app/load-secrets-env.sh") < entrypoint.index(
        ". /usr/local/bin/load-secrets-env.sh"
    )
    workflow = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert (
        "python3 scripts/test_canvas_worker_image_entrypoint.py marty-issuance:ci"
        in workflow
    )
    assert "name: Smoke-test issuance image" in workflow


def test_preflight_matrix_retains_aliases_and_secret_conflicts(entrypoint):
    assert len(entrypoint.CASES) == 8
    assert {case.name for case in entrypoint.CASES} == {
        "hyphen",
        "underscore",
        "direct_key",
        "file_key",
        "conflicting_key_sources",
        "missing_file",
        "unknown_service",
        "empty_service",
    }
