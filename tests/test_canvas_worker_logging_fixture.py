"""Logging corpus and container ownership controls, not process parity evidence."""

import importlib
import json
from pathlib import Path
import subprocess

import pytest


def test_logging_reference_preserves_all_declared_inputs_and_source():
    root = Path(__file__).resolve().parents[1]
    contracts = root / "contracts"
    reference = json.loads(
        (contracts / "canvas-worker-logging-oracle.json").read_text()
    )
    spec = json.loads((contracts / "canvas-worker-logging-scenarios.json").read_text())
    startup = json.loads((contracts / "canvas-worker-startup-oracle.json").read_text())
    assert (
        reference["source_sha256"] == startup["source_sha256"]["issuance.canvas_worker"]
    )
    assert [case["input"] for case in reference["cases"]] == spec["levels"]
    assert len(reference["cases"]) == 16
    assert sum("error_class" in case["observed"] for case in reference["cases"]) == 7
    workflow = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "python3 scripts/test_canvas_worker_logging_reference.py" in workflow
    dockerfile = (root / "rust/services/Dockerfile.ci").read_text(encoding="utf-8")
    issuance = dockerfile.split("FROM runtime AS issuance\n", 1)[1].split(
        "FROM runtime AS gateway\n", 1
    )[0]
    assert "RUST_LOG=" not in issuance, "image defaults must not mask deployed LOG_LEVEL"
    assert "RUST_LOG=" not in (root / "services/Dockerfile").read_text(encoding="utf-8")


@pytest.mark.parametrize("failure", [None, "start", "wait", "exit", "mismatch"])
def test_reference_container_is_reaped_after_every_observation_path(
    monkeypatch, failure
):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    runner = importlib.import_module("test_canvas_worker_logging_reference")
    owner = importlib.import_module("test_canvas_worker_image_entrypoint")
    calls = []
    identity = "a" * 64

    def docker(*arguments, **options):
        calls.append(arguments)
        operation = arguments[0]
        if operation == "create":
            return identity
        if operation == failure:
            raise subprocess.CalledProcessError(1, ["docker", operation])
        if operation == "wait":
            assert options["timeout"] == 20
            return "1" if failure == "exit" else "0"
        if operation == "logs":
            return (
                "mismatch"
                if failure == "mismatch"
                else "Published worker logging reference passed (16 cases)"
            )
        return ""

    monkeypatch.setattr(owner, "docker", docker)
    monkeypatch.setattr(runner, "docker", docker)
    if failure:
        with pytest.raises((AssertionError, subprocess.CalledProcessError)):
            runner.run()
    else:
        runner.run()
    assert calls[-1] == ("rm", "--force", identity)
    create = calls[0]
    assert create[create.index("--network") + 1] == "none"
    assert "--read-only" in create and "--publish" not in create
    assert create[-1] == "--check"
