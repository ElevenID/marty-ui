"""Recovery rehearsal contract and opt-in container integration test."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from rehearse_selfhost_state_recovery import probe_check, read_model, rehearse, stop_owned  # noqa: E402


def model(state_root: Path, postgres_image: str = "postgres:15-alpine") -> dict:
    return {
        "services": {
            "postgres": {"image": postgres_image, "volumes": [{
                "type": "bind", "source": str(state_root / "postgres"),
                "target": "/var/lib/postgresql/data"}]},
            "redis": {"image": "redis:7-alpine", "volumes": [{
                "type": "bind", "source": str(state_root / "redis"), "target": "/data"}]},
            "applicant": {"volumes": [{
                "type": "bind", "source": str(state_root / "applicant"), "target": "/app/data"}]},
        }
    }


def test_models_must_preserve_frozen_state_mounts(tmp_path: Path) -> None:
    root = tmp_path / "state"
    fixture = model(root)
    path = tmp_path / "model.json"
    path.write_text(json.dumps(fixture), encoding="utf-8")
    loaded, digest = read_model(path, root)
    assert loaded == fixture
    assert digest == hashlib.sha256(path.read_bytes()).hexdigest()
    fixture["services"]["applicant"]["volumes"][0]["source"] = str(tmp_path / "outside")
    path.write_text(json.dumps(fixture), encoding="utf-8")
    with pytest.raises(ValueError, match="escaped backup root"):
        read_model(path, root)


def test_unversioned_or_missing_state_image_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "state"
    path = tmp_path / "model.json"
    for image in ("postgres:latest", "postgres", ""):
        path.write_text(json.dumps(model(root, image)), encoding="utf-8")
        with pytest.raises(ValueError, match="versioned image"):
            read_model(path, root)


def test_corrupted_applicant_restore_is_detected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    applicant = tmp_path / "applicant"
    applicant.mkdir()
    (applicant / "applicant_store.json").write_text('{"recovery_probe":"wrong"}', encoding="utf-8")
    monkeypatch.setattr("rehearse_selfhost_state_recovery.run", lambda *args, **kwargs: "expected")
    with pytest.raises(RuntimeError, match="probe mismatch"):
        probe_check("pg", "redis", applicant, "expected")


def test_cold_stop_is_graceful_and_docker_api_errors_propagate(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, ...]] = []

    def docker(*args: str, **kwargs: object) -> str:
        calls.append(args)
        if args[1] == "ps":
            return "container-id"
        if args[1] == "inspect" and args[3] == "{{.State.ExitCode}}":
            return "0"
        if args[1] == "inspect":
            return "true"
        return ""

    monkeypatch.setattr("rehearse_selfhost_state_recovery.run", docker)
    stop_owned("owned", graceful=True)
    assert ("docker", "stop", "--time", "30", "owned") in calls
    assert ("docker", "rm", "owned") in calls
    assert not any(args[:3] == ("docker", "rm", "-f") for args in calls)

    calls.clear()

    def killed(*args: str, **kwargs: object) -> str:
        if args[1] == "inspect" and args[3] == "{{.State.ExitCode}}":
            return "137"
        return docker(*args, **kwargs)

    monkeypatch.setattr("rehearse_selfhost_state_recovery.run", killed)
    with pytest.raises(RuntimeError, match="did not stop cleanly"):
        stop_owned("owned", graceful=True)
    assert not any(args[:2] == ("docker", "rm") for args in calls)

    def unavailable(*args: str, **kwargs: object) -> str:
        raise subprocess.CalledProcessError(1, args)

    monkeypatch.setattr("rehearse_selfhost_state_recovery.run", unavailable)
    with pytest.raises(subprocess.CalledProcessError):
        stop_owned("owned")


@pytest.mark.skipif(os.environ.get("MARTY_RUN_DOCKER_RECOVERY_TEST") != "1" or not shutil.which("docker"),
                    reason="opt-in Docker state rehearsal")
def test_cold_backup_restores_all_three_state_mounts(tmp_path: Path) -> None:
    source = model(tmp_path / "source-state")
    target = model(tmp_path / "target-state")
    report = rehearse(source, target, "source-model", "target-model", "fixture-v1", "fixture-v2", tmp_path / "work")
    assert report["result"] == "pass"
    assert report["verified_state"] == ["postgres-row", "redis-aof-key", "applicant-json-file"]
    assert report["qualification"] == "state-mechanics-only"
    assert "OpenBao state/export" in report["excluded"]
