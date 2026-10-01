"""Production recovery uses only mock Docker records and never contacts a host."""

from __future__ import annotations

import json
import hashlib
from pathlib import Path
import sys

import pytest

from scripts import recover_passport_beta_production as recovery
from scripts.probe_passport_beta_host import HostProbeError


def container(char: str, project: str, service: str, *, running: bool = True) -> dict:
    return {
        "Id": char * 64,
        "Image": "sha256:" + "1" * 64,
        "Name": "/" + service,
        "Config": {
            "Image": "ghcr.io/elevenid/prod@sha256:" + "2" * 64,
            "Labels": {"com.docker.compose.project": project,
                       "com.docker.compose.service": service},
            "Env": ["PRIVATE_TEST_SECRET=never-copy-this"],
        },
        "State": {"Running": running, "Status": "running" if running else "exited",
                  "StartedAt": "2026-10-01T00:00:00Z",
                  "Health": {"Status": "healthy" if running else "unhealthy"}},
        "Mounts": [{"Type": "bind", "Source": "/private/never-copy-this",
                    "Destination": "/data", "RW": True}],
        "NetworkSettings": {"Networks": {"prod-net": {
            "NetworkID": "network-1", "Aliases": [service],
            "IPAddress": "172.30.1.1"}}},
        "HostConfig": {"PortBindings": {}},
    }


class FakeDocker:
    def __init__(self) -> None:
        self.context = "prod-context"
        self.daemon = "daemon-1"
        self.records = {
            item["Id"]: item for item in (
                container("a", "marty-selfhost-prod", "gateway"),
                container("b", "marty-selfhost-prod", "postgres"),
                container("c", "marty-selfhost-prod", "ui"),
                container("d", "marty-selfhost-openbao", "openbao"),
                container("e", "marty-selfhost-prod", "old-worker", running=False),
            )
        }
        self.started = []

    def __call__(self, command: list[str]) -> str:
        if command == ["docker", "context", "show"]:
            return self.context
        if command == ["docker", "info", "--format", "{{.ID}}"]:
            return self.daemon
        if command[:2] == ["docker", "ps"]:
            project = command[command.index("--filter") + 1].rsplit("=", 1)[1]
            return "\n".join(key[:12] for key, value in self.records.items()
                             if value["Config"]["Labels"]["com.docker.compose.project"] == project)
        if command[:2] == ["docker", "inspect"]:
            key = next(key for key in self.records if key.startswith(command[2]))
            return json.dumps([self.records[key]])
        if command[:2] == ["docker", "start"]:
            key = command[2]
            self.started.append(key)
            self.records[key]["State"].update(
                Running=True, Status="running", StartedAt="2026-10-02T00:00:00Z",
                Health={"Status": "healthy"})
            self.records[key]["NetworkSettings"]["Networks"]["prod-net"]["NetworkID"] = "network-1"
            return key
        raise AssertionError(command)


def public_ok() -> dict:
    return {"origin": "https://elevenidllc.com/", "status": 200}


def captured() -> tuple[FakeDocker, dict]:
    docker = FakeDocker()
    return docker, recovery.capture(docker, public_ok)


def test_captures_sanitized_exact_baseline_and_noop_recovery() -> None:
    docker, baseline = captured()
    encoded = json.dumps(baseline)
    assert "never-copy-this" not in encoded
    assert baseline["schema"] == recovery.SCHEMA
    assert len(baseline["containers"]) == 5
    result = recovery.recover(baseline, docker, public_ok, timeout_seconds=0)
    assert result["verified"] is True
    assert result["status"] == "unchanged"
    assert result["continuity_breached"] is False
    assert docker.started == []


def test_restores_only_previously_running_stopped_identity() -> None:
    docker, baseline = captured()
    gateway = "a" * 64
    docker.records[gateway]["State"].update(Running=False, Status="exited")
    # Docker may clear the network ID of a stopped container.
    docker.records[gateway]["NetworkSettings"]["Networks"]["prod-net"]["NetworkID"] = ""
    result = recovery.recover(baseline, docker, public_ok, timeout_seconds=0)
    assert result["verified"] is True
    assert result["status"] == "restored"
    assert result["continuity_breached"] is True
    assert result["restarted_container_ids"] == [gateway]
    assert docker.started == [gateway]
    assert docker.records["e" * 64]["State"]["Running"] is False


def test_changed_daemon_blocks_without_any_start() -> None:
    docker, baseline = captured()
    docker.records["a" * 64]["State"].update(Running=False, Status="exited")
    docker.daemon = "different-daemon"
    result = recovery.recover(baseline, docker, public_ok, timeout_seconds=0)
    assert result["verified"] is False
    assert result["reason_code"] == "docker_identity_changed"
    assert docker.started == []


def test_image_mount_or_network_drift_blocks_before_start() -> None:
    for drift in ("image", "mount", "network"):
        docker, baseline = captured()
        docker.records["a" * 64]["State"].update(Running=False, Status="exited")
        if drift == "image":
            docker.records["b" * 64]["Image"] = "sha256:" + "9" * 64
        elif drift == "mount":
            docker.records["b" * 64]["Mounts"][0]["Source"] = "/changed"
        else:
            docker.records["b" * 64]["NetworkSettings"]["Networks"]["prod-net"]["NetworkID"] = "different"
        result = recovery.recover(baseline, docker, public_ok, timeout_seconds=0)
        assert result["verified"] is False
        assert result["reason_code"] == "production_container_identity_changed"
        assert docker.started == []


def test_public_route_failure_after_restart_retains_continuity_breach() -> None:
    docker, baseline = captured()
    docker.records["a" * 64]["State"].update(Running=False, Status="exited")
    result = recovery.recover(baseline, docker,
        lambda: {"origin": "https://elevenidllc.com/", "status": 503},
        timeout_seconds=0)
    assert result["verified"] is False
    assert result["continuity_breached"] is True
    assert result["restarted_container_ids"] == ["a" * 64]
    assert result["reason_code"] == "production_health_or_public_route_unavailable"


def test_extra_production_container_blocks_before_start() -> None:
    docker, baseline = captured()
    additional = container("f", "marty-selfhost-prod", "unexpected", running=False)
    docker.records[additional["Id"]] = additional
    docker.records["a" * 64]["State"].update(Running=False, Status="exited")
    result = recovery.recover(baseline, docker, public_ok, timeout_seconds=0)
    assert result["verified"] is False
    assert result["reason_code"] == "production_container_set_changed"
    assert docker.started == []


def test_lost_docker_start_reply_is_still_a_continuity_breach() -> None:
    docker, baseline = captured()
    docker.records["a" * 64]["State"].update(Running=False, Status="exited")

    def lost_reply(command: list[str]) -> str:
        output = docker(command)
        if command[:2] == ["docker", "start"]:
            raise HostProbeError("Docker reply lost")
        return output

    result = recovery.recover(baseline, lost_reply, public_ok, timeout_seconds=0)
    assert result["verified"] is False
    assert result["continuity_breached"] is True
    assert result["restart_attempted_container_ids"] == ["a" * 64]
    assert docker.started == ["a" * 64]


def test_restore_rejects_mutated_baseline_before_docker_access(tmp_path: Path) -> None:
    docker, baseline = captured()
    path = tmp_path / "private-baseline.json"
    expected_sha256 = recovery.write_private(path, baseline)
    assert expected_sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    altered = json.loads(path.read_text(encoding="utf-8"))
    next(item for item in altered["containers"] if item["id"] == "e" * 64)[
        "was_running"] = True
    path.write_text(json.dumps(altered), encoding="utf-8")

    def no_docker(_command: list[str]) -> str:
        raise AssertionError("Docker was called before baseline hash verification")

    result = recovery.restore_from_path(path, expected_sha256, no_docker, public_ok)
    assert result["verified"] is False
    assert result["reason_code"] == "baseline_sha256_mismatch"
    assert docker.started == []


@pytest.mark.parametrize("drift", ["added", "changed"])
def test_prestart_full_inventory_recheck_blocks_other_container_drift(drift: str) -> None:
    docker, baseline = captured()
    docker.records["a" * 64]["State"].update(Running=False, Status="exited")
    prod_lists = 0
    postgres_inspects = 0

    def concurrent_change(command: list[str]) -> str:
        nonlocal prod_lists, postgres_inspects
        if command[:2] == ["docker", "ps"] and any(
            "com.docker.compose.project=marty-selfhost-prod" in part
            for part in command
        ):
            prod_lists += 1
            if drift == "added" and prod_lists == 2:
                added = container("f", "marty-selfhost-prod", "unexpected", running=False)
                docker.records[added["Id"]] = added
        if command[:2] == ["docker", "inspect"] and command[2] == "b" * 12:
            postgres_inspects += 1
            if drift == "changed" and postgres_inspects == 2:
                docker.records["b" * 64]["Image"] = "sha256:" + "9" * 64
        return docker(command)

    result = recovery.recover(baseline, concurrent_change, public_ok, timeout_seconds=0)
    assert result["verified"] is False
    assert result["reason_code"] == "production_identity_changed_before_start"
    assert docker.started == []


def test_capture_cli_prints_only_small_hash_envelope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    _docker, baseline = captured()
    path = tmp_path / "private-baseline.json"
    monkeypatch.setattr(recovery, "capture", lambda: baseline)
    monkeypatch.setattr(sys, "argv", ["capture", "--capture", "--output", str(path)])
    recovery.main()
    envelope = json.loads(capsys.readouterr().out)
    assert envelope == {
        "schema": recovery.CAPTURE_SCHEMA,
        "baseline_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "snapshot_sha256": baseline["snapshot_sha256"],
        "attachments_sha256": baseline["attachments_sha256"],
        "docker": baseline["docker"],
        "captured_at_utc": baseline["captured_at_utc"],
    }
    assert "containers" not in envelope
    assert len(json.loads(path.read_text(encoding="utf-8"))["containers"]) == 5
