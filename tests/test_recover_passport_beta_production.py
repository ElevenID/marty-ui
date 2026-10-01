"""Production recovery uses only mock Docker records and never contacts a host."""

from __future__ import annotations

import json

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
