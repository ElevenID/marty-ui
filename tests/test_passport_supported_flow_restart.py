"""Owned Rust restart must establish new processes in the same project."""

from datetime import datetime, timezone

import pytest

from scripts import passport_supported_flow_restart as restart_module


def test_restart_requires_new_processes_and_same_owned_containers(monkeypatch):
    started = "before"
    inspected = []

    def verify(record, surface, now, inspector):
        assert surface == "base"
        assert isinstance(now, datetime) and now.tzinfo == timezone.utc
        return {"live_ownership_verified": True}

    def inspect(kind, identifier, inspector):
        inspected.append(identifier)
        return {"Id": identifier, "State": {"StartedAt": started}}

    def run(args, environment, timeout):
        nonlocal started
        assert args == ["docker", "compose", "restart", "flow", "issuance-native"]
        assert environment == {"DOCKER_HOST": "unix:///var/run/docker.sock"}
        assert timeout == 120
        started = "after"
        return True

    monkeypatch.setattr(restart_module, "verify", verify)
    monkeypatch.setattr(restart_module, "_inspect", inspect)
    record = {"containers": {"flow": "flow-id", "issuance-native": "native-id"}}
    assert restart_module.restart_owned_rust(
        record, "base", ["docker", "compose"],
        {"DOCKER_HOST": "unix:///var/run/docker.sock"}, run=run,
        inspector=lambda args: "", sleep=lambda seconds: None)
    assert inspected == ["flow-id", "native-id"] * 2


def test_restart_rejects_unchanged_process_start(monkeypatch):
    monkeypatch.setattr(restart_module, "verify", lambda *args: {
        "live_ownership_verified": True})
    monkeypatch.setattr(restart_module, "_inspect", lambda kind, identifier, inspector: {
        "Id": identifier, "State": {"StartedAt": "unchanged"}})
    with pytest.raises(ValueError, match="did not resume"):
        restart_module.restart_owned_rust(
            {"containers": {"flow": "flow-id", "issuance-native": "native-id"}},
            "base", ["docker", "compose"], {},
            run=lambda *args: True, inspector=lambda args: "",
            sleep=lambda seconds: None)
