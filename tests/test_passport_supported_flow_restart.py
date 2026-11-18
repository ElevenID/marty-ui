"""A durable Rust checkpoint must survive replacement of owned containers."""

from datetime import datetime, timezone

import pytest

from scripts import passport_supported_flow_restart as restart_module


def test_recreate_requires_new_owned_containers_and_same_image(monkeypatch):
    project = "passport-acceptance-base-123"
    old = {"flow": "flow-old", "issuance-native": "native-old"}
    new = {"flow": "flow-new", "issuance-native": "native-new"}
    current = old
    verified = []

    def verify(record, surface, now, inspector):
        assert surface == "base"
        assert isinstance(now, datetime) and now.tzinfo == timezone.utc
        verified.append(dict(record["containers"]))
        return {"live_ownership_verified": True}

    def inspect(kind, identifier, inspector):
        assert kind == "container"
        service = "flow" if identifier.startswith("flow-") else "issuance-native"
        return {"Id": identifier, "Image": "sha256:" + "a" * 64,
                "Config": {"Labels": {"com.docker.compose.service": service}},
                "State": {"StartedAt": "after" if identifier.endswith("new") else "before"}}

    def inspector(args):
        assert args == ["ps", "-aq", "--no-trunc", "--filter",
                        f"label=com.docker.compose.project={project}"]
        return " ".join(current.values())

    def run(args, environment, timeout):
        nonlocal current
        assert args == ["docker", "compose", "up", "-d", "--no-deps",
                        "--force-recreate", "--wait", "--wait-timeout", "120",
                        "flow", "issuance-native"]
        assert environment == {"DOCKER_HOST": "unix:///var/run/docker.sock"}
        assert timeout == 300
        current = new
        return True

    monkeypatch.setattr(restart_module, "verify", verify)
    monkeypatch.setattr(restart_module, "_inspect", inspect)
    record = {"project": project, "containers": dict(old)}
    assert restart_module.restart_owned_rust(
        record, "base", ["docker", "compose"],
        {"DOCKER_HOST": "unix:///var/run/docker.sock"}, run=run,
        inspector=inspector, sleep=lambda seconds: None)
    assert verified == [old, new]
    assert record["containers"] == new
    assert record["pre_restart_native_container_id"] == "native-old"


@pytest.mark.parametrize("replacement,image", [
    (False, "sha256:" + "a" * 64),
    (True, "sha256:" + "b" * 64),
])
def test_recreate_rejects_unchanged_id_or_image(monkeypatch, replacement, image):
    old = {"flow": "flow-old", "issuance-native": "native-old"}
    new = {"flow": "flow-new", "issuance-native": "native-new"} if replacement else old
    monkeypatch.setattr(restart_module, "verify", lambda *args: {
        "live_ownership_verified": True})

    def inspect(kind, identifier, inspector):
        service = "flow" if identifier.startswith("flow-") else "issuance-native"
        return {"Id": identifier,
                "Image": image if identifier.endswith("new") else "sha256:" + "a" * 64,
                "Config": {"Labels": {"com.docker.compose.service": service}},
                "State": {"StartedAt": "now"}}

    monkeypatch.setattr(restart_module, "_inspect", inspect)
    record = {"project": "passport-acceptance-base-123", "containers": dict(old)}
    with pytest.raises(ValueError, match="did not resume"):
        restart_module.restart_owned_rust(
            record, "base", ["docker", "compose"], {},
            run=lambda *args: True,
            inspector=lambda args: " ".join(new.values()),
            sleep=lambda seconds: None)
    assert record["containers"] == old
