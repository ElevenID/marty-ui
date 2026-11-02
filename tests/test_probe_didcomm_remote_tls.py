"""The native DIDComm probe owns its guarded replay/registry fixture lifecycle."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import probe_didcomm_remote_tls as probe  # noqa: E402


@pytest.mark.parametrize("test_exit", [0, 1])
def test_native_contract_gets_owned_redis_and_cleans_it_after_any_outcome(
    monkeypatch: pytest.MonkeyPatch, test_exit: int,
) -> None:
    calls: list[tuple[str, ...]] = []
    environments: list[dict[str, str]] = []
    redis_id = "b" * 64
    marker: list[str] = []
    monkeypatch.setenv("MARTY_TEST_REDIS_URL", "redis://foreign.example:6379/0")
    monkeypatch.setenv("MARTY_TEST_REDIS_DISPOSABLE_NONCE", "foreign-nonce")
    monkeypatch.setattr(probe, "docker_host_path", str)
    monkeypatch.setattr(probe.ssl, "create_default_context", lambda **_kwargs: object())
    monkeypatch.setattr(probe, "request", lambda *_args, **_kwargs: (200, {}))

    def docker(*args: str, **_kwargs: object) -> str:
        calls.append(args)
        if args[:2] == ("image", "inspect"):
            return "sha256:" + "a" * 64
        if args[:2] == ("run", "-d"):
            return redis_id if probe.REDIS_IMAGE in args else "c" * 64
        if args[0] == "port":
            return "127.0.0.1:26379" if args[-1] == "6379/tcp" else "127.0.0.1:28200"
        if args[-1] == "/pub/ca.crt":
            return "public-test-certificate"
        if args[0] == "exec" and "sha256sum" in args:
            return "d" * 64 + "  /plugins/openbao-didcomm-authcrypt"
        if args[:4] == ("exec", redis_id, "redis-cli", "ping"):
            return "PONG"
        if args[:6] == ("exec", redis_id, "redis-cli", "-n", "13", "SET"):
            assert args[6] == "marty:tests:disposable-guard"
            marker.append(args[7])
            return "OK"
        return ""

    def run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(tuple(args))
        if args[0] == "cargo":
            assert args == [
                "cargo", "+1.95.0", "test", "--locked", "-p", "marty-issuance-service",
                "--test", "didcomm_remote_kms_live", "--", "--ignored", "--test-threads=1",
            ]
            environments.append(dict(kwargs["env"]))
            return subprocess.CompletedProcess(args, test_exit, "", "")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(probe, "docker", docker)
    monkeypatch.setattr(probe.subprocess, "run", run)
    if test_exit:
        with pytest.raises(RuntimeError, match="native DIDComm authcrypt HTTPS contract failed"):
            probe.probe()
    else:
        probe.probe()

    assert len(environments) == len(marker) == 1
    environment = environments[0]
    assert environment["MARTY_TEST_REDIS_URL"] == "redis://127.0.0.1:26379/13"
    assert environment["MARTY_TEST_REDIS_DISPOSABLE_NONCE"] == marker[0]
    assert len(marker[0]) == 64 and marker[0] != "foreign-nonce"
    assert environment["MARTY_TEST_OPENBAO_URL"] == "https://localhost:28200"
    assert environment["MARTY_TEST_OPENBAO_TOKEN"]
    assert environment["MARTY_TEST_OPENBAO_CA_CERT_FILE"].endswith("/ca.crt")
    redis_runs = [call for call in calls if call[:2] == ("run", "-d") and probe.REDIS_IMAGE in call]
    assert len(redis_runs) == 1
    command = redis_runs[0]
    catalog = json.loads((probe.ROOT / "deploy-config/passport-supported-disposable-infra-images.json").read_text())
    assert probe.REDIS_IMAGE == catalog["images"]["redis"]["reference"]
    assert "@sha256:" in probe.REDIS_IMAGE
    assert command[command.index("-p") + 1] == "127.0.0.1::6379"
    assert command[command.index("--tmpfs") + 1] == "/data:rw,mode=700"
    assert command[-5:] == ("redis-server", "--save", "", "--appendonly", "no")
    assert calls.count(("rm", "-f", redis_id)) == 1
    assert any(call[:3] == ("docker", "rm", "-f") for call in calls)
    assert sum(call[:4] == ("docker", "volume", "rm", "-f") for call in calls) == 2


@pytest.mark.parametrize("binding", ["0.0.0.0:26379", "127.0.0.1:0", "127.0.0.1:65536",
                                      "127.0.0.1:26379\n0.0.0.0:26379"])
def test_redis_binding_must_be_the_requested_single_loopback_listener(
    monkeypatch: pytest.MonkeyPatch, binding: str,
) -> None:
    calls = []

    def docker(*args: str, **_kwargs: object) -> str:
        calls.append(args)
        return binding

    monkeypatch.setattr(probe, "docker", docker)
    with pytest.raises(RuntimeError, match="Redis port is invalid"):
        probe.prepare_redis("b" * 64)
    assert calls == [("port", "b" * 64, "6379/tcp")]
