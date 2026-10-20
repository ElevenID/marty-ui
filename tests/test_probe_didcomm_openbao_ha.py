"""Keep non-idempotent disposable OpenBao initialization bounded and single-shot."""

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import probe_didcomm_openbao_ha as probe  # noqa: E402


def test_docker_retries_only_prelaunch_wsl_interop_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []
    monkeypatch.setenv("WSL_INTEROP", "/run/WSL/test_interop")
    monkeypatch.setattr(probe.time, "sleep", lambda _seconds: None)

    def run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        if len(calls) == 1:
            return subprocess.CompletedProcess(
                args, 1, "", "<3>WSL ERROR: UtilAcceptVsock:271: accept4 failed 110",
            )
        return subprocess.CompletedProcess(args, 0, "ok\n", "")

    monkeypatch.setattr(probe.subprocess, "run", run)
    assert probe.docker("port", "disposable", "8200/tcp") == "ok"
    assert calls == [["docker", "port", "disposable", "8200/tcp"]] * 2

    calls.clear()

    def ordinary_failure(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        return subprocess.CompletedProcess(args, 1, "", "permission denied")

    monkeypatch.setattr(probe.subprocess, "run", ordinary_failure)
    with pytest.raises(RuntimeError, match="permission denied"):
        probe.docker("run", "--rm", "disposable")
    assert len(calls) == 1


def test_slow_init_fails_once_and_cleans_up(monkeypatch: pytest.MonkeyPatch) -> None:
    operations: list[tuple[str, ...]] = []
    init_timeouts: list[float] = []

    monkeypatch.setattr(probe, "prepare_image", lambda: None)
    monkeypatch.setattr(probe, "wait_for", lambda *_args, **_kwargs: True)

    def docker(*args: str, **_kwargs: object) -> str:
        operations.append(args)
        return "127.0.0.1:8200" if args[0] == "port" else ""

    def require_status(
        _base: str,
        method: str,
        path: str,
        _token: str,
        _body: dict | None = None,
        *,
        timeout: float = 10,
    ) -> dict:
        assert (method, path) == ("PUT", "sys/init")
        init_timeouts.append(timeout)
        raise TimeoutError("disposable init response delayed")

    def cleanup(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        operations.append(tuple(args))
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(probe, "docker", docker)
    monkeypatch.setattr(probe, "require_status", require_status)
    monkeypatch.setattr(probe.subprocess, "run", cleanup)

    with pytest.raises(TimeoutError, match="init response delayed"):
        probe.run()

    assert init_timeouts == [30]
    assert sum(op[:3] == ("docker", "rm", "-f") for op in operations) == 3
    assert sum(op[:3] == ("docker", "network", "rm") for op in operations) == 1
