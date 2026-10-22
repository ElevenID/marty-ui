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


@pytest.mark.parametrize("raw, expected", [
    (b'{"errors":["invalid key: failed to decrypt keys: cipher: message authentication failed key=PRIVATE"]}',
     ["DECRYPTION_FAILED", "AUTHENTICATION_FAILED", "INVALID_UNSEAL_KEY"]),
    (b'{"errors":["invalid key size 33; PRIVATE"]}', ["INVALID_KEY_SIZE", "INVALID_UNSEAL_KEY"]),
    (b'{"errors":["arbitrary PRIVATE token"]}', ["UNCLASSIFIED_ERROR"]),
    (b'{"errors":"PRIVATE"}', ["UNCLASSIFIED_ERROR"]),
    (b'PRIVATE not JSON', ["UNCLASSIFIED_ERROR"]),
])
def test_unseal_error_diagnostics_never_echo_response(raw: bytes, expected: list[str]) -> None:
    assert probe.classify_unseal_error(raw) == expected
    assert "PRIVATE" not in str(probe.classify_unseal_error(raw))


def test_request_unseal_error_diagnostics_are_opt_in_and_never_return_body(monkeypatch: pytest.MonkeyPatch) -> None:
    import io
    import urllib.error

    def reject(*_args: object, **_kwargs: object) -> None:
        raise urllib.error.HTTPError(
            "https://127.0.0.1/v1/sys/unseal", 400, "Bad Request", {},
            io.BytesIO(b'{"errors":["invalid key PRIVATE"]}'),
        )

    monkeypatch.setattr(probe.urllib.request, "urlopen", reject)
    assert probe.request("https://127.0.0.1", "POST", "sys/unseal") == (400, {})
    assert probe.request("https://127.0.0.1", "POST", "sys/unseal", unseal_error_diagnostics=True) == (
        400, {"error_classes": ["INVALID_UNSEAL_KEY"]},
    )


def test_snapshot_process_replacement_tracks_cleanup_and_new_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    import probe_selfhost_openbao_raft_bootstrap as raft

    events = []
    started = ["owned-original", "owned-other"]
    monkeypatch.setattr(raft, "docker", lambda *args: events.append(args))

    def start(name, volume, ca):
        assert started == ["owned-other", "owned-restored"]
        assert (name, volume, ca) == ("owned-restored", "owned-state", Path("ca.crt"))
        return "https://127.0.0.1:22002"

    monkeypatch.setattr(raft, "start_node", start)
    assert raft.replace_node("owned-original", "owned-restored", "owned-state",
                             Path("ca.crt"), started) == "https://127.0.0.1:22002"
    assert events == [("stop", "owned-original"), ("rm", "owned-original")]


def test_failed_snapshot_replacement_remains_owned_for_cleanup(monkeypatch: pytest.MonkeyPatch) -> None:
    import probe_selfhost_openbao_raft_bootstrap as raft

    started = ["owned-original"]
    monkeypatch.setattr(raft, "docker", lambda *args: None)

    def fail(*_args):
        raise RuntimeError("replacement did not start")

    monkeypatch.setattr(raft, "start_node", fail)
    with pytest.raises(RuntimeError, match="replacement did not start"):
        raft.replace_node("owned-original", "owned-restored", "owned-state",
                          Path("ca.crt"), started)
    assert started == ["owned-restored"]


@pytest.mark.parametrize("raw, expected", [
    (b'{"errors":["failed to revoke token PRIVATE: context deadline exceeded"]}',
     ["REVOCATION_FAILED", "DEADLINE_EXCEEDED"]),
    (b'{"errors":["PRIVATE unrecognized detail"]}', ["UNCLASSIFIED_ERROR"]),
    (b'{"errors":"PRIVATE"}', ["UNCLASSIFIED_ERROR"]),
])
def test_revocation_diagnostics_are_fixed_classes_only(raw, expected):
    assert probe.classify_revocation_error(raw) == expected
    assert "PRIVATE" not in str(probe.classify_revocation_error(raw))


def test_revocation_response_diagnostics_are_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    import io
    import urllib.error

    def reject(*_args, **_kwargs):
        raise urllib.error.HTTPError(
            "https://127.0.0.1/v1/auth/token/revoke-self", 500, "error", {},
            io.BytesIO(b'{"errors":["failed to revoke PRIVATE"]}'),
        )

    monkeypatch.setattr(probe.urllib.request, "urlopen", reject)
    assert probe.request("https://127.0.0.1", "POST", "auth/token/revoke-self") == (500, {})
    assert probe.request("https://127.0.0.1", "POST", "auth/token/revoke-self",
                         revocation_error_diagnostics=True) == (
        500, {"error_classes": ["REVOCATION_FAILED"]},
    )
