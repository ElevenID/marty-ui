"""Local development must not redirect rootless operations to another daemon."""

import json
from pathlib import Path
import runpy
import stat
import subprocess
from types import SimpleNamespace

import pytest

from scripts import local_docker
from scripts.dev import worktree_stack
from scripts import passport_supported_disposable_ceremony as ceremony
from scripts.passport_supported_infra_rehearsal import _local_docker_environment
from scripts import passport_supported_infra_rehearsal as infrastructure
from scripts import passport_supported_protected_producer as producer
from scripts import passport_supported_provisioning_producer as provisioning
from scripts import verify_passport_beta_issuer_profiles as profiles


UID = 1001
RUNTIME = Path(f"/run/user/{UID}")
SOCKET = RUNTIME / "docker.sock"
ROOTLESS_HOST = f"unix://{SOCKET}"


def info(mode, uid=0, inode=1):
    return SimpleNamespace(st_mode=mode, st_uid=uid, st_dev=8, st_ino=inode)


@pytest.fixture
def local_filesystem(monkeypatch, tmp_path):
    """Model the canonical kernel paths without using a host Docker daemon."""
    entries = {
        Path("/"): info(stat.S_IFDIR | 0o755),
        Path("/run"): info(stat.S_IFDIR | 0o755),
        Path("/run/user"): info(stat.S_IFDIR | 0o755),
        RUNTIME: info(stat.S_IFDIR | 0o700, UID),
        SOCKET: info(stat.S_IFSOCK | 0o1660, UID, 20),
    }
    original = Path.lstat

    def lstat(path, *args, **kwargs):
        if path in entries:
            return entries[path]
        if path == SOCKET:
            raise FileNotFoundError(path)
        return original(path, *args, **kwargs)

    local_docker._selected_endpoint.cache_clear()
    monkeypatch.setattr(local_docker.os, "geteuid", lambda: UID)
    monkeypatch.setattr(local_docker.os, "getuid", lambda: UID)
    monkeypatch.setattr(Path, "lstat", lstat)
    try:
        yield entries
    finally:
        local_docker._selected_endpoint.cache_clear()


@pytest.mark.parametrize("foreign_host", (
    "tcp://production.invalid:2376", "ssh://production.invalid",
    "unix:///run/user/1234/docker.sock",
))
def test_existing_local_rootful_default_strips_remote_overrides(
    local_filesystem, foreign_host,
):
    del local_filesystem[SOCKET]
    original = {
        "DOCKER_HOST": foreign_host, "DOCKER_CONTEXT": "production",
        "DOCKER_TLS_VERIFY": "1", "DOCKER_CERT_PATH": "/foreign/certs",
        "KEEP": "value",
    }
    selected = local_docker.local_docker_environment(original)
    assert selected == {"DOCKER_HOST": "unix:///var/run/docker.sock", "KEEP": "value"}
    assert original["DOCKER_HOST"] == foreign_host


def test_current_user_rootless_socket_wins_without_trusting_context_or_xdg(
    local_filesystem,
):
    selected = local_docker.local_docker_environment({
        "DOCKER_HOST": "tcp://production.invalid:2376", "DOCKER_CONTEXT": "production",
        "DOCKER_TLS_VERIFY": "1", "DOCKER_CERT_PATH": "/foreign/certs",
        "XDG_RUNTIME_DIR": "/foreign/runtime",
    })
    assert selected["DOCKER_HOST"] == ROOTLESS_HOST
    assert all(name not in selected for name in (
        "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH",
    ))


@pytest.mark.parametrize("rootless", (False, True))
def test_private_tls_bind_user_matches_verified_daemon_without_changing_permissions(
    local_filesystem, monkeypatch, tmp_path, rootless,
):
    if not rootless:
        del local_filesystem[SOCKET]
    monkeypatch.setattr(local_docker.os, "getgid", lambda: 1002)
    host = ROOTLESS_HOST if rootless else local_docker.ROOTFUL_HOST
    calls = []

    def inspect(command, **kwargs):
        calls.append(command)
        assert command[:5] == ["docker", "--host", host, "info", "--format"]
        assert command[5] == ('{"ID":{{json .ID}},"OSType":{{json .OSType}},'
                              '"SecurityOptions":{{json .SecurityOptions}}}')
        assert kwargs["env"]["DOCKER_HOST"] == host
        assert "DOCKER_CONTEXT" not in kwargs["env"]
        assert kwargs["timeout"] == 25 and kwargs["check"] is True
        assert kwargs["stderr"] == subprocess.DEVNULL
        return SimpleNamespace(stdout=json.dumps({
            "ID": "existing-daemon-id", "OSType": "linux",
            "SecurityOptions": ["name=rootless"] if rootless else ["name=seccomp,profile=builtin"],
        }))

    monkeypatch.setattr(local_docker.subprocess, "run", inspect)
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    (root / "secrets").mkdir(mode=0o700)
    token = root / "secrets/bao_root_token"
    token.write_text("synthetic-test-token")
    token.chmod(0o600)
    output = root / "tls-output"
    output.mkdir(mode=0o700)
    plan = {"project": "marty-passport-unit-test", "owner_labels": {
        "com.marty.passport.acceptance.owner": "supported-consumer",
    }, "services_reference": "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "b" * 64}
    command = provisioning._tls_bootstrap_args(plan, root, output, environment={
        "DOCKER_HOST": "tcp://remote.invalid:2376", "DOCKER_CONTEXT": "foreign",
    })
    assert command[command.index("--user") + 1] == ("0:0" if rootless else "1001:1002")
    assert command[-1] == plan["services_reference"]
    assert "type=bind,src=" + str(token) + ",dst=/run/secrets/bao_root_token,readonly" in command
    assert "type=bind,src=" + str(output) + ",dst=/work/output" in command
    assert token.stat().st_mode & 0o777 == 0o600
    assert output.stat().st_mode & 0o777 == 0o700
    assert len(calls) == 1


def test_other_tls_callers_keep_legacy_user_without_daemon_inspection(monkeypatch, tmp_path):
    monkeypatch.setattr(provisioning.os, "getuid", lambda: UID)
    monkeypatch.setattr(provisioning.os, "getgid", lambda: 1002)
    monkeypatch.setattr(local_docker.subprocess, "run",
                        lambda *args, **kwargs: pytest.fail("legacy caller must not inspect a daemon"))
    command = provisioning._tls_bootstrap_args({
        "project": "marty-passport-unit-test", "owner_labels": {},
        "services_reference": "services@sha256:" + "b" * 64,
    }, tmp_path, tmp_path / "tls-output")
    assert command[command.index("--user") + 1] == "1001:1002"


@pytest.mark.parametrize("socket_rootless", (False, True))
def test_private_bind_user_refuses_socket_daemon_mismatch(
    local_filesystem, monkeypatch, socket_rootless,
):
    if not socket_rootless:
        del local_filesystem[SOCKET]
    monkeypatch.setattr(local_docker.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(
        stdout=json.dumps({"ID": "existing-daemon-id", "OSType": "linux",
                           "SecurityOptions": [] if socket_rootless else ["name=rootless"]})))
    with pytest.raises(ValueError, match="rootless identity differ"):
        local_docker.local_bind_mount_user({})


@pytest.mark.parametrize("field,value", (
    ("ID", ""), ("ID", 1), ("ID", "has whitespace"), ("ID", "x" * 129),
    ("OSType", "windows"), ("OSType", None),
    ("SecurityOptions", None), ("SecurityOptions", "name=rootless"),
    ("SecurityOptions", [1]), ("SecurityOptions", [""]),
    ("SecurityOptions", ["x" * 257]), ("SecurityOptions", ["name=rootless"] * 33),
))
def test_private_bind_user_rejects_invalid_daemon_identity(
    local_filesystem, monkeypatch, field, value,
):
    daemon = {"ID": "existing-daemon-id", "OSType": "linux", "SecurityOptions": ["name=rootless"]}
    daemon[field] = value
    monkeypatch.setattr(local_docker.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(stdout=json.dumps(daemon)))
    with pytest.raises(ValueError, match="daemon identity is invalid"):
        local_docker.local_bind_mount_user({})


@pytest.mark.parametrize("response", ("not-json", "x" * 4097, "[]", "{}"))
def test_private_bind_user_rejects_unusable_daemon_response(local_filesystem, monkeypatch, response):
    monkeypatch.setattr(local_docker.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(stdout=response))
    with pytest.raises(ValueError, match="daemon identity"):
        local_docker.local_bind_mount_user({})


@pytest.mark.parametrize("failure", (
    OSError("daemon unavailable"), subprocess.TimeoutExpired("docker", 25),
    subprocess.CalledProcessError(1, "docker"),
))
def test_private_bind_user_does_not_fall_back_after_inspection_failure(
    local_filesystem, monkeypatch, failure,
):
    calls = []
    def inspect(command, **kwargs):
        calls.append(command)
        raise failure
    monkeypatch.setattr(local_docker.subprocess, "run", inspect)
    with pytest.raises(ValueError, match="identity cannot be verified"):
        local_docker.local_bind_mount_user({})
    assert len(calls) == 1 and calls[0][2] == ROOTLESS_HOST


def test_private_bind_user_refuses_socket_replacement_during_inspection(local_filesystem, monkeypatch):
    def inspect(*args, **kwargs):
        local_filesystem[SOCKET] = info(stat.S_IFSOCK | 0o660, UID, 21)
        return SimpleNamespace(stdout=json.dumps({
            "ID": "existing-daemon-id", "OSType": "linux", "SecurityOptions": ["name=rootless"],
        }))
    monkeypatch.setattr(local_docker.subprocess, "run", inspect)
    with pytest.raises(ValueError, match="socket changed"):
        local_docker.local_bind_mount_user({})


@pytest.mark.parametrize("path,replacement", (
    (RUNTIME, info(stat.S_IFLNK | 0o777, UID)),
    (RUNTIME, info(stat.S_IFDIR | 0o700, 1234)),
    (RUNTIME, info(stat.S_IFDIR | 0o755, UID)),
    (Path("/run/user"), info(stat.S_IFDIR | 0o775)),
    (Path("/run"), info(stat.S_IFLNK | 0o777)),
    (SOCKET, info(stat.S_IFLNK | 0o777, UID)),
    (SOCKET, info(stat.S_IFREG | 0o600, UID)),
    (SOCKET, info(stat.S_IFSOCK | 0o660, 1234)),
    (SOCKET, info(stat.S_IFSOCK | 0o666, UID)),
))
def test_unsafe_rootless_candidate_is_refused_without_rootful_fallback(
    local_filesystem, path, replacement,
):
    local_filesystem[path] = replacement
    with pytest.raises(ValueError, match="unsafe"):
        local_docker.local_docker_environment({})


def test_missing_explicit_rootless_selection_does_not_fall_back(local_filesystem):
    del local_filesystem[SOCKET]
    with pytest.raises(ValueError, match="rootless Docker socket is unavailable"):
        local_docker.local_docker_environment({"DOCKER_HOST": ROOTLESS_HOST})


@pytest.mark.parametrize("replacement", (None, info(stat.S_IFSOCK | 0o660, UID, 21)))
def test_selected_rootless_socket_cannot_disappear_or_be_replaced(
    local_filesystem, replacement,
):
    assert local_docker.local_docker_environment({})["DOCKER_HOST"] == ROOTLESS_HOST
    if replacement is None:
        del local_filesystem[SOCKET]
    else:
        local_filesystem[SOCKET] = replacement
    with pytest.raises(ValueError, match="socket (is unavailable|changed)"):
        local_docker.local_docker_environment({})


def test_rehearsal_and_ceremony_share_the_selected_endpoint(local_filesystem, monkeypatch):
    monkeypatch.setenv("DOCKER_HOST", "tcp://production.invalid:2376")
    monkeypatch.setenv("DOCKER_CONTEXT", "production")
    assert _local_docker_environment({})["DOCKER_HOST"] == ROOTLESS_HOST
    selected = ceremony._local_docker_env()
    assert selected["DOCKER_HOST"] == ROOTLESS_HOST
    assert "DOCKER_CONTEXT" not in selected


def test_stale_rootless_socket_connection_is_not_retried_on_another_daemon(
    local_filesystem, monkeypatch,
):
    calls = []

    def disconnected(command, **kwargs):
        calls.append(kwargs["env"]["DOCKER_HOST"])
        raise subprocess.CalledProcessError(1, command)

    monkeypatch.setattr(ceremony.subprocess, "run", disconnected)
    with pytest.raises(ceremony.DisposableCeremonyError, match="inspection failed"):
        ceremony._local_inspect(["ps"])
    assert calls == [ROOTLESS_HOST]


def test_managed_issuer_requests_keep_the_rootless_daemon(local_filesystem, monkeypatch):
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs["env"]))
        return SimpleNamespace(stdout=b'{"ok":true}')

    monkeypatch.setenv("DOCKER_CONTEXT", "production")
    monkeypatch.setattr(profiles.subprocess, "run", run)
    assert profiles.resolve_in_container(
        "a" * 64, "org-a", "did:web:example.invalid:issuer", "csca",
    ) == {"ok": True}
    assert calls[0][1]["DOCKER_HOST"] == ROOTLESS_HOST
    assert "DOCKER_CONTEXT" not in calls[0][1]


def test_worktree_keeps_rootless_selection_and_discards_service_secrets(
    local_filesystem, monkeypatch, tmp_path,
):
    monkeypatch.setenv("DOCKER_HOST", ROOTLESS_HOST)
    monkeypatch.setenv("POSTGRES_PASSWORD", "foreign-secret")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "foreign-secret")
    environment = worktree_stack.environment(tmp_path, "marty-wt-test", 28000)
    assert environment["DOCKER_HOST"] == ROOTLESS_HOST
    assert "POSTGRES_PASSWORD" not in environment
    assert "GOOGLE_CLIENT_SECRET" not in environment
    del local_filesystem[SOCKET]
    with pytest.raises(ValueError, match="socket is unavailable"):
        worktree_stack.environment(tmp_path, "marty-wt-test", 28000)


def test_worktree_refuses_missing_explicit_rootless_endpoint_on_first_call(
    local_filesystem, monkeypatch, tmp_path,
):
    del local_filesystem[SOCKET]
    monkeypatch.setenv("DOCKER_HOST", ROOTLESS_HOST)
    with pytest.raises(ValueError, match="rootless Docker socket is unavailable"):
        worktree_stack.environment(tmp_path, "marty-wt-test", 28000)


def test_windows_worktree_preserves_desktop_lookup_without_host_overrides(
    monkeypatch, tmp_path,
):
    monkeypatch.setattr(worktree_stack, "os", SimpleNamespace(
        name="nt", environ={
            "DOCKER_HOST": "tcp://production.invalid:2376",
            "DOCKER_CONTEXT": "production", "DOCKER_TLS_VERIFY": "1",
            "DOCKER_CERT_PATH": "C:\\foreign\\certs",
            "DOCKER_CONFIG": "C:\\Users\\developer\\.docker",
            "POSTGRES_PASSWORD": "foreign-secret",
        },
    ))
    monkeypatch.setattr(
        worktree_stack, "local_docker_environment",
        lambda env: pytest.fail("Windows must not select a Unix socket"),
    )
    environment = worktree_stack.environment(tmp_path, "marty-wt-test", 28000)
    assert environment["DOCKER_CONFIG"] == "C:\\Users\\developer\\.docker"
    assert all(name not in environment for name in (
        "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH",
        "POSTGRES_PASSWORD",
    ))
    calls = []

    def rendered(command, **kwargs):
        calls.append(kwargs["env"])
        return SimpleNamespace(returncode=0, stdout=json.dumps({
            "services": {},
            "networks": {"marty-network": {"name": "marty-wt-test-network"}},
        }))

    monkeypatch.setattr(worktree_stack.subprocess, "run", rendered)
    worktree_stack.validate_config(
        worktree_stack.compose_command(tmp_path, "marty-wt-test"), environment,
    )
    assert len(calls) == 1 and "DOCKER_HOST" not in calls[0]
    assert calls[0]["DOCKER_CONFIG"] == environment["DOCKER_CONFIG"]


def test_worktree_rechecks_socket_between_inspection_and_start(
    local_filesystem, monkeypatch,
):
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        assert kwargs["env"]["DOCKER_HOST"] == ROOTLESS_HOST
        if command[-3:] == ["config", "--format", "json"]:
            return SimpleNamespace(returncode=0, stdout=json.dumps({
                "services": {},
                "networks": {"marty-network": {
                    "name": kwargs["env"]["MARTY_NETWORK_NAME"],
                }},
            }))
        assert command[:2] == ["docker", "ps"]
        local_filesystem[SOCKET] = info(stat.S_IFSOCK | 0o1660, UID, 21)
        return SimpleNamespace(stdout="")

    monkeypatch.setattr(worktree_stack.sys, "argv", ["worktree_stack.py", "up"])
    monkeypatch.setattr(worktree_stack.subprocess, "run", run)
    monkeypatch.setattr(worktree_stack.subprocess, "call",
                        lambda *args, **kwargs: pytest.fail("up must not run"))
    monkeypatch.setattr(worktree_stack, "require_free_ports", lambda env: None)
    with pytest.raises(ValueError, match="socket changed"):
        worktree_stack.main()
    assert len(calls) == 2


@pytest.mark.parametrize("phase", (
    "infrastructure-run", "infrastructure-inspect", "watcher-run", "producer-execute",
    "ceremony-inspect", "issuer-request",
))
def test_docker_phase_rechecks_cached_socket_before_subprocess(
    local_filesystem, monkeypatch, tmp_path, phase,
):
    environment = local_docker.local_docker_environment({})
    local_filesystem[SOCKET] = info(stat.S_IFSOCK | 0o1660, UID, 21)
    monkeypatch.setattr(subprocess, "run",
                        lambda *args, **kwargs: pytest.fail("changed socket must block Docker"))
    if phase == "infrastructure-run":
        assert infrastructure._run(["docker", "ps"], environment, 30) is False
    elif phase == "infrastructure-inspect":
        with pytest.raises(infrastructure.ProducerError, match="inspection failed"):
            infrastructure._inspect_local(["ps"], environment)
    elif phase == "watcher-run":
        scripts = Path(worktree_stack.__file__).resolve().parents[1]
        monkeypatch.syspath_prepend(str(scripts))
        watcher = runpy.run_path(str(scripts / "passport_local_watch.py"))
        assert watcher["run"](
            ["docker", "compose", "up"], environment, tmp_path / "watch.log", 30,
        ) is False
    elif phase == "producer-execute":
        assert producer._execute_local(["exec", "container"], None, environment) is False
    elif phase == "ceremony-inspect":
        with pytest.raises(ceremony.DisposableCeremonyError, match="inspection failed"):
            ceremony._local_inspect(["ps"])
    else:
        with pytest.raises(profiles.IssuerProfileEvidenceError, match="request failed"):
            profiles.resolve_in_container(
                "a" * 64, "org-a", "did:web:example.invalid:issuer", "csca",
            )
