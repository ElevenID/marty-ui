"""Root-token access is separated from operator-owned Keycloak outputs."""

import json
import os
from pathlib import Path
import stat
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import stage_selfhost_keycloak_inputs as bridge  # noqa: E402
import provision_selfhost_disposable_tls as tls  # noqa: E402


IMAGE = "ghcr.io/elevenid/marty-ui-oss/openbao-didcomm@sha256:" + "a" * 64
OPERATOR = 1000
OPENBAO = 1001
REAL_OPERATOR_ENVIRONMENT = bridge.authenticated_operator_environment


@pytest.fixture(autouse=True)
def isolated_handoff_preflight(monkeypatch):
    # Transfer tests isolate ownership; the real native identity is checked below.
    monkeypatch.setattr(bridge, "authenticated_operator_environment", lambda _source: {
        "MARTY_DEPLOY_BIN": "/reviewed/marty-deploy", "MARTY_DEPLOY_BIN_SHA256": "a" * 64,
        "MARTY_DEPLOY_SOURCE_SHA": "b" * 40, "MARTY_DEPLOY_RELEASE_TAG": "v1.2.3"})


def test_real_installed_native_identity_survives_root_environment(tmp_path, monkeypatch):
    if not os.environ.get("MARTY_DEPLOY_BIN"):
        pytest.skip("requires qualified native operator")
    monkeypatch.setenv("UNRELATED_PRIVATE_ENV", "must-not-forward")
    native_env = REAL_OPERATOR_ENVIRONMENT(tmp_path)
    assert set(native_env) == {"MARTY_DEPLOY_BIN", "MARTY_DEPLOY_BIN_SHA256",
                               "MARTY_DEPLOY_SOURCE_SHA", "MARTY_DEPLOY_RELEASE_TAG"}
    source = Path(__file__).resolve().parents[1]
    if (source / ".git").exists():
        assert REAL_OPERATOR_ENVIRONMENT(source) == native_env
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(tmp_path), "-c", "user.name=Native operator test",
                    "-c", "user.email=native-operator@example.invalid", "commit", "--allow-empty",
                    "-q", "-m", "foreign source checkpoint"], check=True, capture_output=True)
    with pytest.raises(RuntimeError, match="source differs from checkout HEAD"):
        REAL_OPERATOR_ENVIRONMENT(tmp_path)
    monkeypatch.setenv("MARTY_DEPLOY_BIN_SHA256", "0" * 64)
    with pytest.raises(RuntimeError, match="digest mismatch"):
        REAL_OPERATOR_ENVIRONMENT(tmp_path)


def test_root_environment_requires_installed_native_operator(tmp_path, monkeypatch):
    monkeypatch.delenv("MARTY_DEPLOY_BIN", raising=False)
    with pytest.raises(ValueError, match="signed marty-deploy"):
        REAL_OPERATOR_ENVIRONMENT(tmp_path)


def staged(tmp_path: Path) -> Path:
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    (root / "secrets").mkdir(mode=0o700)
    state = root / "openbao-state"
    state.mkdir(mode=0o700)
    (state / "tls").mkdir(mode=0o700)
    (state / "tls" / "ca.crt").write_text("public ca", encoding="ascii")
    (root / "secrets" / "openbao_tls_ca_cert").write_text("public ca", encoding="ascii")
    token = state / "root.token"
    token.write_text("root-only-token", encoding="ascii")
    token.chmod(0o400)
    install = root / "install" / "selfhost-prepared"
    install.mkdir(parents=True)
    (root / "openbao.json").write_text(json.dumps({
        "schema": "marty.selfhost-disposable-openbao/v1",
        "qualification": "unqualified",
        "project": "marty-preview-1234567890abcdef",
        "host_port": 18200,
        "image": IMAGE,
    }), encoding="utf-8")
    for path in (root, root / "secrets", state):
        os.chown(path, OPERATOR, OPERATOR)
    # selfhost-tls-init changes the bind-mounted state directory owner.
    os.chown(state, OPENBAO, OPENBAO)
    return root


def require_root_linux() -> None:
    if os.name != "posix" or os.geteuid() != 0:
        pytest.skip("root-only Linux transfer test")


def test_moves_only_scoped_outputs_to_operator_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    require_root_linux()
    root = staged(tmp_path)
    monkeypatch.setenv("TMPDIR", str(root))
    monkeypatch.setattr(tls, "exact_images", lambda _bundle: ("services", IMAGE))
    monkeypatch.setattr(tls, "openbao_network", lambda *_args, **_kwargs: "owned-network")

    def fake_run(_args: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        assert kwargs["timeout"] is None
        env = kwargs["env"]
        assert env["MARTY_DEPLOY_BIN"] == "/reviewed/marty-deploy"
        assert env["MARTY_DEPLOY_BIN_SHA256"] == "a" * 64
        assert "UNRELATED_PRIVATE_ENV" not in env
        output = Path(env["SELFHOST_KEYCLOAK_OUTPUT_DIR"])
        assert output.parent == Path("/tmp")
        for name in bridge.OUTPUTS:
            target = output / name
            target.write_text("scoped-public-input", encoding="ascii")
            target.chmod(0o444)
        return subprocess.CompletedProcess(_args, 0, "", "")

    monkeypatch.setattr(bridge.subprocess, "run", fake_run)
    assert bridge.stage(root, OPERATOR) == len(bridge.OUTPUTS)
    for name in bridge.OUTPUTS:
        file = root / "secrets" / name
        assert file.stat().st_uid == OPERATOR
        assert stat.S_IMODE(file.stat().st_mode) == 0o444
    assert (root / "openbao-state" / "root.token").stat().st_uid == 0
    assert not (root / "secrets" / "root.token").exists()
    assert not list(root.glob("keycloak-inputs-*"))
    with pytest.raises(ValueError, match="already exists"):
        bridge.stage(root, OPERATOR)


def test_incomplete_root_provisioning_leaves_no_operator_outputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    require_root_linux()
    root = staged(tmp_path)
    monkeypatch.setattr(tls, "exact_images", lambda _bundle: ("services", IMAGE))
    monkeypatch.setattr(tls, "openbao_network", lambda *_args, **_kwargs: "owned-network")

    def fake_run(_args: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        output = Path(kwargs["env"]["SELFHOST_KEYCLOAK_OUTPUT_DIR"])
        (output / next(iter(bridge.OUTPUTS))).write_text("partial", encoding="ascii")
        return subprocess.CompletedProcess(_args, 0, "", "")

    monkeypatch.setattr(bridge.subprocess, "run", fake_run)
    with pytest.raises(RuntimeError, match="incomplete"):
        bridge.stage(root, OPERATOR)
    assert not any((root / "secrets" / name).exists() for name in bridge.OUTPUTS)
    assert not list(root.glob("keycloak-inputs-*"))


def test_rejects_substituted_public_ca_before_root_token_use(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    require_root_linux()
    root = staged(tmp_path)
    monkeypatch.setattr(tls, "exact_images", lambda _bundle: ("services", IMAGE))
    monkeypatch.setattr(tls, "openbao_network", lambda *_args, **_kwargs: "owned-network")
    (root / "secrets" / "openbao_tls_ca_cert").write_text("foreign ca", encoding="ascii")
    monkeypatch.setattr(bridge.subprocess, "run", lambda *_args, **_kwargs:
                        pytest.fail("root token used after CA substitution"))
    with pytest.raises(ValueError, match="public CA does not match"):
        bridge.stage(root, OPERATOR)


def test_rejects_foreign_image_and_unsafe_root_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    require_root_linux()
    root = staged(tmp_path)
    monkeypatch.setattr(tls, "exact_images", lambda _bundle: ("services", IMAGE))
    monkeypatch.setattr(tls, "openbao_network", lambda *_args, **_kwargs: "owned-network")
    marker = root / "openbao.json"
    report = json.loads(marker.read_text(encoding="utf-8"))
    marker.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="lineage"):
        bridge.stage(root, OPERATOR)
    report["image"] = "other"
    marker.write_text(json.dumps(report), encoding="utf-8")
    with pytest.raises(ValueError, match="differs"):
        bridge.stage(root, OPERATOR)
    report["image"] = IMAGE
    marker.write_text(json.dumps(report), encoding="utf-8")
    token = root / "openbao-state" / "root.token"
    token.chmod(0o644)
    with pytest.raises(ValueError, match="unsafe ownership or mode"):
        bridge.stage(root, OPERATOR)


def test_partial_transfer_failure_removes_all_operator_outputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    require_root_linux()
    root = staged(tmp_path)
    monkeypatch.setattr(tls, "exact_images", lambda _bundle: ("services", IMAGE))
    monkeypatch.setattr(tls, "openbao_network", lambda *_args, **_kwargs: "owned-network")

    def fake_run(_args: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        output = Path(kwargs["env"]["SELFHOST_KEYCLOAK_OUTPUT_DIR"])
        for name in bridge.OUTPUTS:
            target = output / name
            target.write_text("scoped-public-input", encoding="ascii")
            target.chmod(0o444)
        return subprocess.CompletedProcess(_args, 0, "", "")

    monkeypatch.setattr(bridge.subprocess, "run", fake_run)
    real_fchown = bridge.os.fchown
    calls = 0

    def fail_second_transfer(fd: int, uid: int, gid: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected transfer failure")
        real_fchown(fd, uid, gid)

    monkeypatch.setattr(bridge.os, "fchown", fail_second_transfer)
    with pytest.raises(OSError, match="injected transfer failure"):
        bridge.stage(root, OPERATOR)
    assert calls == 2
    assert not any((root / "secrets" / name).exists() for name in bridge.OUTPUTS)
    assert (root / "openbao-state" / "root.token").exists()


@pytest.mark.parametrize("code", [3, -15, 101])
def test_uncertain_mint_reports_recovery_without_transfer(tmp_path, monkeypatch, code):
    require_root_linux()
    root = staged(tmp_path)
    monkeypatch.setattr(tls, "exact_images", lambda _bundle: ("services", IMAGE))
    monkeypatch.setattr(tls, "openbao_network", lambda *_args, **_kwargs: "owned-network")
    monkeypatch.setattr(bridge.subprocess, "run", lambda command, **kwargs:
                        subprocess.CompletedProcess(command, code, "", "sensitive-detail"))
    with pytest.raises(bridge.OperatorCleanupError, match="^Keycloak provisioning requires operator recovery$"):
        bridge.stage(root, OPERATOR)
    assert not any((root / "secrets" / name).exists() for name in bridge.OUTPUTS)


def test_cli_keeps_recovery_exit_three(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["stage", "--private-root", str(tmp_path)])
    monkeypatch.setenv("SUDO_UID", "1000")

    def uncertain(*args):
        raise bridge.OperatorCleanupError("Keycloak provisioning requires operator recovery")
    monkeypatch.setattr(bridge, "stage", uncertain)
    assert bridge.main() == 3
    assert capsys.readouterr().err.strip() == "Keycloak provisioning requires operator recovery"
