"""Disposable OpenBao startup must stay scoped to a fresh preview."""

import json
import os
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import start_selfhost_disposable_openbao as starter  # noqa: E402


IMAGE = "ghcr.io/elevenid/marty-ui-oss/openbao-didcomm@sha256:" + "a" * 64


def staged(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    for name in ("secrets", "openbao-state"):
        (root / name).mkdir(mode=0o700)
    bundle = root / "install" / "selfhost-prepared"
    bundle.mkdir(parents=True)
    (bundle / "docker-compose.selfhost.openbao.yml").write_text(
        "services: {}\n", encoding="ascii")
    (root / "stage.json").write_text(json.dumps({
        "schema": "marty.selfhost-disposable-stage/v1",
        "qualification": "unqualified", "install_root": str(bundle),
        "source_sha": "a" * 40, "run_id": "123",
    }), encoding="utf-8")
    return root, bundle


def test_cli_identifies_missing_docker_without_echoing_os_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys,
) -> None:
    monkeypatch.setattr(sys, "argv", ["starter", "--private-root", str(tmp_path)])
    monkeypatch.setattr(starter, "start", lambda *_args: (_ for _ in ()).throw(
        FileNotFoundError(2, "private-path-and-token", "docker")))
    assert starter.main() == 2
    captured = capsys.readouterr()
    assert "[DOCKER_MISSING]" in captured.err
    assert "private-path-and-token" not in captured.err


def model(root: Path, bundle: Path, port: int = 18200,
          project: str = "marty-preview-1234567890abcdef") -> dict:
    state = root / "openbao-state"
    secrets = root / "secrets"

    def bind(source: Path, target: str, read_only: bool = False) -> dict:
        return {"type": "bind", "source": str(source), "target": target,
                "read_only": read_only}

    return {"name": project, "networks": {"default": {"name": project + "_default"}},
            "services": {
        "openbao-tls-init": {"image": IMAGE, "networks": {"default": None},
                             "entrypoint": ["/usr/local/bin/selfhost-tls-init"],
                             "restart": "no", "volumes": [bind(state, "/bao/data")]},
        "openbao": {"image": IMAGE, "networks": {"default": None},
                    "entrypoint": None, "command": [
                        "server", "-config=/bao/config/openbao.hcl"],
                    "restart": "unless-stopped", "depends_on": {
                        "openbao-tls-init": {
                            "condition": "service_completed_successfully", "required": True}},
                    "healthcheck": {"test": ["CMD-SHELL", "bao status -address=https://127.0.0.1:8200 -ca-cert=/bao/data/tls/ca.crt >/dev/null 2>&1"],
                                    "timeout": "5s", "interval": "10s", "retries": 12,
                                    "start_period": "20s"},
                    "ports": [{
            "host_ip": "127.0.0.1", "target": 8200,
            "published": str(port), "protocol": "tcp",
        }], "volumes": [
            bind(state, "/bao/data"),
            bind(bundle / "docker" / "openbao-selfhost.hcl", "/bao/config/openbao.hcl", True),
        ]},
        "openbao-unseal": {"image": IMAGE, "networks": {"default": None},
                            "entrypoint": ["/usr/local/bin/selfhost-unseal"],
                            "restart": "unless-stopped", "depends_on": {"openbao": {
                                "condition": "service_started", "required": True}},
                            "environment": {
                                "BAO_ADDR": "https://openbao:8200",
                                "BAO_CACERT": "/bao/data/tls/ca.crt",
                                "BAO_UNSEAL_KEY_FILE": "/bao/data/unseal.key",
                            }, "volumes": [bind(state, "/bao/data", True)]},
        "openbao-bootstrap": {"image": IMAGE, "networks": {"default": None},
                              "entrypoint": ["/bin/sh", "/scripts/openbao-selfhost-init.sh"],
                              "profiles": ["kms-init"], "restart": "no", "depends_on": {"openbao": {
                                  "condition": "service_started", "required": True}},
                              "environment": {
                                  "BAO_ADDR": "https://openbao:8200",
                                  "BAO_BOOTSTRAP_TOKEN_FILE": "/bao/runtime/openbao_bootstrap_token",
                                  "BAO_CACERT": "/bao/data/tls/ca.crt",
                                  "BAO_DIDCOMM_ISSUANCE_TOKEN_FILE": "/bao/runtime/didcomm_issuance_openbao_token",
                                  "BAO_HAIP_POLICY_FILE": "/scripts/openbao-haip-workload-policy.hcl",
                                  "BAO_HAIP_TOKEN_FILE": "/bao/runtime/haip_kms_token",
                                  "BAO_INIT_FILE": "/bao/data/selfhost-init.json",
                                  "BAO_NOTIFICATION_TOKEN_FILE": "/bao/runtime/notification_openbao_token",
                                  "BAO_ROOT_TOKEN_FILE": "/bao/data/root.token",
                                  "BAO_SERVICE_TOKEN_FILE": "/bao/runtime/openbao_service_token",
                                  "BAO_SIGNING_KEYS_TOKEN_FILE": "/bao/runtime/signing_keys_openbao_token",
                                  "BAO_UNSEAL_KEY_FILE": "/bao/data/unseal.key",
                                  "DIDCOMM_KMS_PLUGIN_REQUIRED": "true",
                              }, "volumes": [
            bind(state, "/bao/data"), bind(secrets, "/bao/runtime"),
            bind(bundle / "docker" / "openbao-init.sh", "/scripts/openbao-init.sh", True),
            bind(bundle / "docker" / "openbao-haip-workload-policy.hcl",
                 "/scripts/openbao-haip-workload-policy.hcl", True),
            bind(bundle / "docker" / "openbao-selfhost-init.sh",
                 "/scripts/openbao-selfhost-init.sh", True),
        ]},
    }}


def test_model_rejects_public_port_foreign_mount_and_extra_service(tmp_path: Path) -> None:
    root, bundle = staged(tmp_path)
    valid = model(root, bundle)
    starter.verify_model(valid, IMAGE, root / "openbao-state", root / "secrets",
                         bundle, 18200, "marty-preview-1234567890abcdef")
    valid["services"]["openbao"]["ports"][0]["host_ip"] = "0.0.0.0"
    with pytest.raises(ValueError, match="loopback"):
        starter.verify_model(valid, IMAGE, root / "openbao-state", root / "secrets",
                             bundle, 18200, "marty-preview-1234567890abcdef")
    valid = model(root, bundle)
    valid["services"]["openbao-bootstrap"]["volumes"][1]["source"] = "/tmp/other"
    with pytest.raises(ValueError, match="bind mounts"):
        starter.verify_model(valid, IMAGE, root / "openbao-state", root / "secrets",
                             bundle, 18200, "marty-preview-1234567890abcdef")
    valid = model(root, bundle)
    valid["services"]["unexpected"] = {"image": IMAGE}
    with pytest.raises(ValueError, match="service set"):
        starter.verify_model(valid, IMAGE, root / "openbao-state", root / "secrets",
                             bundle, 18200, "marty-preview-1234567890abcdef")
    valid = model(root, bundle)
    valid["services"]["openbao-bootstrap"]["privileged"] = True
    with pytest.raises(ValueError, match="unsafe runtime overrides"):
        starter.verify_model(valid, IMAGE, root / "openbao-state", root / "secrets",
                             bundle, 18200, "marty-preview-1234567890abcdef")
    valid = model(root, bundle)
    valid["services"]["openbao-bootstrap"]["entrypoint"] = ["/bin/sh", "-c", "env"]
    with pytest.raises(ValueError, match="startup contract"):
        starter.verify_model(valid, IMAGE, root / "openbao-state", root / "secrets",
                             bundle, 18200, "marty-preview-1234567890abcdef")
    valid = model(root, bundle)
    valid["services"]["openbao-bootstrap"]["volumes"][2]["read_only"] = False
    with pytest.raises(ValueError, match="bind mounts"):
        starter.verify_model(valid, IMAGE, root / "openbao-state", root / "secrets",
                             bundle, 18200, "marty-preview-1234567890abcdef")
    valid = model(root, bundle)
    valid["services"]["openbao-bootstrap"].pop("profiles")
    with pytest.raises(ValueError, match="opt-in"):
        starter.verify_model(valid, IMAGE, root / "openbao-state", root / "secrets",
                             bundle, 18200, "marty-preview-1234567890abcdef")
    valid = model(root, bundle)
    valid["services"]["openbao-unseal"]["volumes"][0]["read_only"] = False
    with pytest.raises(ValueError, match="bind mounts"):
        starter.verify_model(valid, IMAGE, root / "openbao-state", root / "secrets",
                             bundle, 18200, "marty-preview-1234567890abcdef")


def test_start_uses_fresh_project_and_writes_no_tokens_to_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.name != "posix":
        pytest.skip("non-root Linux-only entrypoint")
    root, bundle = staged(tmp_path)
    monkeypatch.setattr(starter.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(starter, "exact_images", lambda _bundle: ("services", IMAGE))
    monkeypatch.setattr(starter, "free_loopback_port", lambda _port: None)
    def owned_network(*_args: object, expected_host_port: int) -> str:
        assert expected_host_port == 18200
        return "owned-network"

    monkeypatch.setattr(starter, "openbao_network", owned_network)
    commands: list[list[str]] = []
    monkeypatch.setattr(starter, "wait_healthy",
                        lambda *_args: commands.append(["health-after-bootstrap"]))

    def fake_run(args: list[str], **_kwargs: object) -> str:
        commands.append(args)
        if "config" in args:
            project = args[args.index("--project-name") + 1]
            return json.dumps(model(root, bundle, project=project))
        if "run" in args:
            for name in starter.OUTPUTS:
                (root / "secrets" / name).write_text("private-token", encoding="ascii")
            (root / "openbao-state" / "tls").mkdir()
            (root / "openbao-state" / "tls" / "ca.crt").write_text("ca")
            (root / "secrets" / "openbao_tls_ca_cert").write_text("ca")
            root_token = root / "openbao-state" / "root.token"
            root_token.write_text("private-token", encoding="ascii")
            root_token.chmod(0o400)
        return ""

    monkeypatch.setattr(starter, "run", fake_run)
    report = starter.start(root, 18200)
    assert starter.PROJECT.fullmatch(report["project"])
    assert report["qualification"] == "unqualified"
    assert "private-token" not in (root / "openbao.json").read_text(encoding="utf-8")
    assert not (root / "openbao-pending.json").exists()
    assert any("up" in command for command in commands)
    assert any("--profile" in command and "kms-init" in command
               for command in commands if "config" in command)
    assert any("run" in command for command in commands)
    first_up = next(i for i, command in enumerate(commands) if "up" in command)
    bootstrap = next(i for i, command in enumerate(commands) if "run" in command)
    unseal_up = next(i for i, command in enumerate(commands)
                     if "up" in command and command[-1] == "openbao-unseal")
    assert first_up < bootstrap < unseal_up
    assert ["health-after-bootstrap"] in commands
    assert next(i for i, command in enumerate(commands) if "run" in command) < commands.index(
        ["health-after-bootstrap"])
    assert not any("down" in command for command in commands)
    with pytest.raises(ValueError, match="already started"):
        starter.start(root, 18200)


def test_failed_bootstrap_only_tears_down_new_owned_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.name != "posix":
        pytest.skip("non-root Linux-only entrypoint")
    root, bundle = staged(tmp_path)
    monkeypatch.setattr(starter.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(starter, "exact_images", lambda _bundle: ("services", IMAGE))
    monkeypatch.setattr(starter, "free_loopback_port", lambda _port: None)
    commands: list[list[str]] = []

    def fake_run(args: list[str], **_kwargs: object) -> str:
        commands.append(args)
        if "config" in args:
            project = args[args.index("--project-name") + 1]
            return json.dumps(model(root, bundle, project=project))
        if "run" in args:
            raise RuntimeError("bootstrap failed")
        return ""

    monkeypatch.setattr(starter, "run", fake_run)
    with pytest.raises(RuntimeError, match="bootstrap failed"):
        starter.start(root, 18200)
    assert [command for command in commands if "down" in command]
    assert not (root / "openbao.json").exists()
    assert (root / "openbao-pending.json").exists()


def test_failed_cleanup_preserves_project_recovery_marker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.name != "posix":
        pytest.skip("non-root Linux-only entrypoint")
    root, bundle = staged(tmp_path)
    monkeypatch.setattr(starter.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(starter, "exact_images", lambda _bundle: ("services", IMAGE))
    monkeypatch.setattr(starter, "free_loopback_port", lambda _port: None)

    def fake_run(args: list[str], **_kwargs: object) -> str:
        if "config" in args:
            project = args[args.index("--project-name") + 1]
            return json.dumps(model(root, bundle, project=project))
        if "run" in args or "down" in args:
            raise RuntimeError("Docker failed")
        return ""

    monkeypatch.setattr(starter, "run", fake_run)
    with pytest.raises(RuntimeError, match="manual cleanup"):
        starter.start(root, 18200)
    pending = json.loads((root / "openbao-pending.json").read_text(encoding="utf-8"))
    assert starter.PROJECT.fullmatch(pending["project"])
    assert pending["host_port"] == 18200
    assert "token" not in pending


def test_incomplete_cleanup_is_reported_for_exact_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.name != "posix":
        pytest.skip("non-root Linux-only entrypoint")
    root, bundle = staged(tmp_path)
    monkeypatch.setattr(starter.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(starter, "exact_images", lambda _bundle: ("services", IMAGE))
    monkeypatch.setattr(starter, "free_loopback_port", lambda _port: None)
    downs = 0

    def fake_run(args: list[str], **_kwargs: object) -> str:
        nonlocal downs
        if "config" in args:
            project = args[args.index("--project-name") + 1]
            return json.dumps(model(root, bundle, project=project))
        if "run" in args:
            raise RuntimeError("bootstrap failed")
        if "down" in args:
            downs += 1
        if downs and "ps" in args:
            return "a" * 64
        return ""

    monkeypatch.setattr(starter, "run", fake_run)
    with pytest.raises(RuntimeError, match="manual cleanup"):
        starter.start(root, 18200)
    assert downs == 1
    assert starter.PROJECT.fullmatch(json.loads(
        (root / "openbao-pending.json").read_text(encoding="utf-8"))["project"])


def test_wait_healthy_checks_exact_container(tmp_path: Path,
                                             monkeypatch: pytest.MonkeyPatch) -> None:
    commands: list[list[str]] = []
    states = iter(["starting", "healthy"])

    def fake_run(args: list[str], **_kwargs: object) -> str:
        commands.append(args)
        if "ps" in args:
            return "a" * 64
        return next(states)

    monkeypatch.setattr(starter, "run", fake_run)
    monkeypatch.setattr(starter.time, "sleep", lambda _seconds: None)
    starter.wait_healthy(["docker", "compose", "--project-name", "owned"], {})
    assert len([args for args in commands if "inspect" in args]) == 2
    assert all("a" * 64 in args for args in commands if "inspect" in args)
