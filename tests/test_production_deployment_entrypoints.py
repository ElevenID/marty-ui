"""Production deployment must use a fully governed runtime definition."""

from pathlib import Path
import json
import shutil
import runpy
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_selfhost_secret_catalog_runs_offline(monkeypatch: pytest.MonkeyPatch) -> None:
    scope = runpy.run_path(str(ROOT / "scripts/check-selfhost-production.py"))
    catalog_lines = scope["catalog_lines"]
    calls: list[dict[str, object]] = []

    def fake_run(command: list[str], **kwargs: object) -> SimpleNamespace:
        calls.append({"command": command, **kwargs})
        return SimpleNamespace(returncode=0, stdout="notification_webhook_secret\n")

    monkeypatch.setitem(catalog_lines.__globals__, "operator_command", lambda *_: ["owned-catalog", "secrets"])
    monkeypatch.setitem(catalog_lines.__globals__, "subprocess", SimpleNamespace(run=fake_run))
    assert catalog_lines("secrets", "selfhost-production", offline=True) == ["notification_webhook_secret"]
    assert len(calls) == 1
    assert calls[0]["command"] == ["owned-catalog", "secrets"]
    assert calls[0]["env"]["CARGO_NET_OFFLINE"] == "true"


@pytest.mark.parametrize("path_value", ['"{path}"', '"${{FIXTURE_SECRET_ROOT}}"'])
def test_selfhost_secret_preflight_uses_compose_resolved_path(
    path_value: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    if not shutil.which("docker"):
        pytest.skip("Docker Compose local renderer is unavailable")
    scope = runpy.run_path(str(ROOT / "scripts/check-selfhost-production.py"))
    secrets = tmp_path / "secret files"
    secrets.mkdir()
    source = secrets / "notification_webhook_secret"
    source.write_text("local-only-renderer-sentinel", encoding="utf-8")
    env_file = tmp_path / "fixture.env"
    env_file.write_text(
        f'FIXTURE_SECRET_ROOT="{secrets.as_posix()}"\n'
        f"SELFHOST_SECRET_DIR={path_value.format(path=secrets.as_posix())}\n",
        encoding="utf-8",
    )
    compose_file = tmp_path / "compose.yml"
    compose_file.write_text(
        "services:\n  probe:\n    image: busybox:latest\n"
        "    secrets:\n      - notification_webhook_secret\n"
        "secrets:\n  notification_webhook_secret:\n"
        "    file: ${SELFHOST_SECRET_DIR}/notification_webhook_secret\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("DOCKER_HOST", "tcp://127.0.0.1:9")
    monkeypatch.delenv("DOCKER_CONTEXT", raising=False)
    paths = scope["rendered_secret_files"](env_file, compose_file)
    assert paths["notification_webhook_secret"].resolve() == source.resolve()


@pytest.mark.parametrize("bad_file", ["missing", "directory", "empty", "placeholder"])
def test_selfhost_secret_preflight_stops_before_compose(
    bad_file: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    scope = runpy.run_path(str(ROOT / "scripts/check-selfhost-production.py"))
    main = scope["main"]
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    env_file = tmp_path / "production.env"
    env_file.write_text(f"SELFHOST_SECRET_DIR={secrets}\n", encoding="utf-8")
    (secrets / "notification_webhook_secret").write_text("local-only-webhook-sentinel", encoding="utf-8")
    token = secrets / "notification_applicant_event_token"
    if bad_file == "directory":
        token.mkdir()
    elif bad_file == "empty":
        token.write_text("", encoding="utf-8")
    elif bad_file == "placeholder":
        token.write_text("change-me-local-only", encoding="utf-8")

    def only_catalog(*args: str, **kwargs: object) -> list[str]:
        assert kwargs == {"offline": True}
        if args == ("secrets", "selfhost-production"):
            return ["notification_webhook_secret", "notification_applicant_event_token"]
        if args == ("secrets", "selfhost-production", "--field", "compose_secret"):
            return ["notification_webhook_secret", "notification_applicant_event_token"]
        raise AssertionError(f"Unexpected catalog operation: {args}")

    monkeypatch.setitem(main.__globals__, "catalog_lines", only_catalog)
    def only_render(*args: object) -> SimpleNamespace:
        assert args[2:] == ("config", "--format", "json")
        return SimpleNamespace(returncode=0, stdout=json.dumps({"secrets": {
            name: {"file": str(secrets / name)}
            for name in ("notification_webhook_secret", "notification_applicant_event_token")
        }}))

    monkeypatch.setitem(main.__globals__, "run_compose_command", only_render)
    monkeypatch.setattr(sys, "argv", ["check-selfhost-production.py", "--env-file", str(env_file), "--required-secrets-only"])
    assert main() == 1
    output = capsys.readouterr().out
    assert "[FAIL] selfhost-required-secrets" in output
    assert "local-only-webhook-sentinel" not in output
    assert "change-me-local-only" not in output


def test_selfhost_secret_preflight_accepts_regular_files_without_compose(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    scope = runpy.run_path(str(ROOT / "scripts/check-selfhost-production.py"))
    main = scope["main"]
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    env_file = tmp_path / "production.env"
    env_file.write_text(f"SELFHOST_SECRET_DIR={secrets}\n", encoding="utf-8")
    for name in ("notification_webhook_secret", "notification_applicant_event_token"):
        (secrets / name).write_text(f"local-only-{name}-sentinel", encoding="utf-8")

    def only_catalog(*args: str, **kwargs: object) -> list[str]:
        assert kwargs == {"offline": True}
        if args == ("secrets", "selfhost-production"):
            return ["notification_webhook_secret", "notification_applicant_event_token"]
        if args == ("secrets", "selfhost-production", "--field", "compose_secret"):
            return ["notification_webhook_secret", "notification_applicant_event_token"]
        raise AssertionError(f"Unexpected catalog operation: {args}")

    monkeypatch.setitem(main.__globals__, "catalog_lines", only_catalog)
    def only_render(*args: object) -> SimpleNamespace:
        assert args[2:] == ("config", "--format", "json")
        return SimpleNamespace(returncode=0, stdout=json.dumps({"secrets": {
            name: {"file": str(secrets / name)}
            for name in ("notification_webhook_secret", "notification_applicant_event_token")
        }}))

    monkeypatch.setitem(main.__globals__, "run_compose_command", only_render)
    monkeypatch.setattr(sys, "argv", ["check-selfhost-production.py", "--env-file", str(env_file), "--required-secrets-only"])
    assert main() == 0
    output = capsys.readouterr().out
    assert "[OK] selfhost-required-secrets" in output
    assert "local-only-" not in output

    recipe = (ROOT / "Makefile").read_text(encoding="utf-8").split("selfhost-prod-up: selfhost-prod-config", 1)[1]
    assert recipe.index("--required-secrets-only") < recipe.index("$(SELFHOST_PROD_COMPOSE) pull")


def test_selfhost_secret_preflight_rejects_external_required_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    scope = runpy.run_path(str(ROOT / "scripts/check-selfhost-production.py"))
    main = scope["main"]
    env_file = tmp_path / "fixture.env"
    env_file.write_text("SELFHOST_SECRET_DIR=/unused\n", encoding="utf-8")
    monkeypatch.setitem(main.__globals__, "catalog_lines", lambda *_, **__: ["notification_webhook_secret"])
    monkeypatch.setitem(main.__globals__, "run_compose_command", lambda *_: SimpleNamespace(
        returncode=0,
        stdout=json.dumps({"secrets": {"notification_webhook_secret": {"external": True}}}),
    ))
    monkeypatch.setattr(sys, "argv", ["check-selfhost-production.py", "--env-file", str(env_file), "--required-secrets-only"])
    assert main() == 1
    assert "has no file source" in capsys.readouterr().out


def test_selfhost_secret_preflight_redacts_renderer_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    scope = runpy.run_path(str(ROOT / "scripts/check-selfhost-production.py"))
    main = scope["main"]
    env_file = tmp_path / "fixture.env"
    env_file.write_text("SELFHOST_SECRET_DIR=/unused\n", encoding="utf-8")
    monkeypatch.setitem(main.__globals__, "run_compose_command", lambda *_: SimpleNamespace(
        returncode=1, stdout="private-sentinel", stderr="private-sentinel",
    ))
    monkeypatch.setattr(sys, "argv", ["check-selfhost-production.py", "--env-file", str(env_file), "--required-secrets-only"])
    assert main() == 1
    output = capsys.readouterr().out
    assert "Could not inspect rendered self-host secret paths" in output
    assert "private-sentinel" not in output


def test_unsafe_layered_production_profile_remains_retired() -> None:
    assert not (ROOT / "docker-compose.profile.prod.yml").exists()


def test_catalog_names_only_governed_production_entrypoints() -> None:
    deployment_guide = (ROOT / "deploy-config" / "README.md").read_text(
        encoding="utf-8"
    )

    assert (
        "Selfhost production compose: docker-compose.selfhost.prod.yml"
        in deployment_guide
    )
    assert (
        "Kubernetes deployment script: scripts/deploy-kubernetes.sh" in deployment_guide
    )
    assert (
        "Do not layer the development-oriented `docker-compose.base.yml`"
        in deployment_guide
    )


def test_production_environment_template_requires_internal_service_auth() -> None:
    environment_template = (ROOT / ".env.production.example").read_text(
        encoding="utf-8"
    )

    assert "GRPC_SERVICE_TOKEN=" in environment_template
    assert "at least 32 random characters" in environment_template
