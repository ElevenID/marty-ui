"""Production deployment must use a fully governed runtime definition."""

from pathlib import Path
import json
import os
import shutil
import runpy
import subprocess
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def compose_observation(monkeypatch: pytest.MonkeyPatch):
    """Use the real renderer without a Docker daemon or deployment mutations."""
    selected = os.environ.get("MARTY_COMPOSE_RENDERER") or os.environ.get("MARTY_BASE_COMPOSE_BINARY")
    if selected:
        assert Path(selected).is_file(), "selected Compose renderer is missing"
        command = [selected]
    elif shutil.which("docker"):
        command = ["docker", "compose"]
    else:
        pytest.skip("Docker Compose local renderer is unavailable")
    scope = runpy.run_path(str(ROOT / "scripts/check-selfhost-production.py"))

    def render(env_file, compose_file, *args, input=None):
        assert "config" in args, "observation must never start a deployment"
        return subprocess.run(
            [*command, "--env-file", str(env_file), "-f", str(compose_file), *args],
            input=input, capture_output=True, text=True, check=False, timeout=15,
            cwd=ROOT,
        )

    monkeypatch.setitem(scope["main"].__globals__, "run_compose_command", render)
    monkeypatch.setenv("DOCKER_HOST", "tcp://127.0.0.1:9")
    monkeypatch.delenv("DOCKER_CONTEXT", raising=False)
    return scope


def test_selfhost_observes_actual_compose_interpolation(
    compose_observation, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    compose = tmp_path / "compose.yml"
    compose.write_text("name: canyon-customer\nservices:\n  probe:\n    image: scratch\n")
    env_file = tmp_path / "customer.env"
    env_file.write_text(
        "export CUSTOMER_HOST=credentials.canyon-skills.example\n"
        'PUBLIC_DOMAIN="${CUSTOMER_HOST}"\n'
        'UI_BASE_URL="https://${CUSTOMER_HOST}:8443" # customer TLS listener\n'
        "MARTY_ORG_NAME='Canyon Skills Academy'\n"
        "SELFHOST_SECRET_DIR='customer $files/${literal}'\n"
        "LITERAL_BACKSLASH='back\\slash'\n"
        "EMPTY_SETTING=\n"
        "MULTILINE_SETTING='first line\nGHOST_TLS_KMS_ADDR=https://not-a-setting.example\nlast line'\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("CUSTOMER_HOST", "credentials.customer-override.example")
    for key in ("PUBLIC_DOMAIN", "UI_BASE_URL", "MARTY_ORG_NAME", "SELFHOST_SECRET_DIR",
                "LITERAL_BACKSLASH", "EMPTY_SETTING", "MULTILINE_SETTING", "COMPOSE_PROJECT_NAME",
                "GHOST_TLS_KMS_ADDR"):
        monkeypatch.delenv(key, raising=False)
    observed = compose_observation["load_env_file"](env_file, compose)
    assert observed["PUBLIC_DOMAIN"] == "credentials.customer-override.example"
    assert observed["UI_BASE_URL"] == "https://credentials.customer-override.example:8443"
    assert observed["MARTY_ORG_NAME"] == "Canyon Skills Academy"
    assert observed["SELFHOST_SECRET_DIR"] == "customer $files/${literal}"
    assert observed["LITERAL_BACKSLASH"] == "back\\slash"
    assert observed["EMPTY_SETTING"] == ""
    assert observed["MULTILINE_SETTING"] == (
        "first line\nGHOST_TLS_KMS_ADDR=https://not-a-setting.example\nlast line"
    )
    assert "GHOST_TLS_KMS_ADDR" not in observed


@pytest.mark.parametrize("folder", ["customer $files", "customer $$files", "customer ${literal}"])
def test_selfhost_resolved_secret_paths_decode_compose_dollars_once(
    compose_observation, tmp_path: Path, folder: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_dir = tmp_path / folder
    secret_dir.mkdir()
    source = secret_dir / "notification_webhook_secret"
    source.write_text("local-only-webhook-value\n")
    env_file = tmp_path / "customer.env"
    env_file.write_text(f"SELFHOST_SECRET_DIR='{folder}'\n")
    compose = tmp_path / "compose.yml"
    compose.write_text(
        "services:\n  probe:\n    image: scratch\n"
        "    secrets: [notification_webhook_secret]\n"
        "secrets:\n  notification_webhook_secret:\n"
        "    file: ${SELFHOST_SECRET_DIR}/notification_webhook_secret\n"
    )
    monkeypatch.delenv("SELFHOST_SECRET_DIR", raising=False)
    paths = compose_observation["rendered_secret_files"](env_file, compose)
    assert paths["notification_webhook_secret"] == source
    assert compose_observation["read_required_secret"](source, "webhook") == "local-only-webhook-value"


@pytest.mark.parametrize("folder", ["customer secrets", " leading-space", "trailing-space "])
def test_selfhost_full_check_resolves_relative_secret_root_from_compose_directory(
    compose_observation, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, folder: str,
) -> None:
    compose_dir = tmp_path / "deployment"
    compose_dir.mkdir()
    compose = compose_dir / "compose.yml"
    compose.write_text("services:\n  probe:\n    image: scratch\n")
    env_file = tmp_path / "customer.env"
    env_file.write_text(f"SELFHOST_SECRET_DIR='{folder}'\n")
    main = compose_observation["main"]
    monkeypatch.delenv("SELFHOST_SECRET_DIR", raising=False)
    monkeypatch.setitem(main.__globals__, "catalog_lines", lambda *_, **__: [])
    for name in ("validate_openbao_plugin_image", "validate_kms_transport"):
        monkeypatch.setitem(main.__globals__, name, lambda *_: "fixture")

    class ObservedRoot(Exception):
        pass

    def inspect_root(secret_dir):
        assert secret_dir == compose_dir / folder
        raise ObservedRoot

    monkeypatch.setitem(main.__globals__, "validate_holder_service_credential", inspect_root)
    monkeypatch.setattr(sys, "argv", [
        "check-selfhost-production.py", "--env-file", str(env_file),
        "--prod-compose-file", str(compose), "--openbao-compose-file", str(compose),
    ])
    with pytest.raises(ObservedRoot):
        main()


def test_selfhost_observes_first_setting_in_a_bom_environment_file(
    compose_observation, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    env_file = tmp_path / "customer.env"
    env_file.write_text("SELFHOST_SECRET_DIR='customer secrets'\r\n", encoding="utf-8-sig")
    compose = tmp_path / "compose.yml"
    compose.write_text("services:\n  probe:\n    image: scratch\n")
    monkeypatch.delenv("SELFHOST_SECRET_DIR", raising=False)
    observed = compose_observation["load_env_file"](env_file, compose)
    assert observed["SELFHOST_SECRET_DIR"] == "customer secrets"


def test_customer_checker_agrees_with_the_canonical_production_model(
    compose_observation, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Synthetic image identities are renderer inputs, never deployment assets.
    settings = {
        "SELFHOST_SECRET_DIR": "customer $secrets",
        "SELFHOST_STATE_DIR": "customer state",
        "SELFHOST_IMAGE_TAG": "customer-render-test",
        "MARTY_ISSUANCE_IMAGE": "ghcr.io/elevenid/test/issuance@sha256:" + "a" * 64,
        "MARTY_KEYCLOAK_KMS_IMAGE": "ghcr.io/elevenid/test/keycloak@sha256:" + "b" * 64,
        "MARTY_OPENBAO_DIDCOMM_IMAGE": "ghcr.io/elevenid/test/openbao@sha256:" + "c" * 64,
        "MARTY_ORG_ID": "750e8400-e29b-41d4-a716-446655440001",
        "MARTY_ORG_NAME": "Canyon Skills Academy",
        "PUBLIC_DOMAIN": "credentials.canyon-skills.example",
    }
    for key in (*settings, "UI_BASE_URL", "PUBLIC_API_URL"):
        monkeypatch.delenv(key, raising=False)
    env_file = tmp_path / "customer.env"
    env_file.write_text(
        (ROOT / ".env.selfhost.production.example").read_text(encoding="utf-8")
        + "\n" + "\n".join(f"{key}='{value}'" for key, value in settings.items())
        + '\nPUBLIC_API_URL="https://${PUBLIC_DOMAIN}:8443"\n'
        + 'UI_BASE_URL="${PUBLIC_API_URL}"\n',
        encoding="utf-8",
    )
    compose = ROOT / "docker-compose.selfhost.prod.yml"
    observed = compose_observation["load_env_file"](env_file, compose)
    assert {key: observed[key] for key in settings} == settings
    assert observed["UI_BASE_URL"] == "https://credentials.canyon-skills.example:8443"
    result = compose_observation["main"].__globals__["run_compose_command"](
        env_file, compose, "config", "--format", "json",
    )
    assert result.returncode == 0, "canonical customer Compose render failed"
    model = json.loads(result.stdout)
    for service in ("organization", "auth", "issuance", "db-migrate"):
        environment = model["services"][service]["environment"]
        assert environment["MARTY_ORG_ID"] == observed["MARTY_ORG_ID"]
        assert environment["MARTY_ORG_NAME"] == observed["MARTY_ORG_NAME"]


def test_selfhost_environment_refusal_is_private_and_precedes_runtime_probes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    scope = runpy.run_path(str(ROOT / "scripts/check-selfhost-production.py"))
    main = scope["main"]
    env_file = tmp_path / "customer.env"
    env_file.write_text("SELFHOST_SECRET_DIR=private-setting-value\n")
    monkeypatch.setitem(main.__globals__, "run_compose_command", lambda *_, **__: SimpleNamespace(
        returncode=1, stdout="private-rendered-model", stderr="private-setting-value",
    ))
    monkeypatch.setitem(main.__globals__, "catalog_lines", lambda *_: pytest.fail("runtime probe after config refusal"))
    monkeypatch.setattr(sys, "argv", ["check-selfhost-production.py", "--env-file", str(env_file)])
    assert main() == 1
    output = capsys.readouterr().out
    assert "[FAIL] selfhost-environment" in output
    assert "private-" not in output


def test_selfhost_compose_validation_is_quiet_and_redacts_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    scope = runpy.run_path(str(ROOT / "scripts/check-selfhost-production.py"))
    validate = scope["ensure_compose_config"]

    def refuse(*args):
        assert args[2:] == ("config", "--quiet")
        return SimpleNamespace(returncode=1, stdout="private-rendered-model", stderr="private-credential")

    monkeypatch.setitem(validate.__globals__, "run_compose_command", refuse)
    with pytest.raises(scope["CheckError"], match="config failed") as error:
        validate(Path("customer.env"), Path("compose.yml"))
    assert "private-" not in str(error.value)


def test_selfhost_missing_docker_reports_actionable_error(monkeypatch: pytest.MonkeyPatch) -> None:
    scope = runpy.run_path(str(ROOT / "scripts/check-selfhost-production.py"))
    run = scope["run_compose_command"]

    def missing(*_, **__):
        raise FileNotFoundError("private-host-diagnostic")

    monkeypatch.setitem(run.__globals__, "subprocess", SimpleNamespace(run=missing))
    with pytest.raises(scope["CheckError"], match="local Docker CLI installation") as error:
        run(Path("customer.env"), Path("compose.yml"), "config")
    assert "private-host-diagnostic" not in str(error.value)


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
    path_value: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, compose_observation,
) -> None:
    scope = compose_observation
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
        "Current Kubernetes development chart: deploy/helm/marty" in deployment_guide
    )
    assert (
        "Legacy Kubernetes manifest script: scripts/deploy-kubernetes.sh" in deployment_guide
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
