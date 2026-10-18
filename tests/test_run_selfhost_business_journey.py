"""Installed journey status gate refuses incomplete service closure and health."""

import base64
import hashlib
from io import BytesIO
import json
import shutil
import subprocess
import sys
import uuid
from pathlib import Path
from types import SimpleNamespace
from urllib.error import HTTPError
from urllib.parse import parse_qs

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import run_selfhost_business_journey as runner  # noqa: E402
from run_selfhost_business_journey import (  # noqa: E402
    BETA_SERVICES,
    COMPLETED,
    LOCAL_SECRET_NAMES,
    LOCAL_SERVICES,
    OPTIONAL_LOCAL_SECRET_NAMES,
    EXPECTED_SERVICES,
    NOT_LOCAL,
    build_public_kms_jwk_tool,
    installed_journey,
    live_services,
    live_custody_signer,
    parse_status,
    required_secrets,
    source_bound_fixture,
    verify_kms_custody,
)
from selfhost_journey_diagnostics import RunDiagnostics  # noqa: E402
from selfhost_managed_reference import managed_reference  # noqa: E402


def test_invalid_operator_password_aborts_before_compose_build_or_startup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    realm = source / "config/keycloak/11id-realm.json"
    realm.parent.mkdir(parents=True)
    realm.write_text((Path(__file__).resolve().parents[1] / "config/keycloak/11id-realm.json").read_text())
    env_file = tmp_path / "operator.env"
    env_file.write_text("PUBLIC_DOMAIN=localhost\n")
    paths = {name: tmp_path / name for name in (
        "archive", "image_lock", "transaction", "receipt", "descriptor", "install_root",
        "state_root", "secret_root", "integration_checkout", "openbao_state_root",
        "kms_custody_evidence", "kms_custody_signature", "kms_custody_public_key",
    )}
    args = SimpleNamespace(**paths, env_file=env_file, source_checkout=source,
                           project_name="marty-selfhost-qual-" + "a" * 16,
                           fixture_setup=source / runner.FIXTURE_PATH,
                           fixture_setup_sha256="f" * 64, source_sha="a" * 40,
                           integration_sha="b" * 40)
    for name in runner.JOURNEY_INPUTS:
        monkeypatch.setenv(name, "present")
    password = "Upperlower123"
    monkeypatch.setenv("SELFHOST_TEST_PASSWORD", password)
    monkeypatch.setattr(runner.sys, "platform", "linux")
    monkeypatch.setattr(runner, "fixture_setup", lambda *args: None)
    monkeypatch.setattr(runner, "source_bound_fixture", lambda *args: None)
    monkeypatch.setattr(runner, "pinned_integration_checkout", lambda *args: None)
    observed = []
    def command(argv, **kwargs):
        observed.append(argv)
        assert argv == ["git", "rev-parse", "HEAD^{commit}"]
        return args.source_sha
    monkeypatch.setattr(runner, "command", command)
    def premature(*args, **kwargs):
        pytest.fail("invalid operator password reached later install work")
    monkeypatch.setattr(runner, "check", premature)
    monkeypatch.setattr(runner, "build_public_kms_jwk_tool", premature)
    monkeypatch.setattr(runner, "installed_journey", premature)
    with pytest.raises(ValueError, match="shipped realm policy") as caught:
        runner.run(args)
    assert password not in str(caught.value)
    assert observed == [["git", "rev-parse", "HEAD^{commit}"]]


def test_fresh_openbao_instances_enroll_distinct_custody_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    install = tmp_path / "install"
    install.mkdir()
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    audit_token = tmp_path / "audit.token"
    audit_token.write_text("audit", encoding="ascii")
    owned = []
    monkeypatch.setattr(runner, "exact_images", lambda _root: ("services", "pinned-openbao"))
    monkeypatch.setattr(runner, "openbao_network", lambda project, state, image,
                        **kwargs: owned.append((project, state, image, kwargs)) or "private")
    monkeypatch.setattr(runner, "custody_signer_public", lambda metadata:
                        (1, metadata["keys"]["1"]["public_key"]))

    class FakeBao:
        excess_capability = False

        def __init__(self, endpoint: str, ca: Path, token: str) -> None:
            assert token == "audit"
            assert ca == secrets / "openbao_tls_ca_cert"
            if ca.read_text(encoding="ascii") == "substituted":
                raise ValueError("invalid installed CA")
            self.ca = ca

        def request(self, method: str, path: str, body: dict | None = None) -> dict:
            if path == "auth/token/lookup-self":
                return {"data": {"policies": ["selfhost-qualification-audit"],
                                 "ttl": 900}}
            if path == "sys/capabilities-self":
                assert method == "POST" and body is not None
                paths = body["paths"]
                assert paths[0] == f"transit/keys/{runner.CUSTODY_SIGNER}"
                result = {item: ["deny"] for item in paths[1:]}
                result[paths[0]] = ["read"]
                if self.excess_capability:
                    result[f"transit/sign/{runner.CUSTODY_SIGNER}"] = ["update"]
                return result
            if path == f"transit/keys/{runner.CUSTODY_SIGNER}":
                return {"data": {"keys": {"1": {"public_key": self.ca.read_text(
                    encoding="ascii")}}}}
            raise HTTPError("https://127.0.0.1", 403, "denied", {}, None)

    monkeypatch.setattr(runner, "Bao", FakeBao)
    model = {"services": {"signing-keys": {"environment": {
        "BAO_ADDR": "https://host.docker.internal:18200"}}}}
    observed = []
    for suffix in ("a", "b"):
        state = tmp_path / f"state-{suffix}"
        (state / "tls").mkdir(parents=True)
        (state / "tls" / "ca.crt").write_text(f"pem-{suffix}", encoding="ascii")
        (secrets / "openbao_tls_ca_cert").write_text(f"pem-{suffix}", encoding="ascii")
        (state / "tls").chmod(0o000)  # The real Raft state is root-only.
        try:
            observed.append(live_custody_signer(install, state, secrets,
                                                f"openbao-{suffix}", model, {
                "SELFHOST_BAO_AUDIT_URL": "https://127.0.0.1:18200",
                "SELFHOST_BAO_AUDIT_TOKEN_FILE": str(audit_token),
            }))
        finally:
            (state / "tls").chmod(0o700)
    assert observed == [(1, "pem-a"), (1, "pem-b")]
    assert [entry[3] for entry in owned] == [
        {"expected_host_port": 18200}, {"expected_host_port": 18200}]
    FakeBao.excess_capability = True
    with pytest.raises(ValueError, match="excess effective capabilities"):
        live_custody_signer(install, state, secrets, "openbao-b", model, {
            "SELFHOST_BAO_AUDIT_URL": "https://127.0.0.1:18200",
            "SELFHOST_BAO_AUDIT_TOKEN_FILE": str(audit_token),
        })
    FakeBao.excess_capability = False
    (secrets / "openbao_tls_ca_cert").write_text("substituted", encoding="ascii")
    with pytest.raises(ValueError, match="installed CA"):
        live_custody_signer(install, state, secrets, "openbao-b", model, {
            "SELFHOST_BAO_AUDIT_URL": "https://127.0.0.1:18200",
            "SELFHOST_BAO_AUDIT_TOKEN_FILE": str(audit_token),
        })
    (secrets / "openbao_tls_ca_cert").write_text("pem-b", encoding="ascii")
    model["services"]["signing-keys"]["environment"]["BAO_ADDR"] = (
        "https://host.docker.internal:18201")
    with pytest.raises(ValueError, match="different OpenBao port"):
        live_custody_signer(install, state, secrets, "openbao-b", model, {
            "SELFHOST_BAO_AUDIT_URL": "https://127.0.0.1:18200",
            "SELFHOST_BAO_AUDIT_TOKEN_FILE": str(audit_token),
        })
    model["services"]["signing-keys"]["environment"]["BAO_ADDR"] = (
        "https://host.docker.internal:18200")

    def wrong_owner(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("OpenBao container does not own the selected state root")

    monkeypatch.setattr(runner, "openbao_network", wrong_owner)
    with pytest.raises(RuntimeError, match="does not own"):
        live_custody_signer(install, state, secrets, "openbao-b", model, {
            "SELFHOST_BAO_AUDIT_URL": "https://127.0.0.1:18200",
            "SELFHOST_BAO_AUDIT_TOKEN_FILE": str(audit_token),
        })


def test_installed_keycloak_custody_uses_release_sql_and_owned_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    sql_path = source / "scripts/sql/keycloak-kms-only-verify.sql"
    sql_path.parent.mkdir(parents=True)
    # A local replacement with the expected markers must never be executed.
    sql_path.write_text("-- Read-only release check\nBEGIN READ ONLY;\nCOMMIT;\n",
                        encoding="utf-8")
    reviewed_sql = "-- Read-only release check\nBEGIN READ ONLY;\nSELECT 1;\nCOMMIT;\n"
    source_sha = "a" * 40
    observed: list[tuple[list[str], dict[str, object]]] = []

    def fake_command(argv: list[str], **kwargs: object) -> str:
        observed.append((argv, kwargs))
        if argv[:2] == ["git", "show"]:
            return reviewed_sql
        return ""

    monkeypatch.setattr(runner, "command", fake_command)
    compose = ["docker", "compose", "--project-name", "marty-selfhost-qual-1234567890abcdef"]
    environment = {"DOCKER_CONFIG": str(tmp_path / "anonymous")}
    runner.verify_keycloak_database_custody(compose, tmp_path, source,
                                            source_sha, environment)
    assert len(observed) == 2
    assert observed[0][0] == ["git", "show", f"{source_sha}:{runner.KEYCLOAK_SQL_PATH}"]
    assert observed[0][1]["cwd"] == source
    argv, kwargs = observed[1]
    assert argv[:len(compose)] == compose
    assert argv[len(compose):] == ["exec", "-T", "postgres", "psql", "-X", "-q",
                                  "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "keycloak"]
    assert kwargs["cwd"] == tmp_path
    assert kwargs["env"] == environment
    assert kwargs["input_text"] == reviewed_sql

    with pytest.raises(ValueError, match="custody source is invalid"):
        runner.verify_keycloak_database_custody(compose, tmp_path, source,
                                                "main", environment)
    assert len(observed) == 2

    def missing_reviewed_sql(argv: list[str], **_kwargs: object) -> str:
        if argv[:2] == ["git", "show"]:
            raise ValueError("installed journey command returned failure")
        pytest.fail("database command ran without reviewed SQL")

    monkeypatch.setattr(runner, "command", missing_reviewed_sql)
    with pytest.raises(ValueError, match="installed journey command returned failure"):
        runner.verify_keycloak_database_custody(compose, tmp_path, source,
                                                source_sha, environment)


def test_installed_keycloak_probe_issues_and_refreshes_both_realms(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "keycloak_admin_password").write_text("admin-secret\n", encoding="utf-8")
    requests: list[tuple[str, dict[str, str]]] = []

    class Opener:
        def open(self, request, *, timeout: int):
            assert timeout == 20
            fields = {key: values[0] for key, values in
                      parse_qs(request.data.decode("ascii")).items()}
            requests.append((request.full_url, fields))
            return BytesIO(json.dumps({"token_type": "Bearer",
                                       "access_token": "access",
                                       "refresh_token": "refresh"}).encode("utf-8"))

    monkeypatch.setattr(runner, "build_opener", lambda *_args: Opener())
    runner.exercise_installed_keycloak_keys(
        {"SELFHOST_KEYCLOAK_URL": "http://127.0.0.1:18080",
         "SELFHOST_TEST_USERNAME": "operator@selfhost.marty.invalid",
         "SELFHOST_TEST_PASSWORD": "operator-secret"}, tmp_path)
    assert [(url.split("/realms/")[1].split("/")[0], fields["grant_type"])
            for url, fields in requests] == [
                ("master", "password"), ("master", "refresh_token"),
                ("11id", "password"), ("11id", "refresh_token")]
    assert requests[0][1]["username"] == "admin"
    assert requests[2][1]["username"] == "operator@selfhost.marty.invalid"
    assert all(fields["client_id"] == "admin-cli" for _, fields in requests)


def test_installed_keycloak_probe_fails_closed_without_leaking_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "keycloak_admin_password").write_text("admin-secret", encoding="utf-8")

    class Opener:
        def open(self, _request, *, timeout: int):
            raise RuntimeError("admin-secret operator-secret")

    monkeypatch.setattr(runner, "build_opener", lambda *_args: Opener())
    environment = {"SELFHOST_KEYCLOAK_URL": "http://localhost:18080",
                   "SELFHOST_TEST_USERNAME": "operator@selfhost.marty.invalid",
                   "SELFHOST_TEST_PASSWORD": "operator-secret"}
    with pytest.raises(ValueError, match="installed Keycloak token use failed") as error:
        runner.exercise_installed_keycloak_keys(environment, tmp_path)
    assert "admin-secret" not in str(error.value)
    assert "operator-secret" not in str(error.value)
    with pytest.raises(ValueError, match="disposable loopback"):
        runner.exercise_installed_keycloak_keys(
            {**environment, "SELFHOST_KEYCLOAK_URL": "https://external.example"}, tmp_path)


def test_installed_marty_custody_scans_schema_and_written_content(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[tuple[list[str], dict[str, object]]] = []

    def fake_command(argv: list[str], **kwargs: object) -> str:
        observed.append((argv, kwargs))
        return ""

    monkeypatch.setattr(runner, "command", fake_command)
    compose = ["docker", "compose", "--project-name", "marty-selfhost-qual-1234567890abcdef"]
    runner.verify_marty_database_custody(compose, tmp_path, {})
    assert len(observed) == 2
    assert all(argv[:len(compose)] == compose for argv, _ in observed)
    assert all(argv[-3:-1] == ["-d", "marty"] for argv, _ in observed)
    assert [argv[-1] for argv, _ in observed] == ["-At", "-q"]
    assert observed[0][1]["input_text"] == runner.PRIVATE_KEY_SCHEMA_QUERY
    assert observed[1][1]["input_text"] == runner.PRIVATE_KEY_CONTENT_QUERY

    def dirty_schema(*_args: object, **_kwargs: object) -> str:
        return "table:public.private_key_cache"

    monkeypatch.setattr(runner, "command", dirty_schema)
    with pytest.raises(ValueError, match="private-key schema"):
        runner.verify_marty_database_custody(compose, tmp_path, {})


def test_rust_public_key_converter_uses_clean_source_and_fresh_build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    target = tmp_path / "target"
    target.mkdir()
    calls: list[list[str]] = []

    def run(args: list[str], **kwargs: object) -> str:
        calls.append(args)
        if args[:2] == ["git", "status"]:
            return ""
        assert args[:3] == ["cargo", "build", "--locked"]
        assert kwargs["env"]["CARGO_TARGET_DIR"] == str(target / "target")
        assert kwargs["env"]["CARGO_HOME"] == str(target / "cargo-home")
        assert "SELFHOST_TEST_PASSWORD" not in kwargs["env"]
        assert "RUSTFLAGS" not in kwargs["env"]
        assert "RUSTC_WRAPPER" not in kwargs["env"]
        assert "RUSTC" not in kwargs["env"]
        output = target / "target" / "debug"
        output.mkdir(parents=True)
        (output / "public-kms-jwk").write_bytes(b"synthetic executable")
        return ""

    monkeypatch.setenv("SELFHOST_TEST_PASSWORD", "private")
    monkeypatch.setenv("RUSTFLAGS", "--cfg altered")
    monkeypatch.setenv("RUSTC_WRAPPER", "other-compiler")
    monkeypatch.setenv("RUSTC", "other-rustc")
    monkeypatch.setattr("run_selfhost_business_journey.command", run)
    assert build_public_kms_jwk_tool(source, target) == target / "target" / "debug" / "public-kms-jwk"
    assert len(calls) == 2
    with pytest.raises(ValueError, match="not fresh"):
        build_public_kms_jwk_tool(source, target)


def test_rust_public_key_converter_rejects_dirty_source_or_missing_build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    target = tmp_path / "target"
    target.mkdir()
    monkeypatch.setattr("run_selfhost_business_journey.command", lambda *_args, **_kwargs: " M rust/Cargo.lock")
    with pytest.raises(ValueError, match="local changes"):
        build_public_kms_jwk_tool(source, target)
    monkeypatch.setattr("run_selfhost_business_journey.command", lambda *_args, **_kwargs: "")
    with pytest.raises(ValueError, match="converter is absent"):
        build_public_kms_jwk_tool(source, target)


def status_fixture() -> tuple[str, dict]:
    model = {"services": {name: {"healthcheck": {"test": ["CMD", "true"]}}
                          for name in EXPECTED_SERVICES}}
    rows = [{"Service": name, "State": "exited" if name in COMPLETED else "running",
             "ExitCode": 0, "Health": "healthy"}
            for name in sorted(EXPECTED_SERVICES - NOT_LOCAL)]
    return json.dumps(rows), model


def disabled_optional_model() -> dict:
    _, model = status_fixture()
    model["services"]["keycloak-configurator"]["environment"] = {
        "KEYCLOAK_SOCIAL_LOGIN_ENABLED": "false", "KEYCLOAK_SMTP_USERNAME": "",
    }
    model["services"]["notification"]["environment"] = {"SMTP_USERNAME": ""}
    model["services"]["issuance"]["environment"] = {
        **{name: "false" for name in runner.CANVAS_DISABLED_FLAGS},
        **{name: "" for name in runner.CANVAS_UNUSED_SETTINGS},
    }
    return model


def test_exact_local_service_closure_passes_without_tunnel() -> None:
    raw, model = status_fixture()
    states = live_services(raw, model)
    assert set(states) == EXPECTED_SERVICES - BETA_SERVICES - {"cloudflared"}


def test_explicitly_disabled_worker_healthcheck_does_not_block_closure() -> None:
    raw, model = status_fixture()
    model["services"]["canvas-sync-worker"]["healthcheck"] = {"disable": True}
    rows = json.loads(raw)
    for row in rows:
        if row["Service"] == "canvas-sync-worker":
            row["Health"] = ""
    assert len(live_services(json.dumps(rows), model)) == len(LOCAL_SERVICES)
    model["services"]["canvas-sync-worker"]["healthcheck"] = {
        "test": ["CMD", "true"],
    }
    with pytest.raises(ValueError, match="not healthy: canvas-sync-worker"):
        live_services(json.dumps(rows), model)
    model["services"]["canvas-sync-worker"]["healthcheck"] = "disabled"
    with pytest.raises(ValueError, match="healthcheck model is invalid"):
        live_services(json.dumps(rows), model)


def test_local_secret_closure_excludes_only_unstarted_tunnels(tmp_path: Path) -> None:
    from check_selfhost_installed_runtime_plan import (
        EXPECTED_ROLE_SECRETS, EXPECTED_SECRET_NAMES,
    )

    assert LOCAL_SECRET_NAMES == frozenset(
        secret for service in LOCAL_SERVICES
        for secret in EXPECTED_ROLE_SECRETS.get(service, ())
    )
    assert EXPECTED_SECRET_NAMES - LOCAL_SECRET_NAMES == {
        "cloudflare_tunnel_token", "cloudflare_beta_tunnel_token",
    }
    for name in LOCAL_SECRET_NAMES:
        (tmp_path / name).write_text("disposable-test-material", encoding="utf-8")
    required_secrets(tmp_path)
    (tmp_path / "marty_db_password").unlink()
    with pytest.raises(ValueError, match="missing: marty_db_password"):
        required_secrets(tmp_path)


def test_local_optional_secrets_follow_catalog_without_weakening_required_files(
    tmp_path: Path,
) -> None:
    model = disabled_optional_model()
    assert OPTIONAL_LOCAL_SECRET_NAMES == {
        "canvas_credentials_shared_secret", "google_analytics_measurement_id",
        "google_client_id", "google_client_secret", "google_site_verification",
        "smtp_password",
    }
    for name in LOCAL_SECRET_NAMES:
        (tmp_path / name).write_text(
            "" if name in OPTIONAL_LOCAL_SECRET_NAMES else "disposable-test-material",
            encoding="utf-8",
        )
    required_secrets(tmp_path, model)
    (tmp_path / "marty_db_password").write_text("", encoding="utf-8")
    with pytest.raises(ValueError, match="missing: marty_db_password"):
        required_secrets(tmp_path, model)
    (tmp_path / "marty_db_password").write_text("disposable-test-material", encoding="utf-8")
    (tmp_path / "google_client_id").write_text("change-me-oauth", encoding="utf-8")
    with pytest.raises(ValueError, match="placeholder: google_client_id"):
        required_secrets(tmp_path, model)
    assert runner.disabled_optional_secrets(model) == OPTIONAL_LOCAL_SECRET_NAMES


@pytest.mark.parametrize("service,setting,value,rejected", [
    ("keycloak-configurator", "KEYCLOAK_SOCIAL_LOGIN_ENABLED", "true", "google_client_id"),
    ("keycloak-configurator", "KEYCLOAK_SOCIAL_LOGIN_ENABLED", "unexpected", "google_client_id"),
    ("keycloak-configurator", "KEYCLOAK_SMTP_USERNAME", "sender", "smtp_password"),
    ("notification", "SMTP_USERNAME", "sender", "smtp_password"),
    ("issuance", "CANVAS_PORTABLE_INTEGRATION_ENABLED", "true", "canvas_credentials_shared_secret"),
    ("issuance", "CANVAS_CREDENTIALS_PUBLISH_URL", "https://canvas.test", "canvas_credentials_shared_secret"),
])
def test_empty_secret_requires_disabled_rendered_integration(
    tmp_path: Path, service: str, setting: str, value: str, rejected: str,
) -> None:
    for name in LOCAL_SECRET_NAMES:
        (tmp_path / name).write_text(
            "" if name in OPTIONAL_LOCAL_SECRET_NAMES else "disposable-test-material",
            encoding="utf-8",
        )
    model = disabled_optional_model()
    model["services"][service]["environment"][setting] = value
    with pytest.raises(ValueError, match=f"missing: {rejected}"):
        required_secrets(tmp_path, model)


def test_empty_secret_fails_closed_without_rendered_controls(tmp_path: Path) -> None:
    for name in LOCAL_SECRET_NAMES:
        (tmp_path / name).write_text(
            "" if name in OPTIONAL_LOCAL_SECRET_NAMES else "disposable-test-material",
            encoding="utf-8",
        )
    with pytest.raises(ValueError, match="canvas_credentials_shared_secret"):
        required_secrets(tmp_path)
    model = disabled_optional_model()
    del model["services"]["issuance"]["environment"]["CANVAS_CREDENTIALS_PUBLISH_URL"]
    with pytest.raises(ValueError, match="canvas_credentials_shared_secret"):
        required_secrets(tmp_path, model)


def test_missing_service_and_unhealthy_gateway_fail_closed() -> None:
    raw, model = status_fixture()
    rows = json.loads(raw)
    with pytest.raises(ValueError, match="exact local service closure"):
        live_services(json.dumps(rows[:-1]), model)
    for row in rows:
        if row["Service"] == "gateway":
            row["Health"] = "unhealthy"
    with pytest.raises(ValueError, match="not healthy: gateway"):
        live_services(json.dumps(rows), model)


def test_failed_migration_or_duplicate_service_fails_closed() -> None:
    raw, model = status_fixture()
    rows = json.loads(raw)
    for row in rows:
        if row["Service"] == "db-migrate":
            row["ExitCode"] = 1
    with pytest.raises(ValueError, match="one-shot service did not complete"):
        live_services(json.dumps(rows), model)
    rows[-1] = dict(rows[0])
    with pytest.raises(ValueError, match="duplicate or unnamed"):
        live_services(json.dumps(rows), model)


def test_compose_ndjson_status_is_accepted() -> None:
    raw, _ = status_fixture()
    rows = json.loads(raw)
    assert parse_status("\n".join(json.dumps(row) for row in rows)) == rows


@pytest.mark.parametrize("stale_name", [None, "custody.json", "custody.sig"])
def test_custody_failure_tears_down_owned_project(
    monkeypatch, tmp_path: Path, stale_name: str | None,
) -> None:
    import run_selfhost_business_journey as runner

    raw, model = status_fixture()
    calls = []
    active = False
    setup_script = tmp_path / "setup.py"
    setup_script.write_text("pass\n", encoding="utf-8")
    integration = tmp_path / "integration"
    integration.mkdir()
    state = tmp_path / "state"
    state.mkdir()
    if stale_name is not None:
        (tmp_path / stale_name).write_text("stale", encoding="utf-8")

    def fake_command(argv, **_kwargs):
        nonlocal active
        calls.append(argv)
        if "ps" in argv:
            return raw if active else "[]"
        if "up" in argv:
            active = True
        if "down" in argv:
            active = False
        return ""

    monkeypatch.setattr(runner, "command", fake_command)
    diagnostics = RunDiagnostics(tmp_path)
    monkeypatch.setattr(runner, "live_custody_signer", lambda *_args: (1, "public"))
    error = ("KMS custody output exists before fresh fixture setup" if stale_name
             else "signed custody evidence is absent")
    with pytest.raises(ValueError, match=error):
        installed_journey(["docker", "compose", "--project-name", "marty-selfhost-qual-1234567890abcdef"],
                          tmp_path, state, tmp_path / "compose.json", tmp_path / "secrets",
                          model, integration, {}, setup_script,
                          hashlib.sha256(setup_script.read_bytes()).hexdigest(),
                          tmp_path / "custody.json", tmp_path / "custody.sig",
                          tmp_path / "custody.pub",
                          {"source_sha": "a" * 40, "archive_sha256": "b" * 64,
                           "image_lock_sha256": "c" * 64, "run_id": "123"}, diagnostics,
                          openbao_state_root=state, openbao_project="openbao")
    assert any("pull" in call for call in calls)
    assert any("down" in call for call in calls)
    assert active is False
    report = diagnostics.report(checks_result="failed")
    expected_phase = "fixture_setup" if stale_name else "custody_verification"
    assert report["first_failure_phase"] == expected_phase
    expected_names = ["fresh_project", "image_pull", "startup", "readiness",
                      "fixture_setup"]
    if stale_name is None:
        expected_names.append("custody_verification")
    expected_names.append("cleanup")
    assert [row["name"] for row in report["phases"]] == expected_names
    assert next(row for row in report["phases"] if row["name"] == expected_phase)["status"] == "failed"
    assert report["phases"][-1]["status"] == "passed"


def test_nonempty_state_refuses_start(monkeypatch, tmp_path: Path) -> None:
    import run_selfhost_business_journey as runner

    (tmp_path / "old-state").write_text("keep", encoding="utf-8")
    monkeypatch.setattr(runner, "command", lambda *_args, **_kwargs: pytest.fail("Docker was touched"))
    with pytest.raises(ValueError, match="fresh empty directory"):
        installed_journey(["docker", "compose"], tmp_path, tmp_path,
                          tmp_path / "compose.json", tmp_path / "secrets",
                          {}, tmp_path, {},
                          tmp_path / "setup.py", "0" * 64, tmp_path / "custody.json",
                          tmp_path / "custody.sig", tmp_path / "custody.pub", {},
                          None)


def test_startup_retries_share_one_deadline_and_clean_up(monkeypatch, tmp_path: Path) -> None:
    import run_selfhost_business_journey as runner

    clock = [0.0]
    timeouts = []
    calls = []
    state = tmp_path / "state"
    state.mkdir()
    setup_script = tmp_path / "setup.py"
    setup_script.write_text("pass\n", encoding="utf-8")

    def fake_command(argv, **kwargs):
        calls.append(argv)
        if "ps" in argv:
            return "[]"
        if "up" in argv:
            timeout = kwargs["timeout"]
            timeouts.append(timeout)
            clock[0] += timeout
            raise ValueError("installed journey command returned failure")
        return ""

    monkeypatch.setattr(runner, "command", fake_command)
    monkeypatch.setattr(runner.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(runner.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    with pytest.raises(ValueError, match="installed journey command returned failure"):
        installed_journey(["docker", "compose"], tmp_path, state,
                          tmp_path / "compose.json", tmp_path / "secrets", {},
                          tmp_path, {}, setup_script,
                          hashlib.sha256(setup_script.read_bytes()).hexdigest(),
                          tmp_path / "custody.json", tmp_path / "custody.sig",
                          tmp_path / "custody.pub", {})
    assert timeouts == [240, 240, 100]
    assert clock[0] == 600
    assert any("down" in call for call in calls)


def test_kms_custody_must_bind_installed_profile(monkeypatch, tmp_path: Path) -> None:
    import run_selfhost_business_journey as runner

    evidence = tmp_path / "custody.json"
    signature = tmp_path / "custody.sig"
    public_key = tmp_path / "custody.pub"
    signature.write_text("signature", encoding="utf-8")
    public_key.write_text("public key", encoding="utf-8")
    preflight = {"source_sha": "a" * 40, "archive_sha256": "b" * 64,
                 "image_lock_sha256": "c" * 64, "run_id": "123"}
    environment = {"SELFHOST_ORG_ID": "org", "SELFHOST_ISSUER_DID": "did:example:issuer",
                   "SELFHOST_VERIFIER_DID": "did:example:verifier",
                   "SELFHOST_FIXTURE_SHA256": "f" * 64,
                   "SELFHOST_CUSTODY_CHALLENGE": "d" * 64}
    document = {"schema": "marty.selfhost-kms-custody/v1", **preflight,
                "organization_id": "org", "issuer_did": "did:example:wrong",
                "verifier_did": "did:example:verifier",
                "issuer_key_non_exportable": True, "verifier_key_non_exportable": True}
    evidence.write_text(json.dumps(document), encoding="utf-8")
    monkeypatch.setattr(runner, "command", lambda *_args, **_kwargs: pytest.fail("cosign was called"))
    with pytest.raises(ValueError, match="does not bind installed fixture"):
        verify_kms_custody(evidence, signature, public_key, preflight, environment,
                           (1, "public key"))


def test_unapproved_custody_signer_fails_before_signature_check(monkeypatch,
                                                                tmp_path: Path) -> None:
    import run_selfhost_business_journey as runner

    evidence = tmp_path / "evidence.json"
    signature = tmp_path / "evidence.sig"
    public_key = tmp_path / "attacker.pub"
    for path in (evidence, signature, public_key):
        path.write_text("attacker", encoding="utf-8")
    monkeypatch.setattr(runner, "command", lambda *_args, **_kwargs: pytest.fail("cosign was called"))
    with pytest.raises(ValueError, match="differs from owned OpenBao metadata"):
        verify_kms_custody(evidence, signature, public_key, {}, {},
                           (1, "reviewed public key"))


@pytest.mark.parametrize("changed_field", [
    "source_sha", "archive_sha256", "image_lock_sha256", "run_id",
    "fixture_sha256", "challenge",
])
def test_custody_rejects_replayed_or_changed_release_binding(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, changed_field: str,
) -> None:
    evidence = tmp_path / "custody.json"
    signature = tmp_path / "custody.sig"
    public_key = tmp_path / "custody.pub"
    public_key.write_text("public", encoding="ascii")
    signature.write_bytes(b"signature")
    preflight = {"source_sha": "a" * 40, "archive_sha256": "b" * 64,
                 "image_lock_sha256": "c" * 64, "run_id": "123"}
    environment = {"SELFHOST_ORG_ID": "org",
                   "SELFHOST_ISSUER_DID": "did:example:issuer",
                   "SELFHOST_VERIFIER_DID": "did:example:verifier",
                   "SELFHOST_FIXTURE_SHA256": "f" * 64,
                   "SELFHOST_CUSTODY_CHALLENGE": "d" * 64}
    document = {"schema": "marty.selfhost-kms-custody/v1", **preflight,
                "fixture_sha256": environment["SELFHOST_FIXTURE_SHA256"],
                "challenge": environment["SELFHOST_CUSTODY_CHALLENGE"],
                "organization_id": "org", "issuer_did": environment["SELFHOST_ISSUER_DID"],
                "verifier_did": environment["SELFHOST_VERIFIER_DID"],
                "issuer_key_non_exportable": True, "verifier_key_non_exportable": True,
                "attestation_key_reference": runner.CUSTODY_SIGNER,
                "attestation_key_version": 1, "attestation_key_non_exportable": True,
                "profile_proofs": custody_profile_proofs(environment)}
    document[changed_field] = "previous-run-value"
    evidence.write_text(json.dumps(document), encoding="utf-8")
    monkeypatch.setattr(runner, "command", lambda *_args, **_kwargs:
                        pytest.fail("signature check was reached"))
    with pytest.raises(ValueError, match="does not bind installed fixture"):
        verify_kms_custody(evidence, signature, public_key, preflight, environment,
                           (1, "public"))


@pytest.mark.parametrize("placeholder", [
    "change-me-later", "CHANGE_ME_sign_grant_verify_token",
    "replace-me", "replace_me_token", "placeholder",
])
def test_required_secrets_rejects_placeholder(monkeypatch, tmp_path: Path,
                                              placeholder: str) -> None:
    import run_selfhost_business_journey as runner

    monkeypatch.setattr(runner, "LOCAL_SECRET_NAMES", frozenset({"issuer_token"}))
    (tmp_path / "issuer_token").write_text(placeholder, encoding="utf-8")
    with pytest.raises(ValueError, match="placeholder: issuer_token"):
        required_secrets(tmp_path)


def test_fixture_hook_must_match_prepared_source_commit(monkeypatch,
                                                        tmp_path: Path) -> None:
    import run_selfhost_business_journey as runner

    path = tmp_path / "scripts" / "setup_selfhost_synthetic_fixture.py"
    path.parent.mkdir()
    path.write_bytes(b"print('reviewed')\n")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()

    def git_result(argv, **_kwargs):
        return "" if "status" in argv else "print('reviewed')\n"

    monkeypatch.setattr(runner, "command", git_result)
    source_bound_fixture(path, digest, tmp_path, "a" * 40)
    with pytest.raises(ValueError, match="prepared source commit"):
        source_bound_fixture(path, "b" * 64, tmp_path, "a" * 40)
    with pytest.raises(ValueError, match="reviewed source hook"):
        source_bound_fixture(tmp_path / "other.py", digest, tmp_path, "a" * 40)


def test_frozen_ed25519_signature_oracle_and_live_custody_bytes(tmp_path: Path) -> None:
    if shutil.which("openssl") is None:
        pytest.skip("OpenSSL is unavailable")
    public = tmp_path / "short-lived.pub"
    evidence = tmp_path / "evidence.json"
    signature = tmp_path / "evidence.sig"
    # Public-only fixture signed once by a non-exportable disposable Transit key.
    public.write_bytes(base64.b64decode(
        "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUNvd0JRWURLMlZ3QXlFQVY0UjVEcmNORU9haEwwNDZqZmsv"
        "UVlPK2hENDREQ1ovTE16U0hxY01Jck09Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo="
    ))
    signature.write_bytes(base64.b64decode(
        "27o1srHYD4e0kJ6/nlvdJ45L6c0A3agoJrvwCAfzpK9ooqgIg6eJueJ0uuZbpaHtHqJOOWHSQXjfyowKusjqAA=="
    ))
    preflight = {"source_sha": "a" * 40, "archive_sha256": "b" * 64,
                 "image_lock_sha256": "c" * 64, "run_id": "123"}
    environment = {"SELFHOST_ORG_ID": "org", "SELFHOST_ISSUER_DID": "did:example:issuer",
                   "SELFHOST_VERIFIER_DID": "did:example:verifier",
                   "SELFHOST_FIXTURE_SHA256": "f" * 64,
                   "SELFHOST_CUSTODY_CHALLENGE": "d" * 64}
    # Preserve the original public-only signature oracle byte-for-byte. Its
    # historical tuple reference is never accepted by the current verifier.
    frozen_proofs = custody_profile_proofs(environment)
    for proof, prefix in zip(frozen_proofs, ("cred-issuer-", "oid4vp-verifier-")):
        selector = proof["profile_selector"]
        tuple_value = (f'{environment["SELFHOST_ORG_ID"]}|{selector["issuer_did"]}|'
                       f'{selector["key_purpose"]}|SD_JWT_VC|ES256')
        proof["key_reference"] = (
            f"{prefix}{uuid.uuid5(uuid.NAMESPACE_URL, tuple_value).hex[:20]}-es256"
        )
    frozen_document = {"schema": "marty.selfhost-kms-custody/v1",
                "source_sha": preflight["source_sha"],
                "archive_sha256": preflight["archive_sha256"],
                "image_lock_sha256": preflight["image_lock_sha256"],
                "organization_id": "org", "issuer_did": "did:example:issuer",
                "verifier_did": "did:example:verifier",
                "issuer_key_non_exportable": True, "verifier_key_non_exportable": True,
                "attestation_key_reference": "selfhost-qualification-custody-v1",
                "attestation_key_version": 1, "attestation_key_non_exportable": True,
                "profile_proofs": frozen_proofs}
    evidence.write_bytes((json.dumps(frozen_document, indent=2, sort_keys=True) + "\n")
                         .encode("utf-8"))
    subprocess.run(["openssl", "pkeyutl", "-verify", "-rawin", "-pubin",
                    "-inkey", str(public), "-sigfile", str(signature),
                    "-in", str(evidence)], check=True, capture_output=True)

    # The current runner additionally binds a fresh, unpredictable challenge.
    key = tmp_path / "local-test-key.pem"
    subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(key)],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "pkey", "-in", str(key), "-pubout", "-out", str(public)],
                   check=True, capture_output=True)
    document = {**frozen_document, "profile_proofs": custody_profile_proofs(environment),
                "run_id": preflight["run_id"],
                "fixture_sha256": environment["SELFHOST_FIXTURE_SHA256"],
                "challenge": environment["SELFHOST_CUSTODY_CHALLENGE"]}
    evidence.write_bytes((json.dumps(document, indent=2, sort_keys=True) + "\n")
                         .encode("utf-8"))
    subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(key),
                    "-in", str(evidence), "-out", str(signature)],
                   check=True, capture_output=True)
    assert verify_kms_custody(evidence, signature, public, preflight,
                              environment, (1, public.read_text(encoding="ascii"))) == (
                                  hashlib.sha256(evidence.read_bytes()).hexdigest())
    changed = json.loads(json.dumps(document))
    changed["profile_proofs"][0]["key_version"] = 2
    evidence.write_text(json.dumps(changed), encoding="utf-8")
    with pytest.raises(ValueError, match="installed journey command returned failure"):
        verify_kms_custody(evidence, signature, public, preflight, environment,
                           (1, public.read_text(encoding="ascii")))


def custody_profile_proofs(environment: dict[str, str]) -> list[dict]:
    proofs = []
    for did, purpose in (
        (environment["SELFHOST_ISSUER_DID"], "vc_jwt_issuer"),
        (environment["SELFHOST_VERIFIER_DID"], "oid4vp_request_signing"),
    ):
        proofs.append({
            "profile_selector": {"issuer_did": did, "key_purpose": purpose,
                                 "credential_format": "SD_JWT_VC", "algorithm": "ES256"},
            "key_reference": managed_reference(environment["SELFHOST_ORG_ID"], purpose),
            "key_version": 1,
        })
    return proofs


@pytest.mark.parametrize("mutation", [
    "missing", "duplicate", "extra", "wrong_selector", "wrong_reference",
    "zero_version", "bool_version", "extra_field",
])
def test_custody_rejects_unbound_profile_proofs(monkeypatch, tmp_path: Path,
                                                mutation: str) -> None:
    import run_selfhost_business_journey as runner

    evidence = tmp_path / "custody.json"
    signature = tmp_path / "custody.sig"
    public_key = tmp_path / "custody.pub"
    signature.write_text("signature", encoding="utf-8")
    public_key.write_text("public key", encoding="utf-8")
    preflight = {"source_sha": "a" * 40, "archive_sha256": "b" * 64,
                 "image_lock_sha256": "c" * 64, "run_id": "123"}
    environment = {"SELFHOST_ORG_ID": "org", "SELFHOST_ISSUER_DID": "did:example:issuer",
                   "SELFHOST_VERIFIER_DID": "did:example:verifier",
                   "SELFHOST_FIXTURE_SHA256": "f" * 64,
                   "SELFHOST_CUSTODY_CHALLENGE": "d" * 64}
    proofs = custody_profile_proofs(environment)
    if mutation == "missing":
        proofs = []
    elif mutation == "duplicate":
        proofs[1] = proofs[0]
    elif mutation == "extra":
        proofs.append(proofs[0])
    elif mutation == "wrong_selector":
        proofs[0]["profile_selector"]["issuer_did"] = "did:example:other"
    elif mutation == "wrong_reference":
        proofs[0]["key_reference"] = "cred-issuer-unbound-es256"
    elif mutation == "zero_version":
        proofs[0]["key_version"] = 0
    elif mutation == "bool_version":
        proofs[0]["key_version"] = True
    else:
        proofs[0]["extra"] = "unreviewed"
    document = {"schema": "marty.selfhost-kms-custody/v1", **preflight,
                "fixture_sha256": environment["SELFHOST_FIXTURE_SHA256"],
                "challenge": environment["SELFHOST_CUSTODY_CHALLENGE"],
                "organization_id": "org", "issuer_did": environment["SELFHOST_ISSUER_DID"],
                "verifier_did": environment["SELFHOST_VERIFIER_DID"],
                "issuer_key_non_exportable": True, "verifier_key_non_exportable": True,
                "attestation_key_reference": "selfhost-qualification-custody-v1",
                "attestation_key_version": 1, "attestation_key_non_exportable": True,
                "profile_proofs": proofs}
    evidence.write_text(json.dumps(document), encoding="utf-8")
    monkeypatch.setattr(runner, "command", lambda *_args, **_kwargs: pytest.fail("signature check was called"))
    with pytest.raises(ValueError, match="signed KMS custody profile proof"):
        verify_kms_custody(evidence, signature, public_key, preflight, environment,
                           (1, "public key"))
