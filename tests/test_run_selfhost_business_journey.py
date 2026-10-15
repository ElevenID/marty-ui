"""Installed journey status gate refuses incomplete service closure and health."""

import hashlib
import json
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

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
    parse_status,
    required_secrets,
    source_bound_fixture,
    trusted_custody_keys,
    verify_kms_custody,
)
from selfhost_journey_diagnostics import RunDiagnostics  # noqa: E402


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


def test_missing_custody_proof_tears_down_owned_project(monkeypatch, tmp_path: Path) -> None:
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
    with pytest.raises(ValueError, match="signed custody evidence is absent"):
        installed_journey(["docker", "compose", "--project-name", "marty-selfhost-qual-1234567890abcdef"],
                          tmp_path, state, tmp_path / "compose.json", tmp_path / "secrets",
                          model, integration, {}, setup_script,
                          hashlib.sha256(setup_script.read_bytes()).hexdigest(),
                          tmp_path / "custody.json", tmp_path / "custody.sig",
                          tmp_path / "custody.pub",
                          {"source_sha": "a" * 40, "archive_sha256": "b" * 64,
                           "image_lock_sha256": "c" * 64}, frozenset(), diagnostics)
    assert any("pull" in call for call in calls)
    assert any("down" in call for call in calls)
    assert active is False
    report = diagnostics.report(result="failed")
    assert report["first_failure_phase"] == "custody_verification"
    assert [row["name"] for row in report["phases"]] == [
        "fresh_project", "image_pull", "startup", "readiness", "fixture_setup",
        "custody_verification", "cleanup",
    ]
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
                          frozenset())


def test_kms_custody_must_bind_installed_profile(monkeypatch, tmp_path: Path) -> None:
    import run_selfhost_business_journey as runner

    evidence = tmp_path / "custody.json"
    signature = tmp_path / "custody.sig"
    public_key = tmp_path / "custody.pub"
    signature.write_text("signature", encoding="utf-8")
    public_key.write_text("public key", encoding="utf-8")
    trusted_keys = frozenset({hashlib.sha256(public_key.read_bytes()).hexdigest()})
    preflight = {"source_sha": "a" * 40, "archive_sha256": "b" * 64,
                 "image_lock_sha256": "c" * 64}
    environment = {"SELFHOST_ORG_ID": "org", "SELFHOST_ISSUER_DID": "did:example:issuer",
                   "SELFHOST_VERIFIER_DID": "did:example:verifier"}
    document = {"schema": "marty.selfhost-kms-custody/v1", **preflight,
                "organization_id": "org", "issuer_did": "did:example:wrong",
                "verifier_did": "did:example:verifier",
                "issuer_key_non_exportable": True, "verifier_key_non_exportable": True}
    evidence.write_text(json.dumps(document), encoding="utf-8")
    monkeypatch.setattr(runner, "command", lambda *_args, **_kwargs: pytest.fail("cosign was called"))
    with pytest.raises(ValueError, match="does not bind installed fixture"):
        verify_kms_custody(evidence, signature, public_key, preflight, environment,
                           trusted_keys)


def test_unapproved_custody_signer_fails_before_signature_check(monkeypatch,
                                                                tmp_path: Path) -> None:
    import run_selfhost_business_journey as runner

    evidence = tmp_path / "evidence.json"
    signature = tmp_path / "evidence.sig"
    public_key = tmp_path / "attacker.pub"
    for path in (evidence, signature, public_key):
        path.write_text("attacker", encoding="utf-8")
    monkeypatch.setattr(runner, "command", lambda *_args, **_kwargs: pytest.fail("cosign was called"))
    with pytest.raises(ValueError, match="signer is not approved"):
        verify_kms_custody(evidence, signature, public_key, {}, {},
                           frozenset({"a" * 64}))


def test_source_policy_with_no_approved_keys_fails_closed(monkeypatch,
                                                         tmp_path: Path) -> None:
    import run_selfhost_business_journey as runner

    policy = {"schema": "marty.selfhost-kms-custody-trust-roots/v1",
              "approved_public_key_sha256": []}
    monkeypatch.setattr(runner, "command", lambda *_args, **_kwargs: json.dumps(policy))
    with pytest.raises(ValueError, match="signer is not approved"):
        trusted_custody_keys(tmp_path, "a" * 40)


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


def test_source_approved_ed25519_signature_binds_custody_bytes(tmp_path: Path) -> None:
    if shutil.which("openssl") is None:
        pytest.skip("OpenSSL is unavailable")
    private = tmp_path / "short-lived.key"
    public = tmp_path / "short-lived.pub"
    evidence = tmp_path / "evidence.json"
    signature = tmp_path / "evidence.sig"
    subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private)],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)],
                   check=True, capture_output=True)
    preflight = {"source_sha": "a" * 40, "archive_sha256": "b" * 64,
                 "image_lock_sha256": "c" * 64}
    environment = {"SELFHOST_ORG_ID": "org", "SELFHOST_ISSUER_DID": "did:example:issuer",
                   "SELFHOST_VERIFIER_DID": "did:example:verifier"}
    document = {"schema": "marty.selfhost-kms-custody/v1", **preflight,
                "organization_id": "org", "issuer_did": "did:example:issuer",
                "verifier_did": "did:example:verifier",
                "issuer_key_non_exportable": True, "verifier_key_non_exportable": True,
                "profile_proofs": custody_profile_proofs(environment)}
    evidence.write_text(json.dumps(document), encoding="utf-8")
    subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(private),
                    "-in", str(evidence), "-out", str(signature)],
                   check=True, capture_output=True)
    approved = frozenset({hashlib.sha256(public.read_bytes()).hexdigest()})
    assert verify_kms_custody(evidence, signature, public, preflight,
                              environment, approved) == hashlib.sha256(evidence.read_bytes()).hexdigest()
    changed = json.loads(json.dumps(document))
    changed["profile_proofs"][0]["key_version"] = 2
    evidence.write_text(json.dumps(changed), encoding="utf-8")
    with pytest.raises(ValueError, match="installed journey command returned failure"):
        verify_kms_custody(evidence, signature, public, preflight, environment, approved)


def custody_profile_proofs(environment: dict[str, str]) -> list[dict]:
    proofs = []
    for did, purpose, prefix in (
        (environment["SELFHOST_ISSUER_DID"], "vc_jwt_issuer", "cred-issuer-"),
        (environment["SELFHOST_VERIFIER_DID"], "oid4vp_request_signing", "oid4vp-verifier-"),
    ):
        tuple_value = f'{environment["SELFHOST_ORG_ID"]}|{did}|{purpose}|SD_JWT_VC|ES256'
        proofs.append({
            "profile_selector": {"issuer_did": did, "key_purpose": purpose,
                                 "credential_format": "SD_JWT_VC", "algorithm": "ES256"},
            "key_reference": f"{prefix}{uuid.uuid5(uuid.NAMESPACE_URL, tuple_value).hex[:20]}-es256",
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
    trusted_keys = frozenset({hashlib.sha256(public_key.read_bytes()).hexdigest()})
    preflight = {"source_sha": "a" * 40, "archive_sha256": "b" * 64,
                 "image_lock_sha256": "c" * 64}
    environment = {"SELFHOST_ORG_ID": "org", "SELFHOST_ISSUER_DID": "did:example:issuer",
                   "SELFHOST_VERIFIER_DID": "did:example:verifier"}
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
                "organization_id": "org", "issuer_did": environment["SELFHOST_ISSUER_DID"],
                "verifier_did": environment["SELFHOST_VERIFIER_DID"],
                "issuer_key_non_exportable": True, "verifier_key_non_exportable": True,
                "profile_proofs": proofs}
    evidence.write_text(json.dumps(document), encoding="utf-8")
    monkeypatch.setattr(runner, "command", lambda *_args, **_kwargs: pytest.fail("signature check was called"))
    with pytest.raises(ValueError, match="signed KMS custody profile proof"):
        verify_kms_custody(evidence, signature, public_key, preflight, environment,
                           trusted_keys)
