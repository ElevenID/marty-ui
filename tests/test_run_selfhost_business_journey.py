"""Installed journey status gate refuses incomplete service closure and health."""

import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from run_selfhost_business_journey import (  # noqa: E402
    BETA_SERVICES,
    COMPLETED,
    EXPECTED_SERVICES,
    NOT_LOCAL,
    installed_journey,
    live_services,
    parse_status,
    required_secrets,
    trusted_custody_keys,
    verify_kms_custody,
)


def status_fixture() -> tuple[str, dict]:
    model = {"services": {name: {"healthcheck": {"test": ["CMD", "true"]}}
                          for name in EXPECTED_SERVICES}}
    rows = [{"Service": name, "State": "exited" if name in COMPLETED else "running",
             "ExitCode": 0, "Health": "healthy"}
            for name in sorted(EXPECTED_SERVICES - NOT_LOCAL)]
    return json.dumps(rows), model


def test_exact_local_service_closure_passes_without_tunnel() -> None:
    raw, model = status_fixture()
    states = live_services(raw, model)
    assert set(states) == EXPECTED_SERVICES - BETA_SERVICES - {"cloudflared"}


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
    with pytest.raises(ValueError, match="signed custody evidence is absent"):
        installed_journey(["docker", "compose", "--project-name", "marty-selfhost-qual-1234567890abcdef"],
                          tmp_path, state, model, integration, {}, setup_script,
                          hashlib.sha256(setup_script.read_bytes()).hexdigest(),
                          tmp_path / "custody.json", tmp_path / "custody.sig",
                          tmp_path / "custody.pub", {}, frozenset())
    assert any("pull" in call for call in calls)
    assert any("down" in call for call in calls)
    assert active is False


def test_nonempty_state_refuses_start(monkeypatch, tmp_path: Path) -> None:
    import run_selfhost_business_journey as runner

    (tmp_path / "old-state").write_text("keep", encoding="utf-8")
    monkeypatch.setattr(runner, "command", lambda *_args, **_kwargs: pytest.fail("Docker was touched"))
    with pytest.raises(ValueError, match="fresh empty directory"):
        installed_journey(["docker", "compose"], tmp_path, tmp_path, {}, tmp_path, {},
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


def test_required_secrets_rejects_placeholder(monkeypatch, tmp_path: Path) -> None:
    import run_selfhost_business_journey as runner

    monkeypatch.setattr(runner, "EXPECTED_SECRET_NAMES", frozenset({"issuer_token"}))
    (tmp_path / "issuer_token").write_text("change-me-later", encoding="utf-8")
    with pytest.raises(ValueError, match="placeholder: issuer_token"):
        required_secrets(tmp_path)
