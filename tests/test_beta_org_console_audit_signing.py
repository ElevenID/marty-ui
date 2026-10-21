"""D10 adapter contracts. All inputs are generated fixtures; no live KMS is used."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _audit():
    spec = importlib.util.spec_from_file_location("d10_signing_audit", ROOT / "scripts/beta_org_console_audit.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _vectors():
    return json.loads((ROOT / "rust/crates/release-evidence/tests/fixtures/signing-capability-es256.json").read_text())["vectors"]


def _configured_steps(vectors):
    first = vectors[0]["expected"]
    return [{"label": "kms-service-configured", "signing_configuration": {
        "organization_id": first["organization_id"], "run_id": first["run_id"], "default_service_id": first["service_id"],
    }}] + [{"label": label, "issuer_identity": vector["identity_response"]["body"]["identity"]}
           for label, vector in zip(("issuer-identity-active", "verifier-issuer-identity-active"), vectors)]


def _environment(tmp_path):
    token_file = tmp_path / "fixture-token"
    token_file.write_text("synthetic-token-for-input-validation-only\n")
    executable = tmp_path / "validator"
    executable.write_text("fixture placeholder; execution is stubbed by the test")
    return {"DEMO_D10_KMS_URL": "https://kms.internal.company", "DEMO_D10_KMS_MOUNT": "transit",
            "DEMO_D10_KMS_KEY_REFERENCE": "existing-es256", "DEMO_D10_KMS_TOKEN_FILE": str(token_file),
            "DEMO_SIGNING_CAPABILITY_BIN": str(executable)}


def test_missing_real_signing_inputs_stop_before_browser_or_setup(monkeypatch, capsys):
    audit = _audit()
    monkeypatch.setattr(audit, "load_env_file", lambda _path: {})
    monkeypatch.setattr(audit, "sync_playwright", lambda: pytest.fail("browser must not start"))
    monkeypatch.setattr(audit.sys, "argv", ["beta_org_console_audit.py", "--record-video"])
    monkeypatch.setenv("TEST_VENDOR_EMAIL", "operator@unit.invalid")
    monkeypatch.setenv("TEST_VENDOR_PASSWORD", "synthetic-browser-password")
    for name in ["DEMO_D10_KMS_URL", "DEMO_D10_KMS_MOUNT", "DEMO_D10_KMS_KEY_REFERENCE",
                 "DEMO_D10_KMS_TOKEN_FILE", "DEMO_SIGNING_CAPABILITY_BIN"]:
        monkeypatch.delenv(name, raising=False)
    assert audit.main() == 2
    assert "no placeholder signer is permitted" in capsys.readouterr().err


@pytest.mark.parametrize("endpoint", ["https://kms.audit.invalid/transit", "http://kms.internal.company",
                                     "https://user:password@kms.internal.company", "https://kms.internal.company/v1/transit",
                                     "https://example.com"])
def test_rejects_placeholder_or_credential_bearing_transit_origins(tmp_path, endpoint):
    audit = _audit()
    environment = _environment(tmp_path)
    environment["DEMO_D10_KMS_URL"] = endpoint
    with pytest.raises(ValueError, match="real HTTPS OpenBao origin"):
        audit.load_signing_inputs(environment)


def test_preflight_reads_token_file_without_passing_secret_to_validator(monkeypatch, tmp_path):
    audit = _audit()
    calls = []
    environment = _environment(tmp_path)
    monkeypatch.setattr(audit.subprocess, "run", lambda args, **_kwargs: (
        calls.append(args) or SimpleNamespace(returncode=0, stdout=audit.SIGNING_CAPABILITY_SCHEMA + "\n")))
    inputs = audit.load_signing_inputs(environment)
    assert inputs["token"] == "synthetic-token-for-input-validation-only"
    assert inputs["validator_sha256"] == hashlib.sha256(Path(inputs["validator"]).read_bytes()).hexdigest()
    assert calls == [[str(Path(environment["DEMO_SIGNING_CAPABILITY_BIN"]).resolve()), "--version"]]
    assert inputs["token"] not in audit.redact_sensitive(json.dumps({"provider_error": inputs["token"]}))
    Path(environment["DEMO_D10_KMS_TOKEN_FILE"]).write_bytes(b"x" * 4097)
    with pytest.raises(ValueError, match="bounded readable token file"):
        audit.load_signing_inputs(environment)


def test_signer_setup_is_bound_to_the_new_active_organization(monkeypatch):
    audit = _audit()
    monkeypatch.setattr(audit, "active_organization_id", lambda _page: "new-org")
    before = {"/v1/organizations/mine": {"status": 200, "body": [{"id": "old-org", "slug": "old"}]}}
    after = {"/v1/organizations/mine": {"status": 200, "body": [{"id": "new-org", "slug": "new-run"}]}}
    assert audit.require_created_organization(object(), "new-run", before, after) == "new-org"
    for old, new, slug in [(after, after, "new-run"), (before, after, None), (before, after, "wrong-run"),
                           (before, {"/v1/organizations/mine": {"status": 503}}, "new-run")]:
        with pytest.raises(ValueError, match="organization"):
            audit.require_created_organization(object(), slug, old, new)


def test_registration_requires_masked_transit_token_before_fill(monkeypatch):
    audit = _audit()
    monkeypatch.setattr(audit, "active_organization_id", lambda _page: "new-org")
    field = SimpleNamespace(get_attribute=lambda _name: "text")
    field.first = field
    fake = SimpleNamespace(page=SimpleNamespace(get_by_label=lambda *_args: field), goto=lambda *_args: None,
                           snapshot=lambda *_args: None, click_role=lambda *_args, **_kwargs: True,
                           fill_label=lambda *_args: pytest.fail("must not fill an unmasked token"))
    with pytest.raises(ValueError, match="mask its value"):
        audit.create_key_service_if_possible(fake, "fixture-run", {
            "endpoint": "https://kms.internal.company", "mount": "transit", "namespace": "",
            "token": "synthetic-token-not-entered", "key_reference": "fixture-key",
        })


def test_signing_adapter_preserves_authenticated_public_scope():
    audit = _audit()
    captured = {}
    def evaluate(script, args):
        captured.update(script=script, args=args)
        return {"status": 403, "body": {"error": "denied"}}
    response = audit.public_signing_post(SimpleNamespace(evaluate=evaluate), "/v1/signing-keys/config/resolve",
                                         "org/with scope", {"algorithm": "ES256"})
    assert response["status"] == 403
    assert captured["args"] == {"path": "/v1/signing-keys/config/resolve?organization_id=org%2Fwith%20scope",
                                "body": {"algorithm": "ES256"}}
    assert "credentials: 'include'" in captured["script"]


def test_native_validator_bytes_must_match_before_and_after_invocation(monkeypatch, tmp_path):
    audit = _audit()
    executable = tmp_path / "fixture-validator"
    executable.write_bytes(b"original fixture bytes")
    expected = audit.signing_validator_digest(executable)
    calls = []
    def changed_during_run(*_args, **_kwargs):
        calls.append("invoked")
        executable.write_bytes(b"changed fixture bytes")
        return SimpleNamespace(returncode=0, stdout=json.dumps({"schema": audit.SIGNING_CAPABILITY_SCHEMA}))
    monkeypatch.setattr(audit.subprocess, "run", changed_during_run)
    with pytest.raises(ValueError, match="no working-signer claim"):
        audit.native_signing_capability(str(executable), "prepare", {}, expected_binary_sha256="0" * 64)
    assert not calls
    with pytest.raises(ValueError, match="no working-signer claim"):
        audit.native_signing_capability(str(executable), "prepare", {}, expected_binary_sha256=expected)
    assert calls == ["invoked"]


def test_active_rows_alone_and_unbound_receipts_cannot_claim_working_profiles():
    audit = _audit()
    vectors = _vectors()
    report = {"steps": _configured_steps(vectors)}
    assert not audit.signing_capability_proven(report)
    assert not audit.organization_management_behavior_assertions(report)["configure_issuer_profiles"]
    assert "signing_capability_unverified" in {entry["code"] for entry in audit.evaluate_release_checks(report)["blockers"]}


@pytest.mark.skipif(not os.environ.get("DEMO_SIGNING_CAPABILITY_TEST_BIN"), reason="build the native signing CLI for the cross-language fixture test")
def test_public_probe_adapter_uses_real_native_es256_verification_and_rejects_replay(monkeypatch, tmp_path):
    audit = _audit()
    vectors = _vectors()
    expected = vectors[0]["expected"]
    nonces = iter(vector["expected"]["nonce"] for vector in vectors)
    monkeypatch.setattr(audit.secrets, "token_hex", lambda size: next(nonces) if size == 32 else pytest.fail("wrong nonce size"))
    monkeypatch.setattr(audit, "active_organization_id", lambda _page: expected["organization_id"])
    calls = []

    def public_post(_page, endpoint, organization_id, body):
        assert organization_id == expected["organization_id"]
        assert "auth_reference" not in body and "token" not in body
        vector = next(vector for vector in vectors if vector["expected"]["key_purpose"] == body["key_purpose"])
        calls.append(endpoint)
        if endpoint.endswith("config/resolve"):
            return vector["service_response"]
        if endpoint.endswith("issuer-identities/resolve"):
            return vector["identity_response"]
        assert endpoint == f"/v1/signing-keys/services/{expected['service_id']}/sign"
        assert body == audit.native_signing_capability(os.environ["DEMO_SIGNING_CAPABILITY_TEST_BIN"], "prepare", vector)["request"]
        return vector["signing_response"]

    monkeypatch.setattr(audit, "public_signing_post", public_post)
    fake = SimpleNamespace(page=object(), artifact_dir=tmp_path, steps=_configured_steps(vectors))
    fake.snapshot = lambda label, _note, extra: fake.steps.append({"label": label, **extra})
    inputs = {"validator": os.environ["DEMO_SIGNING_CAPABILITY_TEST_BIN"], "key_reference": expected["key_reference"],
              "validator_sha256": audit.signing_validator_digest(os.environ["DEMO_SIGNING_CAPABILITY_TEST_BIN"])}
    audit.verify_issuer_signing_capabilities(fake, expected["run_id"], inputs)
    assert audit.signing_capability_proven({"steps": fake.steps})
    assert len(calls) == 6
    for step in fake.steps[-2:]:
        artifact = tmp_path / step["evidence_artifact"]
        assert hashlib.sha256(artifact.read_bytes()).hexdigest() == step["evidence_sha256"]
        saved = json.loads(artifact.read_text())
        assert saved["validator"]["sha256"] == inputs["validator_sha256"]
        assert saved["validator"]["scope"] == "LOCAL_EXECUTABLE_BYTES_NOT_DEPLOYED_BUILD_ATTESTATION"
        assert audit.native_signing_capability(inputs["validator"], "verify", saved["input"]) == saved["receipt"]
        saved["input"]["expected"]["nonce"] = "ff" * 32
        with pytest.raises(ValueError, match="no working-signer claim"):
            audit.native_signing_capability(inputs["validator"], "verify", saved["input"])

    for field in ("organization_id", "service_id", "issuer_did", "key_purpose", "algorithm", "challenge_sha256"):
        changed = copy.deepcopy(fake.steps)
        changed[-1]["signing_capability"][field] = "wrong"
        assert not audit.signing_capability_proven({"steps": changed})
    changed = copy.deepcopy(fake.steps)
    changed[-1]["signing_capability"]["challenge_sha256"] = changed[-2]["signing_capability"]["challenge_sha256"]
    assert not audit.signing_capability_proven({"steps": changed})

    # A tuple mismatch must fail at native prepare, before the public sign call.
    calls.clear()
    vectors[0]["identity_response"]["body"]["identity"]["algorithm"] = "ES384"
    monkeypatch.setattr(audit.secrets, "token_hex", lambda _size: expected["nonce"])
    fake.steps = _configured_steps(vectors)
    with pytest.raises(ValueError, match="prepare failed"):
        audit.verify_issuer_signing_capabilities(fake, expected["run_id"], inputs)
    assert len(calls) == 2 and not any(path.endswith("/sign") for path in calls)


@pytest.mark.parametrize("ca_path", ["relative/ca.pem", "/run/secrets/ca\nforged", "x" * 4097])
def test_rejects_unusable_beta_server_ca_paths_before_validator_or_mutation(tmp_path, ca_path):
    audit = _audit()
    environment = {**_environment(tmp_path), "DEMO_D10_KMS_CA_CERT_FILE": ca_path}
    with pytest.raises(ValueError, match="mounted on the beta signing server"):
        audit.load_signing_inputs(environment)


def test_explicit_mounted_ca_path_is_preserved_for_real_ui_registration(monkeypatch, tmp_path):
    audit = _audit()
    monkeypatch.setattr(audit.subprocess, "run", lambda *_args, **_kwargs:
                        SimpleNamespace(returncode=0, stdout=audit.SIGNING_CAPABILITY_SCHEMA + "\n"))
    environment = {**_environment(tmp_path), "DEMO_D10_KMS_CA_CERT_FILE": "/run/secrets/customer-ca"}
    assert audit.load_signing_inputs(environment)["ca_cert_file"] == "/run/secrets/customer-ca"
    environment.pop("DEMO_D10_KMS_CA_CERT_FILE")
    assert audit.load_signing_inputs(environment)["ca_cert_file"] == ""
