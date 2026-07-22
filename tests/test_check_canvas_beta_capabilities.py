from __future__ import annotations

import json

import pytest

from scripts import check_canvas_beta_capabilities as capabilities


def _environment() -> dict[str, str]:
    return {
        "CANVAS_PORTABLE_INTEGRATION_ENABLED": "true",
        "CANVAS_PILOT_ORGANIZATION_IDS": "org-pilot",
        "CANVAS_LTI_EXPERIENCE_BASE_URL": "https://beta.elevenidllc.com",
        "CANVAS_OAUTH_COMPLETION_REDIRECT_URL": "https://beta.elevenidllc.com/console/org/deploy/canvas",
        "CANVAS_SELF_MANAGED_ORIGIN_ALLOWLIST": "https://canvas-test.elevenidllc.com",
        "CANVAS_LEGACY_EVENT_INGEST_ENABLED": "false",
        "CANVAS_ALLOW_PRIVATE_BASE_URLS": "false",
        "CANVAS_ALLOW_HTTP_LOCALHOST_BASE_URLS": "false",
        "CANVAS_BINDING_READINESS_MAX_AGE_SECONDS": "900",
        "CANVAS_ISSUANCE_EVIDENCE_MAX_AGE_SECONDS": "900",
        "CANVAS_LTI_TOOL_SIGNING_ORGANIZATION_ID": "org-signing-system",
        "CANVAS_LTI_TOOL_ISSUER_PROFILE_ID": "ip-marty-canvas-lti-tool",
        "CANVAS_LTI_TOOL_ISSUER_DID": "did:web:beta.elevenidllc.com:orgs:marty",
        "CANVAS_CREDENTIAL_ISSUER_PROFILE_IDS": "ip-marty-vc-jwt-issuer",
        "CANVAS_LTI_TOOL_ACTIVE_KID": "did:web:beta.elevenidllc.com:orgs:marty#lti-tool-marty-rs256",
        "CANVAS_LTI_TOOL_PUBLIC_JWKS": json.dumps(
            {
                "keys": [
                    {
                        "kty": "RSA",
                        "kid": "did:web:beta.elevenidllc.com:orgs:marty#lti-tool-marty-rs256",
                        "alg": "RS256",
                        "use": "sig",
                        "n": "public-modulus",
                        "e": "AQAB",
                    }
                ]
            }
        ),
        "CANVAS_SYNC_PROCESSOR": "issuance.infrastructure.api.canvas_routes:process_authoritative_canvas_sync_target",
        "CANVAS_SYNC_WORKER_JOB_TIMEOUT_SECONDS": "600",
    }


def _install_runtime(monkeypatch: pytest.MonkeyPatch, issuance: dict[str, str], worker: dict[str, str] | None = None) -> None:
    worker = dict(issuance if worker is None else worker)
    monkeypatch.setattr(
        capabilities,
        "_container",
        lambda name: (
            dict(issuance if name == capabilities.ISSUANCE_CONTAINER else worker),
            "sha256:" + "a" * 64,
            "elevenid-local/issuance:test",
        ),
    )
    configured = json.loads(issuance["CANVAS_LTI_TOOL_PUBLIC_JWKS"])["keys"][0]
    monkeypatch.setattr(capabilities, "_public_jwks", lambda: {configured["kid"]: configured})


def test_beta_capability_preflight_proves_deployed_runtime_without_secret_output(monkeypatch: pytest.MonkeyPatch) -> None:
    env = _environment()
    _install_runtime(monkeypatch, env)
    report = capabilities.validate("org-pilot")
    serialized = json.dumps(report)
    assert report["checks"]["issuer_profile_did_rs256_signer"] is True
    assert report["checks"]["readiness_and_evidence_ttls_fail_closed"] is True
    assert report["checks"]["worker_job_deadline_fail_closed"] is True
    assert report["composite_binding_readiness_required"] is True
    assert "public-modulus" not in serialized
    assert "org-signing-system" not in serialized


def test_beta_capability_preflight_rejects_job_only_feature_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    env = _environment()
    env["CANVAS_PORTABLE_INTEGRATION_ENABLED"] = "false"
    _install_runtime(monkeypatch, env)
    with pytest.raises(capabilities.CapabilityError, match="not enabled in deployed beta issuance"):
        capabilities.validate("org-pilot")


@pytest.mark.parametrize(
    ("setting", "value", "message"),
    [
        ("CANVAS_BINDING_READINESS_MAX_AGE_SECONDS", "901", "readiness/KMS challenge TTL"),
        ("CANVAS_ISSUANCE_EVIDENCE_MAX_AGE_SECONDS", "", "issuance evidence TTL"),
        ("CANVAS_SYNC_WORKER_JOB_TIMEOUT_SECONDS", "601", "absolute job deadline"),
    ],
)
def test_beta_capability_preflight_requires_pilot_ttls(
    monkeypatch: pytest.MonkeyPatch,
    setting: str,
    value: str,
    message: str,
) -> None:
    env = _environment()
    env[setting] = value
    _install_runtime(monkeypatch, env)
    with pytest.raises(capabilities.CapabilityError, match=message):
        capabilities.validate("org-pilot")


def test_beta_capability_preflight_rejects_lti_credential_profile_overlap(monkeypatch: pytest.MonkeyPatch) -> None:
    env = _environment()
    env["CANVAS_CREDENTIAL_ISSUER_PROFILE_IDS"] = env["CANVAS_LTI_TOOL_ISSUER_PROFILE_ID"]
    _install_runtime(monkeypatch, env)
    with pytest.raises(capabilities.CapabilityError, match="overlaps a credential issuer profile"):
        capabilities.validate("org-pilot")
