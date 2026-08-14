"""Owned regressions for mdoc direct-anchor policy evidence."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from services.presentation_policy import main as pp


ISSUER_CERTIFICATE_SHA256 = "a" * 64
ISSUER_ID = f"x509-sha256:{ISSUER_CERTIFICATE_SHA256}"
ROOT_CERTIFICATE_PEM = (
    "-----BEGIN CERTIFICATE-----\ncm9vdA==\n-----END CERTIFICATE-----\n"
)


def _active_root_profile() -> dict[str, object]:
    return {
        "id": "60000000-0000-0000-0000-000000000001",
        "organization_id": "org-1",
        "status": "active",
        "allowed_issuers": [],
        "denied_issuers": [],
        "issuer_relationships": None,
        "trust_sources": [
            {
                "source_type": "ROOT_CA",
                "certificate_pem": ROOT_CERTIFICATE_PEM,
                "enabled": True,
            }
        ],
    }


def _verified_mdoc_result() -> dict[str, object]:
    return {
        "verified": True,
        "claims": {"email": "member@example.com"},
        "issuer_did": ISSUER_ID,
        "format": "mdoc",
        "error": None,
        "issuer_signature_valid": True,
        "issuer_trusted": True,
        "device_authentication_valid": True,
        "revocation_checked": False,
        "not_revoked": None,
        "verification_evidence": {
            "issuer_id": ISSUER_ID,
            "issuer_certificate_sha256": ISSUER_CERTIFICATE_SHA256,
            "algorithm": "ES256",
            "issued_at": int(datetime.now(timezone.utc).timestamp()),
            "expires_at": None,
            "validity_checked": True,
            "is_expired": False,
            "revocation_checked": False,
            "not_revoked": None,
            "holder_binding_verified": True,
            "holder_binding_method": "DEVICE_KEY",
            "proof_profile": "OID4VP_VERIFIABLE_PRESENTATION",
            "challenge_verified": True,
            "audience_verified": True,
            "credential_count": 1,
        },
    }


def _mdoc_policy() -> pp.PresentationPolicy:
    return pp.PresentationPolicy(
        id="50000000-0000-0000-0000-000000000091",
        organization_id="org-1",
        name="Direct-root mdoc",
        status=pp.PolicyStatus.ACTIVE,
        trust_profile_id="60000000-0000-0000-0000-000000000001",
        credential_requirements=[
            pp.CredentialRequirement(
                credential_template_id="70000000-0000-0000-0000-000000000091",
                credential_payload_format="MDOC",
                requested_claims=[
                    pp.RequestedClaim(
                        claim_name="email",
                        display_name="Email",
                        required=True,
                    )
                ],
            )
        ],
    )


@pytest.mark.parametrize("source_type", ["ROOT_CA", "PINNED_ISSUER"])
def test_proven_mdoc_direct_anchor_supplies_numeric_cedar_trust(
    monkeypatch: pytest.MonkeyPatch,
    source_type: str,
) -> None:
    repo = pp.InMemoryPresentationPolicyRepository()
    policy = _mdoc_policy()
    asyncio.run(repo.save(policy))
    profile = _active_root_profile()
    trust_sources = profile["trust_sources"]
    assert isinstance(trust_sources, list)
    trust_sources[0]["source_type"] = source_type
    verification_result = _verified_mdoc_result()
    monkeypatch.setattr(pp, "_detect_credential_format", lambda _token: "mdoc")
    monkeypatch.setattr(
        pp,
        "_load_policy_trust_profile",
        lambda _profile_id, _organization_id: profile,
    )
    monkeypatch.setattr(
        pp,
        "_verify_credential_by_format",
        lambda *_args, **_kwargs: verification_result,
    )
    captured: dict[str, object] = {}

    def is_authorized(**kwargs: object) -> SimpleNamespace:
        captured.update(kwargs)
        return SimpleNamespace(allowed=True, reasons=[], errors=[])

    response = asyncio.run(
        pp.evaluate_presentation(
            policy.id,
            pp.EvaluatePresentationRequest(
                vp_token="credential",
                nonce="nonce",
                audience="verifier.example",
            ),
            repo=repo,
            cedar_engine=SimpleNamespace(is_authorized=is_authorized),
        )
    )

    assert response.decision == "allow"
    assert response.verified_claims == {"email": "member@example.com"}
    context = captured["context"]
    assert isinstance(context, dict)
    assert context["issuer_id"] == ISSUER_ID
    assert context["issuer_trust_level"] == 100


def test_normalized_relationship_remains_authoritative_for_mdoc() -> None:
    profile = _active_root_profile()
    profile["issuer_relationships"] = [
        {
            "issuer_id": ISSUER_ID,
            "trust_level": 87,
            "compliance_status": "ACCREDITED",
            "accreditations": ["ISO27001"],
        }
    ]
    verification_result = _verified_mdoc_result()
    verification_evidence = verification_result["verification_evidence"]
    assert isinstance(verification_evidence, dict)

    assert pp._normalized_issuer_policy_evidence(
        profile,
        ISSUER_ID,
        credential_format="mdoc",
        verification_result=verification_result,
        verification_evidence=verification_evidence,
        trust_check_passed=True,
    ) == {
        "issuer_trust_level": 87,
        "compliance_status": "ACCREDITED",
        "accreditations": ["iso27001"],
    }


@pytest.mark.parametrize(
    "incomplete_case",
    [
        "non_mdoc",
        "inactive_profile",
        "failed_trust_orchestration",
        "unverified",
        "issuer_signature_invalid",
        "issuer_not_trusted",
        "device_authentication_invalid",
        "holder_binding_invalid",
        "issuer_identity_mismatch",
        "disabled_anchor",
        "unmatched_relationship",
    ],
)
def test_mdoc_direct_anchor_translation_fails_closed(
    incomplete_case: str,
) -> None:
    profile = _active_root_profile()
    verification_result = _verified_mdoc_result()
    verification_evidence = verification_result["verification_evidence"]
    assert isinstance(verification_evidence, dict)
    credential_format = "mdoc"
    trust_check_passed = True

    if incomplete_case == "non_mdoc":
        credential_format = "sd-jwt"
    elif incomplete_case == "inactive_profile":
        profile["status"] = "suspended"
    elif incomplete_case == "failed_trust_orchestration":
        trust_check_passed = False
    elif incomplete_case == "unverified":
        verification_result["verified"] = False
    elif incomplete_case == "issuer_signature_invalid":
        verification_result["issuer_signature_valid"] = False
    elif incomplete_case == "issuer_not_trusted":
        verification_result["issuer_trusted"] = False
    elif incomplete_case == "device_authentication_invalid":
        verification_result["device_authentication_valid"] = False
    elif incomplete_case == "holder_binding_invalid":
        verification_evidence["holder_binding_verified"] = False
    elif incomplete_case == "issuer_identity_mismatch":
        verification_evidence["issuer_id"] = "x509-sha256:" + "b" * 64
    elif incomplete_case == "disabled_anchor":
        trust_sources = profile["trust_sources"]
        assert isinstance(trust_sources, list)
        trust_sources[0]["enabled"] = False
    elif incomplete_case == "unmatched_relationship":
        profile["issuer_relationships"] = [
            {
                "issuer_id": "x509-sha256:" + "b" * 64,
                "trust_level": 100,
                "compliance_status": None,
                "accreditations": [],
            }
        ]

    assert (
        pp._normalized_issuer_policy_evidence(
            profile,
            ISSUER_ID,
            credential_format=credential_format,
            verification_result=verification_result,
            verification_evidence=verification_evidence,
            trust_check_passed=trust_check_passed,
        )
        is None
    )


def test_missing_native_mdoc_trust_never_reaches_cedar(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = pp.InMemoryPresentationPolicyRepository()
    policy = _mdoc_policy()
    asyncio.run(repo.save(policy))
    verification_result = _verified_mdoc_result()
    verification_result.pop("issuer_trusted")
    monkeypatch.setattr(pp, "_detect_credential_format", lambda _token: "mdoc")
    monkeypatch.setattr(
        pp,
        "_load_policy_trust_profile",
        lambda _profile_id, _organization_id: _active_root_profile(),
    )
    monkeypatch.setattr(
        pp,
        "_verify_credential_by_format",
        lambda *_args, **_kwargs: verification_result,
    )
    cedar_engine = SimpleNamespace(
        is_authorized=lambda **_kwargs: pytest.fail(
            "Cedar must not receive incomplete mdoc anchor evidence"
        )
    )

    response = asyncio.run(
        pp.evaluate_presentation(
            policy.id,
            pp.EvaluatePresentationRequest(vp_token="credential"),
            repo=repo,
            cedar_engine=cedar_engine,
        )
    )

    assert response.decision == "deny"
    assert response.verified_claims == {}
    assert "numeric issuer trust" in response.decision_reason
