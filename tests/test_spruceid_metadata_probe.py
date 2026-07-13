from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "check_spruceid_metadata",
    ROOT / "scripts/check_spruceid_metadata.py",
)
assert SPEC and SPEC.loader
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


BASE = "https://beta.elevenidllc.com"
ORG_ID = "00000000-0000-0000-0000-000000000001"
ISSUER = f"{BASE}/org/{ORG_ID}/spruce"


def _metadata() -> dict:
    return {
        "credential_issuer": ISSUER,
        "display": [{"name": "ElevenID LLC", "locale": "en"}],
        "credential_configurations_supported": {
            "MemberCredential#spruce-sd-jwt": {
                "format": "spruce-vc+sd-jwt",
                "vct": f"{BASE}/credentials/marty-verified-member-badge",
                "display": [{"name": "Marty Verified Member Badge"}],
            },
            "EmployeeBadge#spruce-sd-jwt": {
                "format": "spruce-vc+sd-jwt",
                "vct": f"{BASE}/credentials/EmployeeBadge",
                "display": [{"name": "Employee Badge"}],
            },
            "org.iso.18013.5.1.mDL#mdoc": {
                "format": "mso_mdoc",
                "doctype": "org.iso.18013.5.1.mDL",
                "display": [{"name": "Mobile Driving Licence (mDL)"}],
            },
        },
    }


def test_validate_spruce_metadata_accepts_public_displayable_configurations() -> None:
    summary = PROBE.validate_spruce_metadata(
        _metadata(),
        expected_issuer=ISSUER,
        expected_member_vct=f"{BASE}/credentials/marty-verified-member-badge",
    )

    assert summary["configuration_count"] == 3
    assert summary["issuer_display_name"] == "ElevenID LLC"
    assert summary["member_vct"] == f"{BASE}/credentials/marty-verified-member-badge"


@pytest.mark.parametrize("mutation, message", [
    (lambda value: value["credential_configurations_supported"].pop("MemberCredential#spruce-sd-jwt"), "MemberCredential"),
    (
        lambda value: value["credential_configurations_supported"]["EmployeeBadge#spruce-sd-jwt"].__setitem__(
            "vct", "https://marty.example/credentials/EmployeeBadge"
        ),
        "legacy VCTs",
    ),
    (
        lambda value: value["credential_configurations_supported"]["EmployeeBadge#spruce-sd-jwt"].__setitem__(
            "display", []
        ),
        "Malformed Spruce credential configurations",
    ),
    (
        lambda value: value["credential_configurations_supported"]["org.iso.18013.5.1.mDL#mdoc"].__setitem__(
            "doctype", "org.example.wrong"
        ),
        "Malformed Spruce credential configurations",
    ),
])
def test_validate_spruce_metadata_fails_closed(mutation, message: str) -> None:
    metadata = _metadata()
    mutation(metadata)

    with pytest.raises(PROBE.MetadataError, match=message):
        PROBE.validate_spruce_metadata(
            metadata,
            expected_issuer=ISSUER,
            expected_member_vct=f"{BASE}/credentials/marty-verified-member-badge",
        )


def test_validate_member_vct_metadata_requires_canonical_badge_identity() -> None:
    vct = f"{BASE}/credentials/marty-verified-member-badge"
    summary = PROBE.validate_member_vct_metadata(
        {
            "vct": vct,
            "name": "Marty Verified Member Badge",
            "display": [{"name": "Marty Verified Member Badge"}],
        },
        expected_vct=vct,
    )

    assert summary == {"member_badge_name": "Marty Verified Member Badge"}


def test_probe_checks_both_standard_metadata_locations(monkeypatch) -> None:
    requested: list[str] = []

    def fake_fetch(url: str, *, timeout: float) -> dict:
        requested.append(url)
        assert timeout == 20.0
        if url == f"{BASE}/credentials/marty-verified-member-badge":
            return {
                "vct": url,
                "name": "Marty Verified Member Badge",
                "display": [{"name": "Marty Verified Member Badge"}],
            }
        return _metadata()

    monkeypatch.setattr(PROBE, "_fetch_json", fake_fetch)

    summary = PROBE.probe(BASE, ORG_ID)

    assert requested == [
        f"{BASE}/.well-known/openid-credential-issuer/org/{ORG_ID}/spruce",
        f"{BASE}/org/{ORG_ID}/spruce/.well-known/openid-credential-issuer",
        f"{BASE}/credentials/marty-verified-member-badge",
    ]
    assert summary["member_configuration"] == "MemberCredential#spruce-sd-jwt"
    assert summary["member_badge_name"] == "Marty Verified Member Badge"


def test_probe_rejects_non_https_origin() -> None:
    with pytest.raises(PROBE.MetadataError, match="absolute HTTPS URL"):
        PROBE.probe("http://localhost:8000", ORG_ID)
