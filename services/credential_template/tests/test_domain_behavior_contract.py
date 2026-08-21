"""Language-neutral parity oracle for the native credential-template domain."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from services.credential_template import main as credential_template


CONTRACT = json.loads(
    (
        Path(__file__).parents[3]
        / "contracts"
        / "credential-template-domain-behavior.json"
    ).read_text(encoding="utf-8")
)


def test_format_and_protocol_aliases_match_native_contract() -> None:
    assert CONTRACT["schema_version"] == 1
    for case in CONTRACT["formats"]:
        parsed = credential_template.normalize_credential_format(case["input"])
        assert parsed.value == case["canonical"], case["input"]
        assert credential_template.format_to_wire(parsed) == case["public_wire"]
        assert (
            credential_template.payload_format_to_signing_wire(case["input"])
            == case["signing_wire"]
        )
    for value in CONTRACT["invalid_formats"]:
        with pytest.raises(ValueError):
            credential_template.normalize_credential_format(value)
    for case in CONTRACT["payload_defaults"]:
        supported = [
            credential_template.normalize_credential_format(value)
            for value in case["supported"]
        ]
        assert (
            credential_template.normalize_credential_payload_format(None, supported)
            == case["canonical"]
        )
    for case in CONTRACT["payload_aliases"]:
        assert (
            credential_template.normalize_credential_payload_format(case["input"], [])
            == case["canonical"]
        )
    for case in CONTRACT["issuance_protocols"]:
        assert credential_template._normalize_issuance_protocol(case["input"]) == case["wire"]


def test_protocol_requirement_decisions_match_native_contract() -> None:
    for case in CONTRACT["protocol_requirements"]:
        try:
            credential_template._validate_template_protocol_requirements(
                compliance_profile=None,
                compliance_profile_id=case.get("compliance_profile_id"),
                credential_payload_format=case["format"],
                vct=case.get("vct"),
                doctype=case.get("doctype"),
            )
            accepted = True
        except Exception:
            accepted = False
        assert accepted is case["accepted"], case["name"]


def test_wallet_uri_and_routing_decisions_match_native_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for case in CONTRACT["inner_uris"]:
        monkeypatch.setenv("ENVIRONMENT", case["environment"])
        try:
            credential_template._validate_wallet_inner_uri(case["uri"])
            accepted = True
        except Exception:
            accepted = False
        assert accepted is case["accepted"], case["uri"]
    for case in CONTRACT["wallet_links"]:
        assert credential_template._render_wallet_open_uri(
            case["template"],
            case["inner_uri"],
            case["wallet_id"],
            case.get("platform"),
        ) == case["expected"]


def test_delivery_destination_decisions_match_native_contract() -> None:
    for case in CONTRACT["delivery_destinations"]:
        entry = credential_template.DeliveryDestinationEntry(**case["policy"])
        try:
            credential_template._validate_delivery_destination(entry)
            accepted = True
        except Exception:
            accepted = False
        assert accepted is case["accepted"], case["name"]
