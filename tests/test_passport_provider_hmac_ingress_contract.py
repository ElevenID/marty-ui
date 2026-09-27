"""Freeze the external bureau bytes before implementing the trusted ingress."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = json.loads(
    (ROOT / "contracts/passport-bureau-provider-ingress-behavior.json").read_text(
        encoding="utf-8"
    )
)
KMS_CONTRACT = json.loads(
    (ROOT / "contracts/passport-bureau-callback-kms-behavior.json").read_text(
        encoding="utf-8"
    )
)


def test_frozen_python_provider_raw_body_hmac() -> None:
    reference = CONTRACT["frozen_reference"]
    raw = reference["raw_body_utf8"].encode("utf-8")
    secret = reference["webhook_secret"].encode("utf-8")
    signature = hmac.new(secret, raw, hashlib.sha256).hexdigest()

    assert raw == (
        b'{"bureau_job_id":"bureau-reference","status":"SHIPPED",'
        b'"tracking_number":"TRACK-42"}'
    )
    assert signature == reference["raw_body_hmac_sha256_hex"]
    assert len(signature) == 64 and signature == signature.lower()
    assert not hmac.compare_digest(
        hmac.new(secret, raw + b" ", hashlib.sha256).digest(),
        bytes.fromhex(signature),
    )
    assert not hmac.compare_digest(
        hmac.new(b"other-provider-secret", raw, hashlib.sha256).digest(),
        bytes.fromhex(signature),
    )


def test_provider_binding_and_new_kms_envelope_are_distinct() -> None:
    reference = CONTRACT["frozen_reference"]
    provider_event = json.loads(reference["raw_body_utf8"])
    durable = reference["durable_match"]
    internal = json.loads(reference["internal_body_utf8"])

    assert "organization_id" not in provider_event
    assert reference["provider_profile_id"] == durable["provider_profile_id"]
    assert provider_event["bureau_job_id"] == durable["bureau_job_id"]
    assert internal["organization_id"] == durable["organization_id"]
    assert {key: value for key, value in internal.items() if key != "organization_id"} == (
        provider_event
    )
    assert CONTRACT["job_resolution"]["lookup_key"] == [
        "authenticated_provider_profile_id",
        "signed_bureau_job_id",
    ]
    forged = reference["forged_organization_id_case"]
    assert forged["bureau_body_organization_id"] != durable["organization_id"]
    assert forged["durable_organization_id"] == durable["organization_id"]
    assert forged["outcome"] == "reject without KMS signing or job mutation"
    assert "sole source" in CONTRACT["event_projection"]["untrusted_organization_id"]
    assert "excluding organization_id" in CONTRACT["event_projection"]["metadata"]

    internal_bytes = reference["internal_body_utf8"].encode("utf-8")
    signed_input = base64.b64decode(reference["kms_signed_input_b64"], validate=True)
    assert signed_input == (
        KMS_CONTRACT["schema"].encode("utf-8")
        + b"\x00"
        + durable["organization_id"].encode("utf-8")
        + b"\x00"
        + internal_bytes
    )
    assert CONTRACT["internal_handoff"]["signature_format"] == KMS_CONTRACT[
        "signature_format"
    ]
    assert CONTRACT["route"]["maximum_raw_body_bytes"] == KMS_CONTRACT[
        "maximum_body_bytes"
    ]


def test_contract_requires_fail_closed_provider_resolution() -> None:
    resolution = CONTRACT["job_resolution"]
    handoff = CONTRACT["internal_handoff"]
    assert "unique non-null" in resolution["durable_binding"]
    assert "without requesting KMS signing" in resolution["zero_or_multiple_matches"]
    assert "before verifying the MAC" in CONTRACT["provider_authentication"][
        "profile_selection"
    ]
    assert "Never use a bureau-supplied organization_id" in CONTRACT[
        "event_projection"
    ]["untrusted_organization_id"]
    assert "exact" in handoff["body"]
    assert "without direct repository update" in handoff["kms_failure"]


def test_existing_beta_signer_does_not_qualify_supported_consumers() -> None:
    deployment = CONTRACT["deployment_gate"]
    assert deployment["supported_consumers"] == ["base", "selfhost", "K8s"]
    assert "beta-only" in deployment["existing_beta_signer"]
    gate = deployment["required_before_python_retirement"]
    assert "same shared Rust implementation" in gate
    assert "narrow signer credential and KMS key policy" in gate
    assert "private signer-to-ingress network" in gate
    assert "no public sign route" in gate
    assert "no OpenBao token exposure" in gate
    assert "marty-credentials #305" in gate


if __name__ == "__main__":
    test_frozen_python_provider_raw_body_hmac()
    test_provider_binding_and_new_kms_envelope_are_distinct()
    test_contract_requires_fail_closed_provider_resolution()
    test_existing_beta_signer_does_not_qualify_supported_consumers()
