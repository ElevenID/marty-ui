"""Keep Envoy's checked-in descriptor aligned with canonical service schemas."""

from pathlib import Path
import subprocess
import sys

from google.protobuf.descriptor_pb2 import FileDescriptorSet

ROOT = Path(__file__).resolve().parents[1]


def descriptors(path):
    return {
        item.name: item for item in FileDescriptorSet.FromString(path.read_bytes()).file
    }


def test_envoy_descriptor_matches_canonical_protos(tmp_path):
    generated = tmp_path / "descriptor.pb"
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/compile_protos.py"),
            "--output",
            str(generated),
        ],
        check=True,
    )
    actual = descriptors(ROOT / "config/envoy/proto_descriptor.pb")
    expected = descriptors(generated)
    service_names = {path.name for path in (ROOT / "proto/v1").glob("*.proto")}
    assert service_names <= actual.keys()
    for name in service_names:
        # Compare complete service schemas, including RPCs and HTTP annotations.
        # Imported Google definitions can vary with the installed compiler version.
        assert actual[name] == expected[name], name


def test_public_field_numbers_remain_wire_compatible():
    files = descriptors(ROOT / "config/envoy/proto_descriptor.pb")

    def fields(filename, message):
        definition = next(
            item for item in files[filename].message_type if item.name == message
        )
        return {field.name: field.number for field in definition.field}

    auth = fields("auth_service.proto", "ValidateSessionResponse")
    assert auth["authentication_time_unix"] == 4
    policy = fields("presentation_policy_service.proto", "EvaluatePresentationRequest")
    assert policy["oid4vp_transport"] == 7
    transport = fields("presentation_policy_service.proto", "Oid4vpEvaluationTransport")
    assert transport["vp_token_raw"] == 5
    assert transport["verifier_client_id"] == 6
    assert transport["request_nonce"] == 7
    credential = fields("credential_template_service.proto", "CreateTemplateRequest")
    assert credential["compliance_profile_id"] == 22
    assert credential["derived_attributes"] == 26
    initiation = fields("issuance_service.proto", "InitiateIssuanceRequest")
    assert {
        name: initiation[name]
        for name in (
            "authorized_client_id",
            "application_id",
            "issuer_did",
            "delivery_mode",
            "idempotency_key",
            "claims_json",
        )
    } == {
        "authorized_client_id": 7,
        "application_id": 8,
        "issuer_did": 9,
        "delivery_mode": 10,
        "idempotency_key": 11,
        "claims_json": 12,
    }
    token = fields("issuance_service.proto", "ExchangeTokenRequest")
    assert token["client_assertion_type"] == 7
    assert token["client_assertion"] == 8
