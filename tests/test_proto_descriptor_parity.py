"""Keep the checked-in Python and Envoy protobuf outputs on the same schema."""

import ast
from pathlib import Path

import pytest
from google.protobuf.descriptor_pb2 import FileDescriptorProto, FileDescriptorSet

ROOT = Path(__file__).resolve().parents[1]


def _embedded_python_descriptor(source: str) -> FileDescriptorProto:
    """Read protoc's schema bytes without executing its service dependency imports."""
    assignments = [
        node
        for node in ast.parse(source).body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "DESCRIPTOR"
            for target in node.targets
        )
    ]
    assert len(assignments) == 1, "Expected one generated DESCRIPTOR assignment"
    call = assignments[0].value
    assert isinstance(call, ast.Call)
    assert (
        isinstance(call.func, ast.Attribute) and call.func.attr == "AddSerializedFile"
    )
    assert len(call.args) == 1 and not call.keywords
    payload = ast.literal_eval(call.args[0])
    assert isinstance(payload, bytes), "Generated descriptor must be literal bytes"
    descriptor = FileDescriptorProto.FromString(payload)
    assert descriptor.name, "Generated descriptor must name its schema"
    return descriptor


def _message_fields(descriptor: FileDescriptorProto) -> dict:
    return {
        message.name: {
            field.name: (field.number, field.type, field.label == 3, field.type_name)
            for field in message.field
        }
        for message in descriptor.message_type
    }


def test_generated_python_and_envoy_descriptors_match_changed_services() -> None:
    descriptor_set = FileDescriptorSet.FromString(
        (ROOT / "config/envoy/proto_descriptor.pb").read_bytes()
    )
    envoy_files = {file.name: file for file in descriptor_set.file}

    python_files = {}
    for filename in (
        "credential_template_service",
        "presentation_policy_service",
    ):
        descriptor = _embedded_python_descriptor(
            (ROOT / "packages/marty_proto/v1" / f"{filename}_pb2.py").read_text(
                encoding="utf-8"
            )
        )
        name = descriptor.name
        assert name == f"{filename}.proto"
        assert name in envoy_files
        python_files[filename] = _message_fields(descriptor)
        assert python_files[filename] == _message_fields(envoy_files[name])

    policy = python_files["presentation_policy_service"]
    assert policy["EvaluatePresentationRequest"]["oid4vp_transport"][0] == 7
    transport = policy["Oid4vpEvaluationTransport"]
    assert transport["vp_token_raw"][0] == 5
    assert transport["verifier_client_id"][0] == 6
    assert transport["request_nonce"][0] == 7

    # The full proto generator also updates this previously stale Python stub.
    credential = python_files["credential_template_service"]["CreateTemplateRequest"]
    assert credential["compliance_profile_id"][0] == 22
    assert credential["derived_attributes"][0] == 26


@pytest.mark.parametrize(
    "source",
    [
        "other = b'not a descriptor'",
        "DESCRIPTOR = pool.AddSerializedFile(b'')\nDESCRIPTOR = pool.AddSerializedFile(b'')",
        "DESCRIPTOR = pool.AddSerializedFile('not bytes')",
        "DESCRIPTOR = pool.AddSerializedFile(payload())",
        "DESCRIPTOR = pool.OtherMethod(b'')",
        "DESCRIPTOR = pool.AddSerializedFile(b'')",
    ],
)
def test_missing_ambiguous_or_nonliteral_generated_descriptor_fails_closed(
    source: str,
) -> None:
    with pytest.raises((AssertionError, ValueError)):
        _embedded_python_descriptor(source)
