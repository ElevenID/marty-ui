"""Keep the checked-in Python and Envoy protobuf outputs on the same schema."""

from pathlib import Path

from google.protobuf.descriptor_pb2 import FileDescriptorSet

from packages.marty_proto.v1 import (
    credential_template_service_pb2,
    presentation_policy_service_pb2,
)


ROOT = Path(__file__).resolve().parents[1]


def test_generated_python_and_envoy_descriptors_match_changed_services() -> None:
    descriptor_set = FileDescriptorSet.FromString(
        (ROOT / "config/envoy/proto_descriptor.pb").read_bytes()
    )
    envoy_files = {file.name: file for file in descriptor_set.file}

    for module in (
        credential_template_service_pb2,
        presentation_policy_service_pb2,
    ):
        name = module.DESCRIPTOR.name
        assert name in envoy_files
        python_messages = {
            name: {
                field.name: (field.number, field.type, field.is_repeated)
                for field in message.fields
            }
            for name, message in module.DESCRIPTOR.message_types_by_name.items()
        }
        envoy_messages = {
            message.name: {
                field.name: (field.number, field.type, field.label == 3)
                for field in message.field
            }
            for message in envoy_files[name].message_type
        }
        assert python_messages == envoy_messages

    request = presentation_policy_service_pb2.EvaluatePresentationRequest.DESCRIPTOR
    assert request.fields_by_name["oid4vp_transport"].number == 7
    transport = presentation_policy_service_pb2.Oid4vpEvaluationTransport.DESCRIPTOR
    assert transport.fields_by_name["vp_token_raw"].number == 5
    assert transport.fields_by_name["verifier_client_id"].number == 6
    assert transport.fields_by_name["request_nonce"].number == 7

    # The full proto generator also updates this previously stale Python stub.
    credential = credential_template_service_pb2.CreateTemplateRequest.DESCRIPTOR
    assert credential.fields_by_name["compliance_profile_id"].number == 22
    assert credential.fields_by_name["derived_attributes"].number == 26
