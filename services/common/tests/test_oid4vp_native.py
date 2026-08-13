from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import common.oid4vp_native as oid4vp_native
from common.native_backend import NativeBackendUnavailable, NativeOperationError
from common.oid4vp_native import (
    build_oid4vp_presentation_request,
    credential_requirement_input,
    initialize_native_oid4vp_backend,
    parse_policy_requirements,
)


@pytest.fixture(autouse=True)
def restore_backend_state():
    backend = oid4vp_native._backend
    diagnostics = oid4vp_native._diagnostics
    try:
        yield
    finally:
        oid4vp_native._backend = backend
        oid4vp_native._diagnostics = diagnostics


def _valid_result() -> dict[str, object]:
    return {
        "presentation_definition": {
            "id": "pd-1",
            "input_descriptors": [{"id": "member"}],
        },
        "dcql_query": {"credentials": [{"id": "member", "format": "dc+sd-jwt"}]},
    }


def test_adapter_calls_native_builder_with_canonical_json() -> None:
    captured: list[str] = []

    def build(request_json: str) -> str:
        captured.append(request_json)
        return json.dumps(_valid_result())

    initialize_native_oid4vp_backend(
        SimpleNamespace(build_oid4vp_presentation_request=build)
    )

    result = build_oid4vp_presentation_request({"z": 1, "a": {"value": True}})

    assert captured == ['{"a":{"value":true},"z":1}']
    assert result == _valid_result()


def test_missing_native_builder_fails_closed() -> None:
    with pytest.raises(NativeBackendUnavailable, match="does not expose"):
        initialize_native_oid4vp_backend(SimpleNamespace())


@pytest.mark.parametrize(
    "native_result",
    [
        "not-json",
        "[]",
        json.dumps({"presentation_definition": {}, "dcql_query": {}}),
        json.dumps(
            {
                "presentation_definition": {
                    "id": "pd-1",
                    "input_descriptors": [{"id": "member"}],
                },
                "dcql_query": {"credentials": [{"id": "different"}]},
            }
        ),
    ],
)
def test_malformed_native_result_is_typed(native_result: str) -> None:
    initialize_native_oid4vp_backend(
        SimpleNamespace(build_oid4vp_presentation_request=lambda _request: native_result)
    )

    with pytest.raises(NativeOperationError):
        build_oid4vp_presentation_request({"id": "pd-1"})


@pytest.mark.parametrize("payload", ["", "[]", "{}", "not-json"])
def test_empty_or_malformed_policy_requirements_fail_closed(payload: str) -> None:
    with pytest.raises(NativeOperationError):
        parse_policy_requirements("policy-1", payload)


def test_requirement_mapping_keeps_only_native_dto_fields() -> None:
    template = SimpleNamespace(
        credential_type="MemberCredential",
        vct="https://issuer.example/member",
        doctype="",
        supported_formats=["sd_jwt_vc"],
        claims=[],
    )

    result = credential_requirement_input(
        {
            "id": "member",
            "credential_template_id": "template-1",
            "requested_claims": [
                {
                    "claim_name": "email",
                    "required": True,
                    "python_only_constraint": {"ignored": True},
                }
            ],
        },
        template,
    )

    assert result["requested_claims"] == [
        {"claim_name": "email", "required": True}
    ]
    assert "credential_template_id" not in result
