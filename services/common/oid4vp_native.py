"""Thin fail-closed adapter for canonical Rust OID4VP request construction."""

from __future__ import annotations

import json
from collections.abc import Mapping
from types import ModuleType
from typing import Any

from common.native_backend import (
    NativeBackendUnavailable,
    NativeOperationError,
    get_marty_rs_diagnostics,
    load_marty_rs,
)

_backend: ModuleType | Any | None = None
_diagnostics: dict[str, Any] | None = None

_REQUESTED_CLAIM_FIELDS = (
    "claim_name",
    "display_name",
    "purpose",
    "required",
    "intent_to_retain",
)


def initialize_native_oid4vp_backend(
    backend: ModuleType | Any | None = None,
) -> dict[str, Any]:
    """Require the request-builder capability and return startup diagnostics."""
    global _backend, _diagnostics
    if backend is None:
        backend = load_marty_rs(required_capability="oid4vp_request_builder")
        diagnostics = get_marty_rs_diagnostics(
            backend, required_capability="oid4vp_request_builder"
        )
    else:
        diagnostics = {
            "available": True,
            "backend": "injected-test-backend",
            "version": "test",
            "build_revision": "test",
            "capabilities": ["oid4vp_request_builder"],
        }
    builder = getattr(backend, "build_oid4vp_presentation_request", None)
    if not callable(builder):
        raise NativeBackendUnavailable(
            "The Marty Rust backend does not expose build_oid4vp_presentation_request"
        )
    _backend = backend
    _diagnostics = diagnostics
    return dict(diagnostics)


def native_oid4vp_diagnostics() -> dict[str, Any]:
    if _diagnostics is None:
        return initialize_native_oid4vp_backend()
    return dict(_diagnostics)


def build_oid4vp_presentation_request(
    request: dict[str, Any],
) -> dict[str, Any]:
    """Return Rust-built Presentation Exchange and DCQL query objects."""
    backend = _native_backend()
    try:
        request_json = json.dumps(
            request,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        raw = backend.build_oid4vp_presentation_request(request_json)
    except (NativeBackendUnavailable, NativeOperationError):
        raise
    except (TypeError, ValueError) as error:
        raise NativeOperationError(
            f"Invalid OID4VP request-builder input: {error}"
        ) from error
    except Exception as error:
        raise NativeOperationError(str(error)) from error

    if not isinstance(raw, str):
        raise NativeOperationError("Rust OID4VP request builder did not return JSON")
    try:
        result = json.loads(raw)
    except json.JSONDecodeError as error:
        raise NativeOperationError(
            "Rust OID4VP request builder returned malformed JSON"
        ) from error
    _validate_result(result)
    return result


def parse_policy_requirements(policy_id: str, payload: str) -> list[dict[str, Any]]:
    """Parse a policy response into the bounded DTOs accepted by Rust."""
    try:
        requirements = json.loads(payload or "[]")
    except json.JSONDecodeError as error:
        raise NativeOperationError(
            f"Presentation policy {policy_id} has malformed credential requirements"
        ) from error
    if not isinstance(requirements, list) or not requirements:
        raise NativeOperationError(
            f"Presentation policy {policy_id} has no credential requirements"
        )
    if not all(isinstance(requirement, dict) for requirement in requirements):
        raise NativeOperationError(
            f"Presentation policy {policy_id} has invalid credential requirements"
        )
    return requirements


def credential_requirement_input(
    requirement: Mapping[str, Any],
    template: Any,
) -> dict[str, Any]:
    """Map policy and template service records to the canonical Rust input DTO."""
    requested_claims = requirement.get("requested_claims", []) or []
    if not isinstance(requested_claims, list):
        raise NativeOperationError("OID4VP requested_claims must be a list")

    normalized_claims: list[dict[str, Any]] = []
    for claim in requested_claims:
        if not isinstance(claim, Mapping):
            raise NativeOperationError("OID4VP requested claim must be an object")
        normalized_claims.append(
            {field: claim[field] for field in _REQUESTED_CLAIM_FIELDS if field in claim}
        )

    mdoc_claims: list[dict[str, str]] = []
    for claim in getattr(template, "claims", []) or []:
        name = str(getattr(claim, "name", "") or "").strip()
        namespace = str(getattr(claim, "mdoc_namespace", "") or "").strip()
        element = str(
            getattr(claim, "mdoc_element_identifier", "") or name
        ).strip()
        if namespace:
            mdoc_claims.append(
                {
                    "claim_name": name,
                    "namespace": namespace,
                    "element_identifier": element,
                }
            )

    return {
        "id": requirement.get("id"),
        "display_name": requirement.get("display_name"),
        "description": requirement.get("description"),
        "credential_type": getattr(template, "credential_type", None),
        "credential_vct": getattr(template, "vct", None),
        "credential_doctype": getattr(template, "doctype", None),
        "supported_formats": list(getattr(template, "supported_formats", []) or []),
        "requested_claims": normalized_claims,
        "mdoc_claims": mdoc_claims,
    }


def _native_backend() -> ModuleType | Any:
    if _backend is None:
        initialize_native_oid4vp_backend()
    if _backend is None:  # Defensive: initialization either succeeds or raises.
        raise NativeBackendUnavailable("The Marty Rust OID4VP backend is unavailable")
    return _backend


def _validate_result(result: Any) -> None:
    if not isinstance(result, dict) or set(result) != {
        "presentation_definition",
        "dcql_query",
    }:
        raise NativeOperationError("Rust OID4VP request-builder result shape is invalid")
    definition = result["presentation_definition"]
    query = result["dcql_query"]
    if (
        not isinstance(definition, dict)
        or not isinstance(definition.get("id"), str)
        or not definition["id"]
        or not isinstance(definition.get("input_descriptors"), list)
        or not definition["input_descriptors"]
        or not isinstance(query, dict)
        or not isinstance(query.get("credentials"), list)
        or not query["credentials"]
    ):
        raise NativeOperationError("Rust OID4VP request-builder result is incomplete")
    descriptor_ids = [
        descriptor.get("id")
        for descriptor in definition["input_descriptors"]
        if isinstance(descriptor, dict)
    ]
    credential_ids = [
        credential.get("id")
        for credential in query["credentials"]
        if isinstance(credential, dict)
    ]
    if (
        len(descriptor_ids) != len(definition["input_descriptors"])
        or len(credential_ids) != len(query["credentials"])
        or descriptor_ids != credential_ids
        or any(not isinstance(value, str) or not value for value in descriptor_ids)
    ):
        raise NativeOperationError(
            "Rust OID4VP request-builder descriptor mapping is invalid"
        )


__all__ = [
    "build_oid4vp_presentation_request",
    "credential_requirement_input",
    "initialize_native_oid4vp_backend",
    "native_oid4vp_diagnostics",
    "parse_policy_requirements",
]
