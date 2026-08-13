"""Thin fail-closed adapter for canonical Rust flow decisions."""

from __future__ import annotations

import json
from types import ModuleType
from typing import Any

from common.native_backend import get_marty_rs_diagnostics, load_marty_rs


class NativeFlowOperationError(ValueError):
    """The canonical native flow kernel rejected or malformed an operation."""


_backend: ModuleType | Any | None = None
_diagnostics: dict[str, Any] | None = None


def initialize_native_flow_backend(
    backend: ModuleType | Any | None = None,
) -> dict[str, Any]:
    """Require the canonical backend and return startup diagnostics."""
    global _backend, _diagnostics
    if backend is None:
        backend = load_marty_rs(required_capability="flow_state_machine")
        diagnostics = get_marty_rs_diagnostics(
            backend, required_capability="credential_presentation_metadata"
        )
        diagnostics = get_marty_rs_diagnostics(
            backend, required_capability="openid4vp_mdoc_handover"
        )
        diagnostics = get_marty_rs_diagnostics(
            backend, required_capability="haip_response_encryption"
        )
        diagnostics = get_marty_rs_diagnostics(
            backend, required_capability="oid4vp_x509_identity"
        )
        diagnostics = get_marty_rs_diagnostics(
            backend, required_capability="siop_jwk_id_token_verification"
        )
        diagnostics = get_marty_rs_diagnostics(
            backend, required_capability="did_identifier_derivation"
        )
    else:
        diagnostics = {
            "available": True,
            "backend": "injected-test-backend",
            "version": "test",
            "build_revision": "test",
            "capabilities": [
                "flow_state_machine",
                "credential_presentation_metadata",
                "openid4vp_mdoc_handover",
                "haip_response_encryption",
                "oid4vp_x509_identity",
                "siop_jwk_id_token_verification",
                "did_identifier_derivation",
            ],
        }
    _backend = backend
    _diagnostics = diagnostics
    return dict(diagnostics)


def native_flow_diagnostics() -> dict[str, Any]:
    if _diagnostics is None:
        return initialize_native_flow_backend()
    return dict(_diagnostics)


def _native() -> ModuleType | Any:
    if _backend is None:
        initialize_native_flow_backend()
    if _backend is None:  # Defensive: initialization either succeeds or raises.
        raise NativeFlowOperationError("FLOW.NATIVE_BACKEND_UNAVAILABLE")
    return _backend


def _json_object(raw: Any, operation: str) -> dict[str, Any]:
    if not isinstance(raw, str):
        raise NativeFlowOperationError(
            f"FLOW.INVALID_NATIVE_RESULT: {operation} did not return JSON"
        )
    try:
        result = json.loads(raw)
    except json.JSONDecodeError as error:
        raise NativeFlowOperationError(
            f"FLOW.INVALID_NATIVE_RESULT: {operation} returned malformed JSON"
        ) from error
    if not isinstance(result, dict):
        raise NativeFlowOperationError(
            f"FLOW.INVALID_NATIVE_RESULT: {operation} did not return an object"
        )
    return result


def _jwk_json(response_encryption_jwk: dict[str, Any] | None) -> str | None:
    if response_encryption_jwk is None:
        return None
    if not isinstance(response_encryption_jwk, dict):
        raise NativeFlowOperationError(
            "FLOW.INVALID_OPENID4VP_RESPONSE_KEY: expected a JWK object"
        )
    try:
        return json.dumps(
            response_encryption_jwk,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as error:
        raise NativeFlowOperationError(
            "FLOW.INVALID_OPENID4VP_RESPONSE_KEY: JWK is not JSON serializable"
        ) from error


def _native_bytes(raw: Any, operation: str, *, expected_length: int) -> bytes:
    if isinstance(raw, bytes):
        result = raw
    elif isinstance(raw, bytearray):
        result = bytes(raw)
    elif isinstance(raw, list) and all(
        isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 255
        for value in raw
    ):
        result = bytes(raw)
    else:
        raise NativeFlowOperationError(
            f"FLOW.INVALID_NATIVE_RESULT: {operation} did not return bytes"
        )
    if len(result) != expected_length:
        raise NativeFlowOperationError(
            f"FLOW.INVALID_NATIVE_RESULT: {operation} returned an invalid length"
        )
    return result


def build_openid4vp_mdoc_session_transcript(
    *,
    client_id: str,
    nonce: str,
    response_uri: str,
    response_encryption_jwk: dict[str, Any] | None,
) -> bytes:
    """Build verifier-bound ISO 18013-7 bytes in the canonical Rust kernel."""
    try:
        raw = _native().build_openid4vp_mdoc_session_transcript(
            client_id,
            nonce,
            response_uri,
            _jwk_json(response_encryption_jwk),
        )
        transcript = _native_bytes(
            raw,
            "build_openid4vp_mdoc_session_transcript",
            expected_length=56,
        )
    except NativeFlowOperationError:
        raise
    except Exception as error:
        raise NativeFlowOperationError(str(error)) from error
    if not transcript.startswith(b"\x83\xf6\xf6\x82qOpenID4VPHandover"):
        raise NativeFlowOperationError(
            "FLOW.INVALID_NATIVE_RESULT: OpenID4VP mdoc transcript shape is invalid"
        )
    return transcript


def openid4vp_response_key_thumbprint(
    response_encryption_jwk: dict[str, Any] | None,
) -> bytes | None:
    """Return the Rust-owned raw RFC 7638 response-key thumbprint."""
    jwk_json = _jwk_json(response_encryption_jwk)
    if jwk_json is None:
        return None
    try:
        return _native_bytes(
            _native().openid4vp_response_key_thumbprint(jwk_json),
            "openid4vp_response_key_thumbprint",
            expected_length=32,
        )
    except NativeFlowOperationError:
        raise
    except Exception as error:
        raise NativeFlowOperationError(str(error)) from error


def openid4vp_mdoc_binding_digests(
    *,
    session_transcript: bytes,
    client_id: str,
    nonce: str,
    response_uri: str,
    response_encryption_jwk: dict[str, Any] | None,
    presentation: str,
) -> dict[str, str]:
    """Return Rust-owned non-reversible mdoc binding diagnostics."""
    try:
        result = _json_object(
            _native().openid4vp_mdoc_binding_digests(
                session_transcript,
                client_id,
                nonce,
                response_uri,
                _jwk_json(response_encryption_jwk),
                presentation,
            ),
            "openid4vp_mdoc_binding_digests",
        )
    except NativeFlowOperationError:
        raise
    except Exception as error:
        raise NativeFlowOperationError(str(error)) from error
    expected = {
        "transcript_sha256",
        "client_id_sha256",
        "nonce_sha256",
        "response_uri_sha256",
        "response_key_thumbprint_sha256",
        "presentation_sha256",
    }
    if set(result) != expected:
        raise NativeFlowOperationError(
            "FLOW.INVALID_NATIVE_RESULT: mdoc binding diagnostic shape is invalid"
        )
    for name, value in result.items():
        if name == "response_key_thumbprint_sha256" and value == "none":
            continue
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise NativeFlowOperationError(
                "FLOW.INVALID_NATIVE_RESULT: mdoc binding diagnostic digest is invalid"
            )
    return result


def credential_profile_presentation_metadata(
    profile: str,
    credential_format: str,
    type_identifier: str,
) -> dict[str, Any]:
    """Return canonical OID4VP metadata for a Rust-owned issuer profile."""
    try:
        result = _json_object(
            _native().credential_profile_presentation_metadata(
                profile,
                credential_format,
                type_identifier,
            ),
            "credential_profile_presentation_metadata",
        )
    except NativeFlowOperationError:
        raise
    except Exception as error:
        raise NativeFlowOperationError(str(error)) from error

    if set(result) != {"format", "meta"}:
        raise NativeFlowOperationError(
            "FLOW.INVALID_NATIVE_RESULT: credential presentation metadata shape is invalid"
        )
    if not isinstance(result["format"], str) or not result["format"].strip():
        raise NativeFlowOperationError(
            "FLOW.INVALID_NATIVE_RESULT: credential presentation format is invalid"
        )
    metadata = result["meta"]
    if (
        not isinstance(metadata, dict)
        or len(metadata) != 1
        or not set(metadata).issubset({"type_values", "vct_values"})
    ):
        raise NativeFlowOperationError(
            "FLOW.INVALID_NATIVE_RESULT: credential presentation meta is invalid"
        )
    type_values = metadata.get("type_values")
    valid_type_values = isinstance(type_values, list) and bool(type_values) and all(
        isinstance(type_set, list)
        and bool(type_set)
        and all(isinstance(value, str) and bool(value) for value in type_set)
        for type_set in type_values
    )
    vct_values = metadata.get("vct_values")
    valid_vct_values = isinstance(vct_values, list) and bool(vct_values) and all(
        isinstance(value, str) and bool(value) for value in vct_values
    )
    if not valid_type_values and not valid_vct_values:
        raise NativeFlowOperationError(
            "FLOW.INVALID_NATIVE_RESULT: credential presentation type identifiers are invalid"
        )
    return result


def generate_haip_response_encryption_key() -> tuple[dict[str, Any], dict[str, Any]]:
    """Generate one per-flow HAIP key through the canonical Rust backend."""
    try:
        raw = _native().haip_generate_response_encryption_key()
    except Exception as error:
        raise NativeFlowOperationError(str(error)) from error
    if not isinstance(raw, (tuple, list)) or len(raw) != 2:
        raise NativeFlowOperationError(
            "FLOW.INVALID_NATIVE_RESULT: HAIP key generation did not return a key pair"
        )
    public = _json_object(raw[0], "haip_generate_response_encryption_key.public")
    private = _json_object(raw[1], "haip_generate_response_encryption_key.private")
    public_fields = {"alg", "crv", "kid", "kty", "use", "x", "y"}
    if set(public) != public_fields or set(private) != public_fields | {"d"}:
        raise NativeFlowOperationError(
            "FLOW.INVALID_NATIVE_RESULT: HAIP key generation returned an invalid JWK shape"
        )
    if (
        public.get("alg") != "ECDH-ES"
        or public.get("crv") != "P-256"
        or public.get("kty") != "EC"
        or public.get("use") != "enc"
        or any(
            not isinstance(public.get(field), str) or not public[field]
            for field in public_fields
        )
        or any(private.get(field) != public.get(field) for field in public_fields)
        or not isinstance(private.get("d"), str)
        or not private["d"]
    ):
        raise NativeFlowOperationError(
            "FLOW.INVALID_NATIVE_RESULT: HAIP key generation returned invalid key material"
        )
    return public, private


def validate_haip_response_header(compact_jwe: str) -> dict[str, Any]:
    """Validate a HAIP envelope in Rust before requesting KMS unwrap."""
    try:
        header = _json_object(
            _native().haip_validate_response_header(compact_jwe),
            "haip_validate_response_header",
        )
    except NativeFlowOperationError:
        raise
    except Exception as error:
        raise NativeFlowOperationError(str(error)) from error
    if header.get("alg") != "ECDH-ES" or header.get("enc") not in {
        "A128GCM",
        "A256GCM",
    }:
        raise NativeFlowOperationError(
            "FLOW.INVALID_NATIVE_RESULT: HAIP header validation returned invalid algorithms"
        )
    if not isinstance(header.get("epk"), dict):
        raise NativeFlowOperationError(
            "FLOW.INVALID_NATIVE_RESULT: HAIP header validation returned no epk"
        )
    return header


def decrypt_haip_response(compact_jwe: str, private_jwk: dict[str, Any]) -> bytes:
    """Decrypt a HAIP compact JWE through the canonical Rust backend."""
    try:
        plaintext = _native().haip_decrypt_response(
            compact_jwe,
            json.dumps(private_jwk, separators=(",", ":"), sort_keys=True),
        )
    except Exception as error:
        raise NativeFlowOperationError(str(error)) from error
    if not isinstance(plaintext, bytes):
        raise NativeFlowOperationError(
            "FLOW.INVALID_NATIVE_RESULT: HAIP decryption did not return bytes"
        )
    return plaintext


def oid4vp_x509_hash_client_identity(
    certificate_bundle_pem: str,
    public_jwk: dict[str, Any],
) -> tuple[str, list[str]]:
    """Build an x509_hash identity through the canonical Rust backend."""
    try:
        result = _json_object(
            _native().oid4vp_x509_hash_client_identity(
                certificate_bundle_pem,
                json.dumps(public_jwk, separators=(",", ":"), sort_keys=True),
            ),
            "oid4vp_x509_hash_client_identity",
        )
    except NativeFlowOperationError:
        raise
    except Exception as error:
        raise NativeFlowOperationError(str(error)) from error
    if set(result) != {"client_id", "x5c"}:
        raise NativeFlowOperationError(
            "FLOW.INVALID_NATIVE_RESULT: x509 identity shape is invalid"
        )
    client_id = result["client_id"]
    x5c = result["x5c"]
    if (
        not isinstance(client_id, str)
        or not client_id.startswith("x509_hash:")
        or not isinstance(x5c, list)
        or not x5c
        or any(
            not isinstance(certificate, str) or not certificate
            for certificate in x5c
        )
    ):
        raise NativeFlowOperationError(
            "FLOW.INVALID_NATIVE_RESULT: x509 identity values are invalid"
        )
    return client_id, x5c


def derive_p256_did_identifier(
    public_jwk: dict[str, Any], method: str
) -> str:
    """Derive a self-describing verifier DID through the Rust backend."""
    expected_prefix = {"did:jwk": "did:jwk:", "did:key": "did:key:"}.get(method)
    if expected_prefix is None:
        raise NativeFlowOperationError(
            f"FLOW.UNSUPPORTED_DID_METHOD: unsupported DID method {method}"
        )
    try:
        result = _native().derive_p256_did_identifier(
            json.dumps(public_jwk, separators=(",", ":"), sort_keys=True),
            method,
        )
    except NativeFlowOperationError:
        raise
    except Exception as error:
        raise NativeFlowOperationError(str(error)) from error
    if (
        not isinstance(result, str)
        or not result.startswith(expected_prefix)
        or len(result) > 2048
        or any(character.isspace() for character in result)
    ):
        raise NativeFlowOperationError(
            "FLOW.INVALID_NATIVE_RESULT: DID identifier derivation returned an invalid value"
        )
    return result


def verify_siop_jwk_id_token(id_token: str) -> tuple[dict[str, Any], str]:
    """Verify a JWK-thumbprint SIOPv2 token through the Rust backend."""
    try:
        result = _json_object(
            _native().siop_verify_jwk_id_token(id_token),
            "siop_verify_jwk_id_token",
        )
    except NativeFlowOperationError:
        raise
    except Exception as error:
        raise NativeFlowOperationError(str(error)) from error
    if set(result) != {"claims", "signing_algorithm"}:
        raise NativeFlowOperationError(
            "FLOW.INVALID_NATIVE_RESULT: SIOPv2 verification shape is invalid"
        )
    claims = result["claims"]
    algorithm = result["signing_algorithm"]
    if not isinstance(claims, dict) or algorithm not in {"ES256", "EdDSA"}:
        raise NativeFlowOperationError(
            "FLOW.INVALID_NATIVE_RESULT: SIOPv2 verification values are invalid"
        )
    return claims, algorithm


def evaluate_transition(
    current: str,
    target: str,
    *,
    actor: str | None = None,
    event: str | None = None,
) -> dict[str, Any]:
    request: dict[str, Any] = {"current": current, "target": target}
    if actor is not None:
        request["actor"] = actor
    if event is not None:
        request["event"] = event
    try:
        result = _json_object(
            _native().flow_evaluate_transition(
                json.dumps(request, separators=(",", ":"), sort_keys=True)
            ),
            "flow_evaluate_transition",
        )
    except NativeFlowOperationError:
        raise
    except Exception as error:
        raise NativeFlowOperationError(str(error)) from error
    expected = {
        "prior_state",
        "new_state",
        "terminal",
        "no_op",
        "actor",
        "event",
    }
    if set(result) != expected or not isinstance(result["event"], str):
        raise NativeFlowOperationError(
            "FLOW.INVALID_NATIVE_RESULT: transition decision shape is invalid"
        )
    if result["prior_state"] != current or result["new_state"] != target:
        raise NativeFlowOperationError(
            "FLOW.INVALID_NATIVE_RESULT: transition decision changed requested states"
        )
    if not isinstance(result["terminal"], bool) or not isinstance(result["no_op"], bool):
        raise NativeFlowOperationError(
            "FLOW.INVALID_NATIVE_RESULT: transition flags are invalid"
        )
    return result


def is_terminal_status(status: str) -> bool:
    """Return terminality from the canonical same-state decision."""
    return bool(evaluate_transition(status, status)["terminal"])


def validate_graph(graph: dict[str, Any]) -> dict[str, Any]:
    try:
        result = _json_object(
            _native().flow_validate_graph(
                json.dumps(graph, separators=(",", ":"), sort_keys=True)
            ),
            "flow_validate_graph",
        )
    except NativeFlowOperationError:
        raise
    except Exception as error:
        raise NativeFlowOperationError(str(error)) from error
    if set(result) != {"valid", "step_count", "transition_count"}:
        raise NativeFlowOperationError(
            "FLOW.INVALID_NATIVE_RESULT: graph decision shape is invalid"
        )
    if result["valid"] is not True:
        raise NativeFlowOperationError(
            "FLOW.INVALID_NATIVE_RESULT: native graph validation did not succeed"
        )
    return result


def select_next_step(
    graph: dict[str, Any], current_step_id: str, outcome: str
) -> str | None:
    try:
        result = _native().flow_select_next_step(
            json.dumps(graph, separators=(",", ":"), sort_keys=True),
            current_step_id,
            outcome,
        )
    except Exception as error:
        raise NativeFlowOperationError(str(error)) from error
    if result is not None and not isinstance(result, str):
        raise NativeFlowOperationError(
            "FLOW.INVALID_NATIVE_RESULT: next-step decision is invalid"
        )
    return result
