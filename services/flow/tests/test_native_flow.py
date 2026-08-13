from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from common.native_backend import NativeBackendUnavailable
from flow import native


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "flow_state.json"
MDOC_HANDOVER_FIXTURE_PATH = (
    Path(__file__).parent / "fixtures" / "openid4vp_mdoc_handover.json"
)


@pytest.fixture(autouse=True)
def restore_native_backend_state():
    backend = native._backend
    diagnostics = native._diagnostics
    try:
        yield
    finally:
        native._backend = backend
        native._diagnostics = diagnostics


def test_shared_transition_and_graph_vectors_use_the_native_kernel():
    diagnostics = native.initialize_native_flow_backend()
    assert diagnostics["available"] is True
    assert "flow_state_machine" in diagnostics["capabilities"]

    fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    for case in fixture["transition_cases"]:
        request = case["request"]
        assert native.evaluate_transition(
            request["current"],
            request["target"],
            actor=request.get("actor"),
            event=request.get("event"),
        ) == case["expected"]

    for request in fixture["invalid_transitions"]:
        with pytest.raises(
            native.NativeFlowOperationError, match="FLOW.TRANSITION_NOT_ALLOWED"
        ):
            native.evaluate_transition(request["current"], request["target"])

    graph = fixture["graph"]
    assert native.validate_graph(graph) == {
        "valid": True,
        "step_count": 3,
        "transition_count": 2,
    }
    assert native.select_next_step(graph, "approve", "approval_granted") == "end"
    assert native.select_next_step(graph, "approve", "failure") is None


def test_shared_mdoc_handover_vectors_use_the_native_kernel():
    diagnostics = native.initialize_native_flow_backend()
    assert "openid4vp_mdoc_handover" in diagnostics["capabilities"]
    fixture = json.loads(MDOC_HANDOVER_FIXTURE_PATH.read_text(encoding="utf-8"))

    for case in fixture["valid"]:
        transcript = native.build_openid4vp_mdoc_session_transcript(
            client_id=case["client_id"],
            nonce=case["nonce"],
            response_uri=case["response_uri"],
            response_encryption_jwk=case["response_encryption_jwk"],
        )
        assert transcript.hex() == case["session_transcript_hex"], case["name"]
        if "binding_digests" in case:
            assert native.openid4vp_mdoc_binding_digests(
                session_transcript=transcript,
                client_id=case["client_id"],
                nonce=case["nonce"],
                response_uri=case["response_uri"],
                response_encryption_jwk=case["response_encryption_jwk"],
                presentation=case["presentation"],
            ) == case["binding_digests"]

    for case in fixture["invalid"]:
        with pytest.raises(native.NativeFlowOperationError):
            native.build_openid4vp_mdoc_session_transcript(
                client_id=case["client_id"],
                nonce=case["nonce"],
                response_uri=case["response_uri"],
                response_encryption_jwk=case["response_encryption_jwk"],
            )


def test_missing_native_backend_fails_closed(monkeypatch: pytest.MonkeyPatch):
    def unavailable(*, required_capability: str | None = None):
        raise NativeBackendUnavailable(
            f"missing required native capability: {required_capability}"
        )

    monkeypatch.setattr(native, "_backend", None)
    monkeypatch.setattr(native, "_diagnostics", None)
    monkeypatch.setattr(native, "load_marty_rs", unavailable)
    with pytest.raises(NativeBackendUnavailable, match="flow_state_machine"):
        native.initialize_native_flow_backend()


def test_missing_presentation_metadata_capability_fails_startup(
    monkeypatch: pytest.MonkeyPatch,
):
    backend = object()

    def load(*, required_capability: str | None = None):
        assert required_capability == "flow_state_machine"
        return backend

    def diagnostics(_backend, *, required_capability: str | None = None):
        assert _backend is backend
        assert required_capability == "credential_presentation_metadata"
        raise NativeBackendUnavailable(
            "missing required native capability: credential_presentation_metadata"
        )

    monkeypatch.setattr(native, "_backend", None)
    monkeypatch.setattr(native, "_diagnostics", None)
    monkeypatch.setattr(native, "load_marty_rs", load)
    monkeypatch.setattr(native, "get_marty_rs_diagnostics", diagnostics)

    with pytest.raises(
        NativeBackendUnavailable, match="credential_presentation_metadata"
    ):
        native.initialize_native_flow_backend()


def test_missing_mdoc_handover_capability_fails_startup(
    monkeypatch: pytest.MonkeyPatch,
):
    backend = object()
    requested: list[str | None] = []

    def load(*, required_capability: str | None = None):
        assert required_capability == "flow_state_machine"
        return backend

    def diagnostics(_backend, *, required_capability: str | None = None):
        assert _backend is backend
        requested.append(required_capability)
        if required_capability == "openid4vp_mdoc_handover":
            raise NativeBackendUnavailable(
                "missing required native capability: openid4vp_mdoc_handover"
            )
        return {"available": True}

    monkeypatch.setattr(native, "_backend", None)
    monkeypatch.setattr(native, "_diagnostics", None)
    monkeypatch.setattr(native, "load_marty_rs", load)
    monkeypatch.setattr(native, "get_marty_rs_diagnostics", diagnostics)

    with pytest.raises(NativeBackendUnavailable, match="openid4vp_mdoc_handover"):
        native.initialize_native_flow_backend()
    assert requested == [
        "credential_presentation_metadata",
        "openid4vp_mdoc_handover",
    ]


def test_missing_haip_response_encryption_capability_fails_startup(
    monkeypatch: pytest.MonkeyPatch,
):
    backend = object()
    requested: list[str | None] = []
    monkeypatch.setattr(
        native,
        "load_marty_rs",
        lambda *, required_capability=None: backend,
    )

    def diagnostics(_backend, *, required_capability: str | None = None):
        assert _backend is backend
        requested.append(required_capability)
        if required_capability in {
            "credential_presentation_metadata",
            "openid4vp_mdoc_handover",
        }:
            return {
                "available": True,
                "capabilities": [
                    "flow_state_machine",
                    "credential_presentation_metadata",
                    "openid4vp_mdoc_handover",
                ],
            }
        raise NativeBackendUnavailable(
            f"missing required native capability: {required_capability}"
        )

    monkeypatch.setattr(native, "_backend", None)
    monkeypatch.setattr(native, "_diagnostics", None)
    monkeypatch.setattr(native, "get_marty_rs_diagnostics", diagnostics)

    with pytest.raises(
        NativeBackendUnavailable, match="haip_response_encryption"
    ):
        native.initialize_native_flow_backend()
    assert requested == [
        "credential_presentation_metadata",
        "openid4vp_mdoc_handover",
        "haip_response_encryption",
    ]


def test_missing_x509_identity_capability_fails_startup(
    monkeypatch: pytest.MonkeyPatch,
):
    backend = object()
    requested: list[str | None] = []
    monkeypatch.setattr(
        native,
        "load_marty_rs",
        lambda *, required_capability=None: backend,
    )

    def diagnostics(_backend, *, required_capability: str | None = None):
        assert _backend is backend
        requested.append(required_capability)
        if required_capability in {
            "credential_presentation_metadata",
            "openid4vp_mdoc_handover",
            "haip_response_encryption",
        }:
            return {
                "available": True,
                "capabilities": [
                    "flow_state_machine",
                    "credential_presentation_metadata",
                    "openid4vp_mdoc_handover",
                    "haip_response_encryption",
                ],
            }
        raise NativeBackendUnavailable(
            f"missing required native capability: {required_capability}"
        )

    monkeypatch.setattr(native, "_backend", None)
    monkeypatch.setattr(native, "_diagnostics", None)
    monkeypatch.setattr(native, "get_marty_rs_diagnostics", diagnostics)

    with pytest.raises(NativeBackendUnavailable, match="oid4vp_x509_identity"):
        native.initialize_native_flow_backend()
    assert requested == [
        "credential_presentation_metadata",
        "openid4vp_mdoc_handover",
        "haip_response_encryption",
        "oid4vp_x509_identity",
    ]


def test_missing_siop_verification_capability_fails_startup(
    monkeypatch: pytest.MonkeyPatch,
):
    backend = object()
    requested: list[str | None] = []
    monkeypatch.setattr(
        native,
        "load_marty_rs",
        lambda *, required_capability=None: backend,
    )

    def diagnostics(_backend, *, required_capability: str | None = None):
        assert _backend is backend
        requested.append(required_capability)
        if required_capability in {
            "credential_presentation_metadata",
            "openid4vp_mdoc_handover",
            "haip_response_encryption",
            "oid4vp_x509_identity",
        }:
            return {
                "available": True,
                "capabilities": [
                    "flow_state_machine",
                    "credential_presentation_metadata",
                    "openid4vp_mdoc_handover",
                    "haip_response_encryption",
                    "oid4vp_x509_identity",
                ],
            }
        raise NativeBackendUnavailable(
            f"missing required native capability: {required_capability}"
        )

    monkeypatch.setattr(native, "_backend", None)
    monkeypatch.setattr(native, "_diagnostics", None)
    monkeypatch.setattr(native, "get_marty_rs_diagnostics", diagnostics)

    with pytest.raises(
        NativeBackendUnavailable, match="siop_jwk_id_token_verification"
    ):
        native.initialize_native_flow_backend()
    assert requested == [
        "credential_presentation_metadata",
        "openid4vp_mdoc_handover",
        "haip_response_encryption",
        "oid4vp_x509_identity",
        "siop_jwk_id_token_verification",
    ]


def test_malformed_native_decision_fails_closed(monkeypatch: pytest.MonkeyPatch):
    class MalformedBackend:
        @staticmethod
        def flow_evaluate_transition(request_json: str) -> str:
            return "{}"

    monkeypatch.setattr(native, "_backend", MalformedBackend())
    monkeypatch.setattr(native, "_diagnostics", {"available": True})
    with pytest.raises(native.NativeFlowOperationError, match="decision shape"):
        native.evaluate_transition("created", "pending")


def test_haip_key_and_decryption_adapters_validate_native_results():
    public = {
        "alg": "ECDH-ES",
        "crv": "P-256",
        "kid": "oid4vp-haip-test",
        "kty": "EC",
        "use": "enc",
        "x": "x-coordinate",
        "y": "y-coordinate",
    }
    private = {**public, "d": "private-value"}

    class HaipBackend:
        @staticmethod
        def haip_generate_response_encryption_key():
            return json.dumps(public), json.dumps(private)

        @staticmethod
        def haip_validate_response_header(compact_jwe: str):
            assert compact_jwe == "compact-jwe"
            return json.dumps(
                {
                    "alg": "ECDH-ES",
                    "enc": "A256GCM",
                    "epk": {"kty": "EC", "crv": "P-256"},
                }
            )

        @staticmethod
        def haip_decrypt_response(compact_jwe: str, private_jwk_json: str):
            assert compact_jwe == "compact-jwe"
            assert json.loads(private_jwk_json) == private
            return b'{"vp_token":"fixture"}'

    native.initialize_native_flow_backend(HaipBackend())
    assert native.generate_haip_response_encryption_key() == (public, private)
    assert native.validate_haip_response_header("compact-jwe")["enc"] == "A256GCM"
    assert native.decrypt_haip_response("compact-jwe", private) == (
        b'{"vp_token":"fixture"}'
    )


@pytest.mark.parametrize("result", [None, (), ("{}",), ("{}", "{}")])
def test_malformed_native_haip_key_pair_fails_closed(result):
    class MalformedBackend:
        @staticmethod
        def haip_generate_response_encryption_key():
            return result

    native.initialize_native_flow_backend(MalformedBackend())
    with pytest.raises(native.NativeFlowOperationError, match="INVALID_NATIVE_RESULT"):
        native.generate_haip_response_encryption_key()


def test_credential_profile_presentation_metadata_uses_native_contract():
    class ProfileBackend:
        @staticmethod
        def credential_profile_presentation_metadata(
            profile: str,
            credential_format: str,
            type_identifier: str,
        ) -> str:
            assert profile == "open_badge"
            assert credential_format == "jwt_vc_json"
            assert type_identifier == ""
            return json.dumps(
                {
                    "format": "jwt_vc_json",
                    "meta": {
                        "type_values": [
                            ["VerifiableCredential", "OpenBadgeCredential"]
                        ]
                    },
                }
            )

    native.initialize_native_flow_backend(ProfileBackend())

    assert native.credential_profile_presentation_metadata(
        "open_badge", "jwt_vc_json", ""
    ) == {
        "format": "jwt_vc_json",
        "meta": {
            "type_values": [["VerifiableCredential", "OpenBadgeCredential"]]
        },
    }


def test_x509_identity_adapter_uses_native_contract():
    class IdentityBackend:
        @staticmethod
        def oid4vp_x509_hash_client_identity(
            certificate_bundle_pem: str, public_jwk_json: str
        ) -> str:
            assert certificate_bundle_pem == "certificate bundle"
            assert json.loads(public_jwk_json) == {
                "crv": "P-256",
                "kty": "EC",
                "x": "x",
                "y": "y",
            }
            return json.dumps(
                {
                    "client_id": "x509_hash:thumbprint",
                    "x5c": ["base64-der-leaf"],
                }
            )

    native.initialize_native_flow_backend(IdentityBackend())
    assert native.oid4vp_x509_hash_client_identity(
        "certificate bundle",
        {"kty": "EC", "crv": "P-256", "x": "x", "y": "y"},
    ) == ("x509_hash:thumbprint", ["base64-der-leaf"])


def test_x509_identity_adapter_matches_certificate_vector():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OID4VP Verifier")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    numbers = key.public_key().public_numbers()

    def encoded_coordinate(value: int) -> str:
        return base64.urlsafe_b64encode(value.to_bytes(32, "big")).rstrip(b"=").decode()

    der = certificate.public_bytes(serialization.Encoding.DER)
    client_id, x5c = native.oid4vp_x509_hash_client_identity(
        certificate.public_bytes(serialization.Encoding.PEM).decode(),
        {
            "kty": "EC",
            "crv": "P-256",
            "x": encoded_coordinate(numbers.x),
            "y": encoded_coordinate(numbers.y),
        },
    )
    expected_hash = base64.urlsafe_b64encode(hashlib.sha256(der).digest()).rstrip(b"=")
    assert client_id == f"x509_hash:{expected_hash.decode()}"
    assert x5c == [base64.b64encode(der).decode()]


def test_siop_verification_adapter_uses_native_contract():
    class SiopBackend:
        @staticmethod
        def siop_verify_jwk_id_token(id_token: str) -> str:
            assert id_token == "signed-token"
            return json.dumps(
                {
                    "claims": {"sub": "thumbprint-subject", "nonce": "nonce-1"},
                    "signing_algorithm": "ES256",
                }
            )

    native.initialize_native_flow_backend(SiopBackend())
    assert native.verify_siop_jwk_id_token("signed-token") == (
        {"sub": "thumbprint-subject", "nonce": "nonce-1"},
        "ES256",
    )


@pytest.mark.parametrize(
    "result",
    [
        "{}",
        json.dumps({"client_id": "invalid", "x5c": ["certificate"]}),
        json.dumps({"client_id": "x509_hash:value", "x5c": []}),
    ],
)
def test_malformed_native_x509_identity_fails_closed(result: str):
    class MalformedBackend:
        @staticmethod
        def oid4vp_x509_hash_client_identity(
            _certificate_bundle_pem: str, _public_jwk_json: str
        ) -> str:
            return result

    native.initialize_native_flow_backend(MalformedBackend())
    with pytest.raises(native.NativeFlowOperationError, match="INVALID_NATIVE_RESULT"):
        native.oid4vp_x509_hash_client_identity(
            "certificate bundle",
            {"kty": "EC", "crv": "P-256", "x": "x", "y": "y"},
        )


@pytest.mark.parametrize(
    "result",
    [
        "{}",
        json.dumps({"claims": [], "signing_algorithm": "ES256"}),
        json.dumps({"claims": {}, "signing_algorithm": "RS256"}),
    ],
)
def test_malformed_native_siop_verification_fails_closed(result: str):
    class MalformedBackend:
        @staticmethod
        def siop_verify_jwk_id_token(_id_token: str) -> str:
            return result

    native.initialize_native_flow_backend(MalformedBackend())
    with pytest.raises(native.NativeFlowOperationError, match="INVALID_NATIVE_RESULT"):
        native.verify_siop_jwk_id_token("signed-token")


def test_legacy_sd_jwt_profile_metadata_uses_native_vct_contract():
    class ProfileBackend:
        @staticmethod
        def credential_profile_presentation_metadata(
            profile: str,
            credential_format: str,
            type_identifier: str,
        ) -> str:
            assert profile == "open_badge"
            assert credential_format == "dc+sd-jwt"
            assert type_identifier == "https://issuer.example/member"
            return json.dumps(
                {
                    "format": "dc+sd-jwt",
                    "meta": {
                        "vct_values": [
                            "https://issuer.example/member",
                            "https://marty.example/credentials/open_badge",
                        ]
                    },
                }
            )

    native.initialize_native_flow_backend(ProfileBackend())

    assert native.credential_profile_presentation_metadata(
        "open_badge",
        "dc+sd-jwt",
        "https://issuer.example/member",
    )["meta"]["vct_values"] == [
        "https://issuer.example/member",
        "https://marty.example/credentials/open_badge",
    ]


@pytest.mark.parametrize(
    "result",
    [
        "{}",
        json.dumps({"format": "", "meta": {"type_values": [["A"]]}}),
        json.dumps({"format": "jwt_vc_json", "meta": {"type_values": []}}),
    ],
)
def test_malformed_credential_presentation_metadata_fails_closed(result: str):
    class MalformedBackend:
        @staticmethod
        def credential_profile_presentation_metadata(
            _profile: str,
            _credential_format: str,
            _type_identifier: str,
        ) -> str:
            return result

    native.initialize_native_flow_backend(MalformedBackend())

    with pytest.raises(native.NativeFlowOperationError, match="INVALID_NATIVE_RESULT"):
        native.credential_profile_presentation_metadata(
            "open_badge", "jwt_vc_json", ""
        )
