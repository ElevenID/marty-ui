"""Typed MIP message envelope and payload models.

This module provides a lightweight shared representation of the Marty Identity
Protocol message layer so services can emit typed envelopes for audit and
runtime tracing without rewriting their transport implementations.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _serialize_value(value: Any) -> Any:
    """Serialize dataclass-friendly values into JSON-compatible primitives."""
    if value is None:
        return None
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    if is_dataclass(value):
        return {key: _serialize_value(item) for key, item in asdict(value).items()}
    if isinstance(value, dict):
        return {str(key): _serialize_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_serialize_value(item) for item in value]
    return value


class MessageType(str, Enum):
    """Normative MIP message types currently modeled by the platform."""

    CREDENTIAL_OFFER = "CredentialOffer"
    TOKEN_REQUEST = "TokenRequest"
    TOKEN_RESPONSE = "TokenResponse"
    CREDENTIAL_REQUEST = "CredentialRequest"
    CREDENTIAL_RESPONSE = "CredentialResponse"
    PRESENTATION_REQUEST = "PresentationRequest"
    PRESENTATION_RESPONSE = "PresentationResponse"
    VERIFICATION_RESULT = "VerificationResult"


@dataclass
class MessageSignature:
    """Detached JWS signature metadata for a MIP envelope."""

    alg: str
    kid: str
    value: str


@dataclass
class ClaimResultPayload:
    """Claim-level verification result details."""

    claim_name: str
    required: bool
    present: bool
    satisfies_predicate: bool
    result: str


@dataclass
class CredentialOfferPayload:
    credential_issuer: str
    credential_configuration_ids: list[str] = field(default_factory=list)
    grants: dict[str, Any] = field(default_factory=dict)
    mip_flow_instance_id: str | None = None


@dataclass
class TokenRequestPayload:
    grant_type: str
    pre_authorized_code: str | None = None
    code: str | None = None
    redirect_uri: str | None = None
    client_id: str | None = None
    code_verifier: str | None = None


@dataclass
class TokenResponsePayload:
    access_token: str
    token_type: str = "Bearer"
    expires_in: int | None = None


@dataclass
class CredentialProofPayload:
    proof_type: str
    jwt: str


@dataclass
class CredentialRequestPayload:
    format: str
    proofs: dict[str, list[str]] = field(default_factory=dict)
    credential_configuration_id: str | None = None
    credential_identifier: str | None = None


@dataclass
class CredentialResponsePayload:
    credential: str | None = None
    transaction_id: str | None = None


@dataclass
class PresentationRequestPayload:
    client_id: str
    response_type: str
    nonce: str
    presentation_definition: dict[str, Any] | None = None
    dcql_query: dict[str, Any] | None = None
    mip_flow_instance_id: str | None = None
    mip_policy_id: str | None = None
    response_mode: str | None = None
    response_uri: str | None = None


@dataclass
class PresentationResponsePayload:
    vp_token: str
    presentation_submission: dict[str, Any] | None = None
    state: str | None = None


@dataclass
class VerificationResultPayload:
    flow_instance_id: str
    policy_id: str
    overall_result: str
    claim_results: list[ClaimResultPayload] = field(default_factory=list)
    trust_chain_valid: bool = False
    revocation_checked: bool = False
    revocation_status: str | None = None
    evaluated_at: datetime = field(default_factory=_utc_now)
    verifier_nonce: str = ""


@dataclass
class MIPMessage:
    """Normative MIP message envelope.

    This is intentionally transport-agnostic and primarily used for typed
    runtime artifacts, auditing, and internal flow tracing.
    """

    message_type: MessageType | str
    payload: Any
    mip_version: str = "0.3.1"
    message_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    correlation_id: str | None = None
    timestamp: datetime = field(default_factory=_utc_now)
    sender_id: str | None = None
    nonce: str | None = None
    signature: MessageSignature | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.message_type, MessageType):
            self.message_type = MessageType(str(self.message_type))
        if self.nonce == "":
            self.nonce = None

    def to_dict(self) -> dict[str, Any]:
        """Convert the envelope into a JSON-friendly dictionary."""
        return {
            "mip_version": self.mip_version,
            "message_type": self.message_type.value,
            "message_id": self.message_id,
            "correlation_id": self.correlation_id,
            "timestamp": self.timestamp.isoformat(),
            "sender_id": self.sender_id,
            "nonce": self.nonce,
            "payload": _serialize_value(self.payload),
            "signature": _serialize_value(self.signature),
        }


__all__ = [
    "ClaimResultPayload",
    "CredentialOfferPayload",
    "CredentialProofPayload",
    "CredentialRequestPayload",
    "CredentialResponsePayload",
    "MIPMessage",
    "MessageSignature",
    "MessageType",
    "PresentationRequestPayload",
    "PresentationResponsePayload",
    "TokenRequestPayload",
    "TokenResponsePayload",
    "VerificationResultPayload",
]
