"""Credential type mappings shared across services."""

from __future__ import annotations

from document_service.models import DocumentType
from subscription.models import CredentialType


CREDENTIAL_TO_APPLICATION_TYPE: dict[CredentialType, str] = {
    CredentialType.TRAVEL_VISA: "VISA",
    CredentialType.PASSPORT: "PASSPORT",
    CredentialType.DRIVERS_LICENSE: "MDL",
    CredentialType.ACCESS_BADGE: "ACCESS_BADGE",
    CredentialType.NATIONAL_ID: "NATIONAL_ID",
    CredentialType.DTC: "DTC",
    CredentialType.OPEN_BADGE: "OPEN_BADGE",
}


CREDENTIAL_TO_DOCUMENT_TYPE: dict[CredentialType, DocumentType | None] = {
    CredentialType.TRAVEL_VISA: DocumentType.VISA,
    CredentialType.PASSPORT: DocumentType.EMRTD,
    CredentialType.DRIVERS_LICENSE: DocumentType.MDL,
    CredentialType.ACCESS_BADGE: None,
    CredentialType.NATIONAL_ID: DocumentType.NATIONAL_ID,
    CredentialType.DTC: DocumentType.DTC,
    CredentialType.OPEN_BADGE: None,
}


def credential_to_application_type(credential_type: CredentialType) -> str:
    """Map a credential type to the applicant document_type string."""
    return CREDENTIAL_TO_APPLICATION_TYPE.get(credential_type, "PASSPORT")


def credential_to_document_type(credential_type: CredentialType) -> DocumentType | None:
    """Map a credential type to a document service type."""
    return CREDENTIAL_TO_DOCUMENT_TYPE.get(credential_type)
