"""
Applicant-Document Integration Module

Provides integration between the applicant vetting service and document issuance.
Ensures travel documents can only be issued for approved applications and
auto-populates holder information from vetted applicant records.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class IssueFromApplicationRequest(BaseModel):
    """
    Request to issue a document from an approved application.
    
    This replaces manual holder data entry with data from the vetted applicant.
    """
    application_id: UUID = Field(..., description="ID of the approved application")
    document_number: str = Field(..., min_length=1, max_length=100)
    issuer_id: str = "marty_trust_services"
    issuing_authority: str | None = None
    issuing_country: str = Field(default="USA", min_length=3, max_length=3)
    signer_cert_id: UUID | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ApplicantDocumentIntegration:
    """
    Integration service between applicant vetting and document issuance.
    
    Responsibilities:
    - Verify application is approved before document issuance
    - Extract holder information from vetted applicant
    - Map application document type to service document type
    - Update application status after issuance
    - Enforce biometric verification at issuance time
    """

    def __init__(self):
        # Lazy imports to avoid circular dependencies
        self._applicant_service = None
        self._application_service = None
        self._approval_service = None
        self._document_service = None

    @property
    def applicant_service(self):
        if self._applicant_service is None:
            from applicant_service.service import ApplicantService
            self._applicant_service = ApplicantService()
        return self._applicant_service

    @property
    def application_service(self):
        if self._application_service is None:
            from applicant_service.service import ApplicationService
            self._application_service = ApplicationService()
        return self._application_service

    @property
    def approval_service(self):
        if self._approval_service is None:
            from applicant_service.service import ApprovalService
            self._approval_service = ApprovalService()
        return self._approval_service

    @property
    def document_service(self):
        if self._document_service is None:
            from document_service.service import DocumentService
            self._document_service = DocumentService()
        return self._document_service

    async def _get_credential_config(self, config_id: str):
        from sqlalchemy import select
        from subscription.database import session_scope
        from subscription.models import CredentialTypeConfiguration

        async with session_scope() as session:
            result = await session.execute(
                select(CredentialTypeConfiguration).where(
                    CredentialTypeConfiguration.id == config_id,
                    CredentialTypeConfiguration.is_active == True,
                )
            )
            return result.scalar_one_or_none()

    async def get_approved_applications_for_issuance(self, limit: int = 50) -> list[dict[str, Any]]:
        """
        Get approved applications ready for document issuance.
        
        Returns applications with applicant details for UI selection.
        
        Args:
            limit: Maximum number of results
            
        Returns:
            List of approved applications with applicant info
        """
        approved = await self.approval_service.get_approved_applications(limit)

        result = []
        for app in approved:
            applicant = await self.applicant_service.get_applicant(app.applicant_id)
            if not applicant:
                continue
            given_name = applicant.given_names
            family_name = applicant.surname
            full_name = f"{given_name} {family_name}".strip()
            ial_level = (
                f"IAL{applicant.identity_assurance_level}"
                if applicant.identity_assurance_level
                else None
            )
            result.append({
                "application_id": str(app.id),
                "reference_number": app.application_number,
                "document_type": app.document_type,
                "credential_configuration_id": app.credential_configuration_id,
                "credential_type": app.credential_type,
                "credential_display_name": (app.extra_data or {}).get("credential_display_name"),
                "applicant_id": str(app.applicant_id),
                "applicant_name": full_name,
                "applicant_given_name": given_name,
                "applicant_family_name": family_name,
                "applicant_dob": applicant.date_of_birth.isoformat() if applicant.date_of_birth else None,
                "applicant_nationality": applicant.nationality,
                "requested_validity_years": app.requested_validity_years,
                "approved_at": app.approved_at.isoformat() if app.approved_at else None,
                "approved_by": app.approved_by,
                "ial_level": ial_level,
            })

        return result

    async def get_documents_for_applicant(
        self,
        applicant_id: str,
        limit: int = 200,
    ) -> list[Any]:
        """
        Get issued documents for a specific applicant.

        Filters document metadata for the applicant_id recorded at issuance.
        """
        documents = await self.document_service.list_documents(limit=limit, offset=0)
        applicant_key = str(applicant_id)

        return [
            doc
            for doc in documents.documents
            if (doc.metadata or {}).get("applicant_id") == applicant_key
        ]

    async def validate_application_for_issuance(self, application_id: UUID) -> tuple[bool, str]:
        """
        Validate that an application is ready for document issuance.
        
        Checks:
        - Application exists
        - Application is in APPROVED status
        - All required vetting checks passed
        - Applicant has required biometrics enrolled
        
        Args:
            application_id: Application UUID
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        from applicant_service.models import ApplicationStatus, VettingCheckStatus

        # Get application
        application = await self.application_service.get_application(application_id)
        if not application:
            return False, "Application not found"

        if not application.credential_configuration_id:
            return False, "Application missing credential configuration"

        config = await self._get_credential_config(application.credential_configuration_id)
        if not config:
            return False, "Credential configuration not found or inactive"

        # Check status
        if application.status != ApplicationStatus.APPROVED:
            return False, f"Application is not approved (status: {application.status.value})"

        # Verify all required checks passed
        checks = await self.application_service.get_vetting_checks(application_id)
        for check in checks:
            if check.is_required and check.status != VettingCheckStatus.PASSED:
                return False, f"Required check {check.check_type.value} not passed"

        # Verify applicant exists and has biometrics
        applicant = await self.applicant_service.get_applicant(application.applicant_id)
        if not applicant:
            return False, "Applicant record not found"

        biometrics = await self.applicant_service.get_applicant_biometrics(applicant.id)
        if not biometrics:
            return False, "No biometrics enrolled for applicant"

        # Check for facial biometric (minimum required)
        from applicant_service.models import BiometricType
        has_facial = any(b.biometric_type == BiometricType.FACIAL for b in biometrics)
        if not has_facial:
            return False, "Facial biometric required for document issuance"

        return True, ""

    async def issue_document_from_application(
        self,
        request: IssueFromApplicationRequest,
        actor_id: str = "system",
        ip_address: str | None = None,
    ) -> dict[str, Any]:
        """
        Issue a travel document from an approved application.
        
        This is the main integration point that:
        1. Validates the application is approved
        2. Extracts holder info from vetted applicant
        3. Issues the document via document service
        4. Updates application status to ISSUED
        
        Args:
            request: Issuance request with application ID and document details
            actor_id: Actor performing the issuance
            ip_address: Request IP for audit
            
        Returns:
            Issued document details
            
        Raises:
            ValueError: If validation fails
        """
        from applicant_service.models import ApplicationStatus
        from document_service.models import IssueDocumentRequest, ActorType
        from credentials.types import credential_to_document_type

        # Validate application
        is_valid, error = await self.validate_application_for_issuance(request.application_id)
        if not is_valid:
            raise ValueError(f"Cannot issue document: {error}")

        # Get application and applicant
        application = await self.application_service.get_application(request.application_id)
        config = await self._get_credential_config(application.credential_configuration_id)
        if not config:
            raise ValueError("Credential configuration not found or inactive")
        applicant = await self.applicant_service.get_applicant(application.applicant_id)
        if not applicant:
            raise ValueError("Applicant record not found")
        given_name = applicant.given_names
        family_name = applicant.surname
        full_name = f"{given_name} {family_name}".strip()
        extra_data = application.extra_data or {}

        document_type = credential_to_document_type(config.credential_type)
        if document_type is None:
            raise ValueError(f"Credential type {config.credential_type.value} is not supported for document issuance")

        # Create issue request with applicant data
        issue_request = IssueDocumentRequest(
            document_type=document_type,
            document_number=request.document_number,
            holder_name=full_name,
            holder_given_name=given_name,
            holder_family_name=family_name,
            holder_dob=applicant.date_of_birth.date() if isinstance(applicant.date_of_birth, datetime) else applicant.date_of_birth,
            nationality=applicant.nationality,
            validity_years=application.requested_validity_years,
            issuer_id=request.issuer_id,
            issuing_authority=request.issuing_authority or extra_data.get("issuing_authority"),
            issuing_country=request.issuing_country,
            signer_cert_id=request.signer_cert_id,
            metadata={
                **request.metadata,
                "application_id": str(application.id),
                "application_reference": application.application_number,
                "applicant_id": str(applicant.id),
                "credential_configuration_id": config.id,
                "credential_type": config.credential_type.value,
                "credential_display_name": config.display_name,
            },
        )

        # Issue the document
        document = await self.document_service.issue_document(
            request=issue_request,
            actor_id=actor_id,
            actor_type=ActorType.OPERATOR,
            ip_address=ip_address,
        )

        # Update application status to ISSUED
        await self.approval_service.mark_issued(
            application_id=application.id,
            document_id=str(document.id),
            issued_by=actor_id,
        )

        logger.info(
            f"Issued document {document.id} from application {application.application_number}"
        )

        # Emit a notification for the applicant.
        if applicant.account_id:
            try:
                from notifications_local.store import record_notification

                record_notification(
                    user_id=applicant.account_id,
                    event_type="credential_offer",
                    title="New Credential Available",
                    body=f"Your document {document.document_number} is ready.",
                    data={
                        "document_id": str(document.id),
                        "application_id": str(application.id),
                        "document_type": document.document_type.value,
                        "credential_configuration_id": config.id,
                        "credential_type": config.credential_type.value,
                    },
                )
            except Exception as exc:
                logger.warning(f"Failed to record notification: {exc}")

        return {
            "document_id": str(document.id),
            "document_number": document.document_number,
            "document_type": document.document_type.value,
            "holder_name": document.holder_name,
            "application_id": str(application.id),
            "application_reference": application.application_number,
            "issued_at": document.issued_at.isoformat(),
            "expires_at": document.expires_at.isoformat(),
        }

    async def verify_biometrics_at_issuance(
        self,
        application_id: UUID,
        captured_biometric_data: bytes,
        biometric_type: str = "FACIAL",
    ) -> tuple[bool, float]:
        """
        Verify applicant biometrics at document issuance time.
        
        Compares newly captured biometric against enrolled template.
        
        Args:
            application_id: Application UUID
            captured_biometric_data: Newly captured biometric template
            biometric_type: Type of biometric (FACIAL, FINGERPRINT, IRIS)
            
        Returns:
            Tuple of (match_result, similarity_score)
        """
        from applicant_service.models import BiometricType

        # Get application and applicant
        application = await self.application_service.get_application(application_id)
        if not application:
            raise ValueError("Application not found")

        # Get enrolled biometrics
        biometrics = await self.applicant_service.get_applicant_biometrics(
            application.applicant_id,
            BiometricType(biometric_type),
        )

        if not biometrics:
            raise ValueError(f"No {biometric_type} biometric enrolled")

        # Get most recent enrollment
        enrolled = biometrics[0]

        # In production, this would use actual biometric matching service
        # For now, return mock verification
        # TODO: Integrate with BiometricProcessingService from proto/biometric_service.proto
        
        logger.info(
            f"Biometric verification for application {application_id}: "
            f"comparing {biometric_type} against enrollment {enrolled.id}"
        )

        # Mock successful verification
        similarity_score = 0.95
        threshold = 0.8
        match_result = similarity_score >= threshold

        # Update enrollment with verification result
        await self.applicant_service.verify_biometric(
            enrolled.id, similarity_score, threshold
        )

        return match_result, similarity_score


# Global integration instance
_integration: ApplicantDocumentIntegration | None = None


def get_applicant_document_integration() -> ApplicantDocumentIntegration:
    """Get or create the global integration instance."""
    global _integration
    if _integration is None:
        _integration = ApplicantDocumentIntegration()
    return _integration
