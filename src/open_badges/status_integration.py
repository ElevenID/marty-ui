"""
Open Badges Status Integration

Integration module that provides credential status functionality
for Open Badge issuance. This module bridges the status_list module
with the Open Badges router.
"""

from __future__ import annotations

import logging
from typing import Optional, Any

from status_list.domain.value_objects import BitstringStatusListEntry
from status_list.application.services.credential_status_service import CredentialStatusService

logger = logging.getLogger(__name__)

# Global credential status service instance (set during app initialization)
_credential_status_service: Optional[CredentialStatusService] = None


def configure_credential_status_service(service: CredentialStatusService) -> None:
    """
    Configure the global credential status service.
    
    This should be called during application startup to enable
    credential status for Open Badge issuance.
    
    Args:
        service: The CredentialStatusService instance
    """
    global _credential_status_service
    _credential_status_service = service
    logger.info("Credential status service configured for Open Badges")


def get_credential_status_service() -> Optional[CredentialStatusService]:
    """
    Get the configured credential status service.
    
    Returns:
        The service if configured, None otherwise
    """
    return _credential_status_service


def is_credential_status_enabled() -> bool:
    """Check if credential status is enabled."""
    return _credential_status_service is not None


async def allocate_credential_status(
    credential_id: str,
    issuer_id: str,
    include_revocation: bool = True,
    include_suspension: bool = True,
) -> list[dict[str, Any]]:
    """
    Allocate status entries for a credential.
    
    This is called during credential issuance to allocate
    positions in the status list for the new credential.
    
    Args:
        credential_id: ID of the credential being issued
        issuer_id: ID of the issuer (typically the DID)
        include_revocation: Whether to include revocation status
        include_suspension: Whether to include suspension status
        
    Returns:
        List of credentialStatus entries to embed in the credential
    """
    if _credential_status_service is None:
        logger.debug("Credential status service not configured, skipping status allocation")
        return []
    
    try:
        entries = await _credential_status_service.allocate_credential_status(
            credential_id=credential_id,
            issuer_id=issuer_id,
            include_revocation=include_revocation,
            include_suspension=include_suspension,
        )
        
        return [entry.to_dict() for entry in entries]
        
    except Exception as e:
        logger.error(
            "Failed to allocate credential status for %s: %s",
            credential_id,
            e,
        )
        # Don't fail issuance if status allocation fails
        return []


def build_credential_status_field(
    entries: list[dict[str, Any]],
) -> dict[str, Any] | list[dict[str, Any]] | None:
    """
    Build the credentialStatus field for a credential.
    
    Per W3C spec, if there's one entry it can be an object,
    if multiple it should be an array.
    
    Args:
        entries: List of status entries
        
    Returns:
        credentialStatus field value, or None if empty
    """
    if not entries:
        return None
    
    if len(entries) == 1:
        return entries[0]
    
    return entries


async def inject_credential_status(
    credential: dict[str, Any],
    credential_id: str,
    issuer_id: str,
    include_revocation: bool = True,
    include_suspension: bool = True,
) -> tuple[dict[str, Any], list[str]]:
    """
    Inject credentialStatus into a credential before signing.
    
    This is the main integration point for Open Badge issuance.
    
    Args:
        credential: The unsigned credential
        credential_id: ID of the credential
        issuer_id: ID of the issuer
        include_revocation: Whether to include revocation status
        include_suspension: Whether to include suspension status
        
    Returns:
        Tuple of (modified credential, warnings list)
    """
    warnings: list[str] = []
    
    if not is_credential_status_enabled():
        warnings.append("Credential status not configured; credential will not be revocable")
        return credential, warnings
    
    # Allocate status entries
    entries = await allocate_credential_status(
        credential_id=credential_id,
        issuer_id=issuer_id,
        include_revocation=include_revocation,
        include_suspension=include_suspension,
    )
    
    if not entries:
        warnings.append("Failed to allocate credential status; credential will not be revocable")
        return credential, warnings
    
    # Build and inject the credentialStatus field
    status_field = build_credential_status_field(entries)
    
    if status_field:
        # Create a copy to avoid mutating the original
        modified = credential.copy()
        modified["credentialStatus"] = status_field
        
        logger.debug(
            "Injected credentialStatus for credential %s with %d entries",
            credential_id,
            len(entries),
        )
        
        return modified, warnings
    
    return credential, warnings
