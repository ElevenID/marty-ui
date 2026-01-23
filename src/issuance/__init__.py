"""Credential issuance module (OID4VCI compliant).

This module implements credential issuance following the OID4VCI specification,
using hexagonal architecture with storage ports for persistence.

Ports (interfaces):
    - IIssuanceStorage: Session and offer storage

Adapters (implementations):
    - RedisIssuanceStorage: Redis-backed session/offer storage

Services:
    - IssuanceService: Business logic for credential issuance
    - CredentialSigner: Credential signing using SpruceIDKeyManager

Note: Key management has been migrated to SpruceIDKeyManager.
Use get_key_manager() from marty_plugin.adapters.credentials.spruceid.
"""

from issuance.router import router
from issuance.ports import (
    IIssuanceStorage,
    StoredOffer,
    StoredSession,
)
from issuance.adapters import (
    RedisIssuanceStorage,
    create_issuance_storage,
)
from issuance.service import (
    IssuanceService,
    get_issuance_service,
    get_issuance_storage,
)

__all__ = [
    # Router
    "router",
    # Ports
    "IIssuanceStorage",
    "StoredOffer",
    "StoredSession",
    # Adapters
    "RedisIssuanceStorage",
    "create_issuance_storage",
    # Service
    "IssuanceService",
    "get_issuance_service",
    "get_issuance_storage",
]
