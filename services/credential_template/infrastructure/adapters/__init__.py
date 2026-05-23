"""Infrastructure adapters for credential template service."""

from credential_template.infrastructure.adapters.postgres_adapter import (
    PostgresCredentialTemplateRepository,
    PostgresDeliveryDestinationRepository,
    PostgresWalletRegistryRepository,
)

__all__ = [
    "PostgresCredentialTemplateRepository",
    "PostgresDeliveryDestinationRepository",
    "PostgresWalletRegistryRepository",
]
