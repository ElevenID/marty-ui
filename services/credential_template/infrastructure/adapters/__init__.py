"""Infrastructure adapters for credential template service."""

from credential_template.infrastructure.adapters.postgres_adapter import PostgresCredentialTemplateRepository
from credential_template.infrastructure.adapters.postgres_adapter import PostgresWalletRegistryRepository

__all__ = ["PostgresCredentialTemplateRepository", "PostgresWalletRegistryRepository"]
