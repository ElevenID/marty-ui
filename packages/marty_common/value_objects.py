"""
Shared Value Objects

Immutable value objects used across multiple services.
These represent domain concepts with validation and type safety.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class UserId:
    """Unique identifier for a user."""
    
    value: str
    
    def __post_init__(self) -> None:
        if not self.value or not self.value.strip():
            raise ValueError("UserId cannot be empty")
    
    @classmethod
    def generate(cls) -> UserId:
        """Generate a new unique UserId."""
        return cls(str(uuid.uuid4()))
    
    @classmethod
    def from_string(cls, value: str) -> UserId:
        """Create UserId from string."""
        return cls(value)
    
    def __str__(self) -> str:
        return self.value
    
    def __hash__(self) -> int:
        return hash(self.value)
    
    def __eq__(self, other: Any) -> bool:
        if isinstance(other, UserId):
            return self.value == other.value
        if isinstance(other, str):
            return self.value == other
        return False


@dataclass(frozen=True)
class OrganizationId:
    """Unique identifier for an organization."""
    
    value: str
    
    def __post_init__(self) -> None:
        if not self.value or not self.value.strip():
            raise ValueError("OrganizationId cannot be empty")
    
    @classmethod
    def generate(cls) -> OrganizationId:
        """Generate a new unique OrganizationId."""
        return cls(str(uuid.uuid4()))
    
    @classmethod
    def from_string(cls, value: str) -> OrganizationId:
        """Create OrganizationId from string."""
        return cls(value)
    
    def __str__(self) -> str:
        return self.value
    
    def __hash__(self) -> int:
        return hash(self.value)
    
    def __eq__(self, other: Any) -> bool:
        if isinstance(other, OrganizationId):
            return self.value == other.value
        if isinstance(other, str):
            return self.value == other
        return False


@dataclass(frozen=True)
class Email:
    """Email address value object with validation."""
    
    value: str
    
    # RFC 5322 compliant email regex (simplified)
    EMAIL_PATTERN = re.compile(
        r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    )
    
    def __post_init__(self) -> None:
        if not self.value:
            raise ValueError("Email cannot be empty")
        
        normalized = self.value.lower().strip()
        if not self.EMAIL_PATTERN.match(normalized):
            raise ValueError(f"Invalid email format: {self.value}")
        
        # Use object.__setattr__ since dataclass is frozen
        object.__setattr__(self, "value", normalized)
    
    @classmethod
    def from_string(cls, value: str) -> Email:
        """Create Email from string."""
        return cls(value)
    
    @property
    def domain(self) -> str:
        """Get the domain part of the email."""
        return self.value.split("@")[1]
    
    @property
    def local_part(self) -> str:
        """Get the local part (before @) of the email."""
        return self.value.split("@")[0]
    
    def __str__(self) -> str:
        return self.value
    
    def __hash__(self) -> int:
        return hash(self.value)
    
    def __eq__(self, other: Any) -> bool:
        if isinstance(other, Email):
            return self.value == other.value
        if isinstance(other, str):
            return self.value == other.lower()
        return False


@dataclass(frozen=True)
class CredentialTypeId:
    """Unique identifier for a credential type configuration."""
    
    value: str
    
    def __post_init__(self) -> None:
        if not self.value or not self.value.strip():
            raise ValueError("CredentialTypeId cannot be empty")
    
    @classmethod
    def generate(cls) -> CredentialTypeId:
        """Generate a new unique CredentialTypeId."""
        return cls(str(uuid.uuid4()))
    
    def __str__(self) -> str:
        return self.value
    
    def __hash__(self) -> int:
        return hash(self.value)


@dataclass(frozen=True)
class TransactionId:
    """Unique identifier for an issuance transaction."""
    
    value: str
    
    def __post_init__(self) -> None:
        if not self.value or not self.value.strip():
            raise ValueError("TransactionId cannot be empty")
    
    @classmethod
    def generate(cls) -> TransactionId:
        """Generate a new unique TransactionId."""
        import secrets
        return cls(secrets.token_urlsafe(32))
    
    def __str__(self) -> str:
        return self.value
    
    def __hash__(self) -> int:
        return hash(self.value)


@dataclass(frozen=True)
class ApiKeyId:
    """Unique identifier for an API key."""
    
    value: str
    
    def __post_init__(self) -> None:
        if not self.value or not self.value.strip():
            raise ValueError("ApiKeyId cannot be empty")
    
    @classmethod
    def generate(cls) -> ApiKeyId:
        """Generate a new unique ApiKeyId."""
        return cls(str(uuid.uuid4()))
    
    def __str__(self) -> str:
        return self.value
    
    def __hash__(self) -> int:
        return hash(self.value)


@dataclass(frozen=True)
class ApplicantId:
    """Unique identifier for an applicant."""
    
    value: str
    
    def __post_init__(self) -> None:
        if not self.value or not self.value.strip():
            raise ValueError("ApplicantId cannot be empty")
    
    @classmethod
    def generate(cls) -> ApplicantId:
        """Generate a new unique ApplicantId."""
        return cls(str(uuid.uuid4()))
    
    def __str__(self) -> str:
        return self.value
    
    def __hash__(self) -> int:
        return hash(self.value)
