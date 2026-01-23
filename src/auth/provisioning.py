"""
JIT (Just-In-Time) User Provisioning Service

Handles automatic creation of ApplicantRecord when a user logs in via OIDC
for the first time. Follows hexagonal architecture by depending on ports/interfaces.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Any, Protocol
from uuid import uuid4

logger = logging.getLogger(__name__)


@dataclass
class OIDCUserInfo:
    """User information from OIDC claims."""

    sub: str  # OIDC subject (unique user ID from provider)
    email: str
    email_verified: bool = False
    given_name: str | None = None
    family_name: str | None = None
    name: str | None = None
    preferred_username: str | None = None
    phone_number: str | None = None
    phone_number_verified: bool = False
    # Custom claims from Keycloak
    user_type: str | None = None
    nationality: str | None = None
    date_of_birth: str | None = None
    roles: list[str] | None = None
    # Organization claims from Keycloak Organizations feature
    organization_id: str | None = None
    organization_name: str | None = None
    organization: dict[str, Any] | None = None  # Raw organization claim

    @classmethod
    def from_claims(cls, claims: dict[str, Any]) -> OIDCUserInfo:
        """Create from OIDC token claims."""
        roles = claims.get("roles", [])
        if not roles:
            # Try realm_access.roles for Keycloak
            realm_access = claims.get("realm_access", {})
            roles = realm_access.get("roles", [])

        # Parse organization claim from Keycloak
        # Format: { "org-id": { "name": "Org Name", ... } }
        # Note: Keycloak may use org name as key if Organizations feature isn't properly configured
        org_claim = claims.get("organization", {})
        org_id = None
        org_name = None
        if org_claim and isinstance(org_claim, dict):
            org_ids = list(org_claim.keys())
            if org_ids:
                raw_org_id = org_ids[0]  # Use first/primary org
                org_data = org_claim[raw_org_id]
                org_name = org_data.get("name") if isinstance(org_data, dict) else None
                
                # Check if org_id looks like a UUID, otherwise generate one from the name
                import uuid as uuid_module
                try:
                    uuid_module.UUID(raw_org_id)
                    org_id = raw_org_id  # It's a valid UUID
                except (ValueError, TypeError):
                    # Not a UUID - generate a deterministic UUID from the org name/key
                    # This ensures consistency across logins
                    org_id = str(uuid_module.uuid5(uuid_module.NAMESPACE_DNS, f"marty-org:{raw_org_id}"))
                    if not org_name:
                        org_name = raw_org_id  # The key is actually the name

        # Also check for explicit org attributes (fallback)
        if not org_name:
            org_name = claims.get("organization_name")

        return cls(
            sub=claims["sub"],
            email=claims.get("email", ""),
            email_verified=claims.get("email_verified", False),
            given_name=claims.get("given_name"),
            family_name=claims.get("family_name"),
            name=claims.get("name"),
            preferred_username=claims.get("preferred_username"),
            phone_number=claims.get("phone_number"),
            phone_number_verified=claims.get("phone_number_verified", False),
            user_type=claims.get("user_type"),
            nationality=claims.get("nationality"),
            date_of_birth=claims.get("date_of_birth"),
            roles=roles,
            organization_id=org_id,
            organization_name=org_name,
            organization=org_claim if org_claim else None,
        )

    def get_user_type(self) -> str:
        """Determine user type from claims or roles.
        
        Priority: administrator > vendor > applicant
        """
        # Check explicit user_type claim first
        if self.user_type:
            if self.user_type in ("administrator", "vendor", "applicant"):
                return self.user_type

        # Check roles for user type (priority order)
        if self.roles:
            if "administrator" in self.roles:
                return "administrator"
            if "vendor" in self.roles:
                return "vendor"
            if "applicant" in self.roles:
                return "applicant"

        # Default to applicant for self-registered users
        return "applicant"

    def is_vendor(self) -> bool:
        """Check if user is a vendor."""
        return self.get_user_type() == "vendor" or (self.roles and "vendor" in self.roles)

    def is_administrator(self) -> bool:
        """Check if user is an administrator."""
        return self.get_user_type() == "administrator" or (self.roles and "administrator" in self.roles)


@dataclass
class ProvisioningResult:
    """Result of JIT provisioning."""

    user_id: str
    user_type: str
    applicant_id: str | None = None
    organization_id: str | None = None
    organization_name: str | None = None
    is_new_user: bool = False
    is_new_applicant: bool = False
    is_new_organization: bool = False


class IApplicantRepository(Protocol):
    """Port for applicant repository operations."""

    async def get_by_account_id(self, account_id: str) -> Any | None:
        """Get applicant by account ID (OIDC sub)."""
        ...

    async def get_by_email(self, email: str) -> Any | None:
        """Get applicant by email."""
        ...

    async def create(self, applicant: Any) -> Any:
        """Create a new applicant record."""
        ...


class IOrganizationRepository(Protocol):
    """Port for organization repository operations."""

    async def get_by_id(self, org_id: str) -> Any | None:
        """Get organization by ID."""
        ...

    async def get_by_keycloak_id(self, keycloak_org_id: str) -> Any | None:
        """Get organization by Keycloak organization ID."""
        ...

    async def create(self, organization: Any) -> Any:
        """Create a new organization."""
        ...

    async def add_member(self, org_id: str, user_id: str, role: str) -> Any:
        """Add a member to an organization."""
        ...


class IUserRepository(Protocol):
    """Port for user repository operations (optional, for user table)."""

    async def get_by_id(self, user_id: str) -> Any | None:
        """Get user by ID."""
        ...

    async def get_by_oidc_sub(self, oidc_sub: str) -> Any | None:
        """Get user by OIDC subject."""
        ...

    async def create(self, user: Any) -> Any:
        """Create a new user."""
        ...

    async def update(self, user: Any) -> Any:
        """Update user."""
        ...


class JITProvisioningService:
    """
    Just-In-Time user provisioning service.

    - Creates ApplicantRecord on first login for users with 'applicant' role.
    - Links existing ApplicantRecords to OIDC accounts when email matches.
    - Auto-creates Organization for vendors with Keycloak organization membership.
    """

    def __init__(
        self,
        applicant_repository: IApplicantRepository,
        organization_repository: IOrganizationRepository | None = None,
        user_repository: IUserRepository | None = None,
        keycloak_admin_client: Any | None = None,
    ) -> None:
        """
        Initialize JIT provisioning service.

        Args:
            applicant_repository: Repository for applicant records
            organization_repository: Optional repository for organization records
            user_repository: Optional repository for user records
            keycloak_admin_client: Optional Keycloak admin client for org creation
        """
        self._applicant_repo = applicant_repository
        self._org_repo = organization_repository
        self._user_repo = user_repository
        self._keycloak_admin = keycloak_admin_client

    async def provision_user(self, user_info: OIDCUserInfo) -> ProvisioningResult:
        """
        Provision user on OIDC login.

        For applicant users:
        1. Check if ApplicantRecord exists with account_id = OIDC sub
        2. If not, check if ApplicantRecord exists with matching email
        3. If found by email, link it to the OIDC account
        4. If not found, create a new ApplicantRecord

        For vendor users:
        1. Check if Organization exists for their Keycloak organization
        2. If not, auto-create Organization in our database
        3. Add user as organization owner

        Args:
            user_info: User information from OIDC claims

        Returns:
            ProvisioningResult with user, applicant, and organization IDs
        """
        user_type = user_info.get_user_type()
        result = ProvisioningResult(
            user_id=user_info.sub,
            user_type=user_type,
            organization_id=user_info.organization_id,
            organization_name=user_info.organization_name,
        )

        # Handle vendor organization provisioning
        if user_type == "vendor":
            await self._provision_vendor_organization(user_info, result)
            return result

        # Handle administrator (no special provisioning needed)
        if user_type == "administrator":
            logger.info(f"User {user_info.email} is administrator, no provisioning needed")
            return result

        # Only provision ApplicantRecord for applicant users
        if user_type != "applicant":
            logger.info(f"User {user_info.email} is {user_type}, skipping applicant provisioning")
            return result

        # Check for existing applicant by account_id (OIDC sub)
        existing_by_account = await self._applicant_repo.get_by_account_id(user_info.sub)
        if existing_by_account:
            result.applicant_id = existing_by_account.id
            logger.info(f"Found existing applicant {result.applicant_id} for account {user_info.sub}")
            return result

        # Check for existing applicant by email (may be pre-registered or created via admin)
        existing_by_email = await self._applicant_repo.get_by_email(user_info.email)
        if existing_by_email:
            # Link existing record to OIDC account
            existing_by_email.account_id = user_info.sub
            await self._applicant_repo.create(existing_by_email)  # Update
            result.applicant_id = existing_by_email.id
            logger.info(f"Linked existing applicant {result.applicant_id} to account {user_info.sub}")
            return result

        # Create new ApplicantRecord
        applicant = await self._create_applicant_record(user_info)
        result.applicant_id = applicant.id
        result.is_new_applicant = True
        logger.info(f"Created new applicant {result.applicant_id} for {user_info.email}")

        return result

    async def _provision_vendor_organization(
        self, user_info: OIDCUserInfo, result: ProvisioningResult
    ) -> None:
        """
        Provision organization for a vendor user.

        If the vendor has a Keycloak organization but no corresponding
        organization in our database, auto-create it.

        Args:
            user_info: User information from OIDC claims
            result: Provisioning result to update
        """
        if not self._org_repo:
            logger.warning("Organization repository not configured, skipping org provisioning")
            return

        # Check if user has a Keycloak organization
        keycloak_org_id = user_info.organization_id
        if not keycloak_org_id:
            logger.info(f"Vendor {user_info.email} has no Keycloak organization")
            return

        # Check if organization already exists in our database
        existing_org = await self._org_repo.get_by_keycloak_id(keycloak_org_id)
        if existing_org:
            result.organization_id = existing_org.id
            result.organization_name = existing_org.name
            logger.info(f"Found existing organization {existing_org.id} for vendor {user_info.email}")
            return

        # Auto-create organization
        org_name = user_info.organization_name or f"Organization for {user_info.email}"
        now = datetime.now(timezone.utc)
        
        # Import here to avoid circular dependency
        try:
            from subscription.models import Organization, OrganizationMember, MemberRole
        except ImportError:
            logger.warning("subscription.models not available, using dict for organization")
            Organization = None

        if Organization:
            new_org = Organization(
                id=str(uuid4()),
                name=org_name,
                slug=self._generate_slug(org_name),
                keycloak_org_id=keycloak_org_id,
                created_by=user_info.sub,
                created_at=now,
                updated_at=now,
                is_active=True,
            )
            created_org = await self._org_repo.create(new_org)
            
            # Add user as organization owner
            await self._org_repo.add_member(
                org_id=created_org.id,
                user_id=user_info.sub,
                role=MemberRole.OWNER.value if hasattr(MemberRole, 'OWNER') else "owner",
            )
            
            result.organization_id = created_org.id
            result.organization_name = created_org.name
            result.is_new_organization = True
            logger.info(f"Auto-created organization {created_org.id} for vendor {user_info.email}")
        else:
            logger.warning("Could not create organization - models not available")

    def _generate_slug(self, name: str) -> str:
        """Generate a URL-friendly slug from a name."""
        import re
        slug = name.lower()
        slug = re.sub(r'[^a-z0-9\s-]', '', slug)
        slug = re.sub(r'[\s_-]+', '-', slug)
        slug = slug.strip('-')
        # Add uniqueness suffix
        slug = f"{slug}-{uuid4().hex[:6]}"
        return slug

    async def _create_applicant_record(self, user_info: OIDCUserInfo) -> Any:
        """Create a new ApplicantRecord from OIDC claims."""
        # Import here to avoid circular dependency
        from applicant_service.models import ApplicantRecord

        # Parse date of birth if provided
        dob = None
        if user_info.date_of_birth:
            try:
                dob = date.fromisoformat(user_info.date_of_birth)
            except ValueError:
                logger.warning(f"Invalid date_of_birth format: {user_info.date_of_birth}")

        # Build name from claims
        given_names = user_info.given_name or ""
        surname = user_info.family_name or ""

        # Fallback to parsing 'name' claim
        if not given_names and not surname and user_info.name:
            parts = user_info.name.split(" ", 1)
            given_names = parts[0]
            surname = parts[1] if len(parts) > 1 else ""

        now = datetime.now(timezone.utc)
        applicant = ApplicantRecord(
            id=str(uuid4()),
            account_id=user_info.sub,
            email=user_info.email,
            phone=user_info.phone_number,
            surname=surname or "Unknown",
            given_names=given_names or "Unknown",
            date_of_birth=dob or date(1900, 1, 1),  # Placeholder, user must update
            nationality=user_info.nationality or "UNK",  # Unknown
            identity_assurance_level=1,  # IAL1 until proofing
            identity_proofing_completed=False,
            active=True,
            suspended=False,
            created_at=now,
            updated_at=now,
            metadata={
                "provisioned_via": "jit",
                "oidc_claims_incomplete": not (given_names and surname and dob),
            },
        )

        return await self._applicant_repo.create(applicant)


# =============================================================================
# Concrete Repository Adapter for marty-ui
# =============================================================================


class ApplicantRepositoryAdapter:
    """
    Adapter implementing IApplicantRepository for the applicant_service database.

    Bridges the JIT provisioning service to the actual database layer.
    """

    def __init__(self, session_factory) -> None:
        """
        Initialize adapter with async session factory.

        Args:
            session_factory: SQLAlchemy async_sessionmaker
        """
        self._session_factory = session_factory

    async def get_by_account_id(self, account_id: str):
        """Get applicant by OIDC account ID (sub claim)."""
        from sqlalchemy import select
        from applicant_service.models import ApplicantRecord

        async with self._session_factory() as session:
            result = await session.execute(
                select(ApplicantRecord).where(ApplicantRecord.account_id == account_id)
            )
            return result.scalar_one_or_none()

    async def get_by_email(self, email: str):
        """Get applicant by email."""
        from sqlalchemy import select
        from applicant_service.models import ApplicantRecord

        async with self._session_factory() as session:
            result = await session.execute(
                select(ApplicantRecord).where(ApplicantRecord.email == email)
            )
            return result.scalar_one_or_none()

    async def create(self, applicant):
        """Create or update applicant record."""
        async with self._session_factory() as session:
            session.add(applicant)
            await session.commit()
            await session.refresh(applicant)
            return applicant
