#!/usr/bin/env python3
"""
Demo Data Seed Script

Idempotent script to populate the Marty database with demo data matching
the Keycloak demo users. Creates ApplicantRecords, ApplicationRecords,
VettingCheckRecords, and BiometricEnrollmentRecords for demonstration.

Usage:
    python scripts/seed_demo_data.py

Environment Variables:
    APPLICANT_DB_URL: Database connection string
    KEYCLOAK_ADMIN_URL: Keycloak admin API URL (optional, for fetching user IDs)
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from datetime import date, datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

from applicant_service.models import (
    Base,
    ApplicantRecord,
    ApplicationRecord,
    VettingCheckRecord,
    BiometricEnrollmentRecord,
    ApplicationStatus,
    VettingCheckType,
    VettingCheckStatus,
    BiometricType,
    BiometricPurpose,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Demo user definitions matching Keycloak realm config
# The account_id will be the Keycloak user's sub claim
DEMO_USERS = [
    {
        "email": "john.doe@marty.demo",
        "account_id": "demo-john-doe-uuid",  # Will be replaced with actual Keycloak sub if available
        "surname": "Doe",
        "given_names": "John",
        "date_of_birth": date(1985, 3, 15),
        "nationality": "USA",
        "gender": "M",
        "address_line1": "123 Main Street",
        "city": "New York",
        "state_province": "NY",
        "postal_code": "10001",
        "country": "USA",
        "phone": "+1-555-0101",
        "identity_assurance_level": 2,
        "identity_proofing_completed": True,
        "applications": [
            {
                "document_type": "eMRTD",
                "status": ApplicationStatus.APPROVED,
                "vetting_passed": True,
                "biometrics_completed": True,
            },
            {
                "document_type": "DTC",
                "status": ApplicationStatus.PENDING_BIOMETRICS,
                "vetting_passed": True,
                "biometrics_completed": False,
            },
        ],
    },
    {
        "email": "jane.smith@marty.demo",
        "account_id": "demo-jane-smith-uuid",
        "surname": "Smith",
        "given_names": "Jane",
        "date_of_birth": date(1990, 7, 22),
        "nationality": "GBR",
        "gender": "F",
        "address_line1": "456 High Street",
        "city": "London",
        "postal_code": "SW1A 1AA",
        "country": "GBR",
        "phone": "+44-20-7946-0958",
        "identity_assurance_level": 2,
        "identity_proofing_completed": True,
        "applications": [
            {
                "document_type": "eMRTD",
                "status": ApplicationStatus.VETTING_IN_PROGRESS,
                "vetting_passed": None,
                "biometrics_completed": False,
            },
        ],
    },
    {
        "email": "carlos.garcia@marty.demo",
        "account_id": "demo-carlos-garcia-uuid",
        "surname": "Garcia",
        "given_names": "Carlos",
        "date_of_birth": date(1978, 11, 8),
        "nationality": "ESP",
        "gender": "M",
        "address_line1": "789 Calle Principal",
        "city": "Madrid",
        "postal_code": "28001",
        "country": "ESP",
        "phone": "+34-91-555-0123",
        "identity_assurance_level": 1,
        "identity_proofing_completed": False,
        "applications": [
            {
                "document_type": "eMRTD",
                "status": ApplicationStatus.SUBMITTED,
                "vetting_passed": None,
                "biometrics_completed": False,
            },
        ],
    },
]


def generate_application_number() -> str:
    """Generate a unique application number."""
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    random_part = str(uuid4())[:8].upper()
    return f"APP-{timestamp}-{random_part}"


async def create_demo_applicant(
    session: AsyncSession,
    user_data: dict[str, Any],
) -> ApplicantRecord | None:
    """Create or get existing demo applicant."""
    # Check if applicant already exists by email
    result = await session.execute(
        select(ApplicantRecord).where(ApplicantRecord.email == user_data["email"])
    )
    existing = result.scalar_one_or_none()
    
    if existing:
        logger.info(f"Applicant already exists: {user_data['email']}")
        return existing
    
    # Create new applicant
    applicant = ApplicantRecord(
        id=str(uuid4()),
        account_id=user_data["account_id"],
        email=user_data["email"],
        phone=user_data.get("phone"),
        surname=user_data["surname"],
        given_names=user_data["given_names"],
        date_of_birth=user_data["date_of_birth"],
        nationality=user_data["nationality"],
        gender=user_data.get("gender"),
        address_line1=user_data.get("address_line1"),
        city=user_data.get("city"),
        state_province=user_data.get("state_province"),
        postal_code=user_data.get("postal_code"),
        country=user_data.get("country"),
        identity_assurance_level=user_data.get("identity_assurance_level", 1),
        identity_proofing_completed=user_data.get("identity_proofing_completed", False),
        identity_proofing_date=datetime.now(timezone.utc) if user_data.get("identity_proofing_completed") else None,
        identity_proofing_method="in_person" if user_data.get("identity_proofing_completed") else None,
        active=True,
        suspended=False,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    
    session.add(applicant)
    logger.info(f"Created applicant: {user_data['email']}")
    return applicant


async def create_demo_application(
    session: AsyncSession,
    applicant: ApplicantRecord,
    app_data: dict[str, Any],
) -> ApplicationRecord | None:
    """Create demo application for applicant."""
    # Check if similar application already exists
    result = await session.execute(
        select(ApplicationRecord).where(
            ApplicationRecord.applicant_id == applicant.id,
            ApplicationRecord.document_type == app_data["document_type"],
            ApplicationRecord.status == app_data["status"].value,
        )
    )
    existing = result.scalar_one_or_none()
    
    if existing:
        logger.info(f"Application already exists for {applicant.email}: {app_data['document_type']}")
        return existing
    
    now = datetime.now(timezone.utc)
    application = ApplicationRecord(
        id=str(uuid4()),
        application_number=generate_application_number(),
        applicant_id=applicant.id,
        document_type=app_data["document_type"],
        status=app_data["status"].value,
        holder_name=f"{applicant.given_names} {applicant.surname}",
        holder_given_name=applicant.given_names,
        holder_family_name=applicant.surname,
        holder_dob=applicant.date_of_birth,
        nationality=applicant.nationality,
        issuing_country=applicant.nationality,
        requested_validity_years=10,
        vetting_required=True,
        vetting_passed=app_data.get("vetting_passed"),
        biometrics_required=True,
        biometrics_completed=app_data.get("biometrics_completed", False),
        approval_required=True,
        status_changed_at=now,
        created_at=now - timedelta(days=30),
        updated_at=now,
    )
    
    # Set additional fields based on status
    if app_data["status"] in [
        ApplicationStatus.VETTING_IN_PROGRESS,
        ApplicationStatus.PENDING_BIOMETRICS,
        ApplicationStatus.APPROVED,
        ApplicationStatus.ISSUED,
    ]:
        application.vetting_started_at = now - timedelta(days=20)
    
    if app_data.get("vetting_passed"):
        application.vetting_completed_at = now - timedelta(days=10)
    
    if app_data.get("biometrics_completed"):
        application.biometrics_completed_at = now - timedelta(days=5)
    
    if app_data["status"] == ApplicationStatus.APPROVED:
        application.approved_at = now - timedelta(days=2)
        application.approved_by = "admin@marty.demo"
    
    session.add(application)
    logger.info(f"Created application for {applicant.email}: {app_data['document_type']} ({app_data['status'].value})")
    return application


async def create_demo_vetting_checks(
    session: AsyncSession,
    application: ApplicationRecord,
) -> list[VettingCheckRecord]:
    """Create demo vetting checks for application."""
    checks = []
    check_types = [
        VettingCheckType.IDENTITY_VERIFICATION,
        VettingCheckType.CRIMINAL_HISTORY,
        VettingCheckType.SANCTIONS_SCREENING,
        VettingCheckType.WATCHLIST_CHECK,
    ]
    
    for i, check_type in enumerate(check_types):
        # Check if already exists
        result = await session.execute(
            select(VettingCheckRecord).where(
                VettingCheckRecord.application_id == application.id,
                VettingCheckRecord.check_type == check_type.value,
            )
        )
        if result.scalar_one_or_none():
            continue
        
        # Determine status based on application status
        if application.vetting_passed:
            status = VettingCheckStatus.COMPLETED_PASSED
        elif application.status == ApplicationStatus.VETTING_IN_PROGRESS.value:
            # Some completed, some in progress
            status = VettingCheckStatus.COMPLETED_PASSED if i < 2 else VettingCheckStatus.IN_PROGRESS
        else:
            status = VettingCheckStatus.NOT_STARTED
        
        now = datetime.now(timezone.utc)
        check = VettingCheckRecord(
            id=str(uuid4()),
            application_id=application.id,
            check_type=check_type.value,
            status=status.value,
            external_provider="demo-provider",
            requested_at=now - timedelta(days=20) if status != VettingCheckStatus.NOT_STARTED else None,
            completed_at=now - timedelta(days=15) if status == VettingCheckStatus.COMPLETED_PASSED else None,
            result_passed=True if status == VettingCheckStatus.COMPLETED_PASSED else None,
        )
        session.add(check)
        checks.append(check)
    
    if checks:
        logger.info(f"Created {len(checks)} vetting checks for application {application.application_number}")
    return checks


async def create_demo_biometrics(
    session: AsyncSession,
    applicant: ApplicantRecord,
) -> BiometricEnrollmentRecord | None:
    """Create demo biometric enrollment for applicant."""
    # Check if already exists
    result = await session.execute(
        select(BiometricEnrollmentRecord).where(
            BiometricEnrollmentRecord.applicant_id == applicant.id,
            BiometricEnrollmentRecord.biometric_type == BiometricType.FACIAL.value,
        )
    )
    if result.scalar_one_or_none():
        logger.info(f"Biometric enrollment already exists for {applicant.email}")
        return None
    
    now = datetime.now(timezone.utc)
    enrollment = BiometricEnrollmentRecord(
        id=str(uuid4()),
        applicant_id=applicant.id,
        biometric_type=BiometricType.FACIAL.value,
        purpose=BiometricPurpose.ACCOUNT_ENROLLMENT.value,
        template_format="ISO_19794_5",  # Required field
        quality_score=0.95,
        quality_passed=True,
        liveness_check_performed=True,
        liveness_passed=True,
        captured_at=now - timedelta(days=60),
        expires_at=now + timedelta(days=365 * 5),
        active=True,
    )
    session.add(enrollment)
    logger.info(f"Created biometric enrollment for {applicant.email}")
    return enrollment


async def seed_database(db_url: str) -> None:
    """Seed the database with demo data."""
    logger.info(f"Connecting to database...")
    
    # Create async engine
    engine = create_async_engine(db_url, echo=False)
    
    # Create tables if they don't exist
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    logger.info("Database tables ensured")
    
    # Create session factory
    async_session = async_sessionmaker(engine, expire_on_commit=False)
    
    async with async_session() as session:
        for user_data in DEMO_USERS:
            logger.info(f"Processing demo user: {user_data['email']}")
            
            # Create applicant
            applicant = await create_demo_applicant(session, user_data)
            if not applicant:
                continue
            
            # Create biometric enrollment
            await create_demo_biometrics(session, applicant)
            
            # Create applications
            for app_data in user_data.get("applications", []):
                application = await create_demo_application(session, applicant, app_data)
                if application:
                    await create_demo_vetting_checks(session, application)
        
        # Commit all changes
        await session.commit()
        logger.info("All demo data committed successfully")
    
    await engine.dispose()


async def wait_for_database(db_url: str, max_retries: int = 30, delay: int = 2) -> bool:
    """Wait for database to be available."""
    from sqlalchemy.exc import OperationalError
    
    for attempt in range(max_retries):
        try:
            engine = create_async_engine(db_url, echo=False)
            async with engine.begin() as conn:
                await conn.execute(select(1))
            await engine.dispose()
            logger.info("Database is available")
            return True
        except OperationalError as e:
            logger.warning(f"Database not ready (attempt {attempt + 1}/{max_retries}): {e}")
            await asyncio.sleep(delay)
        except Exception as e:
            logger.error(f"Unexpected error checking database: {e}")
            await asyncio.sleep(delay)
    
    return False


async def main() -> int:
    """Main entry point."""
    db_url = os.environ.get(
        "APPLICANT_DB_URL",
        "postgresql+asyncpg://marty:marty@localhost:5432/marty_applicants",
    )
    
    logger.info("Starting demo data seeding...")
    logger.info(f"Database URL: {db_url.replace(db_url.split('@')[0].split('://')[-1], '***')}")
    
    # Wait for database
    if not await wait_for_database(db_url):
        logger.error("Database not available after maximum retries")
        return 1
    
    try:
        await seed_database(db_url)
        logger.info("Demo data seeding completed successfully!")
        return 0
    except Exception as e:
        logger.exception(f"Error seeding demo data: {e}")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
