#!/usr/bin/env python3
"""
Seed Demo Vendor Organization

Creates the Demo Vendor Org in Keycloak and seeds initial configuration
in the local database. This script is idempotent.

Usage:
    python scripts/seed_demo_vendor_org.py

Environment Variables:
    KEYCLOAK_URL: Keycloak base URL (default: http://localhost:8180)
    KEYCLOAK_ADMIN_USER: Admin username (default: admin)
    KEYCLOAK_ADMIN_PASSWORD: Admin password (default: admin)
    KEYCLOAK_REALM: Realm name (default: marty)
    DATABASE_URL: PostgreSQL connection string (optional, for local DB seeding)
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from datetime import datetime
from uuid import uuid4

import httpx

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Configuration
KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://localhost:8180")
KEYCLOAK_ADMIN_USER = os.environ.get("KEYCLOAK_ADMIN_USER", "admin")
KEYCLOAK_ADMIN_PASSWORD = os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "admin")
KEYCLOAK_REALM = os.environ.get("KEYCLOAK_REALM", "marty")

# Demo Vendor Organization configuration
DEMO_VENDOR_ORG = {
    "name": "Demo Vendor Org",
    "description": "Demo organization for testing travel document applications",
    "alias": "demo-vendor-org",
    "enabled": True,
    "attributes": {
        "is_discoverable": ["true"],
        "membership_mode": ["open"],
    },
}

# Test invite code for E2E tests
DEMO_INVITE_CODE = "DEMO1234"

# Demo vendor user email
DEMO_VENDOR_EMAIL = "vendor@marty.demo"


async def get_admin_token(client: httpx.AsyncClient) -> str:
    """Get Keycloak admin access token."""
    token_url = f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token"
    
    response = await client.post(
        token_url,
        data={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": KEYCLOAK_ADMIN_USER,
            "password": KEYCLOAK_ADMIN_PASSWORD,
        },
    )
    response.raise_for_status()
    return response.json()["access_token"]


async def get_organization_by_name(
    client: httpx.AsyncClient, 
    token: str, 
    name: str
) -> dict | None:
    """Get organization by name."""
    url = f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}/organizations"
    
    response = await client.get(
        url,
        headers={"Authorization": f"Bearer {token}"},
        params={"search": name, "first": 0, "max": 10},
    )
    
    if response.status_code == 404:
        return None
    
    response.raise_for_status()
    orgs = response.json()
    
    # Find exact match
    for org in orgs:
        if org.get("name") == name:
            return org
    
    return None


async def create_organization(
    client: httpx.AsyncClient, 
    token: str, 
    org_data: dict
) -> dict:
    """Create a new organization in Keycloak."""
    url = f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}/organizations"
    
    response = await client.post(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        json=org_data,
    )
    
    if response.status_code == 409:
        logger.info(f"Organization already exists: {org_data['name']}")
        return await get_organization_by_name(client, token, org_data["name"])
    
    response.raise_for_status()
    
    # Get the created organization
    return await get_organization_by_name(client, token, org_data["name"])


async def get_user_by_email(
    client: httpx.AsyncClient, 
    token: str, 
    email: str
) -> dict | None:
    """Get user by email."""
    url = f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}/users"
    
    response = await client.get(
        url,
        headers={"Authorization": f"Bearer {token}"},
        params={"email": email, "exact": "true"},
    )
    response.raise_for_status()
    
    users = response.json()
    return users[0] if users else None


async def add_user_to_organization(
    client: httpx.AsyncClient, 
    token: str, 
    org_id: str, 
    user_id: str
) -> bool:
    """Add user to organization."""
    url = f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}/organizations/{org_id}/members"
    
    response = await client.post(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        json=user_id,  # Keycloak expects just the user ID as a string
    )
    
    if response.status_code == 409:
        logger.info(f"User {user_id} already in organization {org_id}")
        return True
    
    if response.status_code >= 400:
        # Try alternative format
        response = await client.post(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "text/plain",
            },
            content=user_id,
        )
        
    if response.status_code >= 400:
        logger.warning(f"Failed to add user to org: {response.status_code} - {response.text}")
        return False
    
    return True


async def update_user_attributes(
    client: httpx.AsyncClient,
    token: str,
    user_id: str,
    attributes: dict,
) -> bool:
    """Update user attributes."""
    # Get current user
    url = f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}/users/{user_id}"
    
    response = await client.get(
        url,
        headers={"Authorization": f"Bearer {token}"},
    )
    response.raise_for_status()
    user = response.json()
    
    # Merge attributes
    current_attrs = user.get("attributes", {})
    current_attrs.update(attributes)
    
    # Update user
    response = await client.put(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        json={"attributes": current_attrs},
    )
    
    return response.status_code < 400


async def seed_local_database(org_id: str) -> bool:
    """Seed organization data in local PostgreSQL database."""
    try:
        from sqlalchemy import select
        from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
        
        from subscription.models import (
            Base,
            Organization,
            OrganizationInvitation,
            MembershipMode,
            MemberRole,
            SubscriptionTier,
        )
        
        database_url = os.environ.get(
            "DATABASE_URL",
            "postgresql+asyncpg://marty:marty@localhost:5432/marty"
        )
        
        engine = create_async_engine(database_url, echo=False)
        SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        
        async with SessionLocal() as session:
            # Check if org exists
            result = await session.execute(
                select(Organization).where(Organization.id == org_id)
            )
            existing = result.scalar_one_or_none()
            
            if existing:
                logger.info(f"Organization already in local DB: {org_id}")
            else:
                # Create org record
                org = Organization(
                    id=org_id,
                    name=DEMO_VENDOR_ORG["name"],
                    slug="demo-vendor-org",
                    subscription_tier=SubscriptionTier.PROFESSIONAL,
                    is_active=True,
                    is_discoverable=True,
                    membership_mode=MembershipMode.OPEN,
                    contact_email=DEMO_VENDOR_EMAIL,
                )
                session.add(org)
                logger.info(f"Created organization in local DB: {org_id}")
            
            # Check for existing invite code
            result = await session.execute(
                select(OrganizationInvitation).where(
                    OrganizationInvitation.code == DEMO_INVITE_CODE
                )
            )
            existing_invite = result.scalar_one_or_none()
            
            if existing_invite:
                logger.info(f"Invite code already exists: {DEMO_INVITE_CODE}")
            else:
                # Create demo invite code
                invitation = OrganizationInvitation(
                    id=str(uuid4()),
                    organization_id=org_id,
                    code=DEMO_INVITE_CODE,
                    role=MemberRole.MEMBER,
                    is_reusable=True,
                    max_uses=None,
                    is_active=True,
                )
                session.add(invitation)
                logger.info(f"Created invite code: {DEMO_INVITE_CODE}")
            
            await session.commit()
        
        await engine.dispose()
        return True
        
    except ImportError as e:
        logger.warning(f"SQLAlchemy not available, skipping local DB seed: {e}")
        return False
    except Exception as e:
        logger.error(f"Failed to seed local database: {e}")
        return False


async def seed_demo_vendor_org():
    """Main function to seed the demo vendor organization."""
    logger.info("=" * 60)
    logger.info("Seeding Demo Vendor Organization")
    logger.info("=" * 60)
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        # Wait for Keycloak to be ready
        for attempt in range(30):
            try:
                response = await client.get(f"{KEYCLOAK_URL}/health/ready")
                if response.status_code == 200:
                    break
            except httpx.ConnectError:
                pass
            logger.info(f"Waiting for Keycloak... (attempt {attempt + 1}/30)")
            await asyncio.sleep(2)
        else:
            logger.error("Keycloak not available after 60 seconds")
            return False
        
        logger.info(f"Keycloak available at {KEYCLOAK_URL}")
        
        # Get admin token
        try:
            token = await get_admin_token(client)
            logger.info("Obtained admin access token")
        except httpx.HTTPStatusError as e:
            logger.error(f"Failed to get admin token: {e}")
            return False
        
        # Check if organization already exists
        existing_org = await get_organization_by_name(
            client, token, DEMO_VENDOR_ORG["name"]
        )
        
        if existing_org:
            org_id = existing_org["id"]
            logger.info(f"Organization already exists: {org_id}")
        else:
            # Create organization
            created_org = await create_organization(client, token, DEMO_VENDOR_ORG)
            if not created_org:
                logger.error("Failed to create organization")
                return False
            org_id = created_org["id"]
            logger.info(f"Created organization: {org_id}")
        
        # Get demo vendor user
        vendor_user = await get_user_by_email(client, token, DEMO_VENDOR_EMAIL)
        
        if vendor_user:
            user_id = vendor_user["id"]
            logger.info(f"Found vendor user: {user_id}")
            
            # Add vendor to organization
            success = await add_user_to_organization(client, token, org_id, user_id)
            if success:
                logger.info(f"Added vendor user to organization")
            
            # Update user attributes with organization info
            await update_user_attributes(client, token, user_id, {
                "organization_id": [org_id],
                "organization_name": [DEMO_VENDOR_ORG["name"]],
                "onboarding_completed": [datetime.utcnow().isoformat()],
            })
            logger.info("Updated vendor user attributes")
        else:
            logger.warning(f"Vendor user not found: {DEMO_VENDOR_EMAIL}")
        
        # Seed local database
        await seed_local_database(org_id)
    
    logger.info("=" * 60)
    logger.info("Demo Vendor Organization seeding complete!")
    logger.info(f"  Organization ID: {org_id}")
    logger.info(f"  Organization Name: {DEMO_VENDOR_ORG['name']}")
    logger.info(f"  Invite Code: {DEMO_INVITE_CODE}")
    logger.info("=" * 60)
    
    return True


if __name__ == "__main__":
    success = asyncio.run(seed_demo_vendor_org())
    sys.exit(0 if success else 1)
