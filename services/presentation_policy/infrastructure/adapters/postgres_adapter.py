"""
PostgreSQL adapter for presentation-policy repository.
"""
from typing import TYPE_CHECKING

from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

if TYPE_CHECKING:
    from presentation_policy.main import PresentationPolicy, PolicyStatus, DisplayMetadata, CredentialRequirement, AlternativeRequirement

from presentation_policy.infrastructure.models import presentation_policies


class PostgresPresentationPolicyRepository:
    """PostgreSQL implementation of presentation policy repository."""
    
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]):
        self._session_factory = session_factory
    
    async def save(self, policy: "PresentationPolicy") -> None:
        """Save or update a presentation policy."""
        async with self._session_factory() as session:
            # Serialize nested objects to JSON
            display_data = {
                "title": policy.display_metadata.title,
                "description": policy.display_metadata.description,
                "purpose": policy.display_metadata.purpose,
                "purpose_description": policy.display_metadata.purpose_description,
                "verifier_name": policy.display_metadata.verifier_name,
                "verifier_logo_url": policy.display_metadata.verifier_logo_url,
                "privacy_policy_url": policy.display_metadata.privacy_policy_url,
                "terms_of_service_url": policy.display_metadata.terms_of_service_url,
            }
            
            credential_reqs = [
                {
                    "id": req.id,
                    "credential_template_id": req.credential_template_id,
                    "display_name": req.display_name,
                    "description": req.description,
                    "required": req.required,
                    "requested_claims": [
                        {
                            "id": claim.id,
                            "claim_name": claim.claim_name,
                            "display_name": claim.display_name,
                            "description": claim.description,
                            "required": claim.required,
                            "selective_disclosure": claim.selective_disclosure,
                            "accept_derived": claim.accept_derived,
                            "constraints": [
                                {
                                    "id": constraint.id,
                                    "claim_name": constraint.claim_name,
                                    "constraint_type": constraint.constraint_type,
                                    "value": constraint.value,
                                    "description": constraint.description,
                                }
                                for constraint in claim.constraints
                            ],
                        }
                        for claim in req.requested_claims
                    ],
                    "trust_profile_id": req.trust_profile_id,
                    "max_age_seconds": req.max_age_seconds,
                    "require_fresh_issuance": req.require_fresh_issuance,
                }
                for req in policy.credential_requirements
            ]
            
            alternative_reqs = [
                {
                    "id": alt.id,
                    "name": alt.name,
                    "description": alt.description,
                    "min_satisfied": alt.min_satisfied,
                    "credential_requirements": [
                        {
                            "id": req.id,
                            "credential_template_id": req.credential_template_id,
                            "display_name": req.display_name,
                            "description": req.description,
                            "required": req.required,
                            "requested_claims": [
                                {
                                    "id": claim.id,
                                    "claim_name": claim.claim_name,
                                    "display_name": claim.display_name,
                                    "description": claim.description,
                                    "required": claim.required,
                                    "selective_disclosure": claim.selective_disclosure,
                                    "accept_derived": claim.accept_derived,
                                    "constraints": [
                                        {
                                            "id": constraint.id,
                                            "claim_name": constraint.claim_name,
                                            "constraint_type": constraint.constraint_type,
                                            "value": constraint.value,
                                            "description": constraint.description,
                                        }
                                        for constraint in claim.constraints
                                    ],
                                }
                                for claim in req.requested_claims
                            ],
                            "trust_profile_id": req.trust_profile_id,
                            "max_age_seconds": req.max_age_seconds,
                            "require_fresh_issuance": req.require_fresh_issuance,
                        }
                        for req in alt.credential_requirements
                    ],
                }
                for alt in policy.alternative_requirements
            ]
            
            # Check if exists
            result = await session.execute(
                select(presentation_policies.c.id).where(presentation_policies.c.id == policy.id)
            )
            exists = result.scalar_one_or_none()
            
            if exists:
                # Update
                await session.execute(
                    presentation_policies.update()
                    .where(presentation_policies.c.id == policy.id)
                    .values(
                        organization_id=policy.organization_id,
                        name=policy.name,
                        description=policy.description,
                        status=policy.status,
                        display_metadata=display_data,
                        credential_requirements=credential_reqs,
                        alternative_requirements=alternative_reqs,
                        compliance_profile_id=policy.compliance_profile_id,
                        version=policy.version,
                        updated_at=policy.updated_at,
                    )
                )
            else:
                # Insert
                await session.execute(
                    presentation_policies.insert().values(
                        id=policy.id,
                        organization_id=policy.organization_id,
                        name=policy.name,
                        description=policy.description,
                        status=policy.status,
                        display_metadata=display_data,
                        credential_requirements=credential_reqs,
                        alternative_requirements=alternative_reqs,
                        compliance_profile_id=policy.compliance_profile_id,
                        version=policy.version,
                        created_at=policy.created_at,
                        updated_at=policy.updated_at,
                    )
                )
            
            await session.commit()
    
    async def get(self, policy_id: str) -> "PresentationPolicy | None":
        """Get a presentation policy by ID."""
        from presentation_policy.main import (
            PresentationPolicy, PolicyStatus, DisplayMetadata, CredentialRequirement,
            AlternativeRequirement, RequestedClaim, ClaimConstraint, RequestPurpose, ConstraintType
        )
        
        async with self._session_factory() as session:
            result = await session.execute(
                select(presentation_policies).where(presentation_policies.c.id == policy_id)
            )
            row = result.first()
            
            if not row:
                return None
            
            # Deserialize display metadata
            display_data = row.display_metadata
            display_metadata = DisplayMetadata(
                title=display_data.get("title", ""),
                description=display_data.get("description", ""),
                purpose=RequestPurpose(display_data.get("purpose", "identity_verification")),
                purpose_description=display_data.get("purpose_description"),
                verifier_name=display_data.get("verifier_name", ""),
                verifier_logo_url=display_data.get("verifier_logo_url"),
                privacy_policy_url=display_data.get("privacy_policy_url"),
                terms_of_service_url=display_data.get("terms_of_service_url"),
            )
            
            # Deserialize credential requirements
            credential_requirements = []
            for req_data in row.credential_requirements:
                requested_claims = []
                for claim_data in req_data.get("requested_claims", []):
                    constraints = [
                        ClaimConstraint(
                            id=c.get("id", ""),
                            claim_name=c.get("claim_name", ""),
                            constraint_type=ConstraintType(c.get("constraint_type", "presence")),
                            value=c.get("value"),
                            description=c.get("description"),
                        )
                        for c in claim_data.get("constraints", [])
                    ]
                    
                    requested_claims.append(
                        RequestedClaim(
                            id=claim_data.get("id", ""),
                            claim_name=claim_data.get("claim_name", ""),
                            display_name=claim_data.get("display_name", ""),
                            description=claim_data.get("description"),
                            required=claim_data.get("required", True),
                            selective_disclosure=claim_data.get("selective_disclosure", True),
                            accept_derived=claim_data.get("accept_derived", True),
                            constraints=constraints,
                        )
                    )
                
                credential_requirements.append(
                    CredentialRequirement(
                        id=req_data.get("id", ""),
                        credential_template_id=req_data.get("credential_template_id", ""),
                        display_name=req_data.get("display_name", ""),
                        description=req_data.get("description"),
                        required=req_data.get("required", True),
                        requested_claims=requested_claims,
                        trust_profile_id=req_data.get("trust_profile_id"),
                        max_age_seconds=req_data.get("max_age_seconds"),
                        require_fresh_issuance=req_data.get("require_fresh_issuance", False),
                    )
                )
            
            # Deserialize alternative requirements
            alternative_requirements = []
            for alt_data in row.alternative_requirements:
                alt_cred_reqs = []
                for req_data in alt_data.get("credential_requirements", []):
                    requested_claims = []
                    for claim_data in req_data.get("requested_claims", []):
                        constraints = [
                            ClaimConstraint(
                                id=c.get("id", ""),
                                claim_name=c.get("claim_name", ""),
                                constraint_type=ConstraintType(c.get("constraint_type", "presence")),
                                value=c.get("value"),
                                description=c.get("description"),
                            )
                            for c in claim_data.get("constraints", [])
                        ]
                        
                        requested_claims.append(
                            RequestedClaim(
                                id=claim_data.get("id", ""),
                                claim_name=claim_data.get("claim_name", ""),
                                display_name=claim_data.get("display_name", ""),
                                description=claim_data.get("description"),
                                required=claim_data.get("required", True),
                                selective_disclosure=claim_data.get("selective_disclosure", True),
                                accept_derived=claim_data.get("accept_derived", True),
                                constraints=constraints,
                            )
                        )
                    
                    alt_cred_reqs.append(
                        CredentialRequirement(
                            id=req_data.get("id", ""),
                            credential_template_id=req_data.get("credential_template_id", ""),
                            display_name=req_data.get("display_name", ""),
                            description=req_data.get("description"),
                            required=req_data.get("required", True),
                            requested_claims=requested_claims,
                            trust_profile_id=req_data.get("trust_profile_id"),
                            max_age_seconds=req_data.get("max_age_seconds"),
                            require_fresh_issuance=req_data.get("require_fresh_issuance", False),
                        )
                    )
                
                alternative_requirements.append(
                    AlternativeRequirement(
                        id=alt_data.get("id", ""),
                        name=alt_data.get("name", ""),
                        description=alt_data.get("description"),
                        credential_requirements=alt_cred_reqs,
                        min_satisfied=alt_data.get("min_satisfied", 1),
                    )
                )
            
            return PresentationPolicy(
                id=row.id,
                organization_id=row.organization_id,
                name=row.name,
                description=row.description,
                status=PolicyStatus(row.status),
                display_metadata=display_metadata,
                credential_requirements=credential_requirements,
                alternative_requirements=alternative_requirements,
                compliance_profile_id=row.compliance_profile_id,
                version=row.version,
                created_at=row.created_at,
                updated_at=row.updated_at,
            )
    
    async def list(self, org_id: str) -> list["PresentationPolicy"]:
        """List all presentation policies for an organization."""
        from presentation_policy.main import (
            PresentationPolicy, PolicyStatus, DisplayMetadata, CredentialRequirement,
            AlternativeRequirement, RequestedClaim, ClaimConstraint, RequestPurpose, ConstraintType
        )
        
        async with self._session_factory() as session:
            result = await session.execute(
                select(presentation_policies)
                .where(presentation_policies.c.organization_id == org_id)
                .order_by(presentation_policies.c.created_at.desc())
            )
            rows = result.all()
            
            policies = []
            for row in rows:
                # Deserialize display metadata
                display_data = row.display_metadata
                display_metadata = DisplayMetadata(
                    title=display_data.get("title", ""),
                    description=display_data.get("description", ""),
                    purpose=RequestPurpose(display_data.get("purpose", "identity_verification")),
                    purpose_description=display_data.get("purpose_description"),
                    verifier_name=display_data.get("verifier_name", ""),
                    verifier_logo_url=display_data.get("verifier_logo_url"),
                    privacy_policy_url=display_data.get("privacy_policy_url"),
                    terms_of_service_url=display_data.get("terms_of_service_url"),
                )
                
                # Deserialize credential requirements
                credential_requirements = []
                for req_data in row.credential_requirements:
                    requested_claims = []
                    for claim_data in req_data.get("requested_claims", []):
                        constraints = [
                            ClaimConstraint(
                                id=c.get("id", ""),
                                claim_name=c.get("claim_name", ""),
                                constraint_type=ConstraintType(c.get("constraint_type", "presence")),
                                value=c.get("value"),
                                description=c.get("description"),
                            )
                            for c in claim_data.get("constraints", [])
                        ]
                        
                        requested_claims.append(
                            RequestedClaim(
                                id=claim_data.get("id", ""),
                                claim_name=claim_data.get("claim_name", ""),
                                display_name=claim_data.get("display_name", ""),
                                description=claim_data.get("description"),
                                required=claim_data.get("required", True),
                                selective_disclosure=claim_data.get("selective_disclosure", True),
                                accept_derived=claim_data.get("accept_derived", True),
                                constraints=constraints,
                            )
                        )
                    
                    credential_requirements.append(
                        CredentialRequirement(
                            id=req_data.get("id", ""),
                            credential_template_id=req_data.get("credential_template_id", ""),
                            display_name=req_data.get("display_name", ""),
                            description=req_data.get("description"),
                            required=req_data.get("required", True),
                            requested_claims=requested_claims,
                            trust_profile_id=req_data.get("trust_profile_id"),
                            max_age_seconds=req_data.get("max_age_seconds"),
                            require_fresh_issuance=req_data.get("require_fresh_issuance", False),
                        )
                    )
                
                # Deserialize alternative requirements
                alternative_requirements = []
                for alt_data in row.alternative_requirements:
                    alt_cred_reqs = []
                    for req_data in alt_data.get("credential_requirements", []):
                        requested_claims = []
                        for claim_data in req_data.get("requested_claims", []):
                            constraints = [
                                ClaimConstraint(
                                    id=c.get("id", ""),
                                    claim_name=c.get("claim_name", ""),
                                    constraint_type=ConstraintType(c.get("constraint_type", "presence")),
                                    value=c.get("value"),
                                    description=c.get("description"),
                                )
                                for c in claim_data.get("constraints", [])
                            ]
                            
                            requested_claims.append(
                                RequestedClaim(
                                    id=claim_data.get("id", ""),
                                    claim_name=claim_data.get("claim_name", ""),
                                    display_name=claim_data.get("display_name", ""),
                                    description=claim_data.get("description"),
                                    required=claim_data.get("required", True),
                                    selective_disclosure=claim_data.get("selective_disclosure", True),
                                    accept_derived=claim_data.get("accept_derived", True),
                                    constraints=constraints,
                                )
                            )
                        
                        alt_cred_reqs.append(
                            CredentialRequirement(
                                id=req_data.get("id", ""),
                                credential_template_id=req_data.get("credential_template_id", ""),
                                display_name=req_data.get("display_name", ""),
                                description=req_data.get("description"),
                                required=req_data.get("required", True),
                                requested_claims=requested_claims,
                                trust_profile_id=req_data.get("trust_profile_id"),
                                max_age_seconds=req_data.get("max_age_seconds"),
                                require_fresh_issuance=req_data.get("require_fresh_issuance", False),
                            )
                        )
                    
                    alternative_requirements.append(
                        AlternativeRequirement(
                            id=alt_data.get("id", ""),
                            name=alt_data.get("name", ""),
                            description=alt_data.get("description"),
                            credential_requirements=alt_cred_reqs,
                            min_satisfied=alt_data.get("min_satisfied", 1),
                        )
                    )
                
                policies.append(
                    PresentationPolicy(
                        id=row.id,
                        organization_id=row.organization_id,
                        name=row.name,
                        description=row.description,
                        status=PolicyStatus(row.status),
                        display_metadata=display_metadata,
                        credential_requirements=credential_requirements,
                        alternative_requirements=alternative_requirements,
                        compliance_profile_id=row.compliance_profile_id,
                        version=row.version,
                        created_at=row.created_at,
                        updated_at=row.updated_at,
                    )
                )
            
            return policies
    
    async def delete(self, policy_id: str) -> None:
        """Delete a presentation policy."""
        async with self._session_factory() as session:
            await session.execute(
                delete(presentation_policies).where(presentation_policies.c.id == policy_id)
            )
            await session.commit()
