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
                "protocol": {
                    "purpose": policy.purpose,
                    "trust_profile_id": policy.trust_profile_id,
                    "accepted_credential_types": policy.accepted_credential_types,
                    "holder_binding": {
                        "required": policy.holder_binding.required,
                        "binding_methods": policy.holder_binding.binding_methods,
                        "nonce_required": policy.holder_binding.nonce_required,
                    },
                    "freshness": {
                        "max_age_seconds": policy.freshness.max_age_seconds,
                        "require_not_revoked": policy.freshness.require_not_revoked,
                        "revocation_grace_seconds": policy.freshness.revocation_grace_seconds,
                    } if policy.freshness else None,
                    "issuer_constraints": {
                        "min_trust_level": policy.issuer_constraints.min_trust_level,
                        "required_compliance_statuses": policy.issuer_constraints.required_compliance_statuses,
                        "required_accreditations": policy.issuer_constraints.required_accreditations,
                    } if policy.issuer_constraints else None,
                    "credential_ranking_strategy": policy.credential_ranking_strategy,
                    "credential_ranking_weights": policy.credential_ranking_weights,
                },
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
                            "predicate_spec": claim.predicate_spec,
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
                                    "predicate_spec": claim.predicate_spec,
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
            AlternativeRequirement, RequestedClaim, ClaimConstraint, RequestPurpose, ConstraintType,
            HolderBinding, FreshnessPolicy, IssuerConstraints
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
            protocol_data = display_data.get("protocol", {}) if isinstance(display_data, dict) else {}
            _purpose_raw = display_data.get("purpose", "identity_verification")
            try:
                _purpose = RequestPurpose(_purpose_raw)
            except ValueError:
                _purpose = RequestPurpose.IDENTITY_VERIFICATION
            display_metadata = DisplayMetadata(
                title=display_data.get("title", ""),
                description=display_data.get("description", ""),
                purpose=_purpose,
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
                            predicate_spec=claim_data.get("predicate_spec"),
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
                                predicate_spec=claim_data.get("predicate_spec"),
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
                required_claims=[],
                accepted_credential_types=protocol_data.get("accepted_credential_types") or [req.credential_template_id for req in credential_requirements if req.credential_template_id],
                credential_requirements=credential_requirements,
                alternative_requirements=alternative_requirements,
                trust_profile_id=protocol_data.get("trust_profile_id"),
                holder_binding=HolderBinding(**(protocol_data.get("holder_binding") or {})),
                freshness=FreshnessPolicy(**protocol_data["freshness"]) if protocol_data.get("freshness") else None,
                issuer_constraints=IssuerConstraints(**protocol_data["issuer_constraints"]) if protocol_data.get("issuer_constraints") else None,
                credential_ranking_strategy=protocol_data.get("credential_ranking_strategy", "FRESHEST_FIRST"),
                credential_ranking_weights=protocol_data.get("credential_ranking_weights"),
                purpose=protocol_data.get("purpose") or display_metadata.purpose_description,
                compliance_profile_id=row.compliance_profile_id,
                version=row.version,
                created_at=row.created_at,
                updated_at=row.updated_at,
            )
    
    async def list(self, org_id: str) -> list["PresentationPolicy"]:
        """List all presentation policies for an organization."""
        from presentation_policy.main import (
            PresentationPolicy, PolicyStatus, DisplayMetadata, CredentialRequirement,
            AlternativeRequirement, RequestedClaim, ClaimConstraint, RequestPurpose, ConstraintType,
            HolderBinding, FreshnessPolicy, IssuerConstraints
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
                protocol_data = display_data.get("protocol", {}) if isinstance(display_data, dict) else {}
                _purpose_raw2 = display_data.get("purpose", "identity_verification")
                try:
                    _purpose2 = RequestPurpose(_purpose_raw2)
                except ValueError:
                    _purpose2 = RequestPurpose.IDENTITY_VERIFICATION
                display_metadata = DisplayMetadata(
                    title=display_data.get("title", ""),
                    description=display_data.get("description", ""),
                    purpose=_purpose2,
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
                                predicate_spec=claim_data.get("predicate_spec"),
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
                                    predicate_spec=claim_data.get("predicate_spec"),
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
                        required_claims=[],
                        accepted_credential_types=protocol_data.get("accepted_credential_types") or [req.credential_template_id for req in credential_requirements if req.credential_template_id],
                        credential_requirements=credential_requirements,
                        alternative_requirements=alternative_requirements,
                        trust_profile_id=protocol_data.get("trust_profile_id"),
                        holder_binding=HolderBinding(**(protocol_data.get("holder_binding") or {})),
                        freshness=FreshnessPolicy(**protocol_data["freshness"]) if protocol_data.get("freshness") else None,
                        issuer_constraints=IssuerConstraints(**protocol_data["issuer_constraints"]) if protocol_data.get("issuer_constraints") else None,
                        credential_ranking_strategy=protocol_data.get("credential_ranking_strategy", "FRESHEST_FIRST"),
                        credential_ranking_weights=protocol_data.get("credential_ranking_weights"),
                        purpose=protocol_data.get("purpose") or display_metadata.purpose_description,
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
