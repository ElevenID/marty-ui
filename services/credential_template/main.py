"""
Credential Template Service

Manages Credential Templates - the blueprint for what credentials
can be issued and their structure.

A Credential Template defines:
- Display metadata (name, description, visual styling)
- Claims schema (what data the credential contains)
- Privacy posture (selective disclosure, derived attributes)
- Validity rules (expiration, refresh)
- Format-specific settings (SD-JWT, mdoc)

Port: 8003
"""

from __future__ import annotations

import logging
import os
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, AsyncGenerator

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from credential_template.infrastructure.adapters import PostgresCredentialTemplateRepository

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SERVICE_NAME = "credential-template-service"
SERVICE_PORT = int(os.environ.get("CREDENTIAL_TEMPLATE_SERVICE_PORT", "8003"))


def get_config() -> dict:
    """Get service configuration from environment."""
    return {
        "database_url": os.environ.get(
            "DATABASE_URL",
            "postgresql+asyncpg://marty:marty_dev@localhost:5432/marty_credentials"
        ),
    }


# =============================================================================
# Domain Layer
# =============================================================================

class TemplateStatus(str, Enum):
    """Credential template status."""
    DRAFT = "draft"
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    ARCHIVED = "archived"


class PrivacyPosture(str, Enum):
    """Privacy level for the credential."""
    STANDARD = "standard"           # No special privacy features
    SELECTIVE_DISCLOSURE = "selective_disclosure"  # SD-JWT style
    ZERO_KNOWLEDGE = "zero_knowledge"  # ZKP-enabled
    MINIMAL = "minimal"             # Derived attributes only


class ClaimType(str, Enum):
    """Supported claim data types."""
    STRING = "string"
    INTEGER = "integer"
    BOOLEAN = "boolean"
    DATE = "date"
    DATETIME = "datetime"
    OBJECT = "object"
    ARRAY = "array"
    IMAGE = "image"  # base64 or URL
    BINARY = "binary"


class CredentialFormat(str, Enum):
    """Supported credential formats."""
    SD_JWT_VC = "sd_jwt_vc"
    MDOC = "mdoc"
    JWT_VC = "jwt_vc"
    JSON_LD_VC = "json_ld_vc"


@dataclass
class ClaimDefinition:
    """
    Definition of a claim within a credential.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    display_name: str = ""
    description: str | None = None
    claim_type: ClaimType = ClaimType.STRING
    required: bool = True
    
    # Privacy settings
    selectively_disclosable: bool = True  # Can be disclosed individually
    derivable: bool = False  # Can derive predicates (e.g., age > 21)
    
    # Validation
    pattern: str | None = None  # Regex for validation
    enum_values: list[str] | None = None  # Allowed values
    min_value: float | None = None
    max_value: float | None = None
    
    # Format-specific
    mdoc_namespace: str | None = None  # For mdoc: org.iso.18013.5.1
    mdoc_element_identifier: str | None = None


@dataclass
class DisplayStyle:
    """
    Visual styling for credential display.
    """
    background_color: str = "#1a1a2e"
    text_color: str = "#ffffff"
    logo_url: str | None = None
    background_image_url: str | None = None
    icon: str | None = None


@dataclass
class ValidityRules:
    """
    Rules for credential validity.
    """
    default_validity_days: int = 365
    max_validity_days: int = 1095  # 3 years
    renewable: bool = True
    renewal_window_days: int = 30  # Can renew 30 days before expiry
    require_revalidation: bool = False
    revalidation_interval_days: int | None = None


@dataclass
class IssuerRequirements:
    """Requirements for the issuer."""
    allowed_issuer_dids: list[str] = field(default_factory=list)
    trust_tier_required: str | None = None
    audit_level_required: str | None = None


@dataclass
class DerivedAttribute:
    """
    An attribute that can be derived from credential claims.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str | None = None
    source_claim: str = ""  # The claim to derive from
    derivation_type: str = ""  # age_over, range, presence, etc.
    parameters: dict[str, Any] = field(default_factory=dict)


@dataclass
class CredentialTemplate:
    """
    Credential Template - blueprint for credential issuance.
    
    This defines the structure and rules for a type of credential.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str = ""
    name: str = ""
    description: str | None = None
    status: TemplateStatus = TemplateStatus.DRAFT
    
    # Type identifiers
    credential_type: str = ""  # e.g., "VerifiedEmployeeCredential"
    vct: str = ""  # Verifiable Credential Type URI
    doctype: str = ""  # For mdoc: org.iso.18013.5.1.mDL
    
    # Schema
    claims: list[ClaimDefinition] = field(default_factory=list)
    
    # Privacy
    privacy_posture: PrivacyPosture = PrivacyPosture.SELECTIVE_DISCLOSURE
    selective_disclosure_fields: list[str] = field(default_factory=list)
    derived_attributes: list[DerivedAttribute] = field(default_factory=list)
    
    # Display
    display_style: DisplayStyle = field(default_factory=DisplayStyle)
    
    # Validity
    validity_rules: ValidityRules = field(default_factory=ValidityRules)
    
    # Issuer Constraints
    issuer_requirements: IssuerRequirements = field(default_factory=IssuerRequirements)
    
    # Supported formats
    supported_formats: list[CredentialFormat] = field(
        default_factory=lambda: [CredentialFormat.SD_JWT_VC]
    )
    
    # Timestamps
    version: int = 1
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def activate(self) -> None:
        self.status = TemplateStatus.ACTIVE
        self.updated_at = datetime.now(timezone.utc)
    
    def deprecate(self) -> None:
        self.status = TemplateStatus.DEPRECATED
        self.updated_at = datetime.now(timezone.utc)
    
    def new_version(self) -> "CredentialTemplate":
        """Create a new draft version of this template."""
        new = CredentialTemplate(
            organization_id=self.organization_id,
            name=self.name,
            description=self.description,
            credential_type=self.credential_type,
            vct=self.vct,
            doctype=self.doctype,
            claims=self.claims.copy(),
            privacy_posture=self.privacy_posture,
            display_style=self.display_style,
            validity_rules=self.validity_rules,
            supported_formats=self.supported_formats.copy(),
            version=self.version + 1,
        )
        return new


# =============================================================================
# Application Layer
# =============================================================================

class InMemoryCredentialTemplateRepository:
    """In-memory repository for development."""
    
    def __init__(self):
        self._templates: dict[str, CredentialTemplate] = {}
    
    async def save(self, template: CredentialTemplate) -> None:
        self._templates[template.id] = template
    
    async def get(self, template_id: str) -> CredentialTemplate | None:
        return self._templates.get(template_id)
    
    async def list(self, org_id: str, status: TemplateStatus | None = None) -> list[CredentialTemplate]:
        templates = [t for t in self._templates.values() if t.organization_id == org_id]
        if status:
            templates = [t for t in templates if t.status == status]
        return templates
    
    async def delete(self, template_id: str) -> None:
        self._templates.pop(template_id, None)


# =============================================================================
# HTTP Adapter - Request/Response Models
# =============================================================================

class ClaimDefinitionModel(BaseModel):
    name: str
    display_name: str
    description: str | None = None
    claim_type: str = "string"
    required: bool = True
    selectively_disclosable: bool = True
    derivable: bool = False
    pattern: str | None = None
    enum_values: list[str] | None = None
    min_value: float | None = None
    max_value: float | None = None
    mdoc_namespace: str | None = None
    mdoc_element_identifier: str | None = None


class DisplayStyleModel(BaseModel):
    background_color: str = "#1a1a2e"
    text_color: str = "#ffffff"
    logo_url: str | None = None
    background_image_url: str | None = None
    icon: str | None = None


class ValidityRulesModel(BaseModel):
    default_validity_days: int = 365
    max_validity_days: int = 1095
    renewable: bool = True
    renewal_window_days: int = 30
    require_revalidation: bool = False
    revalidation_interval_days: int | None = None


class IssuerRequirementsModel(BaseModel):
    allowed_issuer_dids: list[str] = []
    trust_tier_required: str | None = None
    audit_level_required: str | None = None


class DerivedAttributeModel(BaseModel):
    name: str
    description: str | None = None
    source_claim: str
    derivation_type: str  # age_over, range, presence
    parameters: dict = {}


class CreateCredentialTemplateRequest(BaseModel):
    organization_id: str
    name: str
    description: str | None = None
    credential_type: str
    vct: str | None = None
    doctype: str | None = None
    claims: list[ClaimDefinitionModel] = []
    privacy_posture: str = "selective_disclosure"
    selective_disclosure_fields: list[str] = []
    derived_attributes: list[DerivedAttributeModel] = []
    display_style: DisplayStyleModel | None = None
    validity_rules: ValidityRulesModel | None = None
    issuer_requirements: IssuerRequirementsModel | None = None
    supported_formats: list[str] = ["sd_jwt_vc"]


class UpdateCredentialTemplateRequest(BaseModel):
    name: str | None = None
    description: str | None = None
    claims: list[ClaimDefinitionModel] | None = None
    privacy_posture: str | None = None
    selective_disclosure_fields: list[str] | None = None
    derived_attributes: list[DerivedAttributeModel] | None = None
    display_style: DisplayStyleModel | None = None
    validity_rules: ValidityRulesModel | None = None
    issuer_requirements: IssuerRequirementsModel | None = None
    supported_formats: list[str] | None = None


class CredentialTemplateResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    description: str | None
    status: str
    credential_type: str
    vct: str
    doctype: str
    claims: list[dict]
    privacy_posture: str
    selective_disclosure_fields: list[str]
    derived_attributes: list[dict]
    display_style: dict
    validity_rules: dict
    issuer_requirements: dict
    supported_formats: list[str]
    version: int
    created_at: str
    updated_at: str


# =============================================================================
# HTTP Adapter - Router
# =============================================================================

router = APIRouter(prefix="/v1/credential-templates", tags=["credential-templates"])

_repo: InMemoryCredentialTemplateRepository | None = None


def get_repo() -> InMemoryCredentialTemplateRepository:
    if _repo is None:
        raise RuntimeError("Service not configured")
    return _repo


@router.post("", response_model=CredentialTemplateResponse)
async def create_credential_template(
    request: CreateCredentialTemplateRequest,
    repo: InMemoryCredentialTemplateRepository = Depends(get_repo),
) -> CredentialTemplateResponse:
    """Create a new Credential Template."""
    template = CredentialTemplate(
        organization_id=request.organization_id,
        name=request.name,
        description=request.description,
        credential_type=request.credential_type,
        vct=request.vct or f"https://credentials.example.com/{request.credential_type}",
        doctype=request.doctype or "",
        privacy_posture=PrivacyPosture(request.privacy_posture),
        selective_disclosure_fields=request.selective_disclosure_fields,
        supported_formats=[CredentialFormat(f) for f in request.supported_formats],
    )
    
    # Set claims
    for claim in request.claims:
        template.claims.append(ClaimDefinition(
            name=claim.name,
            display_name=claim.display_name,
            description=claim.description,
            claim_type=ClaimType(claim.claim_type),
            required=claim.required,
            selectively_disclosable=claim.selectively_disclosable,
            derivable=claim.derivable,
            pattern=claim.pattern,
            enum_values=claim.enum_values,
            min_value=claim.min_value,
            max_value=claim.max_value,
            mdoc_namespace=claim.mdoc_namespace,
            mdoc_element_identifier=claim.mdoc_element_identifier,
        ))
    
    # Set derived attributes
    for da in request.derived_attributes:
        template.derived_attributes.append(DerivedAttribute(
            name=da.name,
            description=da.description,
            source_claim=da.source_claim,
            derivation_type=da.derivation_type,
            parameters=da.parameters,
        ))
    
    # Set display style
    if request.display_style:
        template.display_style = DisplayStyle(
            background_color=request.display_style.background_color,
            text_color=request.display_style.text_color,
            logo_url=request.display_style.logo_url,
            background_image_url=request.display_style.background_image_url,
            icon=request.display_style.icon,
        )
    
    # Set validity rules
    if request.validity_rules:
        template.validity_rules = ValidityRules(
            default_validity_days=request.validity_rules.default_validity_days,
            max_validity_days=request.validity_rules.max_validity_days,
            renewable=request.validity_rules.renewable,
            renewal_window_days=request.validity_rules.renewal_window_days,
            require_revalidation=request.validity_rules.require_revalidation,
            revalidation_interval_days=request.validity_rules.revalidation_interval_days,
        )

    # Set issuer requirements
    if request.issuer_requirements:
        template.issuer_requirements = IssuerRequirements(
            allowed_issuer_dids=request.issuer_requirements.allowed_issuer_dids,
            trust_tier_required=request.issuer_requirements.trust_tier_required,
            audit_level_required=request.issuer_requirements.audit_level_required,
        )
    
    await repo.save(template)
    logger.info(f"Created Credential Template: {template.id}")
    return _template_to_response(template)


@router.get("", response_model=list[CredentialTemplateResponse])
async def list_credential_templates(
    organization_id: str = Query(..., description="Organization ID"),
    status: str | None = Query(None, description="Filter by status"),
    repo: InMemoryCredentialTemplateRepository = Depends(get_repo),
) -> list[CredentialTemplateResponse]:
    """List Credential Templates for an organization."""
    status_filter = TemplateStatus(status) if status else None
    templates = await repo.list(organization_id, status_filter)
    return [_template_to_response(t) for t in templates]


@router.get("/{template_id}", response_model=CredentialTemplateResponse)
async def get_credential_template(
    template_id: str,
    repo: InMemoryCredentialTemplateRepository = Depends(get_repo),
) -> CredentialTemplateResponse:
    """Get a Credential Template by ID."""
    template = await repo.get(template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Credential Template not found")
    return _template_to_response(template)


@router.patch("/{template_id}", response_model=CredentialTemplateResponse)
async def update_credential_template(
    template_id: str,
    request: UpdateCredentialTemplateRequest,
    repo: InMemoryCredentialTemplateRepository = Depends(get_repo),
) -> CredentialTemplateResponse:
    """Update a Credential Template (only allowed in draft status)."""
    template = await repo.get(template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Credential Template not found")
    
    if template.status != TemplateStatus.DRAFT:
        raise HTTPException(
            status_code=400, 
            detail="Only draft templates can be modified. Create a new version instead."
        )
    
    if request.name is not None:
        template.name = request.name
    if request.description is not None:
        template.description = request.description
    if request.privacy_posture is not None:
        template.privacy_posture = PrivacyPosture(request.privacy_posture)
    if request.selective_disclosure_fields is not None:
        template.selective_disclosure_fields = request.selective_disclosure_fields
    if request.supported_formats is not None:
        template.supported_formats = [CredentialFormat(f) for f in request.supported_formats]
    
    template.updated_at = datetime.now(timezone.utc)
    await repo.save(template)
    return _template_to_response(template)


@router.post("/{template_id}/activate", response_model=CredentialTemplateResponse)
async def activate_credential_template(
    template_id: str,
    repo: InMemoryCredentialTemplateRepository = Depends(get_repo),
) -> CredentialTemplateResponse:
    """Activate a Credential Template."""
    template = await repo.get(template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Credential Template not found")
    
    if not template.claims:
        raise HTTPException(status_code=400, detail="Template must have at least one claim")
    
    template.activate()
    await repo.save(template)
    return _template_to_response(template)


@router.post("/{template_id}/deprecate", response_model=CredentialTemplateResponse)
async def deprecate_credential_template(
    template_id: str,
    repo: InMemoryCredentialTemplateRepository = Depends(get_repo),
) -> CredentialTemplateResponse:
    """Deprecate a Credential Template."""
    template = await repo.get(template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Credential Template not found")
    template.deprecate()
    await repo.save(template)
    return _template_to_response(template)


@router.post("/{template_id}/new-version", response_model=CredentialTemplateResponse)
async def create_new_version(
    template_id: str,
    repo: InMemoryCredentialTemplateRepository = Depends(get_repo),
) -> CredentialTemplateResponse:
    """Create a new draft version from an existing template."""
    template = await repo.get(template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Credential Template not found")
    
    new_template = template.new_version()
    await repo.save(new_template)
    return _template_to_response(new_template)


@router.delete("/{template_id}")
async def delete_credential_template(
    template_id: str,
    repo: InMemoryCredentialTemplateRepository = Depends(get_repo),
) -> dict:
    """Delete a Credential Template (only allowed for drafts)."""
    template = await repo.get(template_id)
    if template and template.status != TemplateStatus.DRAFT:
        raise HTTPException(
            status_code=400, 
            detail="Only draft templates can be deleted. Deprecate active templates instead."
        )
    await repo.delete(template_id)
    return {"success": True}


# Claims sub-resource
@router.post("/{template_id}/claims", response_model=CredentialTemplateResponse)
async def add_claim(
    template_id: str,
    claim: ClaimDefinitionModel,
    repo: InMemoryCredentialTemplateRepository = Depends(get_repo),
) -> CredentialTemplateResponse:
    """Add a claim to a Credential Template."""
    template = await repo.get(template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Credential Template not found")
    
    if template.status != TemplateStatus.DRAFT:
        raise HTTPException(status_code=400, detail="Only draft templates can be modified")
    
    template.claims.append(ClaimDefinition(
        name=claim.name,
        display_name=claim.display_name,
        description=claim.description,
        claim_type=ClaimType(claim.claim_type),
        required=claim.required,
        selectively_disclosable=claim.selectively_disclosable,
        derivable=claim.derivable,
    ))
    
    template.updated_at = datetime.now(timezone.utc)
    await repo.save(template)
    return _template_to_response(template)


def _template_to_response(template: CredentialTemplate) -> CredentialTemplateResponse:
    return CredentialTemplateResponse(
        id=template.id,
        organization_id=template.organization_id,
        name=template.name,
        description=template.description,
        status=template.status.value,
        credential_type=template.credential_type,
        vct=template.vct,
        doctype=template.doctype,
        claims=[
            {
                "id": c.id,
                "name": c.name,
                "display_name": c.display_name,
                "description": c.description,
                "claim_type": c.claim_type.value,
                "required": c.required,
                "selectively_disclosable": c.selectively_disclosable,
                "derivable": c.derivable,
            }
            for c in template.claims
        ],
        privacy_posture=template.privacy_posture.value,
        selective_disclosure_fields=template.selective_disclosure_fields,
        derived_attributes=[
            {
                "id": da.id,
                "name": da.name,
                "source_claim": da.source_claim,
                "derivation_type": da.derivation_type,
                "parameters": da.parameters,
            }
            for da in template.derived_attributes
        ],
        display_style={
            "background_color": template.display_style.background_color,
            "text_color": template.display_style.text_color,
            "logo_url": template.display_style.logo_url,
            "background_image_url": template.display_style.background_image_url,
            "icon": template.display_style.icon,
        },
        validity_rules={
            "default_validity_days": template.validity_rules.default_validity_days,
            "max_validity_days": template.validity_rules.max_validity_days,
            "renewable": template.validity_rules.renewable,
            "renewal_window_days": template.validity_rules.renewal_window_days,
            "require_revalidation": template.validity_rules.require_revalidation,
        },
        issuer_requirements={
            "allowed_issuer_dids": template.issuer_requirements.allowed_issuer_dids,
            "trust_tier_required": template.issuer_requirements.trust_tier_required,
            "audit_level_required": template.issuer_requirements.audit_level_required,
        },
        supported_formats=[f.value for f in template.supported_formats],
        version=template.version,
        created_at=template.created_at.isoformat(),
        updated_at=template.updated_at.isoformat(),
    )


# =============================================================================
# Application Setup
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    global _repo
    logger.info(f"Starting {SERVICE_NAME}...")
    
    config = get_config()
    
    # Initialize database
    engine = create_async_engine(config["database_url"], echo=False)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    
    # Initialize repository
    _repo = PostgresCredentialTemplateRepository(session_factory)
    
    yield
    logger.info(f"Shutting down {SERVICE_NAME}...")


def create_app() -> FastAPI:
    app = FastAPI(
        title="Credential Template Service",
        description="Manages Credential Templates - blueprints for credential issuance",
        version="1.0.0",
        lifespan=lifespan,
    )
    
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    app.include_router(router)
    
    @app.get("/health")
    async def health_check() -> dict:
        return {"status": "healthy", "service": SERVICE_NAME}
    
    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=SERVICE_PORT, reload=False)
