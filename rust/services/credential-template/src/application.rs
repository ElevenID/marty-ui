use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

use crate::{
    normalize_payload_format, resolve_validity_rules, validate_claim_definitions,
    validate_credential_type, validate_protocol_requirements, ClaimDefinition, CredentialFormat,
    CredentialTemplate, CredentialTemplateError, CredentialTemplateRepositoryError,
    DerivedAttribute, DisplayStyle, IssuerRequirements, PostgresCredentialTemplateStore,
    PrivacyPosture, TemplateStatus, ValidityRules, ValidityRulesInput, WalletConfig,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuerIdentity {
    pub issuer_did: String,
    pub issuer_algorithm: String,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ControlPlaneError {
    #[error("CREDENTIAL_TEMPLATE.CONTROL_PLANE_UNAVAILABLE: {0}")]
    Unavailable(String),
    #[error("CREDENTIAL_TEMPLATE.MEMBERSHIP_REQUIRED")]
    MembershipRequired,
    #[error("CREDENTIAL_TEMPLATE.WALLET_ADMIN_REQUIRED")]
    WalletAdminRequired,
    #[error("CREDENTIAL_TEMPLATE.DESTINATION_ADMIN_REQUIRED")]
    DestinationAdminRequired,
    #[error("CREDENTIAL_TEMPLATE.ISSUER_DID_INVALID: {0}")]
    InvalidIssuer(String),
    #[error("CREDENTIAL_TEMPLATE.REVOCATION_PROFILE_INVALID: {0}")]
    InvalidRevocationProfile(String),
    #[error("CREDENTIAL_TEMPLATE.TRUST_PROFILE_REJECTED: {0}")]
    TrustProfileRejected(String),
}

#[async_trait]
pub trait CredentialTemplateControlPlane: Send + Sync {
    async fn require_membership(
        &self,
        user_id: &str,
        organization_id: &str,
    ) -> Result<(), ControlPlaneError>;

    async fn require_wallet_admin(
        &self,
        user_id: &str,
        organization_id: &str,
    ) -> Result<(), ControlPlaneError>;

    async fn require_destination_admin(
        &self,
        user_id: &str,
        organization_id: &str,
    ) -> Result<(), ControlPlaneError>;

    async fn organization_display_name(
        &self,
        organization_id: &str,
    ) -> Result<Option<String>, ControlPlaneError>;

    async fn resolve_active_issuer(
        &self,
        organization_id: &str,
        requested_issuer_did: Option<&str>,
        credential_format: &str,
    ) -> Result<IssuerIdentity, ControlPlaneError>;

    async fn require_active_revocation_profile(
        &self,
        organization_id: &str,
        revocation_profile_id: Option<&str>,
    ) -> Result<(), ControlPlaneError>;

    async fn require_trust_profile_accepts_issuer(
        &self,
        trust_profile_id: Option<&str>,
        issuer_did: &str,
    ) -> Result<(), ControlPlaneError>;
}

#[async_trait]
pub trait CredentialTemplateRepository: Send + Sync {
    async fn save(
        &self,
        template: &CredentialTemplate,
    ) -> Result<(), CredentialTemplateRepositoryError>;
    async fn by_id(
        &self,
        template_id: &str,
    ) -> Result<Option<CredentialTemplate>, CredentialTemplateRepositoryError>;
    async fn by_organization(
        &self,
        organization_id: &str,
        status: Option<TemplateStatus>,
    ) -> Result<Vec<CredentialTemplate>, CredentialTemplateRepositoryError>;
    async fn all_internal(
        &self,
        status: Option<TemplateStatus>,
    ) -> Result<Vec<CredentialTemplate>, CredentialTemplateRepositoryError>;
    async fn delete(&self, template_id: &str) -> Result<bool, CredentialTemplateRepositoryError>;
}

#[async_trait]
impl CredentialTemplateRepository for PostgresCredentialTemplateStore {
    async fn save(
        &self,
        template: &CredentialTemplate,
    ) -> Result<(), CredentialTemplateRepositoryError> {
        self.save_template(template).await
    }

    async fn by_id(
        &self,
        template_id: &str,
    ) -> Result<Option<CredentialTemplate>, CredentialTemplateRepositoryError> {
        self.template_by_id(template_id).await
    }

    async fn by_organization(
        &self,
        organization_id: &str,
        status: Option<TemplateStatus>,
    ) -> Result<Vec<CredentialTemplate>, CredentialTemplateRepositoryError> {
        self.templates_by_organization(organization_id, status)
            .await
    }

    async fn all_internal(
        &self,
        status: Option<TemplateStatus>,
    ) -> Result<Vec<CredentialTemplate>, CredentialTemplateRepositoryError> {
        self.templates_all_internal(status).await
    }

    async fn delete(&self, template_id: &str) -> Result<bool, CredentialTemplateRepositoryError> {
        self.delete_template(template_id).await
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct CreateTemplateCommand {
    pub user_id: String,
    pub organization_id: String,
    pub name: String,
    pub description: Option<String>,
    pub credential_type: String,
    pub vct: Option<String>,
    pub doctype: Option<String>,
    pub claims: Vec<ClaimDefinition>,
    pub privacy_posture: PrivacyPosture,
    pub selective_disclosure_fields: Vec<String>,
    pub zk_predicate_claims: Vec<String>,
    pub derived_attributes: Vec<DerivedAttribute>,
    pub display_style: Option<DisplayStyle>,
    pub validity_rules: Option<ValidityRules>,
    pub supported_formats: Vec<CredentialFormat>,
    pub application_template_id: Option<String>,
    pub trust_profile_id: Option<String>,
    pub revocation_profile_id: Option<String>,
    pub compliance_profile: Option<Value>,
    pub compliance_profile_id: String,
    pub issuer_did: Option<String>,
    pub credential_payload_format: Option<String>,
    pub now: DateTime<Utc>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct UpdateTemplatePatch {
    pub name: Option<String>,
    pub description: Option<String>,
    pub claims: Option<Vec<ClaimDefinition>>,
    pub privacy_posture: Option<PrivacyPosture>,
    pub selective_disclosure_fields: Option<Vec<String>>,
    pub zk_predicate_claims: Option<Vec<String>>,
    pub derived_attributes: Option<Vec<DerivedAttribute>>,
    pub display_style: Option<DisplayStyle>,
    pub validity_rules: Option<ValidityRulesInput>,
    pub supported_formats: Option<Vec<CredentialFormat>>,
    pub application_template_id: Option<String>,
    pub trust_profile_id: Option<String>,
    pub revocation_profile_id: Option<String>,
    pub issuer_did: Option<String>,
    pub credential_payload_format: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct UpdateTemplateCommand {
    pub user_id: String,
    pub template_id: String,
    pub patch: UpdateTemplatePatch,
    pub now: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CredentialConfigurations {
    pub configurations: BTreeMap<String, Value>,
    pub issuer_display_name: Option<String>,
}

#[derive(Clone)]
pub struct CredentialTemplateApplication {
    repository: Arc<dyn CredentialTemplateRepository>,
    control_plane: Arc<dyn CredentialTemplateControlPlane>,
}

impl CredentialTemplateApplication {
    #[must_use]
    pub fn new(
        repository: Arc<dyn CredentialTemplateRepository>,
        control_plane: Arc<dyn CredentialTemplateControlPlane>,
    ) -> Self {
        Self {
            repository,
            control_plane,
        }
    }

    pub async fn create_template(
        &self,
        command: CreateTemplateCommand,
    ) -> Result<CredentialTemplate, CredentialTemplateApplicationError> {
        validate_create_command(&command)?;
        self.control_plane
            .require_membership(&command.user_id, &command.organization_id)
            .await?;
        let payload_format = normalize_payload_format(
            command.credential_payload_format.as_deref(),
            &command.supported_formats,
        )?;
        validate_protocol_requirements(
            Some(&command.compliance_profile_id),
            payload_format,
            command.vct.as_deref(),
            command.doctype.as_deref(),
        )?;
        let issuer = self
            .control_plane
            .resolve_active_issuer(
                &command.organization_id,
                command.issuer_did.as_deref(),
                payload_format.public_wire(),
            )
            .await?;
        let template = CredentialTemplate {
            id: Uuid::new_v4().to_string(),
            organization_id: command.organization_id,
            name: command.name,
            description: command.description,
            status: TemplateStatus::Draft,
            credential_type: command.credential_type,
            vct: command.vct.unwrap_or_default(),
            doctype: command.doctype,
            claims: command.claims,
            privacy_posture: command.privacy_posture,
            selective_disclosure_fields: command.selective_disclosure_fields,
            zk_predicate_claims: command.zk_predicate_claims,
            derived_attributes: command.derived_attributes,
            display_style: command.display_style.unwrap_or_default(),
            validity_rules: command.validity_rules.unwrap_or_default(),
            issuer_requirements: IssuerRequirements::default(),
            supported_formats: command.supported_formats,
            credential_payload_format: payload_format.canonical().to_owned(),
            wallet_configs: Vec::<WalletConfig>::new(),
            compliance_profile: command.compliance_profile,
            compliance_profile_id: Some(command.compliance_profile_id),
            application_template_id: command.application_template_id,
            trust_profile_id: command.trust_profile_id,
            revocation_profile_id: command.revocation_profile_id,
            issuer_algorithm: Some(issuer.issuer_algorithm),
            issuer_did: Some(issuer.issuer_did),
            issuance_protocol: "oid4vci".to_owned(),
            version: 1,
            created_at: command.now,
            updated_at: command.now,
        };
        self.repository.save(&template).await?;
        Ok(template)
    }

    pub async fn get_template(
        &self,
        user_id: &str,
        template_id: &str,
    ) -> Result<CredentialTemplate, CredentialTemplateApplicationError> {
        let template = self.load(template_id).await?;
        self.require_membership(user_id, &template).await?;
        Ok(template)
    }

    pub async fn list_templates(
        &self,
        user_id: &str,
        organization_id: &str,
        status: Option<TemplateStatus>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<CredentialTemplate>, CredentialTemplateApplicationError> {
        self.control_plane
            .require_membership(user_id, organization_id)
            .await?;
        let templates = self
            .repository
            .by_organization(organization_id, status)
            .await?;
        Ok(templates
            .into_iter()
            .filter(|template| {
                template.status != TemplateStatus::Deprecated
                    || managed_issuer_did(template).is_some()
            })
            .skip(offset)
            .take(limit.min(500))
            .collect())
    }

    pub async fn update_template(
        &self,
        command: UpdateTemplateCommand,
    ) -> Result<CredentialTemplate, CredentialTemplateApplicationError> {
        let current = self.load(&command.template_id).await?;
        self.require_membership(&command.user_id, &current).await?;
        current.ensure_draft_mutation()?;
        let mut candidate = apply_update(current, command.patch, command.now)?;
        let payload_format = normalize_payload_format(
            Some(&candidate.credential_payload_format),
            &candidate.supported_formats,
        )?;
        validate_protocol_requirements(
            candidate.compliance_profile_id.as_deref(),
            payload_format,
            Some(&candidate.vct),
            candidate.doctype.as_deref(),
        )?;
        let issuer = self
            .control_plane
            .resolve_active_issuer(
                &candidate.organization_id,
                candidate.issuer_did.as_deref(),
                payload_format.public_wire(),
            )
            .await?;
        candidate.credential_payload_format = payload_format.canonical().to_owned();
        candidate.issuer_did = Some(issuer.issuer_did);
        candidate.issuer_algorithm = Some(issuer.issuer_algorithm);
        self.repository.save(&candidate).await?;
        Ok(candidate)
    }

    pub async fn activate_template(
        &self,
        user_id: &str,
        template_id: &str,
        now: DateTime<Utc>,
    ) -> Result<CredentialTemplate, CredentialTemplateApplicationError> {
        let mut template = self.load(template_id).await?;
        self.require_membership(user_id, &template).await?;
        let payload_format = normalize_payload_format(
            Some(&template.credential_payload_format),
            &template.supported_formats,
        )?;
        validate_protocol_requirements(
            template.compliance_profile_id.as_deref(),
            payload_format,
            Some(&template.vct),
            template.doctype.as_deref(),
        )?;
        self.control_plane
            .require_active_revocation_profile(
                &template.organization_id,
                template.revocation_profile_id.as_deref(),
            )
            .await?;
        let issuer = self
            .control_plane
            .resolve_active_issuer(
                &template.organization_id,
                template.issuer_did.as_deref(),
                payload_format.public_wire(),
            )
            .await?;
        self.control_plane
            .require_trust_profile_accepts_issuer(
                template.trust_profile_id.as_deref(),
                &issuer.issuer_did,
            )
            .await?;
        template.issuer_did = Some(issuer.issuer_did);
        template.issuer_algorithm = Some(issuer.issuer_algorithm);
        template.activate(now)?;
        self.repository.save(&template).await?;
        Ok(template)
    }

    pub async fn deprecate_template(
        &self,
        user_id: &str,
        template_id: &str,
        now: DateTime<Utc>,
    ) -> Result<CredentialTemplate, CredentialTemplateApplicationError> {
        let mut template = self.load(template_id).await?;
        self.require_membership(user_id, &template).await?;
        template.deprecate(now);
        self.repository.save(&template).await?;
        Ok(template)
    }

    pub async fn new_version(
        &self,
        user_id: &str,
        template_id: &str,
        now: DateTime<Utc>,
    ) -> Result<CredentialTemplate, CredentialTemplateApplicationError> {
        let template = self.load(template_id).await?;
        self.require_membership(user_id, &template).await?;
        managed_issuer_did(&template)
            .ok_or(CredentialTemplateApplicationError::ManagedIssuerRequired)?;
        let version = template.new_version(Uuid::new_v4().to_string(), now);
        self.repository.save(&version).await?;
        Ok(version)
    }

    pub async fn delete_template(
        &self,
        user_id: &str,
        template_id: &str,
    ) -> Result<(), CredentialTemplateApplicationError> {
        let template = self.load(template_id).await?;
        self.require_membership(user_id, &template).await?;
        template.ensure_deletable()?;
        if !self.repository.delete(template_id).await? {
            return Err(CredentialTemplateApplicationError::NotFound(
                template_id.to_owned(),
            ));
        }
        Ok(())
    }

    pub async fn add_claim(
        &self,
        user_id: &str,
        template_id: &str,
        claim: ClaimDefinition,
        now: DateTime<Utc>,
    ) -> Result<CredentialTemplate, CredentialTemplateApplicationError> {
        let mut template = self.load(template_id).await?;
        self.require_membership(user_id, &template).await?;
        template.add_claim(claim, now)?;
        self.repository.save(&template).await?;
        Ok(template)
    }

    pub async fn active_templates_internal(
        &self,
    ) -> Result<Vec<CredentialTemplate>, CredentialTemplateApplicationError> {
        Ok(self
            .repository
            .all_internal(Some(TemplateStatus::Active))
            .await?)
    }

    pub async fn template_internal(
        &self,
        template_id: &str,
    ) -> Result<CredentialTemplate, CredentialTemplateApplicationError> {
        self.load(template_id).await
    }

    pub async fn credential_configurations_internal(
        &self,
    ) -> Result<CredentialConfigurations, CredentialTemplateApplicationError> {
        let templates = self.active_templates_internal().await?;
        let mut configurations = BTreeMap::new();
        let mut first_organization_id = None;
        for template in templates {
            if managed_issuer_did(&template).is_none() {
                continue;
            }
            let Some((credential_type, configuration)) = oid4vci_configuration(&template)? else {
                continue;
            };
            first_organization_id.get_or_insert_with(|| template.organization_id.clone());
            configurations.insert(credential_type, configuration);
        }
        let issuer_display_name = if let Some(organization_id) = first_organization_id {
            self.control_plane
                .organization_display_name(&organization_id)
                .await
                .unwrap_or(None)
        } else {
            None
        };
        Ok(CredentialConfigurations {
            configurations,
            issuer_display_name,
        })
    }

    async fn load(
        &self,
        template_id: &str,
    ) -> Result<CredentialTemplate, CredentialTemplateApplicationError> {
        self.repository
            .by_id(template_id)
            .await?
            .ok_or_else(|| CredentialTemplateApplicationError::NotFound(template_id.to_owned()))
    }

    async fn require_membership(
        &self,
        user_id: &str,
        template: &CredentialTemplate,
    ) -> Result<(), CredentialTemplateApplicationError> {
        self.control_plane
            .require_membership(user_id, &template.organization_id)
            .await?;
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum CredentialTemplateApplicationError {
    #[error("CREDENTIAL_TEMPLATE.APPLICATION_INVALID_COMMAND: {0}")]
    InvalidCommand(&'static str),
    #[error("CREDENTIAL_TEMPLATE.NOT_FOUND: {0}")]
    NotFound(String),
    #[error("CREDENTIAL_TEMPLATE.WALLET_NOT_FOUND: {0}")]
    WalletNotFound(String),
    #[error("CREDENTIAL_TEMPLATE.DESTINATION_NOT_FOUND: {0}")]
    DestinationNotFound(String),
    #[error("CREDENTIAL_TEMPLATE.SYSTEM_WALLET_READ_ONLY")]
    SystemWalletReadOnly,
    #[error("CREDENTIAL_TEMPLATE.SYSTEM_DESTINATION_READ_ONLY")]
    SystemDestinationReadOnly,
    #[error("CREDENTIAL_TEMPLATE.OWNERSHIP_TRANSFER_FORBIDDEN")]
    OwnershipTransferForbidden,
    #[error("CREDENTIAL_TEMPLATE.DEEP_LINKS_UNSUPPORTED")]
    DeepLinksUnsupported,
    #[error("CREDENTIAL_TEMPLATE.ALREADY_EXISTS: {0}")]
    AlreadyExists(String),
    #[error("CREDENTIAL_TEMPLATE.MANAGED_ISSUER_REQUIRED")]
    ManagedIssuerRequired,
    #[error(transparent)]
    Domain(#[from] CredentialTemplateError),
    #[error(transparent)]
    ControlPlane(#[from] ControlPlaneError),
    #[error(transparent)]
    Repository(#[from] CredentialTemplateRepositoryError),
}

fn validate_create_command(
    command: &CreateTemplateCommand,
) -> Result<(), CredentialTemplateApplicationError> {
    if command.user_id.trim().is_empty()
        || command.organization_id.trim().is_empty()
        || command.name.trim().is_empty()
        || command.name.len() > 255
        || command
            .description
            .as_ref()
            .is_some_and(|value| value.len() > 2_000)
        || command.compliance_profile_id.trim().is_empty()
    {
        return Err(CredentialTemplateApplicationError::InvalidCommand(
            "required field missing or outside its length bound",
        ));
    }
    validate_credential_type(&command.credential_type)?;
    if command.claims.is_empty() {
        return Err(CredentialTemplateError::MissingClaims.into());
    }
    validate_claim_definitions(&command.claims)?;
    Ok(())
}

fn oid4vci_configuration(
    template: &CredentialTemplate,
) -> Result<Option<(String, Value)>, CredentialTemplateApplicationError> {
    let credential_type = template.credential_type.trim();
    if credential_type.is_empty() {
        return Ok(None);
    }
    let format = normalize_payload_format(
        Some(&template.credential_payload_format),
        &template.supported_formats,
    )?;
    let algorithm = template
        .issuer_algorithm
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("ES256");
    let mut configuration = json_object(serde_json::json!({
        "scope":format!("{credential_type}_credential"),
        "cryptographic_binding_methods_supported":["jwk"],
        "credential_signing_alg_values_supported":[algorithm],
        "proof_types_supported":{
            "jwt":{"proof_signing_alg_values_supported":["ES256"]}
        },
        "credential_metadata":{
            "display":[{"name":non_empty_value(&template.name).unwrap_or(credential_type),"locale":"en-US"}]
        }
    }));
    match format {
        CredentialFormat::SdJwtVc => {
            let Some(vct) = non_empty_value(&template.vct) else {
                return Ok(None);
            };
            configuration.insert("format".to_owned(), Value::String("dc+sd-jwt".to_owned()));
            configuration.insert("vct".to_owned(), Value::String(vct.to_owned()));
        }
        CredentialFormat::Mdoc => {
            let doctype = template
                .doctype
                .as_deref()
                .and_then(non_empty_value)
                .unwrap_or(credential_type);
            configuration.insert("format".to_owned(), Value::String("mso_mdoc".to_owned()));
            configuration.insert("doctype".to_owned(), Value::String(doctype.to_owned()));
        }
        CredentialFormat::VcJwt => {
            configuration.insert("format".to_owned(), Value::String("jwt_vc_json".to_owned()));
            configuration.insert(
                "credential_definition".to_owned(),
                serde_json::json!({"type":["VerifiableCredential",credential_type]}),
            );
        }
        CredentialFormat::JsonLd | CredentialFormat::ZkMdoc | CredentialFormat::VdsNc => {
            return Ok(None);
        }
    }
    Ok(Some((
        credential_type.to_owned(),
        Value::Object(configuration),
    )))
}

fn json_object(value: Value) -> serde_json::Map<String, Value> {
    value.as_object().cloned().unwrap_or_default()
}

fn non_empty_value(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}

fn apply_update(
    mut template: CredentialTemplate,
    patch: UpdateTemplatePatch,
    now: DateTime<Utc>,
) -> Result<CredentialTemplate, CredentialTemplateApplicationError> {
    if let Some(name) = patch.name {
        if name.trim().is_empty() || name.len() > 255 {
            return Err(CredentialTemplateApplicationError::InvalidCommand(
                "name is invalid",
            ));
        }
        template.name = name;
    }
    if let Some(description) = patch.description {
        if description.len() > 2_000 {
            return Err(CredentialTemplateApplicationError::InvalidCommand(
                "description is too long",
            ));
        }
        template.description = Some(description);
    }
    if let Some(claims) = patch.claims {
        if claims.is_empty() {
            return Err(CredentialTemplateError::MissingClaims.into());
        }
        validate_claim_definitions(&claims)?;
        template.claims = claims;
    }
    if let Some(value) = patch.privacy_posture {
        template.privacy_posture = value;
    }
    if let Some(value) = patch.selective_disclosure_fields {
        template.selective_disclosure_fields = value;
    }
    if let Some(value) = patch.zk_predicate_claims {
        template.zk_predicate_claims = value;
    }
    if let Some(value) = patch.derived_attributes {
        template.derived_attributes = value;
    }
    if let Some(value) = patch.display_style {
        template.display_style = value;
    }
    if let Some(value) = patch.validity_rules {
        template.validity_rules = resolve_validity_rules(&value, Some(&template.validity_rules))?;
    }
    if let Some(value) = patch.supported_formats {
        template.supported_formats = value;
    }
    if let Some(value) = patch.application_template_id {
        template.application_template_id = Some(value);
    }
    if let Some(value) = patch.trust_profile_id {
        template.trust_profile_id = Some(value);
    }
    if let Some(value) = patch.revocation_profile_id {
        template.revocation_profile_id = Some(value);
    }
    if let Some(value) = patch.issuer_did {
        template.issuer_did = Some(value);
    }
    if let Some(value) = patch.credential_payload_format {
        template.credential_payload_format = value;
    }
    template.updated_at = now;
    Ok(template)
}

fn managed_issuer_did(template: &CredentialTemplate) -> Option<&str> {
    template
        .issuer_did
        .as_deref()
        .map(str::trim)
        .filter(|value| value.starts_with("did:"))
}
