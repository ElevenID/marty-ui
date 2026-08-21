use std::{collections::BTreeSet, sync::Arc};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

use crate::{
    allowed_issuers_after_request, normalize_accreditations, normalize_jurisdictions,
    reject_private_custody_metadata, require_issuer_status_transition, CascadeRevocationPolicy,
    ComplianceStatus, IssuerEntity, IssuerEntityComplianceStatus, IssuerEntityType,
    OrganizationTrustProfile, RegistryImportSource, RegistryImportedIssuer, RegistryStatus,
    TimePolicy, TrustAnchorType, TrustDomainError, TrustFramework, TrustProfile,
    TrustProfileIssuer, TrustProfileRepository, TrustProfileRepositoryError, TrustRegistryEntry,
    TrustRelationshipStatus, TrustSource, ValidationRules,
};

const VALID_ALGORITHMS: &[&str] = &[
    "BBS_BLS12381_SHA256",
    "BBS_BLS12381_SHAKE256",
    "ES256",
    "ES384",
    "ES512",
    "EdDSA",
    "PS256",
    "PS384",
    "PS512",
    "RS256",
    "RS384",
    "RS512",
];
const VALID_FORMATS: &[&str] = &["JSON_LD", "MDOC", "SD_JWT_VC", "VC_JWT", "VDS_NC"];

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum TrustAuthorizationError {
    #[error("TRUST_PROFILE.MEMBERSHIP_REQUIRED")]
    MembershipRequired,
    #[error("TRUST_PROFILE.PERMISSION_REQUIRED: {resource}:{action}")]
    PermissionRequired {
        resource: &'static str,
        action: &'static str,
    },
    #[error("TRUST_PROFILE.CONTROL_PLANE_UNAVAILABLE")]
    Unavailable,
}

#[async_trait]
pub trait TrustProfileControlPlane: Send + Sync {
    async fn require_permission(
        &self,
        user_id: &str,
        organization_id: &str,
        resource: &'static str,
        action: &'static str,
    ) -> Result<(), TrustAuthorizationError>;
}

#[derive(Clone, Debug, Error, PartialEq)]
pub enum TrustProfileApplicationError {
    #[error("TRUST_PROFILE.NOT_FOUND: {0}")]
    NotFound(&'static str),
    #[error("TRUST_PROFILE.FORBIDDEN: {0}")]
    Forbidden(&'static str),
    #[error("TRUST_PROFILE.CONFLICT: {0}")]
    Conflict(&'static str),
    #[error("TRUST_PROFILE.INVALID: {0}")]
    Invalid(&'static str),
    #[error(transparent)]
    Authorization(#[from] TrustAuthorizationError),
    #[error(transparent)]
    Domain(#[from] TrustDomainError),
    #[error(transparent)]
    Repository(#[from] TrustProfileRepositoryError),
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum Change<T> {
    #[default]
    Unchanged,
    Set(T),
}

#[derive(Clone, Debug, PartialEq)]
pub struct CreateProfileInput {
    pub profile: TrustProfile,
    pub allowed_issuers_was_provided: bool,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ProfilePatch {
    pub name: Change<String>,
    pub description: Change<Option<String>>,
    pub profile_type: Change<crate::TrustProfileType>,
    pub compliance_status: Change<ComplianceStatus>,
    pub trust_sources: Change<Vec<TrustSource>>,
    pub validation_rules: Change<ValidationRules>,
    pub revocation_profile_id: Change<Option<String>>,
    pub time_policy: Change<TimePolicy>,
    pub supported_formats: Change<Vec<String>>,
    pub allowed_issuers: Change<Option<Vec<String>>>,
    pub denied_issuers: Change<Option<Vec<String>>>,
    pub system_issuer_overrides: Change<serde_json::Map<String, Value>>,
    pub compatible_compliance_codes: Change<Vec<String>>,
    pub verification_policy_set_id: Change<Option<String>>,
    pub auto_generated: Change<bool>,
    pub revocation_policy: Change<crate::RevocationPolicy>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct IssuerEntityPatch {
    pub display_name: Change<String>,
    pub description: Change<Option<String>>,
    pub issuer_type: Change<IssuerEntityType>,
    pub compliance_status: Change<IssuerEntityComplianceStatus>,
    pub accreditation_body: Change<Option<String>>,
    pub accreditations: Change<Vec<String>>,
    pub accreditation_date: Change<Option<DateTime<Utc>>>,
    pub valid_from: Change<DateTime<Utc>>,
    pub valid_until: Change<Option<DateTime<Utc>>>,
    pub trust_anchor_id: Change<Option<String>>,
    pub metadata: Change<Value>,
    pub revocation_reason: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct OrganizationProfilePatch {
    pub name: Change<String>,
    pub display_name: Change<Option<String>>,
    pub description: Change<Option<String>>,
    pub enabled: Change<bool>,
    pub use_case_tags: Change<Vec<String>>,
    pub compliance_status: Change<ComplianceStatus>,
    pub auto_generated: Change<bool>,
    pub revocation_policy: Change<Option<Value>>,
    pub time_policy: Change<Option<Value>>,
    pub allowed_algorithms: Change<Option<Vec<String>>>,
    pub allowed_formats: Change<Option<Vec<String>>>,
    pub allowed_issuers: Change<Option<Vec<String>>>,
    pub denied_issuers: Change<Option<Vec<String>>>,
    pub jurisdiction_filter: Change<Option<Vec<String>>>,
    pub metadata: Change<Value>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct RelationshipPatch {
    pub trust_level: Change<u8>,
    pub relationship_status: Change<TrustRelationshipStatus>,
    pub cascade_revocation_policy: Change<CascadeRevocationPolicy>,
    pub metadata: Change<Value>,
}

#[derive(Clone)]
pub struct TrustProfileApplication {
    repository: Arc<dyn TrustProfileRepository>,
    control_plane: Arc<dyn TrustProfileControlPlane>,
}

impl TrustProfileApplication {
    #[must_use]
    pub fn new(
        repository: Arc<dyn TrustProfileRepository>,
        control_plane: Arc<dyn TrustProfileControlPlane>,
    ) -> Self {
        Self {
            repository,
            control_plane,
        }
    }

    pub async fn create_profile(
        &self,
        user_id: &str,
        mut input: CreateProfileInput,
    ) -> Result<TrustProfile, TrustProfileApplicationError> {
        self.control_plane
            .require_permission(
                user_id,
                &input.profile.organization_id,
                "trust-profile",
                "create",
            )
            .await?;
        input.profile.allowed_issuers = allowed_issuers_after_request(
            None,
            input.profile.trust_sources.len(),
            input.allowed_issuers_was_provided,
            input.profile.allowed_issuers,
            false,
        );
        validate_profile(&input.profile)?;
        self.repository.save_profile(&input.profile, None).await?;
        Ok(input.profile)
    }

    pub async fn create_organization_profile(
        &self,
        user_id: &str,
        mut profile: OrganizationTrustProfile,
    ) -> Result<OrganizationTrustProfile, TrustProfileApplicationError> {
        self.control_plane
            .require_permission(user_id, &profile.organization_id, "trust-profile", "create")
            .await?;
        if self
            .repository
            .framework_by_id(profile.framework_id)
            .await?
            .is_none()
        {
            return Err(TrustProfileApplicationError::Invalid(
                "trust_framework_not_found",
            ));
        }
        validate_organization_profile(&mut profile)?;
        self.repository.save_organization_profile(&profile).await?;
        Ok(profile)
    }

    pub async fn organization_profiles(
        &self,
        user_id: &str,
        organization_id: &str,
    ) -> Result<Vec<OrganizationTrustProfile>, TrustProfileApplicationError> {
        self.control_plane
            .require_permission(user_id, organization_id, "trust-profile", "view")
            .await?;
        self.repository
            .organization_profiles(organization_id)
            .await
            .map_err(Into::into)
    }

    pub async fn organization_profile(
        &self,
        user_id: &str,
        organization_id: &str,
        profile_id: Uuid,
    ) -> Result<OrganizationTrustProfile, TrustProfileApplicationError> {
        let profile = self
            .repository
            .organization_profile_by_id(profile_id)
            .await?
            .filter(|profile| profile.organization_id == organization_id)
            .ok_or(TrustProfileApplicationError::NotFound(
                "organization_trust_profile",
            ))?;
        self.control_plane
            .require_permission(user_id, organization_id, "trust-profile", "view")
            .await?;
        Ok(profile)
    }

    pub async fn update_organization_profile(
        &self,
        user_id: &str,
        organization_id: &str,
        profile_id: Uuid,
        patch: OrganizationProfilePatch,
        now: DateTime<Utc>,
    ) -> Result<OrganizationTrustProfile, TrustProfileApplicationError> {
        let mut profile = self
            .repository
            .organization_profile_by_id(profile_id)
            .await?
            .filter(|profile| profile.organization_id == organization_id)
            .ok_or(TrustProfileApplicationError::NotFound(
                "organization_trust_profile",
            ))?;
        self.control_plane
            .require_permission(user_id, organization_id, "trust-profile", "edit")
            .await?;
        apply(&mut profile.name, patch.name);
        apply(&mut profile.display_name, patch.display_name);
        apply(&mut profile.description, patch.description);
        apply(&mut profile.enabled, patch.enabled);
        apply(&mut profile.use_case_tags, patch.use_case_tags);
        apply(&mut profile.compliance_status, patch.compliance_status);
        apply(&mut profile.auto_generated, patch.auto_generated);
        apply(&mut profile.revocation_policy, patch.revocation_policy);
        apply(&mut profile.time_policy, patch.time_policy);
        apply(&mut profile.allowed_algorithms, patch.allowed_algorithms);
        apply(&mut profile.allowed_formats, patch.allowed_formats);
        apply(&mut profile.allowed_issuers, patch.allowed_issuers);
        apply(&mut profile.denied_issuers, patch.denied_issuers);
        apply(&mut profile.jurisdiction_filter, patch.jurisdiction_filter);
        apply(&mut profile.metadata, patch.metadata);
        profile.updated_at = now;
        validate_organization_profile(&mut profile)?;
        self.repository.save_organization_profile(&profile).await?;
        Ok(profile)
    }

    pub async fn frameworks(&self) -> Result<Vec<TrustFramework>, TrustProfileApplicationError> {
        self.repository.frameworks().await.map_err(Into::into)
    }

    pub async fn framework(
        &self,
        framework_id: Uuid,
    ) -> Result<TrustFramework, TrustProfileApplicationError> {
        self.repository
            .framework_by_id(framework_id)
            .await?
            .ok_or(TrustProfileApplicationError::NotFound("trust_framework"))
    }

    pub async fn registry_entries(
        &self,
        anchor_type: Option<TrustAnchorType>,
        country_code: Option<&str>,
        current_only: bool,
        since_sequence: Option<u64>,
    ) -> Result<Vec<TrustRegistryEntry>, TrustProfileApplicationError> {
        self.repository
            .registry_entries(anchor_type, country_code, current_only, since_sequence)
            .await
            .map_err(Into::into)
    }

    pub async fn registry_status(&self) -> Result<RegistryStatus, TrustProfileApplicationError> {
        self.repository.registry_status().await.map_err(Into::into)
    }

    pub async fn profiles(
        &self,
        user_id: &str,
        organization_id: &str,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<TrustProfile>, TrustProfileApplicationError> {
        self.control_plane
            .require_permission(user_id, organization_id, "trust-profile", "view")
            .await?;
        Ok(self
            .repository
            .profiles_by_organization(organization_id)
            .await?
            .into_iter()
            .skip(offset)
            .take(limit.min(500))
            .collect())
    }

    pub async fn profile(
        &self,
        user_id: &str,
        profile_id: Uuid,
    ) -> Result<TrustProfile, TrustProfileApplicationError> {
        let profile = self.required_profile(profile_id).await?;
        self.control_plane
            .require_permission(user_id, &profile.organization_id, "trust-profile", "view")
            .await?;
        Ok(profile)
    }

    pub async fn update_profile(
        &self,
        user_id: &str,
        profile_id: Uuid,
        patch: ProfilePatch,
        now: DateTime<Utc>,
    ) -> Result<TrustProfile, TrustProfileApplicationError> {
        let mut profile = self.required_profile(profile_id).await?;
        self.control_plane
            .require_permission(user_id, &profile.organization_id, "trust-profile", "edit")
            .await?;

        apply(&mut profile.name, patch.name);
        apply(&mut profile.description, patch.description);
        apply(&mut profile.profile_type, patch.profile_type);
        apply(&mut profile.compliance_status, patch.compliance_status);
        let trust_sources_changed = matches!(patch.trust_sources, Change::Set(_));
        apply(&mut profile.trust_sources, patch.trust_sources);
        apply(&mut profile.validation_rules, patch.validation_rules);
        apply(
            &mut profile.revocation_profile_id,
            patch.revocation_profile_id,
        );
        apply(&mut profile.time_policy, patch.time_policy);
        apply(&mut profile.supported_formats, patch.supported_formats);
        let allowed_was_provided = matches!(patch.allowed_issuers, Change::Set(_));
        let requested_allowed = match patch.allowed_issuers {
            Change::Unchanged => None,
            Change::Set(value) => value,
        };
        profile.allowed_issuers = allowed_issuers_after_request(
            profile.allowed_issuers,
            profile.trust_sources.len(),
            allowed_was_provided,
            requested_allowed,
            trust_sources_changed,
        );
        apply(&mut profile.denied_issuers, patch.denied_issuers);
        apply(
            &mut profile.system_issuer_overrides,
            patch.system_issuer_overrides,
        );
        apply(
            &mut profile.compatible_compliance_codes,
            patch.compatible_compliance_codes,
        );
        apply(
            &mut profile.verification_policy_set_id,
            patch.verification_policy_set_id,
        );
        apply(&mut profile.auto_generated, patch.auto_generated);
        apply(&mut profile.revocation_policy, patch.revocation_policy);
        profile.updated_at = now;
        validate_profile(&profile)?;
        self.repository.save_profile(&profile, None).await?;
        Ok(profile)
    }

    pub async fn activate_profile(
        &self,
        user_id: &str,
        profile_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<TrustProfile, TrustProfileApplicationError> {
        let mut profile = self.required_profile(profile_id).await?;
        self.control_plane
            .require_permission(
                user_id,
                &profile.organization_id,
                "trust-profile",
                "activate",
            )
            .await?;
        validate_registry_sources_for_decision(&profile, now)?;
        profile.activate(now);
        self.repository.save_profile(&profile, None).await?;
        Ok(profile)
    }

    pub async fn suspend_profile(
        &self,
        user_id: &str,
        profile_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<TrustProfile, TrustProfileApplicationError> {
        let mut profile = self.required_profile(profile_id).await?;
        self.control_plane
            .require_permission(
                user_id,
                &profile.organization_id,
                "trust-profile",
                "suspend",
            )
            .await?;
        profile.suspend(now);
        self.repository.save_profile(&profile, None).await?;
        Ok(profile)
    }

    pub async fn delete_profile(
        &self,
        user_id: &str,
        profile_id: Uuid,
    ) -> Result<(), TrustProfileApplicationError> {
        let profile = self.required_profile(profile_id).await?;
        self.control_plane
            .require_permission(user_id, &profile.organization_id, "trust-profile", "delete")
            .await?;
        if !self
            .repository
            .profile_issuers(profile_id)
            .await?
            .is_empty()
        {
            return Err(TrustProfileApplicationError::Conflict(
                "profile_has_trusted_issuers",
            ));
        }
        self.repository.delete_profile(profile_id).await?;
        Ok(())
    }

    pub async fn create_issuer_entity(
        &self,
        user_id: &str,
        mut issuer: IssuerEntity,
    ) -> Result<IssuerEntity, TrustProfileApplicationError> {
        let organization_id =
            issuer
                .organization_id
                .as_deref()
                .ok_or(TrustProfileApplicationError::Invalid(
                    "organization_id_required",
                ))?;
        self.control_plane
            .require_permission(user_id, organization_id, "trusted-issuer", "create")
            .await?;
        if self
            .repository
            .issuer_entity_by_identifier(Some(organization_id), &issuer.issuer_id)
            .await?
            .is_some()
        {
            return Err(TrustProfileApplicationError::Conflict(
                "issuer_identifier_exists",
            ));
        }
        validate_issuer(&mut issuer)?;
        self.repository.save_issuer_entity(&issuer).await?;
        Ok(issuer)
    }

    pub async fn issuer_entities(
        &self,
        user_id: &str,
        organization_id: Option<&str>,
    ) -> Result<Vec<IssuerEntity>, TrustProfileApplicationError> {
        if let Some(organization_id) = organization_id {
            self.control_plane
                .require_permission(user_id, organization_id, "trusted-issuer", "view")
                .await?;
            return self
                .repository
                .issuer_entities(Some(organization_id))
                .await
                .map_err(Into::into);
        }
        Ok(self
            .repository
            .issuer_entities(None)
            .await?
            .into_iter()
            .filter(|issuer| issuer.is_system_issuer || issuer.organization_id.is_none())
            .collect())
    }

    pub async fn issuer_entity(
        &self,
        user_id: &str,
        issuer_id: Uuid,
    ) -> Result<IssuerEntity, TrustProfileApplicationError> {
        let issuer = self.required_issuer(issuer_id).await?;
        if let Some(organization_id) = &issuer.organization_id {
            self.control_plane
                .require_permission(user_id, organization_id, "trusted-issuer", "view")
                .await?;
        }
        Ok(issuer)
    }

    pub async fn update_issuer_entity(
        &self,
        user_id: &str,
        organization_id: &str,
        issuer_id: Uuid,
        patch: IssuerEntityPatch,
        now: DateTime<Utc>,
    ) -> Result<IssuerEntity, TrustProfileApplicationError> {
        let mut issuer = self.required_issuer(issuer_id).await?;
        if issuer.is_system_issuer || issuer.organization_id.is_none() {
            return Err(TrustProfileApplicationError::Forbidden(
                "system_or_global_issuer",
            ));
        }
        if issuer.organization_id.as_deref() != Some(organization_id) {
            return Err(TrustProfileApplicationError::NotFound("issuer_entity"));
        }
        self.control_plane
            .require_permission(user_id, organization_id, "trusted-issuer", "edit")
            .await?;
        apply(&mut issuer.display_name, patch.display_name);
        apply(&mut issuer.description, patch.description);
        apply(&mut issuer.issuer_type, patch.issuer_type);
        apply(&mut issuer.accreditation_body, patch.accreditation_body);
        apply(&mut issuer.accreditations, patch.accreditations);
        apply(&mut issuer.accreditation_date, patch.accreditation_date);
        apply(&mut issuer.valid_from, patch.valid_from);
        apply(&mut issuer.valid_until, patch.valid_until);
        apply(&mut issuer.trust_anchor_id, patch.trust_anchor_id);
        apply(&mut issuer.metadata, patch.metadata);
        if let Change::Set(next_status) = patch.compliance_status {
            require_issuer_status_transition(issuer.compliance_status, next_status)?;
            if next_status == IssuerEntityComplianceStatus::Revoked {
                let reason = patch
                    .revocation_reason
                    .filter(|value| !value.trim().is_empty())
                    .ok_or(TrustProfileApplicationError::Invalid(
                        "revocation_reason_required",
                    ))?;
                issuer.revoked_at = Some(now);
                issuer.revocation_reason = Some(reason);
                issuer.revoked_by = Some(user_id.into());
            } else if patch.revocation_reason.is_some() {
                return Err(TrustProfileApplicationError::Invalid(
                    "revocation_reason_without_revocation",
                ));
            }
            issuer.compliance_status = next_status;
        } else if patch.revocation_reason.is_some() {
            return Err(TrustProfileApplicationError::Invalid(
                "revocation_reason_without_revocation",
            ));
        }
        issuer.updated_at = now;
        validate_issuer(&mut issuer)?;
        self.repository.save_issuer_entity(&issuer).await?;
        Ok(issuer)
    }

    pub async fn delete_issuer_entity(
        &self,
        user_id: &str,
        issuer_id: Uuid,
    ) -> Result<(), TrustProfileApplicationError> {
        let issuer = self.required_issuer(issuer_id).await?;
        let organization_id =
            issuer
                .organization_id
                .as_deref()
                .ok_or(TrustProfileApplicationError::Forbidden(
                    "system_or_global_issuer",
                ))?;
        if issuer.is_system_issuer {
            return Err(TrustProfileApplicationError::Forbidden(
                "system_or_global_issuer",
            ));
        }
        self.control_plane
            .require_permission(user_id, organization_id, "trusted-issuer", "delete")
            .await?;
        self.repository.delete_issuer_entity(issuer_id).await?;
        Ok(())
    }

    pub async fn add_relationship(
        &self,
        user_id: &str,
        mut relationship: TrustProfileIssuer,
    ) -> Result<TrustProfileIssuer, TrustProfileApplicationError> {
        let profile = self.required_profile(relationship.trust_profile_id).await?;
        self.control_plane
            .require_permission(
                user_id,
                &profile.organization_id,
                "trusted-issuer",
                "create",
            )
            .await?;
        let issuer = self.required_issuer(relationship.issuer_id).await?;
        if issuer.organization_id.as_deref() != Some(&profile.organization_id)
            && !(issuer.organization_id.is_none() && issuer.is_system_issuer)
        {
            return Err(TrustProfileApplicationError::NotFound("issuer_entity"));
        }
        if self
            .repository
            .profile_issuer_by_pair(profile.id, issuer.id)
            .await?
            .is_some()
        {
            return Err(TrustProfileApplicationError::Conflict(
                "issuer_already_linked",
            ));
        }
        validate_relationship(&mut relationship)?;
        self.repository.save_profile_issuer(&relationship).await?;
        Ok(relationship)
    }

    pub async fn relationships(
        &self,
        user_id: &str,
        profile_id: Uuid,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<TrustProfileIssuer>, TrustProfileApplicationError> {
        let profile = self.required_profile(profile_id).await?;
        self.control_plane
            .require_permission(user_id, &profile.organization_id, "trusted-issuer", "view")
            .await?;
        let relationships = self.repository.profile_issuers(profile_id).await?;
        for relationship in &relationships {
            self.required_issuer(relationship.issuer_id).await?;
        }
        Ok(relationships
            .into_iter()
            .skip(offset)
            .take(limit.min(500))
            .collect())
    }

    pub async fn relationship(
        &self,
        user_id: &str,
        profile_id: Uuid,
        relationship_id: Uuid,
    ) -> Result<TrustProfileIssuer, TrustProfileApplicationError> {
        let relationship = self.required_relationship(relationship_id).await?;
        if relationship.trust_profile_id != profile_id {
            return Err(TrustProfileApplicationError::NotFound(
                "trusted_issuer_relationship",
            ));
        }
        let profile = self.required_profile(profile_id).await?;
        self.control_plane
            .require_permission(user_id, &profile.organization_id, "trusted-issuer", "view")
            .await?;
        self.required_issuer(relationship.issuer_id).await?;
        Ok(relationship)
    }

    pub async fn update_relationship(
        &self,
        user_id: &str,
        profile_id: Uuid,
        relationship_id: Uuid,
        patch: RelationshipPatch,
        now: DateTime<Utc>,
    ) -> Result<TrustProfileIssuer, TrustProfileApplicationError> {
        let profile = self.required_profile(profile_id).await?;
        self.control_plane
            .require_permission(user_id, &profile.organization_id, "trusted-issuer", "edit")
            .await?;
        let mut relationship = self.required_relationship(relationship_id).await?;
        if relationship.trust_profile_id != profile_id {
            return Err(TrustProfileApplicationError::NotFound(
                "trusted_issuer_relationship",
            ));
        }
        apply(&mut relationship.trust_level, patch.trust_level);
        apply(
            &mut relationship.relationship_status,
            patch.relationship_status,
        );
        apply(
            &mut relationship.cascade_revocation_policy,
            patch.cascade_revocation_policy,
        );
        apply(&mut relationship.metadata, patch.metadata);
        relationship.updated_at = now;
        validate_relationship(&mut relationship)?;
        self.repository.save_profile_issuer(&relationship).await?;
        Ok(relationship)
    }

    pub async fn delete_relationship(
        &self,
        user_id: &str,
        profile_id: Uuid,
        relationship_id: Uuid,
    ) -> Result<(), TrustProfileApplicationError> {
        let relationship = self.required_relationship(relationship_id).await?;
        if relationship.trust_profile_id != profile_id {
            return Err(TrustProfileApplicationError::NotFound(
                "trusted_issuer_relationship",
            ));
        }
        let profile = self.required_profile(profile_id).await?;
        self.control_plane
            .require_permission(
                user_id,
                &profile.organization_id,
                "trusted-issuer",
                "delete",
            )
            .await?;
        self.repository
            .delete_profile_issuer(relationship_id)
            .await?;
        Ok(())
    }

    pub async fn profile_owner(
        &self,
        profile_id: Uuid,
    ) -> Result<String, TrustProfileApplicationError> {
        Ok(self.required_profile(profile_id).await?.organization_id)
    }

    pub async fn issuer_owner(
        &self,
        issuer_id: Uuid,
    ) -> Result<String, TrustProfileApplicationError> {
        self.required_issuer(issuer_id)
            .await?
            .organization_id
            .ok_or(TrustProfileApplicationError::NotFound("issuer_entity"))
    }

    pub async fn save_registry_import_source(
        &self,
        user_id: &str,
        source: RegistryImportSource,
    ) -> Result<RegistryImportSource, TrustProfileApplicationError> {
        let profile = self.required_profile(source.trust_profile_id).await?;
        self.control_plane
            .require_permission(user_id, &profile.organization_id, "trust-profile", "edit")
            .await?;
        validate_registry_import_source(&source)?;
        self.repository.save_registry_import_source(&source).await?;
        Ok(source)
    }

    pub async fn save_registry_imported_issuer(
        &self,
        user_id: &str,
        issuer: RegistryImportedIssuer,
    ) -> Result<RegistryImportedIssuer, TrustProfileApplicationError> {
        let profile = self.required_profile(issuer.trust_profile_id).await?;
        self.control_plane
            .require_permission(user_id, &profile.organization_id, "trust-profile", "edit")
            .await?;
        let source = self
            .repository
            .registry_import_source_by_id(issuer.registry_source_id)
            .await?
            .ok_or(TrustProfileApplicationError::NotFound(
                "registry_import_source",
            ))?;
        if source.trust_profile_id != issuer.trust_profile_id {
            return Err(TrustProfileApplicationError::NotFound(
                "registry_import_source",
            ));
        }
        validate_registry_imported_issuer(&issuer)?;
        self.repository
            .save_registry_imported_issuer(&issuer)
            .await?;
        Ok(issuer)
    }

    pub async fn delete_registry_import_source(
        &self,
        user_id: &str,
        source_id: Uuid,
    ) -> Result<(), TrustProfileApplicationError> {
        let source = self
            .repository
            .registry_import_source_by_id(source_id)
            .await?
            .ok_or(TrustProfileApplicationError::NotFound(
                "registry_import_source",
            ))?;
        let profile = self.required_profile(source.trust_profile_id).await?;
        self.control_plane
            .require_permission(user_id, &profile.organization_id, "trust-profile", "edit")
            .await?;
        self.repository
            .delete_registry_import_source(source_id)
            .await?;
        Ok(())
    }

    async fn required_profile(
        &self,
        profile_id: Uuid,
    ) -> Result<TrustProfile, TrustProfileApplicationError> {
        self.repository
            .profile_by_id(profile_id)
            .await?
            .ok_or(TrustProfileApplicationError::NotFound("trust_profile"))
    }

    async fn required_issuer(
        &self,
        issuer_id: Uuid,
    ) -> Result<IssuerEntity, TrustProfileApplicationError> {
        self.repository
            .issuer_entity_by_id(issuer_id)
            .await?
            .ok_or(TrustProfileApplicationError::NotFound("issuer_entity"))
    }

    async fn required_relationship(
        &self,
        relationship_id: Uuid,
    ) -> Result<TrustProfileIssuer, TrustProfileApplicationError> {
        self.repository
            .profile_issuer_by_id(relationship_id)
            .await?
            .ok_or(TrustProfileApplicationError::NotFound(
                "trusted_issuer_relationship",
            ))
    }
}

fn apply<T>(target: &mut T, change: Change<T>) {
    if let Change::Set(value) = change {
        *target = value;
    }
}

fn validate_organization_profile(
    profile: &mut OrganizationTrustProfile,
) -> Result<(), TrustProfileApplicationError> {
    if profile.organization_id.trim().is_empty()
        || profile.name.trim().is_empty()
        || profile.name.chars().count() > 255
    {
        return Err(TrustProfileApplicationError::Invalid(
            "organization_trust_profile",
        ));
    }
    if profile
        .allowed_algorithms
        .as_ref()
        .is_some_and(|algorithms| {
            algorithms.is_empty()
                || algorithms
                    .iter()
                    .any(|value| !VALID_ALGORITHMS.contains(&value.as_str()))
        })
    {
        return Err(TrustProfileApplicationError::Invalid("allowed_algorithms"));
    }
    if profile.allowed_formats.as_ref().is_some_and(|formats| {
        formats.is_empty()
            || formats
                .iter()
                .any(|value| !VALID_FORMATS.contains(&value.as_str()))
    }) {
        return Err(TrustProfileApplicationError::Invalid("allowed_formats"));
    }
    if let Some(jurisdictions) = profile.jurisdiction_filter.take() {
        profile.jurisdiction_filter = Some(normalize_jurisdictions(jurisdictions)?);
    }
    reject_private_custody_metadata(&profile.metadata)?;
    Ok(())
}

fn validate_profile(profile: &TrustProfile) -> Result<(), TrustProfileApplicationError> {
    if profile.organization_id.trim().is_empty() {
        return Err(TrustProfileApplicationError::Invalid("organization_id"));
    }
    if profile.name.trim().is_empty() || profile.name.chars().count() > 255 {
        return Err(TrustProfileApplicationError::Invalid("name"));
    }
    if profile.supported_formats.is_empty()
        || profile
            .supported_formats
            .iter()
            .any(|value| !VALID_FORMATS.contains(&value.as_str()))
    {
        return Err(TrustProfileApplicationError::Invalid("supported_formats"));
    }
    let algorithms = &profile.validation_rules.allowed_algorithms;
    if algorithms.is_empty()
        || algorithms
            .iter()
            .any(|value| !VALID_ALGORITHMS.contains(&value.as_str()))
    {
        return Err(TrustProfileApplicationError::Invalid("allowed_algorithms"));
    }
    for source in &profile.trust_sources {
        validate_trust_source(source)?;
    }
    Ok(())
}

fn validate_trust_source(source: &TrustSource) -> Result<(), TrustProfileApplicationError> {
    let selector_count = usize::from(source.url.is_some())
        + usize::from(source.certificate_pem.is_some())
        + usize::from(source.issuer_did.is_some());
    if selector_count != 1 {
        return Err(TrustProfileApplicationError::Invalid(
            "trust_source_identity",
        ));
    }
    if let Some(url) = &source.url {
        marty_verification::trust_sync::validate_registry_url(url)
            .map_err(|_| TrustProfileApplicationError::Invalid("trust_source_url"))?;
    }
    if source
        .certificate_pem
        .as_ref()
        .is_some_and(|value| !value.starts_with("-----BEGIN CERTIFICATE-----"))
    {
        return Err(TrustProfileApplicationError::Invalid(
            "trust_source_certificate",
        ));
    }
    if source
        .issuer_did
        .as_ref()
        .is_some_and(|value| !value.starts_with("did:"))
    {
        return Err(TrustProfileApplicationError::Invalid(
            "trust_source_issuer_did",
        ));
    }
    let registry_type = matches!(
        source.source_type,
        crate::TrustSourceType::TrustList | crate::TrustSourceType::PkdUrl
    );
    match (&source.registry_sync, source.url.is_some(), registry_type) {
        (Some(config), true, true) => {
            validate_registry_sync_config(config)?;
        }
        (Some(_), _, _) => {
            return Err(TrustProfileApplicationError::Invalid(
                "trust_source_registry_sync",
            ));
        }
        (None, true, true) => {
            return Err(TrustProfileApplicationError::Invalid(
                "trust_source_registry_protocol",
            ));
        }
        (None, _, _) => {}
    }
    Ok(())
}

pub(crate) fn validate_registry_sync_config(
    value: &Value,
) -> Result<u16, TrustProfileApplicationError> {
    let config = value
        .as_object()
        .ok_or(TrustProfileApplicationError::Invalid(
            "registry_sync_config",
        ))?;
    if config.len() != 2
        || config.get("protocol").and_then(Value::as_str)
            != Some(marty_verification::trust_sync::SYNC_PROTOCOL)
    {
        return Err(TrustProfileApplicationError::Invalid(
            "registry_sync_protocol",
        ));
    }
    let interval = config
        .get("refresh_interval_hours")
        .and_then(Value::as_u64)
        .and_then(|value| u16::try_from(value).ok())
        .filter(|value| (1..=720).contains(value))
        .ok_or(TrustProfileApplicationError::Invalid(
            "registry_sync_interval",
        ))?;
    Ok(interval)
}

pub(crate) fn validate_registry_sources_for_decision(
    profile: &TrustProfile,
    now: DateTime<Utc>,
) -> Result<(), TrustProfileApplicationError> {
    for source in profile.trust_sources.iter().filter(|source| source.enabled) {
        if source.registry_sync.is_none() {
            if source.url.is_some()
                && matches!(
                    source.source_type,
                    crate::TrustSourceType::TrustList | crate::TrustSourceType::PkdUrl
                )
            {
                return Err(TrustProfileApplicationError::Conflict(
                    "registry_sync_protocol_missing",
                ));
            }
            continue;
        }
        let interval = validate_registry_sync_config(
            source
                .registry_sync
                .as_ref()
                .expect("registry sync was checked"),
        )?;
        let synchronized_at =
            source
                .registry_last_synced_at
                .ok_or(TrustProfileApplicationError::Conflict(
                    "registry_never_synchronized",
                ))?;
        if now >= synchronized_at + chrono::Duration::hours(i64::from(interval)) {
            return Err(TrustProfileApplicationError::Conflict("registry_stale"));
        }
        let state = marty_verification::trust_sync::RegistryImportState {
            sync_token: source.registry_sync_token.clone(),
            sequence: source.registry_sequence,
            entries: source
                .registry_entries
                .iter()
                .map(|(key, value)| {
                    serde_json::from_value(value.clone())
                        .map(|entry| (key.clone(), entry))
                        .map_err(|_| {
                            TrustProfileApplicationError::Conflict("registry_state_invalid")
                        })
                })
                .collect::<Result<_, _>>()?,
            synchronized_at: source.registry_last_synced_at,
        };
        let state_json = serde_json::to_string(&state)
            .map_err(|_| TrustProfileApplicationError::Conflict("registry_state_invalid"))?;
        let state = marty_verification::trust_sync::parse_state_json(&state_json)
            .map_err(|_| TrustProfileApplicationError::Conflict("registry_state_invalid"))?;
        marty_verification::trust_sync::revalidate_entries(&state.entries, now)
            .map_err(|_| TrustProfileApplicationError::Conflict("registry_state_invalid"))?;
    }
    Ok(())
}

fn validate_issuer(issuer: &mut IssuerEntity) -> Result<(), TrustProfileApplicationError> {
    if issuer.issuer_id.trim().is_empty()
        || issuer.display_name.trim().is_empty()
        || issuer.display_name.chars().count() > 256
    {
        return Err(TrustProfileApplicationError::Invalid("issuer_identity"));
    }
    issuer.accreditations = normalize_accreditations(issuer.accreditations.clone())?;
    reject_private_custody_metadata(&issuer.metadata)?;
    if issuer
        .valid_until
        .is_some_and(|until| until <= issuer.valid_from)
    {
        return Err(TrustProfileApplicationError::Invalid("issuer_validity"));
    }
    Ok(())
}

fn validate_relationship(
    relationship: &mut TrustProfileIssuer,
) -> Result<(), TrustProfileApplicationError> {
    if relationship.trust_level > 100 {
        return Err(TrustProfileApplicationError::Invalid("trust_level"));
    }
    reject_private_custody_metadata(&relationship.metadata)?;
    Ok(())
}

fn validate_registry_import_source(
    source: &RegistryImportSource,
) -> Result<(), TrustProfileApplicationError> {
    if source.registry_name.trim().is_empty() || !(1..=720).contains(&source.sync_interval_hours) {
        return Err(TrustProfileApplicationError::Invalid(
            "registry_import_source",
        ));
    }
    if let Some(url) = &source.registry_url {
        marty_verification::trust_sync::validate_registry_url(url)
            .map_err(|_| TrustProfileApplicationError::Invalid("registry_import_url"))?;
    }
    if source
        .credential_format_filter
        .iter()
        .any(|value| !VALID_FORMATS.contains(&value.as_str()))
    {
        return Err(TrustProfileApplicationError::Invalid(
            "credential_format_filter",
        ));
    }
    reject_private_custody_metadata(&source.metadata)?;
    Ok(())
}

fn validate_registry_imported_issuer(
    issuer: &RegistryImportedIssuer,
) -> Result<(), TrustProfileApplicationError> {
    if !issuer.issuer_did.starts_with("did:") || issuer.status.trim().is_empty() {
        return Err(TrustProfileApplicationError::Invalid(
            "registry_imported_issuer",
        ));
    }
    if issuer.country_code.as_ref().is_some_and(|value| {
        !(2..=3).contains(&value.len())
            || !value
                .bytes()
                .all(|character| character.is_ascii_uppercase())
    }) {
        return Err(TrustProfileApplicationError::Invalid(
            "registry_import_country",
        ));
    }
    if issuer.verification_keys.len() > 32
        || issuer.verification_keys.iter().any(|value| {
            value
                .as_object()
                .and_then(|key| key.get("kty"))
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
        })
    {
        return Err(TrustProfileApplicationError::Invalid(
            "registry_import_verification_keys",
        ));
    }
    reject_private_custody_metadata(&Value::Array(issuer.verification_keys.clone()))?;
    if issuer.valid_until.is_some_and(|until| {
        issuer
            .valid_from
            .is_some_and(|valid_from| until <= valid_from)
    }) {
        return Err(TrustProfileApplicationError::Invalid(
            "registry_import_validity",
        ));
    }
    Ok(())
}

#[must_use]
pub fn valid_algorithms() -> BTreeSet<&'static str> {
    VALID_ALGORITHMS.iter().copied().collect()
}
