use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use marty_oid4vci::discovery::{
    CredentialIssuerMetadata, IssuerVariant, KeyAttestationRequirements, ProofPolicyRequest,
    StaticDiscoveryDocuments, TenantCredentialTemplate,
};
use thiserror::Error;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum TenantDiscoveryError {
    #[error("tenant credential templates are unavailable")]
    RepositoryUnavailable,
    #[error("issuer proof policy is unavailable")]
    ProofPolicyUnavailable,
    #[error("issuer proof policy response is invalid")]
    ProofPolicyResponseInvalid,
    #[error("tenant discovery plan is incomplete")]
    IncompletePlan,
}

#[derive(Clone, Debug)]
pub struct ProfiledTenantTemplate {
    pub policy: marty_jwt_vc_issuance::JwtVcTemplatePolicy,
    pub template: TenantCredentialTemplate,
}

#[async_trait]
pub trait TenantDiscoveryRepository: Send + Sync {
    async fn templates(
        &self,
        organization_id: &str,
    ) -> Result<Vec<TenantCredentialTemplate>, TenantDiscoveryError>;

    async fn profiled_templates(
        &self,
        _organization_id: &str,
    ) -> Result<Vec<ProfiledTenantTemplate>, TenantDiscoveryError> {
        Ok(Vec::new())
    }
}

#[async_trait]
pub trait ProofPolicyResolver: Send + Sync {
    async fn resolve(
        &self,
        request: &ProofPolicyRequest,
    ) -> Result<KeyAttestationRequirements, TenantDiscoveryError>;
}

#[derive(Clone)]
pub struct TenantDiscoveryService {
    documents: StaticDiscoveryDocuments,
    repository: Arc<dyn TenantDiscoveryRepository>,
    proof_policies: Arc<dyn ProofPolicyResolver>,
}

impl std::fmt::Debug for TenantDiscoveryService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TenantDiscoveryService")
            .finish_non_exhaustive()
    }
}

impl TenantDiscoveryService {
    #[must_use]
    pub fn new(
        documents: StaticDiscoveryDocuments,
        repository: Arc<dyn TenantDiscoveryRepository>,
        proof_policies: Arc<dyn ProofPolicyResolver>,
    ) -> Self {
        Self {
            documents,
            repository,
            proof_policies,
        }
    }

    /// Serialize once at the wire boundary: the historical Core discovery DTO
    /// has no extension field and must never deserialize these marked entries.
    pub async fn metadata_with_profiles(
        &self,
        organization_id: &str,
        variant: IssuerVariant,
    ) -> Result<serde_json::Value, TenantDiscoveryError> {
        let mut metadata = serde_json::to_value(self.metadata(organization_id, variant).await?)
            .map_err(|_| TenantDiscoveryError::IncompletePlan)?;
        if variant != IssuerVariant::Default {
            return Ok(metadata);
        }
        let configurations = metadata
            .get_mut("credential_configurations_supported")
            .and_then(serde_json::Value::as_object_mut)
            .ok_or(TenantDiscoveryError::IncompletePlan)?;
        for profile in self.repository.profiled_templates(organization_id).await? {
            let credential_type = profile.template.credential_type.clone();
            let plan = self.documents.plan_organization_issuer_metadata(
                organization_id,
                IssuerVariant::Default,
                vec![profile.template],
            );
            let mut policies = BTreeMap::new();
            for legacy_request in plan.proof_policy_requests() {
                if legacy_request.credential_format != "jwt_vc_json" {
                    return Err(TenantDiscoveryError::IncompletePlan);
                }
                let mut exact_request = legacy_request.clone();
                exact_request.credential_format = marty_jwt_vc_issuance::DIRECT_WIRE_FORMAT.into();
                // Reuse only the metadata constructor. Authorization is resolved
                // for the exact new format, never for the historical alias.
                policies.insert(
                    legacy_request.clone(),
                    self.proof_policies.resolve(&exact_request).await?,
                );
            }
            let base = plan
                .build(&policies)
                .map_err(|_| TenantDiscoveryError::IncompletePlan)?;
            let configuration = base
                .credential_configurations_supported
                .get(&credential_type)
                .ok_or(TenantDiscoveryError::IncompletePlan)?;
            let raw = serde_json::to_value(configuration)
                .map_err(|_| TenantDiscoveryError::IncompletePlan)?;
            let (id, raw) = profile
                .policy
                .profile_metadata(&credential_type, raw)
                .map_err(|_| TenantDiscoveryError::IncompletePlan)?;
            if configurations.insert(id, raw).is_some() {
                return Err(TenantDiscoveryError::IncompletePlan);
            }
        }
        Ok(metadata)
    }

    pub async fn metadata(
        &self,
        organization_id: &str,
        variant: IssuerVariant,
    ) -> Result<CredentialIssuerMetadata, TenantDiscoveryError> {
        let templates = self.repository.templates(organization_id).await?;
        let plan =
            self.documents
                .plan_organization_issuer_metadata(organization_id, variant, templates);
        let mut policies = BTreeMap::new();
        for request in plan.proof_policy_requests() {
            policies.insert(request.clone(), self.proof_policies.resolve(request).await?);
        }
        plan.build(&policies)
            .map_err(|_| TenantDiscoveryError::IncompletePlan)
    }
}
