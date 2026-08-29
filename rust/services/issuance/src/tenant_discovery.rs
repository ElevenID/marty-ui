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
    #[error("tenant discovery plan is incomplete")]
    IncompletePlan,
}

#[async_trait]
pub trait TenantDiscoveryRepository: Send + Sync {
    async fn templates(
        &self,
        organization_id: &str,
    ) -> Result<Vec<TenantCredentialTemplate>, TenantDiscoveryError>;
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
