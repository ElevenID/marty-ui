use crate::{
    credential_management::{
        CredentialLifecycleAction, CredentialManagementError, CredentialManagementService,
        CredentialStatusView,
    },
    management_security::ManagementSecurity,
    transaction_reads::TransactionReadError,
};

#[derive(Clone, Debug)]
pub struct CredentialManagementHttpService {
    lifecycle: CredentialManagementService,
    security: ManagementSecurity,
}

impl CredentialManagementHttpService {
    #[must_use]
    pub fn new(lifecycle: CredentialManagementService, management_api_key: Option<&str>) -> Self {
        Self {
            lifecycle,
            security: ManagementSecurity::new(management_api_key),
        }
    }

    pub async fn get_status(
        &self,
        credential_id: &str,
        api_key: Option<&str>,
        trusted_organization: Option<&str>,
    ) -> Result<CredentialStatusView, CredentialManagementHttpError> {
        self.security.authorize(api_key)?;
        let organization_id = required_organization(trusted_organization)?;
        self.lifecycle
            .get_status(credential_id, Some(organization_id))
            .await
            .map_err(Into::into)
    }

    pub async fn transition(
        &self,
        credential_id: &str,
        api_key: Option<&str>,
        trusted_organization: Option<&str>,
        action: CredentialLifecycleAction,
        reason: Option<&str>,
    ) -> Result<CredentialStatusView, CredentialManagementHttpError> {
        self.security.authorize(api_key)?;
        let organization_id = required_organization(trusted_organization)?;
        self.lifecycle
            .transition(credential_id, Some(organization_id), action, reason)
            .await
            .map_err(Into::into)
    }

    pub async fn observe_sd_jwt_status(
        &self,
        request: &marty_oid4vp_contract::managed_status::ManagedCredentialStatusRequestV1,
        api_key: Option<&str>,
        trusted_organization: Option<&str>,
    ) -> Result<
        marty_oid4vp_contract::managed_status::ManagedCredentialStatusObservationV1,
        CredentialManagementHttpError,
    > {
        self.security.authorize(api_key)?;
        self.security
            .require_organization(trusted_organization, &request.organization_id, true)?;
        self.lifecycle
            .observe_sd_jwt_status(request)
            .await
            .map_err(CredentialManagementHttpError::Observation)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CredentialManagementHttpError {
    Security(TransactionReadError),
    Lifecycle(CredentialManagementError),
    Observation(crate::managed_status::ManagedStatusError),
}

impl From<TransactionReadError> for CredentialManagementHttpError {
    fn from(value: TransactionReadError) -> Self {
        Self::Security(value)
    }
}

impl From<CredentialManagementError> for CredentialManagementHttpError {
    fn from(value: CredentialManagementError) -> Self {
        Self::Lifecycle(value)
    }
}

fn required_organization(value: Option<&str>) -> Result<&str, TransactionReadError> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(TransactionReadError::TrustedOrganizationRequired)
}
