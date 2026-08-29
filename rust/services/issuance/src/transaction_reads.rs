use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, SecondsFormat, Utc};
use marty_oid4vci::issuer::create_credential_offer;
use serde::Serialize;
use serde_json::Value;
use thiserror::Error;

use crate::management_security::ManagementSecurity;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionStatus {
    Pending,
    Authorized,
    Signing,
    Issued,
    Failed,
    Expired,
    Revoked,
}

impl TryFrom<&str> for TransactionStatus {
    type Error = TransactionReadError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "pending" => Ok(Self::Pending),
            "authorized" => Ok(Self::Authorized),
            "signing" => Ok(Self::Signing),
            "issued" => Ok(Self::Issued),
            "failed" => Ok(Self::Failed),
            "expired" => Ok(Self::Expired),
            "revoked" => Ok(Self::Revoked),
            _ => Err(TransactionReadError::RepositoryUnavailable),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuanceTransactionRecord {
    pub id: String,
    pub organization_id: String,
    pub credential_template_id: String,
    pub applicant_id: Option<String>,
    pub application_id: Option<String>,
    pub subject_did: Option<String>,
    pub status: TransactionStatus,
    pub pre_auth_code: String,
    pub credential_type: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub issued_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revocation_reason: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IssuanceTransactionResponse {
    pub id: String,
    pub organization_id: String,
    pub credential_template_id: String,
    pub applicant_id: Option<String>,
    pub application_id: Option<String>,
    pub subject_did: Option<String>,
    pub status: TransactionStatus,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub issued_at: Option<String>,
    pub revoked_at: Option<String>,
    pub revocation_reason: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TransactionRevocationStatus {
    pub id: String,
    pub revoked: bool,
    pub status: TransactionStatus,
    pub revoked_at: Option<String>,
    pub revocation_reason: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResourceOwner {
    pub organization_id: String,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum TransactionReadError {
    #[error("issuance transaction repository is unavailable")]
    RepositoryUnavailable,
    #[error("credential offer could not be constructed")]
    OfferUnavailable,
    #[error("offer was not found")]
    OfferNotFound,
    #[error("offer has expired")]
    OfferExpired,
    #[error("transaction was not found")]
    TransactionNotFound,
    #[error("resource was not found")]
    ResourceNotFound,
    #[error("management API key is not configured")]
    ApiKeyNotConfigured,
    #[error("management API key is missing")]
    ApiKeyMissing,
    #[error("management API key is invalid")]
    InvalidApiKey,
    #[error("trusted organization context is required")]
    TrustedOrganizationRequired,
    #[error("organization context does not match")]
    OrganizationMismatch,
    #[error("organization_id query parameter is required")]
    OrganizationIdRequired,
}

#[async_trait]
pub trait TransactionReadRepository: Send + Sync {
    async fn get(
        &self,
        transaction_id: &str,
    ) -> Result<Option<IssuanceTransactionRecord>, TransactionReadError>;

    async fn list(
        &self,
        organization_id: &str,
    ) -> Result<Vec<IssuanceTransactionRecord>, TransactionReadError>;
}

#[derive(Clone)]
pub struct TransactionReadService {
    repository: Arc<dyn TransactionReadRepository>,
    security: ManagementSecurity,
    issuer_base_url: Arc<str>,
}

impl std::fmt::Debug for TransactionReadService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TransactionReadService")
            .field("security", &self.security)
            .field("issuer_base_url", &self.issuer_base_url)
            .finish_non_exhaustive()
    }
}

impl TransactionReadService {
    #[must_use]
    pub fn new(
        repository: Arc<dyn TransactionReadRepository>,
        management_api_key: Option<&str>,
        issuer_base_url: &str,
    ) -> Self {
        Self {
            repository,
            security: ManagementSecurity::new(management_api_key),
            issuer_base_url: Arc::from(issuer_base_url),
        }
    }

    pub async fn offer(&self, transaction_id: &str) -> Result<Value, TransactionReadError> {
        let transaction = self
            .repository
            .get(transaction_id)
            .await?
            .ok_or(TransactionReadError::OfferNotFound)?;
        if Utc::now() > transaction.expires_at {
            return Err(TransactionReadError::OfferExpired);
        }
        let credential_type = transaction
            .credential_type
            .as_deref()
            .filter(|value| !value.is_empty())
            .unwrap_or("default")
            .to_owned();
        let issuer_url = format!(
            "{}/org/{}",
            self.issuer_base_url, transaction.organization_id
        );
        let offer = create_credential_offer(
            &issuer_url,
            &[credential_type],
            Some(&transaction.pre_auth_code),
            false,
        )
        .map_err(|_| TransactionReadError::OfferUnavailable)?;
        serde_json::from_str(&offer).map_err(|_| TransactionReadError::OfferUnavailable)
    }

    pub async fn list(
        &self,
        organization_id: Option<&str>,
        api_key: Option<&str>,
        trusted_organization: Option<&str>,
    ) -> Result<Vec<IssuanceTransactionResponse>, TransactionReadError> {
        self.security.authorize(api_key)?;
        let organization_id =
            organization_id.ok_or(TransactionReadError::OrganizationIdRequired)?;
        self.security
            .require_organization(trusted_organization, organization_id, false)?;
        Ok(self
            .repository
            .list(organization_id)
            .await?
            .into_iter()
            .map(IssuanceTransactionResponse::summary)
            .collect())
    }

    pub async fn get(
        &self,
        transaction_id: &str,
        api_key: Option<&str>,
        trusted_organization: Option<&str>,
    ) -> Result<IssuanceTransactionResponse, TransactionReadError> {
        self.security.authorize(api_key)?;
        let transaction = self
            .repository
            .get(transaction_id)
            .await?
            .ok_or(TransactionReadError::TransactionNotFound)?;
        self.security.require_organization(
            trusted_organization,
            &transaction.organization_id,
            true,
        )?;
        Ok(IssuanceTransactionResponse::detail(transaction))
    }

    pub async fn revocation_status(
        &self,
        transaction_id: &str,
        api_key: Option<&str>,
        trusted_organization: Option<&str>,
    ) -> Result<TransactionRevocationStatus, TransactionReadError> {
        self.security.authorize(api_key)?;
        let transaction = self
            .repository
            .get(transaction_id)
            .await?
            .ok_or(TransactionReadError::TransactionNotFound)?;
        self.security.require_organization(
            trusted_organization,
            &transaction.organization_id,
            true,
        )?;
        Ok(TransactionRevocationStatus {
            id: transaction.id,
            revoked: transaction.status == TransactionStatus::Revoked,
            status: transaction.status,
            revoked_at: transaction.revoked_at.map(python_isoformat),
            revocation_reason: transaction.revocation_reason,
        })
    }

    pub async fn owner(
        &self,
        transaction_id: &str,
        api_key: Option<&str>,
    ) -> Result<ResourceOwner, TransactionReadError> {
        self.security.authorize(api_key)?;
        let transaction = self
            .repository
            .get(transaction_id)
            .await?
            .ok_or(TransactionReadError::ResourceNotFound)?;
        Ok(ResourceOwner {
            organization_id: transaction.organization_id,
        })
    }
}

impl IssuanceTransactionResponse {
    fn summary(transaction: IssuanceTransactionRecord) -> Self {
        Self {
            id: transaction.id,
            organization_id: transaction.organization_id,
            credential_template_id: transaction.credential_template_id,
            applicant_id: transaction.applicant_id,
            application_id: transaction.application_id,
            subject_did: transaction.subject_did,
            status: transaction.status,
            created_at: python_isoformat(transaction.created_at),
            expires_at: None,
            issued_at: None,
            revoked_at: None,
            revocation_reason: None,
        }
    }

    fn detail(transaction: IssuanceTransactionRecord) -> Self {
        Self {
            id: transaction.id,
            organization_id: transaction.organization_id,
            credential_template_id: transaction.credential_template_id,
            applicant_id: transaction.applicant_id,
            application_id: transaction.application_id,
            subject_did: transaction.subject_did,
            status: transaction.status,
            created_at: python_isoformat(transaction.created_at),
            expires_at: Some(python_isoformat(transaction.expires_at)),
            issued_at: transaction.issued_at.map(python_isoformat),
            revoked_at: transaction.revoked_at.map(python_isoformat),
            revocation_reason: transaction.revocation_reason,
        }
    }
}

fn python_isoformat(value: DateTime<Utc>) -> String {
    let precision = if value.timestamp_subsec_micros() == 0 {
        SecondsFormat::Secs
    } else {
        SecondsFormat::Micros
    };
    value.to_rfc3339_opts(precision, false)
}

#[cfg(test)]
mod tests {
    use chrono::DateTime;

    use super::{python_isoformat, TransactionReadError, TransactionStatus};

    #[test]
    fn status_and_timestamps_fail_closed_and_preserve_python_shapes() {
        for status in [
            "pending",
            "authorized",
            "signing",
            "issued",
            "failed",
            "expired",
            "revoked",
        ] {
            TransactionStatus::try_from(status).expect("released status");
        }
        assert_eq!(
            TransactionStatus::try_from("unknown"),
            Err(TransactionReadError::RepositoryUnavailable)
        );
        let time = DateTime::parse_from_rfc3339("2026-08-20T12:34:56.123000+00:00")
            .expect("time")
            .to_utc();
        assert_eq!(python_isoformat(time), "2026-08-20T12:34:56.123000+00:00");
        let whole_second = DateTime::parse_from_rfc3339("2026-08-20T12:34:56+00:00")
            .expect("time")
            .to_utc();
        assert_eq!(python_isoformat(whole_second), "2026-08-20T12:34:56+00:00");
    }
}
