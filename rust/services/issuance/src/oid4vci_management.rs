use std::{collections::BTreeSet, sync::Arc};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use url::{Host, Url};

use crate::{
    client_auth::{normalize_registered_client_jwks, registered_client_private_key_index},
    credential_management::{CredentialManagementError, CredentialManagementService},
    issued_credential_records::{
        IssuedCredentialProjectionSource, IssuedCredentialRecordRepository,
    },
    management_security::ManagementSecurity,
    python_datetime::isoformat,
    transaction_reads::TransactionReadError,
};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct RegisteredClientRequest {
    pub organization_id: String,
    pub client_id: String,
    pub jwks: Value,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default = "default_active")]
    pub active: bool,
}

const fn default_active() -> bool {
    true
}

#[derive(Clone, Debug, PartialEq)]
pub struct RegisteredClientWrite {
    pub organization_id: String,
    pub client_id: String,
    pub jwks: Value,
    pub redirect_uris: Vec<String>,
    pub active: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RegisteredClientRecord {
    pub organization_id: String,
    pub client_id: String,
    pub jwks: Value,
    pub redirect_uris: Vec<String>,
    pub token_endpoint_auth_method: String,
    pub active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RegisteredClientResponse {
    pub organization_id: String,
    pub client_id: String,
    pub jwks: Value,
    pub redirect_uris: Vec<String>,
    pub token_endpoint_auth_method: String,
    pub active: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ManagementCredentialResponse {
    pub id: String,
    pub credential_template_id: String,
    pub applicant_id: Option<String>,
    pub subject_did: Option<String>,
    pub status: String,
    pub issued_at: String,
    pub status_updated_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagementTransaction {
    pub id: String,
    pub organization_id: String,
    pub status: String,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revocation_reason: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionCredentialBinding {
    pub id: String,
    pub transaction_id: String,
    pub organization_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RevokedTransactionResponse {
    pub id: String,
    pub status: String,
    pub revoked_at: Option<String>,
    pub revocation_reason: Option<String>,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("OID4VCI management repository is unavailable")]
pub struct Oid4vciManagementRepositoryError;

#[async_trait]
pub trait Oid4vciManagementRepository: Send + Sync {
    async fn save_registered_client(
        &self,
        client: &RegisteredClientWrite,
    ) -> Result<(), Oid4vciManagementRepositoryError>;

    async fn registered_client(
        &self,
        organization_id: &str,
        client_id: &str,
    ) -> Result<Option<RegisteredClientRecord>, Oid4vciManagementRepositoryError>;

    async fn transaction(
        &self,
        transaction_id: &str,
    ) -> Result<Option<ManagementTransaction>, Oid4vciManagementRepositoryError>;

    async fn credential_for_transaction(
        &self,
        transaction_id: &str,
    ) -> Result<Option<TransactionCredentialBinding>, Oid4vciManagementRepositoryError>;

    async fn revoke_transaction(
        &self,
        transaction_id: &str,
        reason: Option<&str>,
    ) -> Result<ManagementTransaction, Oid4vciManagementRepositoryError>;
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum Oid4vciManagementError {
    #[error(transparent)]
    Security(#[from] TransactionReadError),
    #[error("Invalid registered-client field: {0}")]
    InvalidRegistration(&'static str),
    #[error("Registered-client JWK {0} contains private key material")]
    PrivateKeyMaterial(usize),
    #[error("Registered client was not persisted")]
    RegisteredClientNotPersisted,
    #[error("Transaction not found")]
    TransactionNotFound,
    #[error("Issued credential organization does not match its transaction")]
    CredentialTenantMismatch,
    #[error("OID4VCI management service is temporarily unavailable")]
    RepositoryUnavailable,
    #[error(transparent)]
    CredentialLifecycle(#[from] CredentialManagementError),
}

#[derive(Clone)]
pub struct Oid4vciManagementService {
    repository: Arc<dyn Oid4vciManagementRepository>,
    credentials: Arc<dyn IssuedCredentialRecordRepository>,
    lifecycle: CredentialManagementService,
    security: ManagementSecurity,
}

impl std::fmt::Debug for Oid4vciManagementService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Oid4vciManagementService")
            .field("security", &self.security)
            .finish_non_exhaustive()
    }
}

impl Oid4vciManagementService {
    #[must_use]
    pub fn new(
        repository: Arc<dyn Oid4vciManagementRepository>,
        credentials: Arc<dyn IssuedCredentialRecordRepository>,
        lifecycle: CredentialManagementService,
        management_api_key: Option<&str>,
    ) -> Self {
        Self {
            repository,
            credentials,
            lifecycle,
            security: ManagementSecurity::new(management_api_key),
        }
    }

    pub fn preflight(&self, api_key: Option<&str>) -> Result<(), Oid4vciManagementError> {
        self.security.authorize(api_key).map_err(Into::into)
    }

    pub async fn put_registered_client(
        &self,
        request: RegisteredClientRequest,
        api_key: Option<&str>,
        trusted_organization: Option<&str>,
    ) -> Result<RegisteredClientResponse, Oid4vciManagementError> {
        self.security.authorize(api_key)?;
        let client = validate_registration(request)?;
        self.security
            .require_organization(trusted_organization, &client.organization_id, false)?;
        self.repository
            .save_registered_client(&client)
            .await
            .map_err(|_| Oid4vciManagementError::RepositoryUnavailable)?;
        let saved = self
            .repository
            .registered_client(&client.organization_id, &client.client_id)
            .await
            .map_err(|_| Oid4vciManagementError::RepositoryUnavailable)?
            .ok_or(Oid4vciManagementError::RegisteredClientNotPersisted)?;
        Ok(project_registered_client(saved))
    }

    pub async fn list_credentials(
        &self,
        organization_id: Option<&str>,
        status: Option<&str>,
        api_key: Option<&str>,
        trusted_organization: Option<&str>,
    ) -> Result<Vec<ManagementCredentialResponse>, Oid4vciManagementError> {
        self.security.authorize(api_key)?;
        let organization_id =
            organization_id.ok_or(TransactionReadError::OrganizationIdRequired)?;
        self.security
            .require_organization(trusted_organization, organization_id, false)?;
        let sources = self
            .credentials
            .list_by_organization(organization_id)
            .await
            .map_err(|_| Oid4vciManagementError::RepositoryUnavailable)?;
        Ok(sources
            .into_iter()
            .filter(|source| {
                status
                    .filter(|value| !value.is_empty())
                    .is_none_or(|expected| source.status == expected)
            })
            .map(project_management_credential)
            .collect())
    }

    pub async fn revoke_transaction(
        &self,
        transaction_id: &str,
        reason: Option<&str>,
        api_key: Option<&str>,
        trusted_organization: Option<&str>,
    ) -> Result<RevokedTransactionResponse, Oid4vciManagementError> {
        self.security.authorize(api_key)?;
        let transaction = self
            .repository
            .transaction(transaction_id)
            .await
            .map_err(|_| Oid4vciManagementError::RepositoryUnavailable)?
            .ok_or(Oid4vciManagementError::TransactionNotFound)?;
        self.security.require_organization(
            trusted_organization,
            &transaction.organization_id,
            true,
        )?;
        if let Some(credential) = self
            .repository
            .credential_for_transaction(&transaction.id)
            .await
            .map_err(|_| Oid4vciManagementError::RepositoryUnavailable)?
        {
            if credential.transaction_id != transaction.id
                || credential.organization_id != transaction.organization_id
            {
                return Err(Oid4vciManagementError::CredentialTenantMismatch);
            }
            self.lifecycle
                .reconcile_revocation(&credential.id, trusted_organization, reason)
                .await?;
        }
        let transaction = if transaction.status == "revoked" {
            transaction
        } else {
            self.repository
                .revoke_transaction(&transaction.id, reason)
                .await
                .map_err(|_| Oid4vciManagementError::RepositoryUnavailable)?
        };
        Ok(project_revoked_transaction(transaction))
    }
}

fn validate_registration(
    request: RegisteredClientRequest,
) -> Result<RegisteredClientWrite, Oid4vciManagementError> {
    let organization_id = request.organization_id.trim().to_owned();
    if organization_id.is_empty() {
        return Err(Oid4vciManagementError::InvalidRegistration(
            "organization_id",
        ));
    }
    let client_id = request.client_id.trim().to_owned();
    if client_id.is_empty() || client_id.chars().count() > 512 {
        return Err(Oid4vciManagementError::InvalidRegistration("client_id"));
    }
    if let Some(index) = registered_client_private_key_index(&request.jwks) {
        return Err(Oid4vciManagementError::PrivateKeyMaterial(index));
    }
    let jwks = normalize_registered_client_jwks(&request.jwks)
        .map_err(|_| Oid4vciManagementError::InvalidRegistration("jwks"))?;
    let mut unique = BTreeSet::new();
    for redirect in &request.redirect_uris {
        validate_redirect_uri(redirect)?;
        if !unique.insert(redirect) {
            return Err(Oid4vciManagementError::InvalidRegistration("redirect_uris"));
        }
    }
    Ok(RegisteredClientWrite {
        organization_id,
        client_id,
        jwks,
        redirect_uris: request.redirect_uris,
        active: request.active,
    })
}

fn validate_redirect_uri(value: &str) -> Result<(), Oid4vciManagementError> {
    let parsed = Url::parse(value)
        .map_err(|_| Oid4vciManagementError::InvalidRegistration("redirect_uris"))?;
    let loopback = match parsed.host() {
        Some(Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    };
    if parsed.fragment().is_some()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || (parsed.scheme() != "https" && !(parsed.scheme() == "http" && loopback))
    {
        return Err(Oid4vciManagementError::InvalidRegistration("redirect_uris"));
    }
    Ok(())
}

fn project_registered_client(record: RegisteredClientRecord) -> RegisteredClientResponse {
    RegisteredClientResponse {
        organization_id: record.organization_id,
        client_id: record.client_id,
        jwks: record.jwks,
        redirect_uris: record.redirect_uris,
        token_endpoint_auth_method: record.token_endpoint_auth_method,
        active: record.active,
        created_at: isoformat(record.created_at),
        updated_at: isoformat(record.updated_at),
    }
}

fn project_management_credential(
    source: IssuedCredentialProjectionSource,
) -> ManagementCredentialResponse {
    ManagementCredentialResponse {
        id: source.id,
        credential_template_id: source.credential_template_id,
        applicant_id: source.applicant_id,
        subject_did: source.subject_did,
        status: source.status,
        issued_at: isoformat(source.issued_at),
        status_updated_at: isoformat(source.status_updated_at),
    }
}

fn project_revoked_transaction(transaction: ManagementTransaction) -> RevokedTransactionResponse {
    RevokedTransactionResponse {
        id: transaction.id,
        status: transaction.status,
        revoked_at: transaction.revoked_at.map(isoformat),
        revocation_reason: transaction.revocation_reason,
    }
}

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use p256::{elliptic_curve::sec1::ToEncodedPoint, SecretKey};

    use super::*;

    fn valid_request() -> RegisteredClientRequest {
        let public = SecretKey::from_slice(&[7_u8; 32])
            .unwrap()
            .public_key()
            .to_encoded_point(false);
        RegisteredClientRequest {
            organization_id: " org-a ".to_owned(),
            client_id: " wallet-a ".to_owned(),
            jwks: serde_json::json!({"keys":[{
                "kty":"EC", "crv":"P-256", "alg":"ES256", "use":"sig",
                "key_ops":["verify"], "kid":"key-a",
                "x":URL_SAFE_NO_PAD.encode(public.x().unwrap()),
                "y":URL_SAFE_NO_PAD.encode(public.y().unwrap())
            }]}),
            redirect_uris: vec!["https://wallet.example/callback".to_owned()],
            active: true,
        }
    }

    #[test]
    fn registration_validation_reuses_assertion_key_policy_and_redirect_safety() {
        let valid = validate_registration(valid_request()).unwrap();
        assert_eq!(valid.organization_id, "org-a");
        assert_eq!(valid.client_id, "wallet-a");

        let mut private = valid_request();
        private.jwks["keys"][0]["d"] = Value::String("secret".to_owned());
        assert_eq!(
            validate_registration(private),
            Err(Oid4vciManagementError::PrivateKeyMaterial(0))
        );

        for redirect in [
            "http://wallet.example/callback",
            "https://wallet.example/callback#fragment",
            "https://user:pass@wallet.example/callback",
        ] {
            let mut request = valid_request();
            request.redirect_uris = vec![redirect.to_owned()];
            assert_eq!(
                validate_registration(request),
                Err(Oid4vciManagementError::InvalidRegistration("redirect_uris"))
            );
        }
        let mut loopback = valid_request();
        loopback.redirect_uris = vec!["http://127.0.0.1:8080/callback".to_owned()];
        assert!(validate_registration(loopback).is_ok());
    }

    #[test]
    fn management_projection_is_the_exact_seven_field_legacy_shape() {
        let source = IssuedCredentialProjectionSource {
            id: "credential-a".to_owned(),
            transaction_id: "tx-a".to_owned(),
            organization_id: "org-a".to_owned(),
            credential_template_id: "template-a".to_owned(),
            applicant_id: Some("applicant-a".to_owned()),
            subject_did: Some("did:example:alice".to_owned()),
            issuer_did: Some("did:example:issuer".to_owned()),
            revocation_profile_id: None,
            renewed_from_credential_id: None,
            renewed_to_credential_id: None,
            status_list_entries: vec![],
            credential_hash: Some("private-projection-field".to_owned()),
            status: "active".to_owned(),
            status_updated_at: "2026-08-20T12:34:57Z".parse().unwrap(),
            revoked_at: None,
            revocation_reason: None,
            issued_at: "2026-08-20T12:34:56Z".parse().unwrap(),
            expires_at: None,
            transaction: None,
        };
        assert_eq!(
            serde_json::to_value(project_management_credential(source)).unwrap(),
            serde_json::json!({
                "id":"credential-a",
                "credential_template_id":"template-a",
                "applicant_id":"applicant-a",
                "subject_did":"did:example:alice",
                "status":"active",
                "issued_at":"2026-08-20T12:34:56+00:00",
                "status_updated_at":"2026-08-20T12:34:57+00:00"
            })
        );
    }

    #[test]
    fn registered_client_response_uses_the_persisted_auth_method() {
        let now = "2026-08-20T12:34:56Z".parse().unwrap();
        let projected = project_registered_client(RegisteredClientRecord {
            organization_id: "org-a".to_owned(),
            client_id: "wallet-a".to_owned(),
            jwks: valid_request().jwks,
            redirect_uris: vec!["https://wallet.example/callback".to_owned()],
            token_endpoint_auth_method: "private_key_jwt".to_owned(),
            active: true,
            created_at: now,
            updated_at: now,
        });
        assert_eq!(projected.token_endpoint_auth_method, "private_key_jwt");
        assert_eq!(projected.created_at, "2026-08-20T12:34:56+00:00");
    }
}
