use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use marty_oid4vci::{
    issuer::IssuanceEngine,
    types::{IssuerConfig, IssuerKey, SigningAlgorithm, TokenResponse},
};
use marty_oid4vci::{AuthorizationCodeTokenRequest, AuthorizationSession, CodeChallengeMethod};
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;

pub const PRE_AUTHORIZED_GRANT: &str = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
pub const AUTHORIZATION_CODE_GRANT: &str = "authorization_code";

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
pub struct TokenExchangeRequest {
    pub grant_type: String,
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: Option<String>,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub code_verifier: Option<String>,
    pub client_assertion_type: Option<String>,
    pub client_assertion: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenTransactionStatus {
    Pending,
    Authorized,
    Signing,
    Issued,
    Failed,
    Expired,
    Revoked,
}

impl TryFrom<&str> for TokenTransactionStatus {
    type Error = TokenExchangeError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "pending" => Ok(Self::Pending),
            "authorized" => Ok(Self::Authorized),
            "signing" => Ok(Self::Signing),
            "issued" => Ok(Self::Issued),
            "failed" => Ok(Self::Failed),
            "expired" => Ok(Self::Expired),
            "revoked" => Ok(Self::Revoked),
            _ => Err(TokenExchangeError::RepositoryUnavailable),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct TokenTransaction {
    pub id: String,
    pub organization_id: String,
    pub pre_authorized_code: String,
    pub status: TokenTransactionStatus,
    pub expires_at: DateTime<Utc>,
    pub oid4vci_client_id: Option<String>,
    pub claims: Value,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenAuthorizationSession {
    pub id: String,
    pub code: String,
    pub client_id: String,
    pub organization_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub issuer_state: Option<String>,
    pub credential_configuration_ids: Vec<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<CodeChallengeMethod>,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientAuthenticationRequest<'request> {
    pub organization_id: Option<&'request str>,
    pub expected_client_id: Option<&'request str>,
    pub client_id: Option<&'request str>,
    pub client_assertion_type: Option<&'request str>,
    pub client_assertion: Option<&'request str>,
    pub allowed_audiences: Vec<String>,
    pub registration_required: bool,
}

#[async_trait]
pub trait TokenExchangeRepository: Send + Sync {
    async fn transaction_by_pre_authorized_code(
        &self,
        code: &str,
    ) -> Result<Option<TokenTransaction>, TokenExchangeError>;

    async fn claim_transaction(
        &self,
        transaction: &TokenTransaction,
        access_token: &str,
        dpop_jkt: Option<&str>,
    ) -> Result<bool, TokenExchangeError>;

    async fn authorization_by_code(
        &self,
        code: &str,
    ) -> Result<Option<TokenAuthorizationSession>, TokenExchangeError>;

    async fn claim_authorization(
        &self,
        session: &TokenAuthorizationSession,
        access_token: &str,
        dpop_jkt: Option<&str>,
    ) -> Result<bool, TokenExchangeError>;
}

#[async_trait]
pub trait Oid4vciClientAuthenticator: Send + Sync {
    async fn authenticate(
        &self,
        request: ClientAuthenticationRequest<'_>,
    ) -> Result<(), TokenExchangeError>;
}

pub trait DpopProofVerifier: Send + Sync {
    fn verify(
        &self,
        proof: &str,
        method: &str,
        expected_htu: &str,
    ) -> Result<String, TokenExchangeError>;
}

pub trait TokenGenerator: Send + Sync {
    fn pre_authorized(
        &self,
        pre_authorized_code: &str,
        lifetime_seconds: u64,
    ) -> Result<TokenResponse, TokenExchangeError>;

    fn authorization_code(
        &self,
        request: &TokenExchangeRequest,
        session: &TokenAuthorizationSession,
        lifetime_seconds: u64,
    ) -> Result<TokenResponse, TokenExchangeError>;
}

#[derive(Clone)]
pub struct TokenExchangeService {
    repository: Arc<dyn TokenExchangeRepository>,
    client_authenticator: Arc<dyn Oid4vciClientAuthenticator>,
    dpop_verifier: Arc<dyn DpopProofVerifier>,
    token_generator: Arc<dyn TokenGenerator>,
    issuer_base_url: Arc<str>,
}

impl std::fmt::Debug for TokenExchangeService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TokenExchangeService")
            .field("issuer_base_url", &self.issuer_base_url)
            .finish_non_exhaustive()
    }
}

impl TokenExchangeService {
    #[must_use]
    pub fn new(
        repository: Arc<dyn TokenExchangeRepository>,
        client_authenticator: Arc<dyn Oid4vciClientAuthenticator>,
        dpop_verifier: Arc<dyn DpopProofVerifier>,
        token_generator: Arc<dyn TokenGenerator>,
        issuer_base_url: &str,
    ) -> Self {
        Self {
            repository,
            client_authenticator,
            dpop_verifier,
            token_generator,
            issuer_base_url: Arc::from(issuer_base_url.trim_end_matches('/')),
        }
    }

    pub async fn exchange(
        &self,
        request: &TokenExchangeRequest,
        dpop_proof: Option<&str>,
        endpoint_url: &str,
    ) -> Result<TokenResponse, TokenExchangeError> {
        let dpop_jkt = dpop_proof
            .map(|proof| self.dpop_verifier.verify(proof, "POST", endpoint_url))
            .transpose()?;
        if request.grant_type == AUTHORIZATION_CODE_GRANT {
            self.authorization_code(request, dpop_jkt.as_deref(), endpoint_url)
                .await
        } else {
            self.pre_authorized(request, dpop_jkt.as_deref(), endpoint_url)
                .await
        }
    }

    async fn authorization_code(
        &self,
        request: &TokenExchangeRequest,
        dpop_jkt: Option<&str>,
        endpoint_url: &str,
    ) -> Result<TokenResponse, TokenExchangeError> {
        let code = request
            .code
            .as_deref()
            .filter(|value| !value.is_empty())
            .ok_or(TokenExchangeError::AuthorizationCodeRequired)?;
        let session = self
            .repository
            .authorization_by_code(code)
            .await?
            .ok_or(TokenExchangeError::InvalidAuthorizationCode)?;
        if Utc::now() > session.expires_at {
            return Err(TokenExchangeError::AuthorizationCodeExpired);
        }
        if session.status != "pending" {
            return Err(TokenExchangeError::AuthorizationCodeUsed);
        }
        self.client_authenticator
            .authenticate(ClientAuthenticationRequest {
                organization_id: session.organization_id.as_deref(),
                expected_client_id: Some(&session.client_id),
                client_id: request.client_id.as_deref(),
                client_assertion_type: request.client_assertion_type.as_deref(),
                client_assertion: request.client_assertion.as_deref(),
                allowed_audiences: self
                    .allowed_audiences(session.organization_id.as_deref(), endpoint_url),
                registration_required: false,
            })
            .await?;
        let response = self
            .token_generator
            .authorization_code(request, &session, 1_800)?;
        if !self
            .repository
            .claim_authorization(&session, &response.access_token, dpop_jkt)
            .await?
        {
            return Err(TokenExchangeError::AuthorizationCodeUsed);
        }
        Ok(response)
    }

    async fn pre_authorized(
        &self,
        request: &TokenExchangeRequest,
        dpop_jkt: Option<&str>,
        endpoint_url: &str,
    ) -> Result<TokenResponse, TokenExchangeError> {
        let code = request
            .pre_authorized_code
            .as_deref()
            .filter(|value| !value.is_empty())
            .ok_or(TokenExchangeError::PreAuthorizedCodeRequired)?;
        if request.grant_type != PRE_AUTHORIZED_GRANT {
            return Err(TokenExchangeError::UnsupportedGrantType);
        }
        let transaction = self
            .repository
            .transaction_by_pre_authorized_code(code)
            .await?
            .ok_or(TokenExchangeError::InvalidPreAuthorizedCode)?;
        if Utc::now() > transaction.expires_at {
            return Err(TokenExchangeError::TransactionExpired);
        }
        if matches!(
            transaction.status,
            TokenTransactionStatus::Authorized | TokenTransactionStatus::Issued
        ) {
            return Err(TokenExchangeError::PreAuthorizedCodeUsed);
        }
        if transaction.status != TokenTransactionStatus::Pending {
            return Err(TokenExchangeError::InvalidTransactionState);
        }
        self.client_authenticator
            .authenticate(ClientAuthenticationRequest {
                organization_id: Some(&transaction.organization_id),
                expected_client_id: transaction.oid4vci_client_id.as_deref(),
                client_id: request.client_id.as_deref(),
                client_assertion_type: request.client_assertion_type.as_deref(),
                client_assertion: request.client_assertion.as_deref(),
                allowed_audiences: self
                    .allowed_audiences(Some(&transaction.organization_id), endpoint_url),
                registration_required: transaction.oid4vci_client_id.is_some(),
            })
            .await?;
        let response = self.token_generator.pre_authorized(code, 1_800)?;
        if !self
            .repository
            .claim_transaction(&transaction, &response.access_token, dpop_jkt)
            .await?
        {
            return Err(TokenExchangeError::PreAuthorizedCodeUsed);
        }
        Ok(response)
    }

    fn allowed_audiences(&self, organization_id: Option<&str>, endpoint_url: &str) -> Vec<String> {
        let mut audiences = Vec::with_capacity(2);
        if let Some(organization_id) = organization_id {
            audiences.push(format!("{}/org/{organization_id}", self.issuer_base_url));
        }
        audiences.push(endpoint_url.to_owned());
        audiences
    }
}

#[derive(Clone, Debug, Default)]
pub struct MartyTokenGenerator;

impl TokenGenerator for MartyTokenGenerator {
    fn pre_authorized(
        &self,
        pre_authorized_code: &str,
        lifetime_seconds: u64,
    ) -> Result<TokenResponse, TokenExchangeError> {
        engine()
            .create_token_response(pre_authorized_code, lifetime_seconds)
            .map_err(|error| TokenExchangeError::Protocol(error.to_string()))
    }

    fn authorization_code(
        &self,
        request: &TokenExchangeRequest,
        session: &TokenAuthorizationSession,
        lifetime_seconds: u64,
    ) -> Result<TokenResponse, TokenExchangeError> {
        let created_at = u64::try_from(session.created_at.timestamp())
            .map_err(|_| TokenExchangeError::RepositoryUnavailable)?;
        engine()
            .create_token_response_for_auth_code(
                &AuthorizationCodeTokenRequest {
                    grant_type: AUTHORIZATION_CODE_GRANT.to_owned(),
                    code: request.code.clone().unwrap_or_default(),
                    redirect_uri: request.redirect_uri.clone(),
                    client_id: request
                        .client_id
                        .clone()
                        .filter(|client_id| !client_id.is_empty())
                        .or_else(|| Some(session.client_id.clone())),
                    code_verifier: request.code_verifier.clone(),
                },
                &AuthorizationSession {
                    code: session.code.clone(),
                    client_id: session.client_id.clone(),
                    redirect_uri: session.redirect_uri.clone(),
                    code_challenge: session.code_challenge.clone(),
                    code_challenge_method: session.code_challenge_method.clone(),
                    issuer_state: session.issuer_state.clone(),
                    credential_configuration_ids: session.credential_configuration_ids.clone(),
                    created_at,
                    expires_in: 600,
                },
                lifetime_seconds,
            )
            .map_err(|error| TokenExchangeError::Protocol(format!("Token exchange error: {error}")))
    }
}

fn engine() -> IssuanceEngine {
    IssuanceEngine::new(IssuerConfig {
        credential_issuer_url: String::new(),
        issuer_name: String::new(),
        credential_types: vec![],
        issuer_key: IssuerKey {
            issuer_id: String::new(),
            jwk_json: String::new(),
            algorithm: SigningAlgorithm::EdDSA,
        },
        token_endpoint: None,
        credential_endpoint: None,
        authorization_endpoint: None,
        deferred_credential_endpoint: None,
        binding_methods: vec![],
        proof_signing_alg_values: vec![],
    })
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum TokenExchangeError {
    #[error("grant_type is required")]
    GrantTypeRequired,
    #[error("invalid DPoP proof")]
    InvalidDpopProof,
    #[error("authorization code is required")]
    AuthorizationCodeRequired,
    #[error("invalid authorization code")]
    InvalidAuthorizationCode,
    #[error("authorization code expired")]
    AuthorizationCodeExpired,
    #[error("authorization code already used")]
    AuthorizationCodeUsed,
    #[error("pre-authorized code is required")]
    PreAuthorizedCodeRequired,
    #[error("unsupported grant type")]
    UnsupportedGrantType,
    #[error("invalid pre-authorized code")]
    InvalidPreAuthorizedCode,
    #[error("transaction expired")]
    TransactionExpired,
    #[error("pre-authorized code already used")]
    PreAuthorizedCodeUsed,
    #[error("invalid transaction state")]
    InvalidTransactionState,
    #[error("invalid client")]
    InvalidClient,
    #[error("protocol validation failed: {0}")]
    Protocol(String),
    #[error("token repository is unavailable")]
    RepositoryUnavailable,
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};

    use super::{
        MartyTokenGenerator, TokenAuthorizationSession, TokenExchangeRequest, TokenGenerator,
        AUTHORIZATION_CODE_GRANT,
    };

    fn session(created_at: chrono::DateTime<Utc>) -> TokenAuthorizationSession {
        TokenAuthorizationSession {
            id: "session-1".to_owned(),
            code: "code-1".to_owned(),
            client_id: "wallet-client".to_owned(),
            organization_id: Some("org-a".to_owned()),
            redirect_uri: None,
            issuer_state: None,
            credential_configuration_ids: vec![],
            code_challenge: None,
            code_challenge_method: None,
            status: "pending".to_owned(),
            created_at,
            expires_at: Utc::now() + Duration::minutes(10),
        }
    }

    #[test]
    fn authorization_generator_treats_empty_client_id_as_omitted() {
        let request = TokenExchangeRequest {
            grant_type: AUTHORIZATION_CODE_GRANT.to_owned(),
            code: Some("code-1".to_owned()),
            client_id: Some(String::new()),
            ..TokenExchangeRequest::default()
        };
        assert!(MartyTokenGenerator
            .authorization_code(&request, &session(Utc::now()), 1_800)
            .is_ok());
    }
}
