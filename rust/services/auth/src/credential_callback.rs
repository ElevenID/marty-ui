use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use thiserror::Error;

use crate::{
    apply_credential_login_defaults, build_credential_login_user, CallbackClaim,
    CredentialCallbackHeaders, CredentialIdentityProvisioner, CredentialLoginStateStore,
    CredentialStateError, CredentialVerifiedPayload, OidcUserInfo, PortError, Session,
    SessionRepository, SessionSpec,
};

#[derive(Debug, Clone, PartialEq)]
pub struct CredentialAccount {
    pub user: Option<OidcUserInfo>,
    pub id_token: Option<String>,
    pub refresh_token: Option<String>,
    pub validated_claims: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveCredentialAccount {
    pub email: String,
    pub preferred_username: String,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub create_user: bool,
}

#[async_trait]
pub trait CredentialAccountResolver: Send + Sync {
    async fn resolve(
        &self,
        request: &ResolveCredentialAccount,
    ) -> Result<Option<CredentialAccount>, PortError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialCallbackConfig {
    pub default_organization_id: String,
    pub session_ttl_seconds: i64,
    pub require_existing_keycloak_user: bool,
    pub create_keycloak_users: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialCallbackContext {
    pub nonce: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialCallbackResult {
    Completed { session_id: String },
    Denied { reason_code: String },
    AlreadyProcessed,
}

#[derive(Debug, Error)]
pub enum CredentialCallbackError {
    #[error(transparent)]
    State(#[from] CredentialStateError),
    #[error("AUTH.CREDENTIAL_CALLBACK_PORT: {0}")]
    Port(#[from] PortError),
}

pub struct CredentialCallbackApplication {
    state: Arc<CredentialLoginStateStore>,
    sessions: Arc<dyn SessionRepository>,
    accounts: Option<Arc<dyn CredentialAccountResolver>>,
    provisioner: Option<Arc<dyn CredentialIdentityProvisioner>>,
    config: CredentialCallbackConfig,
}

impl CredentialCallbackApplication {
    #[must_use]
    pub fn new(
        state: Arc<CredentialLoginStateStore>,
        sessions: Arc<dyn SessionRepository>,
        accounts: Option<Arc<dyn CredentialAccountResolver>>,
        provisioner: Option<Arc<dyn CredentialIdentityProvisioner>>,
        config: CredentialCallbackConfig,
    ) -> Self {
        Self {
            state,
            sessions,
            accounts,
            provisioner,
            config,
        }
    }

    pub async fn handle(
        &self,
        payload: &CredentialVerifiedPayload,
        headers: &CredentialCallbackHeaders,
        context: &CredentialCallbackContext,
        now: DateTime<Utc>,
    ) -> Result<CredentialCallbackResult, CredentialCallbackError> {
        self.state.verify_callback(payload, headers, now)?;
        let now_ms = u64::try_from(now.timestamp_millis()).unwrap_or_default();
        match self
            .state
            .claim_callback(&context.nonce, payload, now_ms)
            .await?
        {
            CallbackClaim::AlreadyProcessed => {
                return Ok(CredentialCallbackResult::AlreadyProcessed);
            }
            CallbackClaim::Claimed(_) => {}
        }
        if payload.decision != "allow" || payload.result != "passed" {
            let reason =
                nonempty(&payload.decision_reason).unwrap_or("Credential verification failed");
            return self.deny(payload, context, reason, now_ms).await;
        }

        let mut claims = payload.verified_claims.clone();
        claims.insert("role".into(), Value::String("applicant".into()));
        claims.insert(
            "organization_id".into(),
            Value::String(self.config.default_organization_id.clone()),
        );
        claims.remove("organization");
        claims.remove("organization_name");
        let Some(email) = string_claim(&claims, "email") else {
            return self
                .deny(payload, context, "Credential missing email claim", now_ms)
                .await;
        };
        let preferred_username =
            string_claim(&claims, "preferred_username").unwrap_or_else(|| email.clone());
        let require_when_configured =
            self.config.require_existing_keycloak_user || !self.config.create_keycloak_users;
        let account = if let Some(accounts) = &self.accounts {
            match accounts
                .resolve(&ResolveCredentialAccount {
                    email: email.clone(),
                    preferred_username,
                    given_name: string_claim(&claims, "given_name"),
                    family_name: string_claim(&claims, "family_name"),
                    create_user: self.config.create_keycloak_users,
                })
                .await
            {
                Ok(Some(account)) => Some(account),
                Ok(None) if require_when_configured => {
                    return self
                        .deny(payload, context, "keycloak_user_not_found", now_ms)
                        .await;
                }
                Ok(None) => None,
                Err(_) if require_when_configured => {
                    return self
                        .deny(payload, context, "keycloak_user_not_eligible", now_ms)
                        .await;
                }
                Err(_) => None,
            }
        } else if self.config.require_existing_keycloak_user {
            return self
                .deny(payload, context, "keycloak_admin_unavailable", now_ms)
                .await;
        } else {
            None
        };

        let mut user = build_credential_login_user(
            &Value::Object(claims),
            self.provisioner.as_deref(),
            account.as_ref().and_then(|account| account.user.as_ref()),
        )
        .await?;
        user = apply_credential_login_defaults(user, &self.config.default_organization_id);
        let mut session = Session::create(SessionSpec {
            user,
            ttl_seconds: self.config.session_ttl_seconds,
            now,
            ip_address: context.ip_address.clone(),
            user_agent: context.user_agent.clone(),
            id_token: account
                .as_ref()
                .and_then(|account| account.id_token.clone()),
            refresh_token: account
                .as_ref()
                .and_then(|account| account.refresh_token.clone()),
            oidc_claims: account.and_then(|account| account.validated_claims),
        });
        session.session_id = self
            .state
            .callback_session_id(&payload.flow_instance_id, &context.nonce)
            .to_string();
        self.sessions.save(&session).await?;
        let revocation_checked = payload
            .verified_claims
            .get("revocation_checked")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let revocation_status = payload
            .verified_claims
            .get("revocation_status")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        self.state
            .complete(
                &context.nonce,
                &payload.flow_instance_id,
                &session.session_id,
                revocation_checked,
                revocation_status,
                now_ms,
            )
            .await?;
        Ok(CredentialCallbackResult::Completed {
            session_id: session.session_id,
        })
    }

    async fn deny(
        &self,
        payload: &CredentialVerifiedPayload,
        context: &CredentialCallbackContext,
        reason: &str,
        now_ms: u64,
    ) -> Result<CredentialCallbackResult, CredentialCallbackError> {
        let failure = self
            .state
            .fail(&context.nonce, &payload.flow_instance_id, reason, now_ms)
            .await?;
        Ok(CredentialCallbackResult::Denied {
            reason_code: failure
                .reason_code
                .unwrap_or_else(|| "verification_failed".into()),
        })
    }
}

fn string_claim(claims: &Map<String, Value>, key: &str) -> Option<String> {
    claims
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn nonempty(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}
