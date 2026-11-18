//! Server-owned, single-use pairing ticket for later KMS-only device enrollment.

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use redis::{aio::ConnectionManager, Script};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::DeviceError;

const PREFIX: &str = "device-registration:pairing:";
const TOKEN_BYTES: usize = 32;
const TOKEN_CHARS: usize = 43;
const MAX_TTL_SECONDS: u64 = 300;
const TAKE: &str = r#"
local value = redis.call('GET', KEYS[1])
if not value then return nil end
redis.call('DEL', KEYS[1])
return value
"#;

fn random_token(bytes: usize) -> String {
    let mut value = vec![0_u8; bytes];
    rand::rng().fill_bytes(&mut value);
    URL_SAFE_NO_PAD.encode(value)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PairingScope {
    pub pairing_id: String,
    pub user_id: String,
    pub organization_id: String,
    pub trust_profile_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier_trust_profile_id: Option<String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

pub struct IssuedPairingTicket {
    pub token: String,
    pub scope: PairingScope,
}

#[async_trait]
pub trait PairingTicketRepository: Send + Sync {
    /// The caller must authorize the browser session and any required step-up.
    async fn issue(
        &self,
        user_id: &str,
        organization_id: &str,
        trust_profile_id: &str,
    ) -> Result<IssuedPairingTicket, DeviceError>;
    /// Verifier scope must be selected by the authorized browser, not the phone.
    async fn issue_with_verifier_profile(
        &self,
        user_id: &str,
        organization_id: &str,
        trust_profile_id: &str,
        verifier_trust_profile_id: Option<&str>,
    ) -> Result<IssuedPairingTicket, DeviceError> {
        if verifier_trust_profile_id.is_some() {
            return Err(DeviceError::AuthorizationUnavailable);
        }
        self.issue(user_id, organization_id, trust_profile_id).await
    }
    /// A successful redemption consumes the ticket atomically, even on retry.
    async fn take(&self, token: &str) -> Result<Option<PairingScope>, DeviceError>;
}

fn digest_key(token: &str) -> Option<String> {
    if token.len() != TOKEN_CHARS
        || !token
            .bytes()
            .all(|value| value.is_ascii_alphanumeric() || value == b'-' || value == b'_')
        || URL_SAFE_NO_PAD.decode(token).ok()?.len() != TOKEN_BYTES
    {
        return None;
    }
    Some(format!(
        "{PREFIX}{}",
        URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
    ))
}

fn issue_scope(
    user_id: &str,
    organization_id: &str,
    trust_profile_id: &str,
    verifier_trust_profile_id: Option<&str>,
    ttl_seconds: u64,
) -> Result<IssuedPairingTicket, DeviceError> {
    if user_id.trim().is_empty()
        || organization_id.trim().is_empty()
        || Uuid::parse_str(trust_profile_id).is_err()
        || !(1..=MAX_TTL_SECONDS).contains(&ttl_seconds)
    {
        return Err(DeviceError::BadRequest(
            "pairing ticket scope is invalid".into(),
        ));
    }
    let verifier_trust_profile_id = verifier_trust_profile_id
        .map(|value| {
            let id = Uuid::parse_str(value)
                .map_err(|_| DeviceError::BadRequest("verifier Trust Profile is invalid".into()))?;
            if id.is_nil() || Some(id) == Uuid::parse_str(trust_profile_id).ok() {
                return Err(DeviceError::BadRequest(
                    "a distinct verifier Trust Profile is required".into(),
                ));
            }
            Ok(id.to_string())
        })
        .transpose()?;
    let issued_at = Utc::now();
    Ok(IssuedPairingTicket {
        token: random_token(TOKEN_BYTES),
        scope: PairingScope {
            pairing_id: Uuid::new_v4().to_string(),
            user_id: user_id.into(),
            organization_id: organization_id.into(),
            trust_profile_id: trust_profile_id.into(),
            verifier_trust_profile_id,
            issued_at,
            expires_at: issued_at + Duration::seconds(ttl_seconds as i64),
        },
    })
}

#[derive(Clone)]
pub struct MemoryPairingTickets {
    ttl_seconds: u64,
    scopes: Arc<Mutex<HashMap<String, PairingScope>>>,
}

impl MemoryPairingTickets {
    pub fn new(ttl_seconds: u64) -> Self {
        Self {
            ttl_seconds,
            scopes: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl PairingTicketRepository for MemoryPairingTickets {
    async fn issue(
        &self,
        user_id: &str,
        organization_id: &str,
        trust_profile_id: &str,
    ) -> Result<IssuedPairingTicket, DeviceError> {
        self.issue_with_verifier_profile(user_id, organization_id, trust_profile_id, None)
            .await
    }

    async fn issue_with_verifier_profile(
        &self,
        user_id: &str,
        organization_id: &str,
        trust_profile_id: &str,
        verifier_trust_profile_id: Option<&str>,
    ) -> Result<IssuedPairingTicket, DeviceError> {
        for _ in 0..4 {
            let ticket = issue_scope(
                user_id,
                organization_id,
                trust_profile_id,
                verifier_trust_profile_id,
                self.ttl_seconds,
            )?;
            let key = digest_key(&ticket.token).expect("issued ticket format");
            let mut scopes = self.scopes.lock().await;
            scopes.retain(|_, scope| scope.expires_at > Utc::now());
            if let std::collections::hash_map::Entry::Vacant(entry) = scopes.entry(key) {
                entry.insert(ticket.scope.clone());
                return Ok(ticket);
            }
        }
        Err(DeviceError::PairingStore(
            "pairing ticket allocation failed".into(),
        ))
    }

    async fn take(&self, token: &str) -> Result<Option<PairingScope>, DeviceError> {
        let Some(key) = digest_key(token) else {
            return Ok(None);
        };
        Ok(self
            .scopes
            .lock()
            .await
            .remove(&key)
            .filter(|scope| scope.expires_at > Utc::now()))
    }
}

#[derive(Clone)]
pub struct RedisPairingTickets {
    ttl_seconds: u64,
    connection: ConnectionManager,
}

impl RedisPairingTickets {
    pub async fn connect(url: &str, ttl_seconds: u64) -> Result<Self, DeviceError> {
        if !(1..=MAX_TTL_SECONDS).contains(&ttl_seconds) {
            return Err(DeviceError::BadRequest(
                "pairing ticket TTL is invalid".into(),
            ));
        }
        let client = redis::Client::open(url)
            .map_err(|_| DeviceError::PairingStore("pairing ticket Redis URL is invalid".into()))?;
        let mut connection = ConnectionManager::new(client)
            .await
            .map_err(|_| DeviceError::PairingStore("pairing ticket Redis unavailable".into()))?;
        redis::cmd("PING")
            .query_async::<String>(&mut connection)
            .await
            .map_err(|_| DeviceError::PairingStore("pairing ticket Redis unavailable".into()))?;
        Ok(Self {
            ttl_seconds,
            connection,
        })
    }
}

#[async_trait]
impl PairingTicketRepository for RedisPairingTickets {
    async fn issue(
        &self,
        user_id: &str,
        organization_id: &str,
        trust_profile_id: &str,
    ) -> Result<IssuedPairingTicket, DeviceError> {
        self.issue_with_verifier_profile(user_id, organization_id, trust_profile_id, None)
            .await
    }

    async fn issue_with_verifier_profile(
        &self,
        user_id: &str,
        organization_id: &str,
        trust_profile_id: &str,
        verifier_trust_profile_id: Option<&str>,
    ) -> Result<IssuedPairingTicket, DeviceError> {
        let mut connection = self.connection.clone();
        for _ in 0..4 {
            let ticket = issue_scope(
                user_id,
                organization_id,
                trust_profile_id,
                verifier_trust_profile_id,
                self.ttl_seconds,
            )?;
            let key = digest_key(&ticket.token).expect("issued ticket format");
            let value = serde_json::to_string(&ticket.scope)
                .map_err(|_| DeviceError::PairingStore("pairing ticket encoding failed".into()))?;
            let created: Option<String> = redis::cmd("SET")
                .arg(key)
                .arg(value)
                .arg("EX")
                .arg(self.ttl_seconds)
                .arg("NX")
                .query_async(&mut connection)
                .await
                .map_err(|_| {
                    DeviceError::PairingStore("pairing ticket Redis unavailable".into())
                })?;
            if created.is_some() {
                return Ok(ticket);
            }
        }
        Err(DeviceError::PairingStore(
            "pairing ticket allocation failed".into(),
        ))
    }

    async fn take(&self, token: &str) -> Result<Option<PairingScope>, DeviceError> {
        let Some(key) = digest_key(token) else {
            return Ok(None);
        };
        let mut connection = self.connection.clone();
        let value: Option<String> = Script::new(TAKE)
            .key(key)
            .invoke_async(&mut connection)
            .await
            .map_err(|_| DeviceError::PairingStore("pairing ticket Redis unavailable".into()))?;
        let Some(value) = value else { return Ok(None) };
        let scope: PairingScope = serde_json::from_str(&value)
            .map_err(|_| DeviceError::PairingStore("pairing ticket decoding failed".into()))?;
        Ok((scope.expires_at > Utc::now()).then_some(scope))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const PROFILE_ID: &str = "11111111-2222-4333-8444-555555555555";

    #[tokio::test]
    async fn verifier_profile_is_explicit_distinct_and_preserved_through_ticket_consumption() {
        let store = MemoryPairingTickets::new(300);
        let verifier = "21111111-2222-4333-8444-555555555555";
        let issued = store
            .issue_with_verifier_profile("user-a", "org-a", PROFILE_ID, Some(verifier))
            .await
            .unwrap();
        assert_eq!(
            issued.scope.verifier_trust_profile_id.as_deref(),
            Some(verifier)
        );
        let recovered = store.take(&issued.token).await.unwrap().unwrap();
        assert_eq!(recovered, issued.scope);
        assert!(store.take(&issued.token).await.unwrap().is_none());
        for invalid in [
            PROFILE_ID,
            "not-a-profile",
            "00000000-0000-0000-0000-000000000000",
        ] {
            assert!(store
                .issue_with_verifier_profile("user-a", "org-a", PROFILE_ID, Some(invalid))
                .await
                .is_err());
        }
        let legacy = store.issue("user-a", "org-a", PROFILE_ID).await.unwrap();
        assert!(legacy.scope.verifier_trust_profile_id.is_none());
        let value = serde_json::to_value(&legacy.scope).unwrap();
        assert!(value.get("verifier_trust_profile_id").is_none());
        let decoded: PairingScope = serde_json::from_value(value).unwrap();
        assert!(
            decoded.verifier_trust_profile_id.is_none(),
            "legacy scope must not acquire verifier authority"
        );
    }

    #[tokio::test]
    async fn ticket_is_secret_scoped_and_single_use() {
        let store = MemoryPairingTickets::new(300);
        let issued = store.issue("user-a", "org-a", PROFILE_ID).await.unwrap();
        assert_eq!(issued.token.len(), TOKEN_CHARS);
        assert_ne!(digest_key(&issued.token).unwrap(), issued.token);
        assert!(store.take("wrong").await.unwrap().is_none());
        assert_eq!(store.take(&issued.token).await.unwrap(), Some(issued.scope));
        assert!(store.take(&issued.token).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn invalid_scope_or_ttl_cannot_issue() {
        assert!(MemoryPairingTickets::new(0)
            .issue("user", "org", PROFILE_ID)
            .await
            .is_err());
        assert!(MemoryPairingTickets::new(301)
            .issue("user", "org", PROFILE_ID)
            .await
            .is_err());
        assert!(MemoryPairingTickets::new(300)
            .issue("", "org", PROFILE_ID)
            .await
            .is_err());
        assert!(MemoryPairingTickets::new(300)
            .issue("user", "org", "not-a-profile-id")
            .await
            .is_err());
    }
}
