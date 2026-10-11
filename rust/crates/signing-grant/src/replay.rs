//! Atomic one-use consumption for an OpenBao-verified signing grant.

use redis::aio::ConnectionManager;
use thiserror::Error;

use crate::{bound_input, GrantBinding, GrantClaims, VerifiedGrant};

const KEY_PREFIX: &str = "marty:issuer-signing-grant:used:v1:";
const MAX_REPLAY_TTL_SECONDS: i128 = 66;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ReplayError {
    #[error("signing grant has expired")]
    Expired,
    #[error("signing grant was already used")]
    AlreadyUsed,
    #[error("signing grant replay store is unavailable")]
    Unavailable,
}

#[derive(Clone)]
pub struct RedisGrantReplayStore {
    connection: ConnectionManager,
}

/// Created only after OpenBao verification and atomic one-use consumption.
/// Move this value into the KMS signing kernel; it cannot be cloned or forged.
pub struct ConsumedGrant {
    claims: GrantClaims,
}

impl ConsumedGrant {
    /// Recheck the exact operation at the point of KMS use, including expiry.
    pub fn authorizes(&self, binding: &GrantBinding<'_>) -> bool {
        bound_input(&self.claims, binding, chrono::Utc::now().timestamp()).is_ok()
    }
}

impl RedisGrantReplayStore {
    pub fn new(connection: ConnectionManager) -> Self {
        Self { connection }
    }

    /// Atomically records the grant before KMS signing. A failed sign still
    /// consumes the grant; the authorized origin must start a new operation.
    pub async fn consume(&self, verified: &VerifiedGrant) -> Result<ConsumedGrant, ReplayError> {
        self.consume_at(verified, chrono::Utc::now().timestamp())
            .await
    }

    async fn consume_at(
        &self,
        verified: &VerifiedGrant,
        now_seconds: i64,
    ) -> Result<ConsumedGrant, ReplayError> {
        let ttl = i128::from(verified.expires_at()) - i128::from(now_seconds) + 1;
        if !(1..=MAX_REPLAY_TTL_SECONDS).contains(&ttl) {
            return Err(ReplayError::Expired);
        }
        let mut connection = self.connection.clone();
        let result: Option<String> = redis::cmd("SET")
            .arg(format!("{KEY_PREFIX}{}", verified.nonce()))
            .arg("1")
            .arg("NX")
            .arg("EX")
            .arg(ttl as u64)
            .query_async(&mut connection)
            .await
            .map_err(|_| ReplayError::Unavailable)?;
        match result.as_deref() {
            Some("OK") => Ok(ConsumedGrant {
                claims: verified.claims.clone(),
            }),
            None => Err(ReplayError::AlreadyUsed),
            _ => Err(ReplayError::Unavailable),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{payload_digest, SigningOrigin};

    #[tokio::test]
    #[ignore = "requires marked disposable loopback Redis DB 13 or higher"]
    async fn concurrent_consumers_cannot_both_reach_kms() {
        let url = std::env::var("MARTY_TEST_REDIS_URL").expect("disposable Redis URL");
        let parsed = reqwest::Url::parse(&url).expect("Redis URL");
        assert!(matches!(
            parsed.host_str(),
            Some("127.0.0.1" | "localhost" | "::1")
        ));
        assert!(parsed
            .path()
            .trim_start_matches('/')
            .parse::<u8>()
            .is_ok_and(|db| db >= 13));
        let nonce = std::env::var("MARTY_TEST_REDIS_DISPOSABLE_NONCE").expect("guard nonce");
        assert!(nonce.len() >= 16);
        let client = redis::Client::open(url.as_str()).expect("Redis URL");
        let mut connection = client
            .get_connection_manager()
            .await
            .expect("disposable Redis connection");
        let observed: Option<String> = redis::cmd("GET")
            .arg("marty:tests:disposable-guard")
            .query_async(&mut connection)
            .await
            .expect("disposable marker");
        assert_eq!(observed.as_deref(), Some(nonce.as_str()));
        let store = RedisGrantReplayStore::new(connection);
        let grant = VerifiedGrant {
            claims: GrantClaims {
                version: 1,
                origin: SigningOrigin::GatewayService,
                operation_id: "disposable-operation".into(),
                organization_id: "disposable-org".into(),
                route: "/v1/signing-keys/services/service-1/sign".into(),
                service_id: Some("service-1".into()),
                issuer_did: None,
                key_reference: None,
                key_purpose: "vc_jwt_issuer".into(),
                algorithm: "ES256".into(),
                payload_sha256_b64: payload_digest(b"exact.payload"),
                issued_at: 1_700_000_000,
                expires_at: 1_700_000_030,
                nonce,
            },
        };
        let now = 1_700_000_000;
        let (a, b) = tokio::join!(store.consume_at(&grant, now), store.consume_at(&grant, now));
        assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
        assert!(
            matches!(a, Err(ReplayError::AlreadyUsed))
                || matches!(b, Err(ReplayError::AlreadyUsed))
        );
        assert!(matches!(
            store.consume_at(&grant, now).await,
            Err(ReplayError::AlreadyUsed)
        ));
        assert!(matches!(
            store.consume_at(&grant, 1_700_000_031).await,
            Err(ReplayError::Expired)
        ));
    }
}
