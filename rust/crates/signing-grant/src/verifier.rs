//! Fail-closed issuer-signing authorization shared by every Signing Keys route.

use std::{collections::HashMap, path::PathBuf};

use thiserror::Error;

use crate::{
    replay::{ConsumedGrant, RedisGrantReplayStore, ReplayError},
    transit::{TransitGrantClient, TransitGrantError},
    verify_envelope, GrantBinding, GrantEnvelope, GrantError, SigningOrigin,
};

const ORIGINS: [SigningOrigin; 6] = [
    SigningOrigin::GatewayService,
    SigningOrigin::GatewayIssuerDid,
    SigningOrigin::FlowWalletRequest,
    SigningOrigin::IssuanceCredential,
    SigningOrigin::IssuanceCanvas,
    SigningOrigin::IssuancePassport,
];

#[derive(Clone)]
pub struct GrantVerifier {
    clients: HashMap<SigningOrigin, TransitGrantClient>,
    verify_token_file: PathBuf,
    replay: RedisGrantReplayStore,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum GrantAuthorizationError {
    #[error("signing grant is denied")]
    Denied,
    #[error("signing grant authority is unavailable")]
    Unavailable,
}

impl GrantVerifier {
    pub fn for_managed_openbao(
        endpoint: &str,
        verify_token_file: PathBuf,
        replay: RedisGrantReplayStore,
    ) -> Result<Self, TransitGrantError> {
        if !verify_token_file.is_absolute() {
            return Err(TransitGrantError::InvalidConfig);
        }
        let clients = ORIGINS
            .into_iter()
            .map(|origin| {
                TransitGrantClient::for_origin(endpoint, origin).map(|client| (origin, client))
            })
            .collect::<Result<HashMap<_, _>, _>>()?;
        Ok(Self {
            clients,
            verify_token_file,
            replay,
        })
    }

    /// Call immediately before any issuer KMS sign operation. Verification,
    /// replay storage, and token-file failures all stop signing.
    pub async fn authorize(
        &self,
        header_value: &str,
        binding: &GrantBinding<'_>,
    ) -> Result<ConsumedGrant, GrantAuthorizationError> {
        let envelope = GrantEnvelope::from_header_value(header_value)
            .map_err(|_| GrantAuthorizationError::Denied)?;
        let client = self
            .clients
            .get(&binding.origin)
            .ok_or(GrantAuthorizationError::Denied)?;
        let token = tokio::fs::read_to_string(&self.verify_token_file)
            .await
            .map_err(|_| GrantAuthorizationError::Unavailable)?;
        let verified = verify_envelope(
            client,
            token.trim_end_matches(['\r', '\n']),
            &envelope,
            binding,
        )
        .await
        .map_err(map_grant_error)?;
        self.replay
            .consume(&verified)
            .await
            .map_err(map_replay_error)
    }
}

fn map_grant_error(error: GrantError) -> GrantAuthorizationError {
    match error {
        GrantError::VerifierUnavailable | GrantError::MinterUnavailable => {
            GrantAuthorizationError::Unavailable
        }
        GrantError::Malformed
        | GrantError::Expired
        | GrantError::BindingMismatch
        | GrantError::InvalidHmac => GrantAuthorizationError::Denied,
    }
}

fn map_replay_error(error: ReplayError) -> GrantAuthorizationError {
    match error {
        ReplayError::Unavailable => GrantAuthorizationError::Unavailable,
        ReplayError::Expired | ReplayError::AlreadyUsed => GrantAuthorizationError::Denied,
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use serde_json::Value;

    use super::*;
    use crate::{mint_bound, HEADER_NAME};

    #[tokio::test]
    #[ignore = "requires marked disposable loopback OpenBao and Redis with scoped grant tokens"]
    async fn live_grant_verification_is_one_use_before_kms_signing() {
        let endpoint = std::env::var("MARTY_TEST_OPENBAO_URL").expect("disposable OpenBao URL");
        let parsed = reqwest::Url::parse(&endpoint).expect("OpenBao URL");
        assert_eq!(parsed.scheme(), "http");
        assert_eq!(parsed.host_str(), Some("127.0.0.1"));
        assert_eq!(
            std::env::var("BAO_ADDR").ok().as_deref(),
            Some(endpoint.as_str())
        );
        let root = std::env::var("MARTY_TEST_OPENBAO_ROOT_TOKEN").expect("root guard token");
        let nonce = std::env::var("MARTY_TEST_OPENBAO_DISPOSABLE_NONCE").expect("guard nonce");
        assert!(nonce.len() >= 16);
        let marker: Value = reqwest::Client::new()
            .get(format!(
                "{endpoint}/v1/secret/data/marty-test-disposable-guard"
            ))
            .header("X-Vault-Token", &root)
            .send()
            .await
            .expect("marker request")
            .error_for_status()
            .expect("disposable marker")
            .json()
            .await
            .expect("marker JSON");
        assert_eq!(marker["data"]["data"]["nonce"], nonce);

        let redis_url = std::env::var("MARTY_TEST_REDIS_URL").expect("disposable Redis URL");
        let redis_parsed = reqwest::Url::parse(&redis_url).expect("Redis URL");
        assert!(matches!(
            redis_parsed.host_str(),
            Some("127.0.0.1" | "localhost" | "::1")
        ));
        assert!(redis_parsed
            .path()
            .trim_start_matches('/')
            .parse::<u8>()
            .is_ok_and(|db| db >= 13));
        let redis_nonce =
            std::env::var("MARTY_TEST_REDIS_DISPOSABLE_NONCE").expect("Redis guard nonce");
        assert!(redis_nonce.len() >= 16);
        let mut redis = redis::Client::open(redis_url.as_str())
            .expect("Redis URL")
            .get_connection_manager()
            .await
            .expect("Redis connection");
        let observed: Option<String> = redis::cmd("GET")
            .arg("marty:tests:disposable-guard")
            .query_async(&mut redis)
            .await
            .expect("Redis marker");
        assert_eq!(observed.as_deref(), Some(redis_nonce.as_str()));

        let mint_token = std::env::var("MARTY_TEST_GRANT_MINT_TOKEN").expect("mint token");
        let verify_token = std::env::var("MARTY_TEST_GRANT_VERIFY_TOKEN").expect("verify token");
        assert_ne!(mint_token, verify_token);
        assert_ne!(mint_token, root);
        assert_ne!(verify_token, root);
        let mut token_file = tempfile::NamedTempFile::new().expect("temporary token file");
        token_file
            .write_all(verify_token.as_bytes())
            .expect("write verify token");
        let client = TransitGrantClient::for_origin(&endpoint, SigningOrigin::GatewayService)
            .expect("mounted Gateway grant key");
        let verifier = GrantVerifier::for_managed_openbao(
            &endpoint,
            token_file.path().to_owned(),
            RedisGrantReplayStore::new(redis),
        )
        .expect("grant verifier");
        let binding = GrantBinding {
            origin: SigningOrigin::GatewayService,
            operation_id: "disposable-gateway-sign-1",
            organization_id: "disposable-org-1",
            route: "/v1/signing-keys/services/service-1/sign",
            service_id: Some("service-1"),
            issuer_did: None,
            key_reference: Some("disposable-key-1"),
            key_purpose: "vc_jwt_issuer",
            algorithm: "ES256",
            payload: b"exact.payload",
        };
        let grant = mint_bound(&client, &mint_token, &binding)
            .await
            .expect("OpenBao mint");
        let header = grant.to_header_value().expect(HEADER_NAME);
        let (first, second) = tokio::join!(
            verifier.authorize(&header, &binding),
            verifier.authorize(&header, &binding),
        );
        assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
        assert!(
            matches!(first.as_ref(), Err(GrantAuthorizationError::Denied))
                || matches!(second.as_ref(), Err(GrantAuthorizationError::Denied))
        );
        let consumed = first
            .ok()
            .or_else(|| second.ok())
            .expect("one use succeeds");
        assert!(consumed.authorizes(&binding));
        let altered = GrantBinding {
            payload: b"altered.payload",
            ..binding
        };
        assert!(matches!(
            verifier.authorize(&header, &altered).await,
            Err(GrantAuthorizationError::Denied)
        ));
    }
}
