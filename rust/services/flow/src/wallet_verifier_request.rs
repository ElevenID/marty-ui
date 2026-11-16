//! Owner-produced exact request evidence for paired wallet governance.
//! Caller locators select an instance; they never supply its tenant, query,
//! signing key or response destination. HTTP/workload admission is separate.

use chrono::{DateTime, Duration, Utc};
use marty_verification::flow::FlowInstanceStatus;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    presentation_request::load_frozen_flow_presentation_request,
    request_object::{REQUEST_ALGORITHM, REQUEST_FORMAT, REQUEST_PURPOSE},
    FlowInstanceRecord, FlowProviderError, FlowProviderRegistry, FlowRequestObjectError,
    Oid4vpClientIdScheme, RequestObjectCompatibility, RequestObjectOptions, RequestObjectTransport,
};

const STORED_REQUEST: &str = "paired_wallet_signed_request_v1";
const CONTRACT: &str = "marty.flow/wallet-verifier-request/v1";
const MAXIMUM_BYTES: usize = 64 * 1024;

#[derive(Debug, Error)]
pub enum WalletVerifierRequestError {
    #[error("FLOW.WALLET_VERIFIER_REQUEST_UNAVAILABLE")]
    Unavailable,
    #[error(transparent)]
    Provider(#[from] FlowProviderError),
    #[error(transparent)]
    Request(#[from] FlowRequestObjectError),
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredRequest {
    scope_sha256: String,
    compact_request_jws: String,
}

#[derive(Clone, Serialize)]
pub struct WalletVerifierRequestProjection {
    contract: &'static str,
    organization_id: String,
    instance_id: String,
    request_uri: String,
    client_id: String,
    request_key_id: String,
    public_jwk: Value,
    compact_request_jws: String,
    request_jws_sha256: String,
    response_uri: String,
    nonce: String,
    request_issued_at: DateTime<Utc>,
    request_expires_at: DateTime<Utc>,
    observed_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl WalletVerifierRequestProjection {
    pub(crate) fn compact_request_jws(&self) -> &str {
        &self.compact_request_jws
    }

    pub(crate) fn is_current(&self, now: DateTime<Utc>) -> bool {
        self.observed_at <= now && now < self.expires_at && now < self.request_expires_at
    }
}

pub(crate) fn has_wallet_verifier_request(instance: &FlowInstanceRecord) -> bool {
    instance.context.get(STORED_REQUEST).is_some()
}

pub struct PreparedWalletVerifierRequest {
    /// The caller must persist this preimage with its existing status/time CAS
    /// before returning a newly produced projection. Never return an uncommitted
    /// request after a competing writer changed its instance.
    /// Cached responses also require a current-state reread after the async
    /// key lookup; `changed == false` is not an authorization shortcut.
    pub instance: FlowInstanceRecord,
    pub projection: WalletVerifierRequestProjection,
    pub changed: bool,
}

fn paired_query(query: &Value) -> bool {
    let Some(object) = query.as_object().filter(|object| object.len() == 1) else {
        return false;
    };
    let Some(credentials) = object
        .get("credentials")
        .and_then(Value::as_array)
        .filter(|values| values.len() == 1)
    else {
        return false;
    };
    let Some(credential) = credentials[0].as_object() else {
        return false;
    };
    if credential.keys().any(|key| {
        !matches!(
            key.as_str(),
            "id" | "format" | "meta" | "claims" | "require_cryptographic_holder_binding"
        )
    }) || credential
        .get("id")
        .and_then(Value::as_str)
        .is_none_or(|id| !text(id))
        || credential.get("format").and_then(Value::as_str) != Some("dc+sd-jwt")
        || !credential.contains_key("claims")
        || credential
            .get("require_cryptographic_holder_binding")
            .is_some_and(|value| value.as_bool() != Some(true))
    {
        return false;
    }
    if let Some(meta) = credential.get("meta") {
        let Some(meta) = meta.as_object().filter(|meta| meta.len() == 1) else {
            return false;
        };
        let Some(values) = meta
            .get("vct_values")
            .and_then(Value::as_array)
            .filter(|values| !values.is_empty() && values.len() <= 32)
        else {
            return false;
        };
        let mut unique = std::collections::BTreeSet::new();
        if !values.iter().all(|value| {
            value
                .as_str()
                .is_some_and(|value| text(value) && unique.insert(value))
        }) {
            return false;
        }
    }
    if let Some(claims) = credential.get("claims") {
        let Some(claims) = claims
            .as_array()
            .filter(|claims| !claims.is_empty() && claims.len() <= 64)
        else {
            return false;
        };
        let mut unique = std::collections::BTreeSet::new();
        let mut ids = std::collections::BTreeSet::new();
        for claim in claims {
            let Some(claim) = claim.as_object() else {
                return false;
            };
            if claim
                .keys()
                .any(|key| !matches!(key.as_str(), "path" | "id"))
                || claim.get("id").is_some_and(|value| {
                    value.as_str().is_none_or(|id| !text(id) || !ids.insert(id))
                })
            {
                return false;
            }
            let Some(path) = claim
                .get("path")
                .and_then(Value::as_array)
                .filter(|path| path.len() == 1)
            else {
                return false;
            };
            let Some(name) = path[0].as_str() else {
                return false;
            };
            let mut bytes = name.bytes();
            if name.len() > 256
                || !bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic())
                || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                || !unique.insert(name)
            {
                return false;
            }
        }
    }
    true
}

fn text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 2048
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

/// Prepare the owner's canonical signed request or revalidate its immutable
/// stored JWS. The entry point deliberately accepts no caller recipient/key/JWS.
/// `organization_id` must come from the authenticated governance owner.
pub async fn prepare_wallet_verifier_request(
    providers: &FlowProviderRegistry,
    mut instance: FlowInstanceRecord,
    organization_id: &str,
    public_base_url: &str,
    options: &RequestObjectOptions,
    now: DateTime<Utc>,
) -> Result<PreparedWalletVerifierRequest, WalletVerifierRequestError> {
    let invalid = || WalletVerifierRequestError::Unavailable;
    // Sample-bound public sessions are server specimen journeys. Managed
    // authority must not turn them into an external-wallet request channel.
    crate::public_verification_session::require_wallet_session(&instance).map_err(|_| invalid())?;
    let base = public_base_url.trim_end_matches('/');
    let parsed_base = url::Url::parse(base).map_err(|_| invalid())?;
    if organization_id.is_empty()
        || instance.organization_id != organization_id
        || uuid::Uuid::parse_str(&instance.id)
            .map_or(true, |id| id.is_nil() || id.to_string() != instance.id)
        || !matches!(
            instance.status,
            FlowInstanceStatus::AwaitingWallet | FlowInstanceStatus::InProgress
        )
        || instance.expires_at.is_none_or(|expiry| expiry <= now)
        || parsed_base.scheme() != "https"
        || parsed_base.host_str().is_none()
        || !parsed_base.username().is_empty()
        || parsed_base.password().is_some()
        || parsed_base.query().is_some()
        || parsed_base.fragment().is_some()
        || options.client_id_scheme != Oid4vpClientIdScheme::DecentralizedIdentifier
        || options.compatibility != RequestObjectCompatibility::Standard
        || options.transport != RequestObjectTransport::RequestUri
        || options.wallet_nonce.is_some()
        || !options.expected_origins.is_empty()
        || instance.context["flow_type"].as_str() == Some("siop_v2")
        || instance.context["oid4vp_profile"].as_str() == Some("haip")
        || instance.context["request_uri_method"].as_str() == Some("post")
        || instance.context["request_transport"].as_str() == Some("url_query")
    {
        return Err(invalid());
    }
    let frozen = load_frozen_flow_presentation_request(&instance).map_err(|_| invalid())?;
    if !paired_query(&frozen.dcql_query) {
        return Err(invalid());
    }
    let scope_sha256 = marty_oid4vp_contract::digest_domain_json(
        "marty.flow/paired-wallet-request-scope/v1",
        &json!({
            "organization_id":instance.organization_id,"instance_id":instance.id,
            "instance_expires_at":instance.expires_at,"public_base_url":base,
            "frozen":frozen,"options":{
                "verifier_did_method":format!("{:?}",options.verifier_did_method),
                "verifier_client_id":options.verifier_client_id,
                "strict_client_metadata":options.strict_client_metadata,
                "verifier_display_name":options.verifier_display_name,
                "verifier_logo_uri":options.verifier_logo_uri,
            }
        }),
    )
    .map_err(|_| invalid())?;
    let stored = instance.context.get(STORED_REQUEST).cloned();
    let changed = stored.is_none();
    let compact_request_jws = if let Some(stored) = stored {
        let stored: StoredRequest = serde_json::from_value(stored).map_err(|_| invalid())?;
        if stored.scope_sha256 != scope_sha256 {
            return Err(invalid());
        }
        stored.compact_request_jws
    } else {
        // Bound the signed request lifetime without shortening the actual Flow
        // instance or changing its existing expiry/retention behavior.
        let original_expiry = instance.expires_at;
        instance.expires_at = Some(
            original_expiry.ok_or_else(invalid)?.min(
                now.checked_add_signed(Duration::seconds(900))
                    .ok_or_else(invalid)?,
            ),
        );
        let ready = crate::request_object::build_paired_wallet_request_object(
            providers,
            instance,
            &frozen.artifacts(),
            base,
            options,
            now,
        )
        .await?;
        instance = ready.instance;
        instance.expires_at = original_expiry;
        ready.compact_jwt
    };
    if compact_request_jws.is_empty() || compact_request_jws.len() > MAXIMUM_BYTES {
        return Err(invalid());
    }
    let issuer_did = instance.context["oid4vp_issuer_did"]
        .as_str()
        .ok_or_else(invalid)?;
    let identity = providers
        .signing_identity
        .as_ref()
        .ok_or_else(invalid)?
        .resolve(
            organization_id,
            issuer_did,
            REQUEST_PURPOSE,
            REQUEST_FORMAT,
            Some(REQUEST_ALGORITHM),
        )
        .await?;
    identity.validate_binding(
        organization_id,
        issuer_did,
        REQUEST_PURPOSE,
        REQUEST_FORMAT,
        Some(REQUEST_ALGORITHM),
    )?;
    // Identity lookup/signing can await remote owners. Never label a request
    // fresh using only the clock captured before those operations.
    let now = Utc::now().max(now);
    let response_uri = format!("{base}/v1/flows/instances/{}/submit", instance.id);
    let (expected_client_id, expected_did, certificate_chain) =
        crate::request_object::resolve_oid4vp_client_identity(&identity, &response_uri, options)
            .map_err(|_| invalid())?;
    let expected_key_id = crate::request_object::verifier_request_kid(
        &identity,
        &expected_did,
        options.verifier_did_method,
    )
    .map_err(|_| invalid())?;
    if certificate_chain.is_some() {
        return Err(invalid());
    }
    let public_jwk = json!(identity.public_jwk);
    if marty_key_material_policy::contains_private_key(&public_jwk) {
        return Err(invalid());
    }
    let verified = marty_oid4vci::jose::verify_compact_jwt_with_public_jwk(
        &compact_request_jws,
        &public_jwk.to_string(),
        REQUEST_ALGORITHM,
    )
    .map_err(|_| invalid())?;
    let header = verified.header.as_object().ok_or_else(invalid)?;
    if header.len() != 3
        || header.get("alg").and_then(Value::as_str) != Some(REQUEST_ALGORITHM)
        || header.get("typ").and_then(Value::as_str) != Some(REQUEST_FORMAT)
    {
        return Err(invalid());
    }
    let request_key_id = header
        .get("kid")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    let claims = &verified.claims;
    if claims.as_object().is_none_or(|claims| {
        claims.len() != 12
            || claims.keys().any(|key| {
                ![
                    "aud",
                    "client_id",
                    "exp",
                    "iat",
                    "iss",
                    "nonce",
                    "response_mode",
                    "response_type",
                    "response_uri",
                    "state",
                    "client_metadata",
                    "dcql_query",
                ]
                .contains(&key.as_str())
            })
    }) || claims["client_metadata"]
        != crate::request_object::paired_wallet_client_metadata(base, options)
    {
        return Err(invalid());
    }
    let client_id = claims["client_id"].as_str().ok_or_else(invalid)?;
    let client_did = client_id
        .strip_prefix("decentralized_identifier:")
        .ok_or_else(invalid)?;
    if client_id != expected_client_id
        || request_key_id != expected_key_id
        || !client_did.starts_with("did:")
        || request_key_id
            .strip_prefix(&format!("{client_did}#"))
            .is_none_or(str::is_empty)
        || claims["iss"].as_str() != Some(client_id)
        || claims["aud"].as_str() != Some("https://self-issued.me/v2")
        || claims["response_type"].as_str() != Some("vp_token")
        || claims["response_mode"].as_str() != Some("direct_post")
        || claims["response_uri"].as_str() != Some(response_uri.as_str())
        || claims["state"].as_str() != Some(instance.id.as_str())
        || claims["nonce"] != instance.context["nonce"]
        || claims["nonce"].as_str().is_none_or(str::is_empty)
        || claims["dcql_query"] != frozen.dcql_query
    {
        return Err(invalid());
    }
    let issued_at = DateTime::from_timestamp(claims["iat"].as_i64().ok_or_else(invalid)?, 0)
        .ok_or_else(invalid)?;
    let request_expires_at =
        DateTime::from_timestamp(claims["exp"].as_i64().ok_or_else(invalid)?, 0)
            .ok_or_else(invalid)?;
    if issued_at > now
        || request_expires_at <= now
        || request_expires_at <= issued_at
        || request_expires_at > issued_at + Duration::seconds(900)
        || instance
            .expires_at
            .is_none_or(|expiry| request_expires_at > expiry)
    {
        return Err(invalid());
    }
    let projection = WalletVerifierRequestProjection {
        contract: CONTRACT,
        organization_id: organization_id.into(),
        instance_id: instance.id.clone(),
        request_uri: format!("{base}/v1/flows/instances/{}/request", instance.id),
        client_id: client_id.into(),
        request_key_id: request_key_id.into(),
        public_jwk,
        request_jws_sha256: format!("{:x}", Sha256::digest(compact_request_jws.as_bytes())),
        compact_request_jws: compact_request_jws.clone(),
        response_uri: claims["response_uri"].as_str().ok_or_else(invalid)?.into(),
        nonce: claims["nonce"].as_str().ok_or_else(invalid)?.into(),
        request_issued_at: issued_at,
        request_expires_at,
        observed_at: now,
        expires_at: now
            .checked_add_signed(Duration::seconds(60))
            .ok_or_else(invalid)?
            .min(request_expires_at),
    };
    if serde_json::to_vec(&projection)
        .map_err(|_| invalid())?
        .len()
        > MAXIMUM_BYTES
    {
        return Err(invalid());
    }
    if changed {
        instance
            .context
            .as_object_mut()
            .ok_or_else(invalid)?
            .insert(
                STORED_REQUEST.into(),
                serde_json::to_value(StoredRequest {
                    scope_sha256,
                    compact_request_jws,
                })
                .map_err(|_| invalid())?,
            );
        instance.kernel().map_err(|_| invalid())?;
    }
    Ok(PreparedWalletVerifierRequest {
        instance,
        projection,
        changed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SigningIdentity, SigningIdentityProvider, SigningRequest, SigningResult};
    use async_trait::async_trait;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    use std::{
        collections::BTreeMap,
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc,
        },
    };

    // Negative unit cases have only a public key. Positive cases require the
    // separately guarded owned TLS OpenBao driver; no signing feature/key is
    // enabled or constructed in this crate.
    struct FixtureSigner {
        public_jwk: BTreeMap<String, Value>,
        remote: Option<(reqwest::Client, String, String)>,
        signs: AtomicUsize,
        pause_resolve: AtomicBool,
        resolve_started: tokio::sync::Notify,
        resume_resolve: tokio::sync::Notify,
    }

    impl FixtureSigner {
        fn new() -> Self {
            Self {
                public_jwk: BTreeMap::from([
                    ("kty".into(), json!("EC")),
                    ("crv".into(), json!("P-256")),
                    (
                        "x".into(),
                        json!("axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY"),
                    ),
                    (
                        "y".into(),
                        json!("T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"),
                    ),
                ]),
                remote: None,
                signs: AtomicUsize::new(0),
                pause_resolve: AtomicBool::new(false),
                resolve_started: tokio::sync::Notify::new(),
                resume_resolve: tokio::sync::Notify::new(),
            }
        }

        fn from_owned_fixture() -> Self {
            let nonce = std::env::var("MARTY_TEST_WALLET_REQUEST_FIXTURE_NONCE")
                .expect("owned fixture nonce");
            assert!(nonce.len() == 64 && nonce.bytes().all(|byte| byte.is_ascii_hexdigit()));
            let endpoint =
                std::env::var("MARTY_TEST_WALLET_REQUEST_SIGN_URL").expect("owned fixture URL");
            let url = url::Url::parse(&endpoint).unwrap();
            assert!(
                url.scheme() == "https"
                    && url.host_str() == Some("127.0.0.1")
                    && url.port().is_some()
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.path() == format!("/v1/transit/sign/wallet-request-{nonce}")
                    && url.query().is_none()
                    && url.fragment().is_none()
            );
            let ca = std::fs::read(
                std::env::var("MARTY_TEST_WALLET_REQUEST_CA").expect("owned fixture CA"),
            )
            .unwrap();
            let client = reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(10))
                .add_root_certificate(reqwest::Certificate::from_pem(&ca).unwrap())
                .build()
                .unwrap();
            let token = std::fs::read_to_string(
                std::env::var("MARTY_TEST_WALLET_REQUEST_TOKEN_FILE")
                    .expect("owned signer token file"),
            )
            .unwrap();
            let public_jwk = serde_json::from_str(
                &std::env::var("MARTY_TEST_WALLET_REQUEST_PUBLIC_JWK").expect("owned public key"),
            )
            .unwrap();
            Self {
                public_jwk,
                remote: Some((client, endpoint, token)),
                signs: AtomicUsize::new(0),
                pause_resolve: AtomicBool::new(false),
                resolve_started: tokio::sync::Notify::new(),
                resume_resolve: tokio::sync::Notify::new(),
            }
        }
    }

    #[async_trait]
    impl SigningIdentityProvider for FixtureSigner {
        async fn resolve(
            &self,
            organization_id: &str,
            issuer_did: &str,
            key_purpose: &str,
            credential_format: &str,
            algorithm: Option<&str>,
        ) -> Result<SigningIdentity, FlowProviderError> {
            if self.pause_resolve.swap(false, Ordering::SeqCst) {
                self.resolve_started.notify_one();
                self.resume_resolve.notified().await;
            }
            assert_eq!(algorithm, Some("ES256"));
            Ok(SigningIdentity {
                organization_id: organization_id.into(),
                issuer_did: issuer_did.into(),
                verification_method_id: format!("{issuer_did}#key-1"),
                signing_key_reference: "owned-fixture-reference".into(),
                public_jwk: self.public_jwk.clone(),
                key_purpose: key_purpose.into(),
                credential_format: credential_format.into(),
                algorithm: "ES256".into(),
            })
        }
        async fn sign(&self, request: &SigningRequest) -> Result<SigningResult, FlowProviderError> {
            self.signs.fetch_add(1, Ordering::SeqCst);
            let (client, endpoint, token) = self
                .remote
                .as_ref()
                .expect("negative unit case must never sign");
            let input = URL_SAFE_NO_PAD.decode(&request.payload_b64url).unwrap();
            let response = client
                .post(endpoint)
                .header("X-Vault-Token", token)
                .json(
                    &json!({"input":base64::engine::general_purpose::STANDARD.encode(input),
                    "hash_algorithm":"sha2-256","marshaling_algorithm":"jws"}),
                )
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap()
                .json::<Value>()
                .await
                .unwrap();
            let encoded = response["data"]["signature"]
                .as_str()
                .unwrap()
                .strip_prefix("vault:v1:")
                .unwrap();
            let raw = URL_SAFE_NO_PAD.decode(encoded).unwrap();
            assert_eq!(raw.len(), 64);
            Ok(SigningResult {
                issuer_did: request.issuer_did.clone(),
                verification_method_id: request.verification_method_id.clone(),
                algorithm: request.algorithm.clone(),
                signature_raw_b64url: URL_SAFE_NO_PAD.encode(raw),
            })
        }
    }

    fn instance(now: DateTime<Utc>) -> FlowInstanceRecord {
        instance_with_id(now, "11111111-2222-4333-8444-555555555555")
    }

    fn instance_with_id(now: DateTime<Utc>, id: &str) -> FlowInstanceRecord {
        let mut instance = FlowInstanceRecord {
            id: id.into(),
            flow_definition_id: "definition-1".into(),
            organization_id: "org-1".into(),
            status: FlowInstanceStatus::AwaitingWallet,
            current_step_id: None,
            context: json!({"flow_type":"verification","nonce":"nonce-with-at-least-32-bytes-1234567890",
                "oid4vp_issuer_did":"did:web:verifier.example","presentation_policy_id":"policy-1",
                "request_transport":"request_uri","request_uri_method":"get"}),
            step_history: vec![],
            state_history: vec![],
            subject_id: None,
            subject_type: "holder".into(),
            external_reference: None,
            application_flow_key_hash: None,
            started_at: Some(now),
            completed_at: None,
            expires_at: Some(now + Duration::hours(1)),
            result: None,
            error: None,
            created_at: now,
            updated_at: now,
        };
        crate::presentation_request::freeze_flow_presentation_request(&mut instance,
            marty_oid4vp_contract::FrozenPolicyIdentity {id:"policy-1".into(),version:1,content_digest:format!("sha256:{}","a".repeat(64))},
            None,&marty_oid4vci::presentation_request::PresentationRequestArtifacts {
                presentation_definition:json!({"id":"policy-1","input_descriptors":[]}),
                dcql_query:json!({"credentials":[{"id":"member","format":"dc+sd-jwt",
                    "meta":{"vct_values":["https://credentials.example/member"]},"claims":[{"path":["given_name"]}]}]}),
            }).unwrap();
        instance
    }

    fn providers(signer: Arc<FixtureSigner>) -> FlowProviderRegistry {
        FlowProviderRegistry {
            signing_identity: Some(signer),
            ..Default::default()
        }
    }

    #[tokio::test]
    #[ignore = "requires newly owned PostgreSQL and TLS OpenBao fixtures"]
    async fn http_owner_persists_exact_request_and_cancellation_wins_async_reads() {
        use axum::{
            body::{to_bytes, Body},
            http::Request,
        };
        use tower::ServiceExt;
        let nonce = std::env::var("MARTY_TEST_WALLET_REQUEST_FIXTURE_NONCE").unwrap();
        let database_url = std::env::var("MARTY_TEST_WALLET_REQUEST_DATABASE_URL").unwrap();
        let url = url::Url::parse(&database_url).unwrap();
        assert_eq!(url.scheme(), "postgresql");
        assert_eq!(url.host_str(), Some("127.0.0.1"));
        assert!(url.port().is_some());
        assert_eq!(url.path(), format!("/wallet_request_{}", &nonce[..12]));
        assert!(url.query().is_none() && url.fragment().is_none());
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect(&database_url)
            .await
            .unwrap();
        // The driver creates this nonce-named empty database in its own exact
        // labelled container. Never reset or connect to an existing install.
        let empty: bool = sqlx::query_scalar(
            "SELECT NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname NOT IN ('public','information_schema') AND nspname NOT LIKE 'pg_%') AND NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON c.relnamespace=n.oid WHERE n.nspname='public')",
        ).fetch_one(&pool).await.unwrap();
        assert!(
            empty,
            "owned HTTP fixture must start with an empty database"
        );
        crate::migrate_flow_schema(&pool).await.unwrap();
        let repository = crate::PostgresFlowRepository::new(pool.clone());
        let signer = Arc::new(FixtureSigner::from_owned_fixture());
        let token = uuid::Uuid::new_v4().to_string();
        let app = crate::flow_read_router(crate::FlowHttpState {
            service_authenticator: Some(Arc::new(
                mmf_security::ServiceTokenAuthenticator::new(Some(token.clone()), true).unwrap(),
            )),
            repository: repository.clone(),
            providers: Arc::new(providers(signer.clone())),
            public_base_url: "https://verifier.example".into(),
            verification: crate::FlowHttpVerificationOptions::default(),
            application_approval: crate::FlowHttpApplicationApprovalOptions::default(),
        });
        let source = instance(Utc::now());
        let mut specimen=instance_with_id(Utc::now(),"11111111-2222-4333-8444-555555555557");
        specimen.context[crate::public_verification_session::PUBLIC_SESSION]=json!({"example_id":"synthetic-server-specimen"});
        assert!(repository.save_instance(&specimen).await.unwrap());
        let denied=app.clone().oneshot(Request::post(format!("/internal/v1/wallet-verifier-requests/{}",specimen.id))
            .header("x-service-token",&token).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(denied.status(),409);
        assert_eq!(signer.signs.load(Ordering::SeqCst),0);
        assert!(!has_wallet_verifier_request(&repository.instance(&specimen.id).await.unwrap().unwrap()));
        assert!(repository.save_instance(&source).await.unwrap());
        let owner_uri = format!("/internal/v1/wallet-verifier-requests/{}", source.id);
        let public_uri = format!("/v1/flows/instances/{}/request", source.id);
        let owner = app
            .clone()
            .oneshot(
                Request::post(&owner_uri)
                    .header("x-service-token", &token)
                    .header("x-organization-id", "attacker-tenant")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(owner.status(), 200);
        assert_eq!(owner.headers()["cache-control"], "no-store");
        let projection: Value =
            serde_json::from_slice(&to_bytes(owner.into_body(), MAXIMUM_BYTES).await.unwrap())
                .unwrap();
        assert_eq!(projection["organization_id"], "org-1");
        if let Ok(path) = std::env::var("MARTY_TEST_WALLET_REQUEST_PROOF_FILE") {
            use std::io::Write;
            let path = std::path::PathBuf::from(path);
            let parent = path.parent().unwrap().canonicalize().unwrap();
            let temporary = std::env::temp_dir().canonicalize().unwrap();
            assert_eq!(parent.parent(), Some(temporary.as_path()));
            assert!(parent
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("marty-flow-request-"));
            assert_eq!(
                path.file_name().unwrap().to_str().unwrap(),
                format!("flow-owner-{nonce}.json")
            );
            let mut file = std::fs::File::create_new(path).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                file.set_permissions(std::fs::Permissions::from_mode(0o600))
                    .unwrap();
            }
            file.write_all(&serde_json::to_vec(&projection).unwrap())
                .unwrap();
        }
        let original = projection["compact_request_jws"].as_str().unwrap();
        let persisted = repository.instance(&source.id).await.unwrap().unwrap();
        assert_eq!(
            persisted.context[STORED_REQUEST]["compact_request_jws"],
            original
        );
        for uri in [&public_uri, &public_uri] {
            let response = app
                .clone()
                .oneshot(Request::get(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), 200);
            assert_eq!(
                to_bytes(response.into_body(), MAXIMUM_BYTES)
                    .await
                    .unwrap()
                    .as_ref(),
                original.as_bytes()
            );
        }
        for request in [
            Request::post(&public_uri).header("content-type", "application/x-www-form-urlencoded"),
            Request::get(format!("{public_uri}?transport=dc_api")),
            Request::get(format!("{public_uri}?compat=lissi")),
        ] {
            assert_eq!(
                app.clone()
                    .oneshot(request.body(Body::empty()).unwrap())
                    .await
                    .unwrap()
                    .status(),
                409
            );
        }
        assert_eq!(signer.signs.load(Ordering::SeqCst), 1);
        // Exercise both cached-public and first-owner races at the actual async
        // provider boundary, using the real repository CAS, not a mock result.
        for first_owner in [false, true] {
            let id = if first_owner {
                "11111111-2222-4333-8444-555555555556"
            } else {
                &source.id
            };
            if first_owner {
                assert!(repository
                    .save_instance(&instance_with_id(Utc::now(), id))
                    .await
                    .unwrap());
            }
            signer.pause_resolve.store(true, Ordering::SeqCst);
            let request = if first_owner {
                Request::post(format!("/internal/v1/wallet-verifier-requests/{id}"))
                    .header("x-service-token", &token)
            } else {
                Request::get(&public_uri)
            };
            let pending = tokio::spawn(app.clone().oneshot(request.body(Body::empty()).unwrap()));
            tokio::time::timeout(
                std::time::Duration::from_secs(10),
                signer.resolve_started.notified(),
            )
            .await
            .unwrap();
            sqlx::query("UPDATE flow_service.flow_instances SET status='cancelled', updated_at=clock_timestamp() WHERE id=$1")
                .bind(id).execute(&pool).await.unwrap();
            signer.resume_resolve.notify_one();
            let response = tokio::time::timeout(std::time::Duration::from_secs(20), pending)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(response.status(), 409);
            let bytes = to_bytes(response.into_body(), MAXIMUM_BYTES).await.unwrap();
            assert!(!String::from_utf8_lossy(&bytes).contains(original));
            let cancelled = repository.instance(id).await.unwrap().unwrap();
            assert_eq!(cancelled.status, FlowInstanceStatus::Cancelled);
            assert_eq!(has_wallet_verifier_request(&cancelled), !first_owner);
        }
        pool.close().await;
    }

    #[test]
    fn paired_query_preserves_vct_and_refuses_unsupported_security_constraints() {
        let base = load_frozen_flow_presentation_request(&instance(Utc::now()))
            .unwrap()
            .dcql_query;
        assert!(paired_query(&base));
        let mut with_ids = base.clone();
        with_ids["credentials"][0]["require_cryptographic_holder_binding"] = json!(true);
        with_ids["credentials"][0]["claims"][0]["id"] = json!("claim-1");
        assert!(paired_query(&with_ids));
        for mutation in [
            "legacy-format",
            "claim-sets",
            "nested-path",
            "optional",
            "duplicate-claim",
            "empty-vct",
            "duplicate-vct",
            "unknown-meta",
            "missing-claims",
            "empty-claims",
            "leading-underscore",
            "unbound-holder",
        ] {
            let mut query = base.clone();
            match mutation {
                "missing-claims" => {
                    query["credentials"][0]
                        .as_object_mut()
                        .unwrap()
                        .remove("claims");
                }
                "empty-claims" => query["credentials"][0]["claims"] = json!([]),
                "leading-underscore" => {
                    query["credentials"][0]["claims"][0]["path"] = json!(["_unsupported"])
                }
                "unbound-holder" => {
                    query["credentials"][0]["require_cryptographic_holder_binding"] = json!(false)
                }
                "legacy-format" => query["credentials"][0]["format"] = json!("vc+sd-jwt"),
                "claim-sets" => query["credential_sets"] = json!([]),
                "nested-path" => {
                    query["credentials"][0]["claims"][0]["path"] = json!(["address", "street"])
                }
                "optional" => query["credentials"][0]["claims"][0]["optional"] = json!(true),
                "duplicate-claim" => {
                    query["credentials"][0]["claims"] =
                        json!([{"path":["given_name"]},{"path":["given_name"]}])
                }
                "empty-vct" => query["credentials"][0]["meta"]["vct_values"] = json!([]),
                "duplicate-vct" => {
                    query["credentials"][0]["meta"]["vct_values"] = json!(["type", "type"])
                }
                "unknown-meta" => {
                    query["credentials"][0]["meta"]["unsupported_policy"] = json!(true)
                }
                _ => unreachable!(),
            }
            assert!(!paired_query(&query), "{mutation}");
        }
    }

    #[tokio::test]
    #[ignore = "requires the newly owned TLS OpenBao request fixture"]
    async fn immutable_owner_request_is_revalidated_without_resigning_or_shortening_instance() {
        let now = Utc::now();
        let signer = Arc::new(FixtureSigner::from_owned_fixture());
        let ports = providers(signer.clone());
        let source = instance(now);
        let first = prepare_wallet_verifier_request(
            &ports,
            source.clone(),
            "org-1",
            "https://verifier.example",
            &Default::default(),
            now,
        )
        .await
        .unwrap();
        assert!(first.changed);
        assert_eq!(first.instance.expires_at, source.expires_at);
        assert!(first.projection.request_expires_at <= now + Duration::seconds(900));
        assert_eq!(
            first.projection.response_uri,
            format!(
                "https://verifier.example/v1/flows/instances/{}/submit",
                source.id
            )
        );
        let first_json = serde_json::to_value(&first.projection).unwrap();
        let second = prepare_wallet_verifier_request(
            &ports,
            first.instance,
            "org-1",
            "https://verifier.example",
            &Default::default(),
            now + Duration::seconds(3),
        )
        .await
        .unwrap();
        assert!(!second.changed);
        assert_eq!(
            second.projection.compact_request_jws,
            first_json["compact_request_jws"].as_str().unwrap()
        );
        assert_eq!(
            second.projection.request_jws_sha256,
            first_json["request_jws_sha256"].as_str().unwrap()
        );
        assert_eq!(signer.signs.load(Ordering::SeqCst), 1);
        assert!(prepare_wallet_verifier_request(
            &ports,
            second.instance,
            "org-1",
            "https://verifier.example",
            &Default::default(),
            now + Duration::seconds(901)
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn tenant_state_transport_and_missing_frozen_authority_fail_before_signing() {
        let now = Utc::now();
        let signer = Arc::new(FixtureSigner::new());
        let ports = providers(signer.clone());
        for mutation in [
            "tenant",
            "cancelled",
            "instance",
            "nonce",
            "frozen",
            "post",
            "haip",
            "public-specimen",
        ] {
            let mut source = instance(now);
            match mutation {
                "tenant" => source.organization_id = "other-org".into(),
                "cancelled" => source.status = FlowInstanceStatus::Completed,
                "public-specimen" => source.context[crate::public_verification_session::PUBLIC_SESSION]=json!({"example_id":"synthetic-server-specimen"}),
                "instance" => source.id = "../sibling".into(),
                "nonce" => source.context["nonce"] = json!("replaced"),
                "frozen" => {
                    source
                        .context
                        .as_object_mut()
                        .unwrap()
                        .remove(crate::presentation_request::FROZEN_PRESENTATION_REQUEST_KEY);
                }
                "post" => source.context["request_uri_method"] = json!("post"),
                "haip" => source.context["oid4vp_profile"] = json!("haip"),
                _ => unreachable!(),
            }
            assert!(
                prepare_wallet_verifier_request(
                    &ports,
                    source,
                    "org-1",
                    "https://verifier.example",
                    &Default::default(),
                    now
                )
                .await
                .is_err(),
                "{mutation}"
            );
        }
        assert_eq!(signer.signs.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    #[ignore = "requires the newly owned TLS OpenBao request fixture"]
    async fn persisted_scope_and_original_jws_cannot_be_replaced_by_a_sibling_or_tampering() {
        let now = Utc::now();
        let signer = Arc::new(FixtureSigner::from_owned_fixture());
        let ports = providers(signer.clone());
        let first = prepare_wallet_verifier_request(
            &ports,
            instance(now),
            "org-1",
            "https://verifier.example",
            &Default::default(),
            now,
        )
        .await
        .unwrap();
        for mutation in ["id", "nonce", "scope", "jws"] {
            let mut source = first.instance.clone();
            match mutation {
                "id" => source.id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee".into(),
                "nonce" => source.context["nonce"] = json!("sibling-nonce"),
                "scope" => source.context[STORED_REQUEST]["scope_sha256"] = json!("untrusted"),
                "jws" => {
                    source.context[STORED_REQUEST]["compact_request_jws"] = json!("not.a.signature")
                }
                _ => unreachable!(),
            }
            assert!(
                prepare_wallet_verifier_request(
                    &ports,
                    source,
                    "org-1",
                    "https://verifier.example",
                    &Default::default(),
                    now
                )
                .await
                .is_err(),
                "{mutation}"
            );
        }
        assert_eq!(signer.signs.load(Ordering::SeqCst), 1);
        for mutation in ["client", "key_id", "semantics", "metadata", "query"] {
            let mut source = first.instance.clone();
            let original = first
                .projection
                .compact_request_jws
                .split('.')
                .collect::<Vec<_>>();
            let mut header: Value =
                serde_json::from_slice(&URL_SAFE_NO_PAD.decode(original[0]).unwrap()).unwrap();
            let mut claims: Value =
                serde_json::from_slice(&URL_SAFE_NO_PAD.decode(original[1]).unwrap()).unwrap();
            if mutation == "client" {
                claims["client_id"] = json!("decentralized_identifier:did:web:sibling.example");
                claims["iss"] = claims["client_id"].clone();
                header["kid"] = json!("did:web:sibling.example#key-1");
            } else if mutation == "key_id" {
                header["kid"] = json!("did:web:verifier.example#different-method");
            } else if mutation == "semantics" {
                claims["transaction_data"] = json!([{"type":"unsupported-unit-transaction"}]);
            } else if mutation == "metadata" {
                claims["client_metadata"]["client_name"] = json!("different producer display");
            } else {
                claims["dcql_query"]["credentials"][0]["meta"]["vct_values"] =
                    json!(["different-type"]);
            }
            let input = format!(
                "{}.{}",
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
            );
            let signed = signer
                .sign(&SigningRequest {
                    operation_id: source.id.clone(),
                    organization_id: source.organization_id.clone(),
                    issuer_did: "did:web:verifier.example".into(),
                    verification_method_id: "did:web:verifier.example#key-1".into(),
                    signing_key_reference: "owned-fixture-reference".into(),
                    key_purpose: REQUEST_PURPOSE.into(),
                    credential_format: REQUEST_FORMAT.into(),
                    algorithm: REQUEST_ALGORITHM.into(),
                    payload_b64url: URL_SAFE_NO_PAD.encode(input.as_bytes()),
                })
                .await
                .unwrap();
            source.context[STORED_REQUEST]["compact_request_jws"] =
                json!(format!("{input}.{}", signed.signature_raw_b64url));
            let before = signer.signs.load(Ordering::SeqCst);
            assert!(
                prepare_wallet_verifier_request(
                    &ports,
                    source,
                    "org-1",
                    "https://verifier.example",
                    &Default::default(),
                    now
                )
                .await
                .is_err(),
                "{mutation}"
            );
            assert_eq!(signer.signs.load(Ordering::SeqCst), before);
        }
    }
}
