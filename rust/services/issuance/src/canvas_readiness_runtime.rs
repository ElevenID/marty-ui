//! Production input collection for the pure Canvas readiness policy.
//!
//! Every external lookup is bounded and fail-closed. The runtime owns only
//! orchestration and projections; the deterministic readiness decision stays
//! in `canvas_readiness`.

use std::{collections::BTreeSet, sync::Arc, time::Duration};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use marty_oid4vci::{
    jose::{verify_compact_jwt_with_public_jwk, verify_detached_signature_with_public_jwk},
    lti::canvas_lti_trust_profile,
};
use rand::RngCore;
use reqwest::{Client, StatusCode, Url};
use serde_json::{json, Map, Value};
use sqlx::{PgPool, Row};
use thiserror::Error;

use crate::{
    canvas_binding_domain::CanvasProgramBindingRecord,
    canvas_lti_experience::portable_canvas_pilot_enabled,
    canvas_lti_tool_signing::CanvasLtiToolJwtSigner,
    canvas_management_domain::CanvasPlatformRecord,
    canvas_management_service::CanvasReadinessInputProvider,
    canvas_readiness::{
        readiness_issuer_configuration, CanvasOAuthReadinessConnection, CanvasReadinessInputs,
        CanvasReadinessIssuerConfiguration, CanvasSyncReadiness,
    },
    credential_builder::{HttpDidSigner, SignRequest},
    credential_issuer::HttpIssuerContextResolver,
};

const MAX_DOCUMENT_BYTES: usize = 1_048_576;
const READINESS_AUDIENCE: &str = "marty:canvas-readiness";
const PRIVATE_JWK_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("Canvas readiness dependency is unavailable")]
pub struct CanvasReadinessDependencyError;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct CanvasReadinessDocuments {
    pub credential_template: Map<String, Value>,
    pub credential_status_profile: Map<String, Value>,
}

#[async_trait]
pub trait CanvasReadinessStateProvider: Send + Sync {
    async fn oauth_connection(
        &self,
        organization_id: &str,
        platform_id: &str,
    ) -> Result<Option<CanvasOAuthReadinessConnection>, CanvasReadinessDependencyError>;

    async fn worker_heartbeat_configured(
        &self,
        evaluated_at: DateTime<Utc>,
    ) -> Result<bool, CanvasReadinessDependencyError>;

    async fn sync_readiness(
        &self,
        organization_id: &str,
        platform_id: &str,
        binding_id: &str,
        evaluated_at: DateTime<Utc>,
    ) -> Result<CanvasSyncReadiness, CanvasReadinessDependencyError>;
}

#[async_trait]
pub trait CanvasReadinessDocumentProvider: Send + Sync {
    async fn documents(&self, credential_template_id: &str) -> CanvasReadinessDocuments;
}

#[async_trait]
pub trait CanvasReadinessChallengeProvider: Send + Sync {
    async fn lti_tool_signing_ready(&self, evaluated_at: DateTime<Utc>) -> bool;

    async fn kms_did_signing_ready(
        &self,
        organization_id: &str,
        credential_template: &Map<String, Value>,
        evaluated_at: DateTime<Utc>,
    ) -> bool;
}

#[async_trait]
pub(crate) trait CanvasReadinessIssuerResolver: Send + Sync {
    async fn resolve_issuer(
        &self,
        organization_id: &str,
        configuration: &CanvasReadinessIssuerConfiguration,
    ) -> Result<Value, CanvasReadinessDependencyError>;
}

#[async_trait]
pub(crate) trait CanvasReadinessDidSigner: Send + Sync {
    async fn sign_challenge(
        &self,
        organization_id: &str,
        configuration: &CanvasReadinessIssuerConfiguration,
        verification_method_id: &str,
        challenge: &[u8],
    ) -> Result<String, CanvasReadinessDependencyError>;
}

#[async_trait]
impl CanvasReadinessIssuerResolver for HttpIssuerContextResolver {
    async fn resolve_issuer(
        &self,
        organization_id: &str,
        configuration: &CanvasReadinessIssuerConfiguration,
    ) -> Result<Value, CanvasReadinessDependencyError> {
        self.resolve_raw(
            organization_id,
            &configuration.issuer_did,
            None,
            configuration.credential_format,
            configuration.key_purpose,
            &configuration.algorithm,
        )
        .await
        .map_err(|_| CanvasReadinessDependencyError)
    }
}

#[async_trait]
impl CanvasReadinessDidSigner for HttpDidSigner {
    async fn sign_challenge(
        &self,
        organization_id: &str,
        configuration: &CanvasReadinessIssuerConfiguration,
        verification_method_id: &str,
        challenge: &[u8],
    ) -> Result<String, CanvasReadinessDependencyError> {
        self.sign_did(SignRequest {
            organization_id: organization_id.to_owned(),
            issuer_did: configuration.issuer_did.clone(),
            credential_format: configuration.credential_format.to_owned(),
            key_purpose: configuration.key_purpose.to_owned(),
            payload: challenge.to_vec(),
            algorithm: configuration.algorithm.clone(),
            verification_method_id: verification_method_id.to_owned(),
        })
        .await
        .map(|response| response.signature_b64)
        .map_err(|_| CanvasReadinessDependencyError)
    }
}

#[derive(Clone)]
pub struct LiveCanvasReadinessChallengeProvider {
    lti_signer: Arc<dyn CanvasLtiToolJwtSigner>,
    issuer_resolver: Arc<dyn CanvasReadinessIssuerResolver>,
    did_signer: Arc<dyn CanvasReadinessDidSigner>,
}

impl std::fmt::Debug for LiveCanvasReadinessChallengeProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LiveCanvasReadinessChallengeProvider")
            .finish_non_exhaustive()
    }
}

impl LiveCanvasReadinessChallengeProvider {
    pub fn new(
        lti_signer: Arc<dyn CanvasLtiToolJwtSigner>,
        signing_service_url: Url,
        signing_service_api_key: Option<&str>,
        timeout: Duration,
    ) -> Result<Self, String> {
        let issuer_resolver = HttpIssuerContextResolver::new(
            signing_service_url.clone(),
            signing_service_api_key,
            timeout,
        )
        .map_err(|_| "Canvas readiness issuer resolver could not be configured".to_owned())?;
        let did_signer = HttpDidSigner::new(signing_service_url, signing_service_api_key, timeout)
            .map_err(|_| "Canvas readiness DID signer could not be configured".to_owned())?;
        Ok(Self::with_ports(
            lti_signer,
            Arc::new(issuer_resolver),
            Arc::new(did_signer),
        ))
    }

    pub(crate) fn with_ports(
        lti_signer: Arc<dyn CanvasLtiToolJwtSigner>,
        issuer_resolver: Arc<dyn CanvasReadinessIssuerResolver>,
        did_signer: Arc<dyn CanvasReadinessDidSigner>,
    ) -> Self {
        Self {
            lti_signer,
            issuer_resolver,
            did_signer,
        }
    }

    async fn lti_challenge(&self, evaluated_at: DateTime<Utc>) -> Option<()> {
        let mut nonce = [0_u8; 24];
        rand::rng().fill_bytes(&mut nonce);
        let payload = json!({
            "iss": READINESS_AUDIENCE,
            "aud": READINESS_AUDIENCE,
            "iat": evaluated_at.timestamp(),
            "jti": URL_SAFE_NO_PAD.encode(nonce),
        });
        let token = self.lti_signer.sign_jwt(&payload).await.ok()?;
        let segments = token.split('.').collect::<Vec<_>>();
        let [encoded_header, encoded_payload, _] = segments.as_slice() else {
            return None;
        };
        let header: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded_header).ok()?).ok()?;
        let signed_payload: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded_payload).ok()?).ok()?;
        let header = header.as_object()?;
        let key_id = header.get("kid").and_then(Value::as_str)?;
        if header.get("alg").and_then(Value::as_str) != Some("RS256")
            || key_id.trim().is_empty()
            || signed_payload != payload
        {
            return None;
        }
        let jwks = self.lti_signer.public_jwks().await.ok()?;
        let matching = jwks
            .get("keys")
            .and_then(Value::as_array)?
            .iter()
            .filter_map(Value::as_object)
            .filter(|key| key.get("kid").and_then(Value::as_str) == Some(key_id))
            .collect::<Vec<_>>();
        let [public_jwk] = matching.as_slice() else {
            return None;
        };
        if contains_private_jwk_material(public_jwk)
            || public_jwk.get("kty").and_then(Value::as_str) != Some("RSA")
            || !optional_string_matches(public_jwk.get("alg"), "RS256")
            || !optional_string_matches(public_jwk.get("use"), "sig")
        {
            return None;
        }
        let public_jwk = serde_json::to_string(public_jwk).ok()?;
        let verified = verify_compact_jwt_with_public_jwk(&token, &public_jwk, "RS256").ok()?;
        (verified.header == Value::Object(header.clone()) && verified.claims == payload)
            .then_some(())
    }

    async fn kms_did_challenge(
        &self,
        organization_id: &str,
        credential_template: &Map<String, Value>,
    ) -> Option<()> {
        let configuration = readiness_issuer_configuration(credential_template)?;
        let resolution = self
            .issuer_resolver
            .resolve_issuer(organization_id, &configuration)
            .await
            .ok()?;
        let verification_method_id = validate_issuer_resolution(&resolution, &configuration)?;
        let public_jwk = resolution.get("public_jwk")?.as_object()?;
        let mut nonce = [0_u8; 32];
        rand::rng().fill_bytes(&mut nonce);
        let mut challenge = b"marty-canvas-readiness-v1\0".to_vec();
        challenge.extend_from_slice(organization_id.as_bytes());
        challenge.push(0);
        challenge.extend_from_slice(&nonce);
        let signature = self
            .did_signer
            .sign_challenge(
                organization_id,
                &configuration,
                verification_method_id,
                &challenge,
            )
            .await
            .ok()?;
        let signature = URL_SAFE_NO_PAD
            .decode(signature.trim().trim_end_matches('='))
            .ok()?;
        if signature.is_empty() {
            return None;
        }
        let public_jwk = serde_json::to_string(public_jwk).ok()?;
        verify_detached_signature_with_public_jwk(
            &challenge,
            &signature,
            &public_jwk,
            &configuration.algorithm,
        )
        .ok()
        .filter(|verified| *verified)
        .map(|_| ())
    }
}

#[async_trait]
impl CanvasReadinessChallengeProvider for LiveCanvasReadinessChallengeProvider {
    async fn lti_tool_signing_ready(&self, evaluated_at: DateTime<Utc>) -> bool {
        self.lti_challenge(evaluated_at).await.is_some()
    }

    async fn kms_did_signing_ready(
        &self,
        organization_id: &str,
        credential_template: &Map<String, Value>,
        _evaluated_at: DateTime<Utc>,
    ) -> bool {
        self.kms_did_challenge(organization_id, credential_template)
            .await
            .is_some()
    }
}

fn validate_issuer_resolution<'a>(
    resolution: &'a Value,
    configuration: &CanvasReadinessIssuerConfiguration,
) -> Option<&'a str> {
    let resolution = resolution.as_object()?;
    if resolution.get("issuer_did").and_then(Value::as_str)
        != Some(configuration.issuer_did.as_str())
        || !optional_string_matches(resolution.get("algorithm"), &configuration.algorithm)
    {
        return None;
    }
    let verification_method_id = resolution
        .get("verification_method_id")
        .and_then(Value::as_str)?;
    if !verification_method_id.starts_with(&format!("{}#", configuration.issuer_did))
        || !did_publishes_verification_method(resolution, verification_method_id)
    {
        return None;
    }
    let profile = resolution.get("issuer_profile")?.as_object()?;
    if !profile
        .get("status")
        .and_then(Value::as_str)
        .is_some_and(|status| status.eq_ignore_ascii_case("active"))
        || !optional_string_matches(profile.get("issuer_did"), &configuration.issuer_did)
        || !optional_string_matches(profile.get("key_purpose"), configuration.key_purpose)
        || !optional_string_matches(profile.get("algorithm"), &configuration.algorithm)
        || !optional_string_matches(
            profile.get("verification_method_id"),
            verification_method_id,
        )
    {
        return None;
    }
    let public_jwk = resolution.get("public_jwk")?.as_object()?;
    if public_jwk.get("kid").and_then(Value::as_str) != Some(verification_method_id)
        || contains_private_jwk_material(public_jwk)
    {
        return None;
    }
    Some(verification_method_id)
}

fn did_publishes_verification_method(
    resolution: &Map<String, Value>,
    verification_method_id: &str,
) -> bool {
    let Some(document) = resolution.get("did_document").and_then(Value::as_object) else {
        return false;
    };
    let method_published = document
        .get("verificationMethod")
        .and_then(Value::as_array)
        .is_some_and(|methods| {
            methods.iter().any(|method| {
                method.get("id").and_then(Value::as_str) == Some(verification_method_id)
            })
        });
    let assertion_published = document
        .get("assertionMethod")
        .and_then(Value::as_array)
        .is_some_and(|methods| {
            methods.iter().any(|method| {
                method
                    .as_str()
                    .or_else(|| method.get("id").and_then(Value::as_str))
                    == Some(verification_method_id)
            })
        });
    method_published && assertion_published
}

fn optional_string_matches(value: Option<&Value>, expected: &str) -> bool {
    matches!(value, None | Some(Value::Null)) || value.and_then(Value::as_str) == Some(expected)
}

fn contains_private_jwk_material(jwk: &Map<String, Value>) -> bool {
    PRIVATE_JWK_MEMBERS
        .iter()
        .any(|member| jwk.contains_key(*member))
}

#[derive(Clone)]
pub struct CanvasReadinessRuntime {
    state: Arc<dyn CanvasReadinessStateProvider>,
    documents: Arc<dyn CanvasReadinessDocumentProvider>,
    challenges: Arc<dyn CanvasReadinessChallengeProvider>,
    portable_enabled: bool,
    pilot_organizations: Arc<BTreeSet<String>>,
    self_managed_origins: Arc<Vec<String>>,
    evidence_max_age: Duration,
}

impl std::fmt::Debug for CanvasReadinessRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CanvasReadinessRuntime")
            .field("portable_enabled", &self.portable_enabled)
            .field("pilot_organization_count", &self.pilot_organizations.len())
            .field(
                "self_managed_origin_count",
                &self.self_managed_origins.len(),
            )
            .field("evidence_max_age", &self.evidence_max_age)
            .finish_non_exhaustive()
    }
}

impl CanvasReadinessRuntime {
    #[must_use]
    pub fn new(
        state: Arc<dyn CanvasReadinessStateProvider>,
        documents: Arc<dyn CanvasReadinessDocumentProvider>,
        challenges: Arc<dyn CanvasReadinessChallengeProvider>,
        portable_enabled: bool,
        pilot_organizations: BTreeSet<String>,
        self_managed_origins: Vec<String>,
        evidence_max_age: Duration,
    ) -> Self {
        Self {
            state,
            documents,
            challenges,
            portable_enabled,
            pilot_organizations: Arc::new(pilot_organizations),
            self_managed_origins: Arc::new(self_managed_origins),
            evidence_max_age,
        }
    }
}

#[async_trait]
impl CanvasReadinessInputProvider for CanvasReadinessRuntime {
    async fn inputs(
        &self,
        platform: &CanvasPlatformRecord,
        binding: &CanvasProgramBindingRecord,
        evaluated_at: DateTime<Utc>,
    ) -> CanvasReadinessInputs {
        let documents = self
            .documents
            .documents(&binding.credential_template_id)
            .await;
        let (oauth, heartbeat, sync, lti_signing, kms_signing) = tokio::join!(
            self.state
                .oauth_connection(&binding.organization_id, &platform.id),
            self.state.worker_heartbeat_configured(evaluated_at),
            self.state.sync_readiness(
                &binding.organization_id,
                &platform.id,
                &binding.id,
                evaluated_at,
            ),
            self.challenges.lti_tool_signing_ready(evaluated_at),
            self.challenges.kms_did_signing_ready(
                &binding.organization_id,
                &documents.credential_template,
                evaluated_at,
            ),
        );
        let (oauth_lookup_succeeded, oauth_connection) = match oauth {
            Ok(connection) => (true, connection),
            Err(CanvasReadinessDependencyError) => (false, None),
        };
        CanvasReadinessInputs {
            rollout_allowed: portable_canvas_pilot_enabled(
                self.portable_enabled,
                &self.pilot_organizations,
                &binding.organization_id,
            ),
            lti_metadata_ready: lti_metadata_ready(platform, &self.self_managed_origins),
            lti_tool_signing_ready: lti_signing,
            oauth_lookup_succeeded,
            oauth_connection,
            worker_heartbeat_configured: heartbeat.unwrap_or(false),
            sync_state: sync.ok(),
            application_template: None,
            credential_template: documents.credential_template,
            credential_status_profile: documents.credential_status_profile,
            kms_did_signing_ready: kms_signing,
            learner_identity_status: None,
            evidence_observed_at: None,
            evidence_max_age: self.evidence_max_age,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PostgresCanvasReadinessStateProvider {
    pool: PgPool,
    worker_max_age: Duration,
}

impl PostgresCanvasReadinessStateProvider {
    #[must_use]
    pub fn new(pool: PgPool, worker_max_age: Duration) -> Self {
        Self {
            pool,
            worker_max_age,
        }
    }
}

#[async_trait]
impl CanvasReadinessStateProvider for PostgresCanvasReadinessStateProvider {
    async fn oauth_connection(
        &self,
        organization_id: &str,
        platform_id: &str,
    ) -> Result<Option<CanvasOAuthReadinessConnection>, CanvasReadinessDependencyError> {
        let row = sqlx::query(
            "SELECT status, reauthorization_required, access_token_secret_ref,
                    capabilities, scopes
             FROM issuance_service.canvas_oauth_connections
             WHERE organization_id = $1 AND platform_id = $2",
        )
        .bind(organization_id)
        .bind(platform_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| CanvasReadinessDependencyError)?;
        row.map(|row| {
            Ok(CanvasOAuthReadinessConnection {
                connected: row
                    .try_get::<String, _>("status")
                    .map_err(|_| CanvasReadinessDependencyError)?
                    .eq_ignore_ascii_case("connected"),
                reauthorization_required: row
                    .try_get("reauthorization_required")
                    .map_err(|_| CanvasReadinessDependencyError)?,
                access_token_secret_configured: row
                    .try_get::<Option<String>, _>("access_token_secret_ref")
                    .map_err(|_| CanvasReadinessDependencyError)?
                    .is_some_and(|value| !value.trim().is_empty()),
                capabilities: json_string_set(
                    row.try_get("capabilities")
                        .map_err(|_| CanvasReadinessDependencyError)?,
                )?,
                scopes: json_string_set(
                    row.try_get("scopes")
                        .map_err(|_| CanvasReadinessDependencyError)?,
                )?,
            })
        })
        .transpose()
    }

    async fn worker_heartbeat_configured(
        &self,
        evaluated_at: DateTime<Utc>,
    ) -> Result<bool, CanvasReadinessDependencyError> {
        // Preserve the published repository's max(1, max_age_seconds) boundary.
        // The deployed caller uses 120 seconds; zero must still match for other consumers.
        let max_age = chrono::Duration::from_std(self.worker_max_age.max(Duration::from_secs(1)))
            .map_err(|_| CanvasReadinessDependencyError)?;
        let metadata = sqlx::query_scalar::<_, Value>(
            "SELECT metadata
             FROM issuance_service.canvas_worker_heartbeats
             WHERE role = 'canvas_sync' AND last_heartbeat_at >= $1
             ORDER BY last_heartbeat_at DESC LIMIT 1",
        )
        .bind(evaluated_at - max_age)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| CanvasReadinessDependencyError)?;
        Ok(metadata
            .and_then(|value| value.as_object().cloned())
            .and_then(|metadata| metadata.get("processor_configured").cloned())
            .and_then(|value| value.as_bool())
            == Some(true))
    }

    async fn sync_readiness(
        &self,
        organization_id: &str,
        platform_id: &str,
        binding_id: &str,
        evaluated_at: DateTime<Utc>,
    ) -> Result<CanvasSyncReadiness, CanvasReadinessDependencyError> {
        let row = sqlx::query(
            "SELECT
                 EXISTS (
                     SELECT 1
                     FROM issuance_service.canvas_evidence_sync_jobs AS jobs
                     JOIN issuance_service.canvas_evidence_sync_targets AS targets
                       ON targets.id = jobs.target_id
                      AND targets.organization_id = jobs.organization_id
                     WHERE targets.organization_id = $1
                       AND targets.platform_id = $2 AND targets.binding_id = $3
                       AND jobs.organization_id = $1 AND jobs.status = 'dead_letter'
                 ) AS dead_lettered,
                 (
                     EXISTS (
                         SELECT 1
                         FROM issuance_service.canvas_evidence_sync_jobs AS jobs
                         JOIN issuance_service.canvas_evidence_sync_targets AS targets
                           ON targets.id = jobs.target_id
                          AND targets.organization_id = jobs.organization_id
                         WHERE targets.organization_id = $1
                           AND targets.platform_id = $2 AND targets.binding_id = $3
                           AND jobs.organization_id = $1
                           AND jobs.status IN ('queued', 'leased', 'retry')
                           AND EXTRACT(EPOCH FROM ($4::timestamptz - jobs.created_at))
                               > 2 * GREATEST(60, targets.schedule_seconds)
                     ) OR EXISTS (
                         SELECT 1
                         FROM issuance_service.canvas_evidence_sync_targets AS targets
                         WHERE targets.organization_id = $1
                           AND targets.platform_id = $2 AND targets.binding_id = $3
                           AND targets.enabled = true
                           AND EXTRACT(EPOCH FROM ($4::timestamptz - targets.next_run_at))
                               > 2 * GREATEST(60, targets.schedule_seconds)
                     )
                 ) AS stale_backlog",
        )
        .bind(organization_id)
        .bind(platform_id)
        .bind(binding_id)
        .bind(evaluated_at)
        .fetch_one(&self.pool)
        .await
        .map_err(|_| CanvasReadinessDependencyError)?;
        Ok(CanvasSyncReadiness {
            dead_lettered: row
                .try_get("dead_lettered")
                .map_err(|_| CanvasReadinessDependencyError)?,
            stale_backlog: row
                .try_get("stale_backlog")
                .map_err(|_| CanvasReadinessDependencyError)?,
        })
    }
}

#[derive(Clone)]
pub struct HttpCanvasReadinessDocumentProvider {
    client: Client,
    credential_template_base_url: Url,
    status_profile_base_url: Url,
}

impl std::fmt::Debug for HttpCanvasReadinessDocumentProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpCanvasReadinessDocumentProvider")
            .field(
                "credential_template_base_url",
                &self.credential_template_base_url,
            )
            .field("status_profile_base_url", &self.status_profile_base_url)
            .finish_non_exhaustive()
    }
}

impl HttpCanvasReadinessDocumentProvider {
    pub fn new(
        credential_template_base_url: &str,
        status_profile_base_url: Url,
        timeout: Duration,
    ) -> Result<Self, String> {
        let credential_template_base_url = Url::parse(credential_template_base_url)
            .map_err(|_| "Credential template readiness URL is invalid".to_owned())?;
        let client = Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| "Canvas readiness HTTP client could not be configured".to_owned())?;
        Ok(Self {
            client,
            credential_template_base_url,
            status_profile_base_url,
        })
    }

    async fn object(&self, endpoint: Option<Url>) -> Map<String, Value> {
        let Some(endpoint) = endpoint else {
            return Map::new();
        };
        let Ok(mut response) = self.client.get(endpoint).send().await else {
            return Map::new();
        };
        if response.status() != StatusCode::OK
            || response
                .content_length()
                .is_some_and(|length| length > MAX_DOCUMENT_BYTES as u64)
        {
            return Map::new();
        }
        let mut body = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) if body.len() + chunk.len() <= MAX_DOCUMENT_BYTES => {
                    body.extend_from_slice(&chunk);
                }
                Ok(Some(_)) | Err(_) => return Map::new(),
                Ok(None) => break,
            }
        }
        serde_json::from_slice::<Value>(&body)
            .ok()
            .and_then(|value| value.as_object().cloned())
            .unwrap_or_default()
    }
}

#[async_trait]
impl CanvasReadinessDocumentProvider for HttpCanvasReadinessDocumentProvider {
    async fn documents(&self, credential_template_id: &str) -> CanvasReadinessDocuments {
        let credential_template = self
            .object(append_segments(
                &self.credential_template_base_url,
                &[
                    "internal",
                    "credential-templates",
                    credential_template_id,
                    "issuance-context",
                ],
            ))
            .await;
        let profile_id = credential_template
            .get("revocation_profile_id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let credential_status_profile = match profile_id {
            Some(profile_id) => {
                self.object(append_segments(
                    &self.status_profile_base_url,
                    &["v1", "revocation-profiles", profile_id],
                ))
                .await
            }
            None => Map::new(),
        };
        CanvasReadinessDocuments {
            credential_template,
            credential_status_profile,
        }
    }
}

fn append_segments(base: &Url, segments: &[&str]) -> Option<Url> {
    let mut endpoint = base.clone();
    endpoint.set_query(None);
    endpoint.set_fragment(None);
    {
        let mut path = endpoint.path_segments_mut().ok()?;
        path.pop_if_empty();
        for segment in segments {
            path.push(segment);
        }
    }
    Some(endpoint)
}

fn json_string_set(value: Value) -> Result<BTreeSet<String>, CanvasReadinessDependencyError> {
    value
        .as_array()
        .ok_or(CanvasReadinessDependencyError)?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .ok_or(CanvasReadinessDependencyError)
        })
        .collect()
}

fn lti_metadata_ready(platform: &CanvasPlatformRecord, self_managed_origins: &[String]) -> bool {
    let Some(canvas_base_url) = platform.canvas_base_url.as_deref() else {
        return false;
    };
    let Some(metadata) = platform
        .lti_openid_configuration
        .as_ref()
        .and_then(Value::as_object)
    else {
        return false;
    };
    let Ok(expected) = canvas_lti_trust_profile(
        canvas_base_url,
        &platform.lti_trust_profile,
        self_managed_origins,
    ) else {
        return false;
    };
    let jwks_uri = metadata
        .get("jwks_uri")
        .and_then(Value::as_str)
        .or(platform.lti_jwks_url.as_deref())
        .unwrap_or_default()
        .trim();
    https_url(canvas_base_url)
        && platform.lti_issuer.as_deref() == Some(expected.issuer.as_str())
        && metadata.get("issuer").and_then(Value::as_str) == Some(expected.issuer.as_str())
        && metadata
            .get("authorization_endpoint")
            .and_then(Value::as_str)
            == Some(expected.authorization_endpoint.as_str())
        && metadata.get("token_endpoint").and_then(Value::as_str)
            == Some(expected.token_endpoint.as_str())
        && jwks_uri == expected.jwks_uri
        && platform.lti_jwks_url.as_deref() == Some(expected.jwks_uri.as_str())
        && platform
            .lti_jwks_json
            .as_ref()
            .and_then(|jwks| jwks.get("keys"))
            .and_then(Value::as_array)
            .is_some_and(|keys| !keys.is_empty())
        && platform.last_validated_at.is_some()
}

fn https_url(value: &str) -> bool {
    Url::parse(value.trim()).ok().is_some_and(|url| {
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use chrono::TimeZone;
    use rand08::rngs::OsRng;
    use rsa::{
        pkcs1v15::SigningKey,
        signature::{SignatureEncoding, Signer},
        traits::PublicKeyParts,
        RsaPrivateKey,
    };
    use serde_json::json;
    use sha2::Sha256;

    use super::*;
    use crate::{
        canvas_award_candidate::python_canonical_json,
        canvas_lti_tool_signing::CanvasLtiToolSigningError,
    };

    #[derive(Clone)]
    struct RsaFixture {
        private: Arc<RsaPrivateKey>,
        key_id: String,
        public_jwk: Value,
    }

    impl RsaFixture {
        fn new(key_id: &str) -> Self {
            let private =
                Arc::new(RsaPrivateKey::new(&mut OsRng, 2_048).expect("readiness RSA private key"));
            let public = private.to_public_key();
            Self {
                private,
                key_id: key_id.to_owned(),
                public_jwk: json!({
                    "kid": key_id,
                    "kty": "RSA",
                    "alg": "RS256",
                    "use": "sig",
                    "n": URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
                    "e": URL_SAFE_NO_PAD.encode(public.e().to_bytes_be()),
                }),
            }
        }

        fn sign(&self, payload: &[u8]) -> String {
            let signature = SigningKey::<Sha256>::new((*self.private).clone()).sign(payload);
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        }
    }

    struct TestLtiSigner {
        rsa: RsaFixture,
        duplicate_public_key: bool,
    }

    #[async_trait]
    impl CanvasLtiToolJwtSigner for TestLtiSigner {
        async fn sign_jwt(&self, payload: &Value) -> Result<String, CanvasLtiToolSigningError> {
            let header = json!({"alg": "RS256", "typ": "JWT", "kid": self.rsa.key_id});
            let signing_input = format!(
                "{}.{}",
                URL_SAFE_NO_PAD.encode(python_canonical_json(&header)),
                URL_SAFE_NO_PAD.encode(python_canonical_json(payload)),
            );
            Ok(format!(
                "{signing_input}.{}",
                self.rsa.sign(signing_input.as_bytes())
            ))
        }

        async fn public_jwks(&self) -> Result<Value, CanvasLtiToolSigningError> {
            let mut keys = vec![self.rsa.public_jwk.clone()];
            if self.duplicate_public_key {
                keys.push(self.rsa.public_jwk.clone());
            }
            Ok(json!({"keys": keys}))
        }
    }

    struct TestIssuerResolver {
        resolution: Value,
    }

    #[async_trait]
    impl CanvasReadinessIssuerResolver for TestIssuerResolver {
        async fn resolve_issuer(
            &self,
            _organization_id: &str,
            _configuration: &CanvasReadinessIssuerConfiguration,
        ) -> Result<Value, CanvasReadinessDependencyError> {
            Ok(self.resolution.clone())
        }
    }

    struct TestDidSigner {
        rsa: RsaFixture,
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl CanvasReadinessDidSigner for TestDidSigner {
        async fn sign_challenge(
            &self,
            _organization_id: &str,
            _configuration: &CanvasReadinessIssuerConfiguration,
            _verification_method_id: &str,
            challenge: &[u8],
        ) -> Result<String, CanvasReadinessDependencyError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.rsa.sign(challenge))
        }
    }

    fn issuer_resolution(issuer_did: &str, rsa: &RsaFixture) -> Value {
        json!({
            "ok": true,
            "issuer_did": issuer_did,
            "algorithm": "RS256",
            "verification_method_id": rsa.key_id,
            "public_jwk": rsa.public_jwk,
            "issuer_profile": {
                "status": "active",
                "issuer_did": issuer_did,
                "algorithm": "RS256",
                "key_purpose": "vc_jwt_issuer",
                "verification_method_id": rsa.key_id,
            },
            "did_document": {
                "id": issuer_did,
                "verificationMethod": [{"id": rsa.key_id, "publicKeyJwk": rsa.public_jwk}],
                "assertionMethod": [rsa.key_id],
            }
        })
    }

    fn credential_template() -> Map<String, Value> {
        json!({
            "issuer_did": "did:web:issuer.example:org-1",
            "issuer_algorithm": "RS256",
            "credential_payload_format": "dc+sd-jwt",
        })
        .as_object()
        .expect("credential template")
        .clone()
    }

    #[tokio::test]
    async fn live_challenges_prove_the_published_lti_and_kms_keys() {
        let lti_rsa = RsaFixture::new("did:web:issuer.example:canvas#lti-rs256");
        let issuer_did = "did:web:issuer.example:org-1";
        let kms_rsa = RsaFixture::new(&format!("{issuer_did}#credential-rs256"));
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = LiveCanvasReadinessChallengeProvider::with_ports(
            Arc::new(TestLtiSigner {
                rsa: lti_rsa,
                duplicate_public_key: false,
            }),
            Arc::new(TestIssuerResolver {
                resolution: issuer_resolution(issuer_did, &kms_rsa),
            }),
            Arc::new(TestDidSigner {
                rsa: kms_rsa,
                calls: calls.clone(),
            }),
        );
        let now = Utc.with_ymd_and_hms(2026, 8, 31, 2, 0, 0).unwrap();

        assert!(provider.lti_tool_signing_ready(now).await);
        assert!(
            provider
                .kms_did_signing_ready("org-1", &credential_template(), now)
                .await
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn live_challenges_reject_ambiguous_or_private_key_material_before_kms_use() {
        let lti_rsa = RsaFixture::new("did:web:issuer.example:canvas#lti-rs256");
        let issuer_did = "did:web:issuer.example:org-1";
        let kms_rsa = RsaFixture::new(&format!("{issuer_did}#credential-rs256"));
        let mut resolution = issuer_resolution(issuer_did, &kms_rsa);
        resolution["public_jwk"]["d"] = json!("private-material-must-not-cross-boundary");
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = LiveCanvasReadinessChallengeProvider::with_ports(
            Arc::new(TestLtiSigner {
                rsa: lti_rsa,
                duplicate_public_key: true,
            }),
            Arc::new(TestIssuerResolver { resolution }),
            Arc::new(TestDidSigner {
                rsa: kms_rsa,
                calls: calls.clone(),
            }),
        );
        let now = Utc.with_ymd_and_hms(2026, 8, 31, 2, 0, 0).unwrap();

        assert!(!provider.lti_tool_signing_ready(now).await);
        assert!(
            !provider
                .kms_did_signing_ready("org-1", &credential_template(), now)
                .await
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn kms_challenge_requires_the_active_method_in_both_did_relationships() {
        let lti_rsa = RsaFixture::new("did:web:issuer.example:canvas#lti-rs256");
        let issuer_did = "did:web:issuer.example:org-1";
        let kms_rsa = RsaFixture::new(&format!("{issuer_did}#credential-rs256"));
        let mut resolution = issuer_resolution(issuer_did, &kms_rsa);
        resolution["did_document"]["assertionMethod"] = json!([]);
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = LiveCanvasReadinessChallengeProvider::with_ports(
            Arc::new(TestLtiSigner {
                rsa: lti_rsa,
                duplicate_public_key: false,
            }),
            Arc::new(TestIssuerResolver { resolution }),
            Arc::new(TestDidSigner {
                rsa: kms_rsa,
                calls: calls.clone(),
            }),
        );

        assert!(
            !provider
                .kms_did_signing_ready(
                    "org-1",
                    &credential_template(),
                    Utc.with_ymd_and_hms(2026, 8, 31, 2, 0, 0).unwrap(),
                )
                .await
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    struct ReadyState;

    #[async_trait]
    impl CanvasReadinessStateProvider for ReadyState {
        async fn oauth_connection(
            &self,
            organization_id: &str,
            platform_id: &str,
        ) -> Result<Option<CanvasOAuthReadinessConnection>, CanvasReadinessDependencyError>
        {
            assert_eq!(organization_id, "org-1");
            assert_eq!(platform_id, "platform-1");
            Ok(Some(CanvasOAuthReadinessConnection {
                connected: true,
                reauthorization_required: false,
                access_token_secret_configured: true,
                capabilities: BTreeSet::from(["course_completion".to_owned()]),
                scopes: BTreeSet::from(["url:GET|/api/v1/courses/:course_id".to_owned()]),
            }))
        }

        async fn worker_heartbeat_configured(
            &self,
            _evaluated_at: DateTime<Utc>,
        ) -> Result<bool, CanvasReadinessDependencyError> {
            Ok(true)
        }

        async fn sync_readiness(
            &self,
            organization_id: &str,
            platform_id: &str,
            binding_id: &str,
            _evaluated_at: DateTime<Utc>,
        ) -> Result<CanvasSyncReadiness, CanvasReadinessDependencyError> {
            assert_eq!(
                (organization_id, platform_id, binding_id),
                ("org-1", "platform-1", "binding-1")
            );
            Ok(CanvasSyncReadiness {
                dead_lettered: false,
                stale_backlog: false,
            })
        }
    }

    struct ReadyDocuments;

    #[async_trait]
    impl CanvasReadinessDocumentProvider for ReadyDocuments {
        async fn documents(&self, credential_template_id: &str) -> CanvasReadinessDocuments {
            assert_eq!(credential_template_id, "credential-template-1");
            CanvasReadinessDocuments {
                credential_template: credential_template(),
                credential_status_profile: json!({"id": "status-profile-1", "status": "active"})
                    .as_object()
                    .expect("status profile")
                    .clone(),
            }
        }
    }

    struct ReadyChallenges;

    #[async_trait]
    impl CanvasReadinessChallengeProvider for ReadyChallenges {
        async fn lti_tool_signing_ready(&self, _evaluated_at: DateTime<Utc>) -> bool {
            true
        }

        async fn kms_did_signing_ready(
            &self,
            organization_id: &str,
            _credential_template: &Map<String, Value>,
            _evaluated_at: DateTime<Utc>,
        ) -> bool {
            organization_id == "org-1"
        }
    }

    fn binding() -> CanvasProgramBindingRecord {
        let now = Utc.with_ymd_and_hms(2026, 8, 31, 1, 0, 0).unwrap();
        CanvasProgramBindingRecord {
            id: "binding-1".to_owned(),
            organization_id: "org-1".to_owned(),
            platform_id: "platform-1".to_owned(),
            application_template_id: "application-template-1".to_owned(),
            credential_template_id: "credential-template-1".to_owned(),
            display_name: None,
            flow_mode: "elevenid_orchestrated_canvas_evidence".to_owned(),
            direct_issue_enabled: false,
            auto_approve_on_evidence: false,
            evidence_requirements: Vec::new(),
            canvas_scope: Default::default(),
            delivery_mode: "wallet_only".to_owned(),
            issuer_mode: "org_managed".to_owned(),
            approval_policy_set_id: None,
            deployment_profile_id: None,
            feature_flags: Default::default(),
            canvas_credentials: Map::new(),
            config_version: 1,
            validated_config_version: None,
            readiness_checks: Vec::new(),
            readiness_validated_at: None,
            activated_at: None,
            archived_at: None,
            credential_template_snapshot: Map::new(),
            enabled: false,
            created_at: now,
            updated_at: now,
        }
    }

    #[tokio::test]
    async fn runtime_composes_current_state_documents_and_live_challenges() {
        let runtime = CanvasReadinessRuntime::new(
            Arc::new(ReadyState),
            Arc::new(ReadyDocuments),
            Arc::new(ReadyChallenges),
            true,
            BTreeSet::from(["org-1".to_owned()]),
            vec!["https://canvas.example.edu".to_owned()],
            Duration::from_secs(900),
        );
        let now = Utc.with_ymd_and_hms(2026, 8, 31, 2, 0, 0).unwrap();
        let inputs = runtime.inputs(&platform(), &binding(), now).await;

        assert!(inputs.rollout_allowed);
        assert!(inputs.lti_metadata_ready);
        assert!(inputs.lti_tool_signing_ready);
        assert!(inputs.oauth_lookup_succeeded);
        assert!(inputs.oauth_connection.expect("OAuth connection").connected);
        assert!(inputs.worker_heartbeat_configured);
        assert_eq!(inputs.sync_state, Some(CanvasSyncReadiness::default()));
        assert_eq!(
            inputs.credential_template.get("issuer_algorithm"),
            Some(&json!("RS256"))
        );
        assert!(inputs.kms_did_signing_ready);
        assert_eq!(inputs.evidence_max_age, Duration::from_secs(900));
    }

    fn platform() -> CanvasPlatformRecord {
        CanvasPlatformRecord {
            id: "platform-1".to_owned(),
            organization_id: "org-1".to_owned(),
            canvas_account_id: "account-1".to_owned(),
            display_name: Some("Canvas".to_owned()),
            canvas_base_url: Some("https://canvas.example.edu".to_owned()),
            lti_client_id: Some("client-1".to_owned()),
            lti_deployment_id: Some("deployment-1".to_owned()),
            lti_trust_profile: "self_managed_same_origin".to_owned(),
            lti_issuer: Some("https://canvas.example.edu".to_owned()),
            lti_jwks_url: Some("https://canvas.example.edu/api/lti/security/jwks".to_owned()),
            lti_jwks_json: Some(json!({"keys": [{"kty": "RSA"}]})),
            lti_jwks_fetched_at: None,
            lti_jwks_expires_at: None,
            lti_openid_configuration: Some(json!({
                "issuer": "https://canvas.example.edu",
                "authorization_endpoint": "https://canvas.example.edu/api/lti/authorize_redirect",
                "token_endpoint": "https://canvas.example.edu/login/oauth2/token",
                "jwks_uri": "https://canvas.example.edu/api/lti/security/jwks"
            })),
            registration_status: "installed".to_owned(),
            connection_config: Map::new(),
            capability_snapshot: Map::new(),
            last_validated_at: Some(Utc.with_ymd_and_hms(2026, 8, 31, 1, 0, 0).unwrap()),
            last_connection_error: None,
            config_version: 1,
            archived_at: None,
            enabled: true,
            created_at: Utc.with_ymd_and_hms(2026, 8, 31, 0, 0, 0).unwrap(),
            updated_at: Utc.with_ymd_and_hms(2026, 8, 31, 1, 0, 0).unwrap(),
        }
    }

    #[test]
    fn lti_metadata_requires_the_exact_persisted_trust_profile() {
        let mut platform = platform();
        assert!(lti_metadata_ready(
            &platform,
            &["https://canvas.example.edu".to_owned()]
        ));
        platform
            .lti_openid_configuration
            .as_mut()
            .expect("OpenID configuration")["token_endpoint"] =
            json!("https://attacker.example/token");
        assert!(!lti_metadata_ready(
            &platform,
            &["https://canvas.example.edu".to_owned()]
        ));
        platform
            .lti_openid_configuration
            .as_mut()
            .expect("OpenID configuration")["token_endpoint"] =
            json!("https://canvas.example.edu/login/oauth2/token");
        assert!(!lti_metadata_ready(&platform, &[]));
    }

    #[test]
    fn document_paths_percent_encode_identifiers_and_preserve_base_prefixes() {
        let base = Url::parse("http://credential-template:8003/prefix/").unwrap();
        assert_eq!(
            append_segments(
                &base,
                &[
                    "internal",
                    "credential-templates",
                    "template/with space",
                    "issuance-context"
                ]
            )
            .unwrap()
            .as_str(),
            "http://credential-template:8003/prefix/internal/credential-templates/template%2Fwith%20space/issuance-context"
        );
    }

    #[test]
    fn runtime_debug_reports_counts_without_disclosing_operator_origins() {
        struct NoState;
        struct NoDocuments;
        struct NoChallenges;
        #[async_trait]
        impl CanvasReadinessStateProvider for NoState {
            async fn oauth_connection(
                &self,
                _organization_id: &str,
                _platform_id: &str,
            ) -> Result<Option<CanvasOAuthReadinessConnection>, CanvasReadinessDependencyError>
            {
                Err(CanvasReadinessDependencyError)
            }
            async fn worker_heartbeat_configured(
                &self,
                _evaluated_at: DateTime<Utc>,
            ) -> Result<bool, CanvasReadinessDependencyError> {
                Err(CanvasReadinessDependencyError)
            }
            async fn sync_readiness(
                &self,
                _organization_id: &str,
                _platform_id: &str,
                _binding_id: &str,
                _evaluated_at: DateTime<Utc>,
            ) -> Result<CanvasSyncReadiness, CanvasReadinessDependencyError> {
                Err(CanvasReadinessDependencyError)
            }
        }
        #[async_trait]
        impl CanvasReadinessDocumentProvider for NoDocuments {
            async fn documents(&self, _credential_template_id: &str) -> CanvasReadinessDocuments {
                CanvasReadinessDocuments::default()
            }
        }
        #[async_trait]
        impl CanvasReadinessChallengeProvider for NoChallenges {
            async fn lti_tool_signing_ready(&self, _evaluated_at: DateTime<Utc>) -> bool {
                false
            }
            async fn kms_did_signing_ready(
                &self,
                _organization_id: &str,
                _credential_template: &Map<String, Value>,
                _evaluated_at: DateTime<Utc>,
            ) -> bool {
                false
            }
        }
        let runtime = CanvasReadinessRuntime::new(
            Arc::new(NoState),
            Arc::new(NoDocuments),
            Arc::new(NoChallenges),
            true,
            BTreeSet::from(["org-1".to_owned()]),
            vec!["https://private.example.edu".to_owned()],
            Duration::from_secs(900),
        );
        let debug = format!("{runtime:?}");
        assert!(debug.contains("pilot_organization_count: 1"));
        assert!(debug.contains("self_managed_origin_count: 1"));
        assert!(!debug.contains("org-1"));
        assert!(!debug.contains("private.example.edu"));
    }
}
