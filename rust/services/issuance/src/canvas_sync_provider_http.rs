//! Bounded, redirect-free Canvas REST, AGS, and NRPS provider adapter.

use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    sync::Arc,
};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use marty_oid4vci::lti::{
    canvas_lti_trust_profile, validate_canvas_lti_service_url,
    CANVAS_LTI_TRUST_SELF_MANAGED_SAME_ORIGIN,
};
use reqwest::{
    header::{LINK, WWW_AUTHENTICATE},
    Response,
};
use serde_json::{json, Map, Value};
use url::Url;
use uuid::Uuid;

use crate::{
    canvas_lti_tool_signing::CanvasLtiToolJwtSigner,
    canvas_oauth::{CanvasOAuthError, CanvasOAuthService},
    canvas_provider_http::{
        canvas_retry_after_seconds, client_for_canvas_origin, CanvasHttpClientPolicy,
    },
    canvas_sync_processor::{
        ags_assertion, normalized_rest_payload, rest_assertion, CanvasAuthoritativeObservation,
        CanvasAuthoritativeProvider, CanvasProviderReadError, CanvasRosterSnapshot,
        CanvasSyncResources,
    },
    canvas_sync_worker::CanvasSyncTarget,
};

const AGS_RESULT_READ_SCOPE: &str = "https://purl.imsglobal.org/spec/lti-ags/scope/result.readonly";
const NRPS_MEMBERSHIP_READ_SCOPE: &str =
    "https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly";
const AGS_RESULT_ACCEPT: &str = "application/vnd.ims.lis.v2.resultcontainer+json";
const NRPS_MEMBERSHIP_ACCEPT: &str = "application/vnd.ims.lti-nrps.v2.membershipcontainer+json";
const TOKEN_RESPONSE_BYTES: usize = 65_536;
const COLLECTION_PAGE_BYTES: usize = 8_388_608;
const COLLECTION_MAX_PAGES: usize = 200;

#[derive(Clone, Copy, Eq, PartialEq)]
enum CollectionProtocol {
    CanvasRest,
    Lti,
}

impl CollectionProtocol {
    fn first_page(self, mut url: Url, limit: usize) -> Url {
        if self == Self::CanvasRest {
            url.query_pairs_mut()
                .append_pair("per_page", &limit.clamp(1, 100).to_string());
        }
        url
    }

    fn rows(self, payload: &Value) -> Option<&Vec<Value>> {
        payload.as_array().or_else(|| match self {
            Self::CanvasRest => payload.get("items").and_then(Value::as_array),
            Self::Lti => payload
                .get("members")
                .and_then(Value::as_array)
                .or_else(|| payload.get("results").and_then(Value::as_array)),
        })
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
enum LtiCollectionKind {
    AgsResult,
    NrpsMembership,
}

impl LtiCollectionKind {
    const fn scope(self) -> &'static str {
        match self {
            Self::AgsResult => AGS_RESULT_READ_SCOPE,
            Self::NrpsMembership => NRPS_MEMBERSHIP_READ_SCOPE,
        }
    }

    const fn accept(self) -> &'static str {
        match self {
            Self::AgsResult => AGS_RESULT_ACCEPT,
            Self::NrpsMembership => NRPS_MEMBERSHIP_ACCEPT,
        }
    }
}

// Owned, non-secret identity for a successful grant within ONE processor run.
// Include the complete platform/trust identity, not just the requested scope.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
struct LtiTokenKey {
    organization_id: String,
    platform_id: String,
    config_version: i32,
    canvas_base_url: String,
    trust_profile: String,
    issuer: String,
    client_id: String,
    deployment_id: String,
    token_endpoint: String,
    kind: LtiCollectionKind,
}

impl LtiTokenKey {
    fn new(resources: &CanvasSyncResources, endpoint: &str, kind: LtiCollectionKind) -> Self {
        let platform = &resources.platform;
        Self {
            organization_id: platform.organization_id.clone(),
            platform_id: platform.id.clone(),
            config_version: platform.config_version,
            canvas_base_url: platform.canvas_base_url.clone(),
            trust_profile: platform.lti_trust_profile.clone(),
            issuer: platform.lti_issuer.clone(),
            client_id: platform.lti_client_id.clone(),
            deployment_id: platform.lti_deployment_id.clone(),
            token_endpoint: endpoint.to_owned(),
            kind,
        }
    }
}

#[derive(Default)]
struct RunLtiTokens {
    tokens: tokio::sync::Mutex<BTreeMap<LtiTokenKey, String>>,
}

impl std::fmt::Debug for RunLtiTokens {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RunLtiTokens")
            .finish_non_exhaustive()
    }
}

impl RunLtiTokens {
    async fn get_or_request<F, Fut>(
        &self,
        key: LtiTokenKey,
        request: F,
    ) -> Result<String, CanvasProviderReadError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<String, CanvasProviderReadError>>,
    {
        // The async guard coalesces identical concurrent reads within this run.
        // Cancellation/errors release it without caching a partial acquisition.
        let mut tokens = self.tokens.lock().await;
        if let Some(token) = tokens.get(&key) {
            return Ok(token.clone());
        }
        let token = request().await?;
        tokens.insert(key, token.clone());
        Ok(token)
    }
}

#[derive(Clone)]
pub struct HttpCanvasAuthoritativeProvider {
    oauth: Arc<CanvasOAuthService>,
    oauth_api_key: String,
    signer: Arc<dyn CanvasLtiToolJwtSigner>,
    policy: CanvasHttpClientPolicy,
    self_managed_origin_allowlist: Vec<String>,
    run_tokens: Option<Arc<RunLtiTokens>>,
}

impl std::fmt::Debug for HttpCanvasAuthoritativeProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpCanvasAuthoritativeProvider")
            .field("policy", &self.policy)
            .field("oauth_api_key_configured", &!self.oauth_api_key.is_empty())
            .field("run_scoped", &self.run_tokens.is_some())
            .finish_non_exhaustive()
    }
}

impl HttpCanvasAuthoritativeProvider {
    #[must_use]
    pub fn new(
        oauth: Arc<CanvasOAuthService>,
        oauth_api_key: impl Into<String>,
        signer: Arc<dyn CanvasLtiToolJwtSigner>,
        policy: CanvasHttpClientPolicy,
        self_managed_origin_allowlist: Vec<String>,
    ) -> Self {
        Self {
            oauth,
            oauth_api_key: oauth_api_key.into(),
            signer,
            policy,
            self_managed_origin_allowlist,
            run_tokens: None,
        }
    }

    fn fresh_run(&self) -> Self {
        Self {
            run_tokens: Some(Arc::new(RunLtiTokens::default())),
            ..self.clone()
        }
    }

    async fn oauth_token(
        &self,
        resources: &CanvasSyncResources,
    ) -> Result<String, CanvasProviderReadError> {
        self.oauth
            .access_token(
                &resources.platform.id,
                Some(&self.oauth_api_key),
                Some(&resources.platform.organization_id),
            )
            .await
            .map_err(map_oauth_error)?
            .filter(|value| !value.is_empty())
            .ok_or(CanvasProviderReadError::ReauthorizationRequired)
    }

    async fn rest_record(
        &self,
        resources: &CanvasSyncResources,
        requirement: &Value,
        canvas_user_id: &str,
    ) -> Result<Value, CanvasProviderReadError> {
        let token = self.oauth_token(resources).await?;
        let (client, base) =
            client_for_canvas_origin(&resources.platform.canvas_base_url, &self.policy)
                .await
                .map_err(|_| CanvasProviderReadError::InvalidConfiguration)?;
        let scope = requirement
            .get("scope")
            .and_then(Value::as_object)
            .ok_or(CanvasProviderReadError::InvalidConfiguration)?;
        let course = encoded(text(scope.get("course_id")))?;
        let user = encoded(canvas_user_id.to_owned())?;
        let fact_type = text(requirement.get("fact_type"));
        let mut url = match fact_type.as_str() {
            "canvas.assignment_score" | "canvas.quiz_score" => {
                let activity = encoded(text(scope.get("activity_id")))?;
                api_url(
                    &base,
                    &format!("courses/{course}/assignments/{activity}/submissions/{user}"),
                )?
            }
            "canvas.module_completion" => {
                let module = encoded(text(scope.get("module_id")))?;
                api_url(&base, &format!("courses/{course}/modules/{module}"))?
            }
            "canvas.course_completion" => {
                api_url(&base, &format!("courses/{course}/users/{user}/progress"))?
            }
            _ => return Err(CanvasProviderReadError::InvalidConfiguration),
        };
        if matches!(
            fact_type.as_str(),
            "canvas.assignment_score" | "canvas.quiz_score"
        ) {
            url.query_pairs_mut().append_pair("include[]", "assignment");
        } else if fact_type == "canvas.module_completion" {
            url.query_pairs_mut()
                .append_pair("student_id", canvas_user_id);
        }
        let response = client
            .get(url)
            .bearer_auth(&token)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|_| CanvasProviderReadError::Unavailable)?;
        if response.status().as_u16() == 401 && response.headers().contains_key(WWW_AUTHENTICATE) {
            self.oauth
                .mark_rejected_access_token(
                    &resources.platform.id,
                    &token,
                    Some(&self.oauth_api_key),
                    Some(&resources.platform.organization_id),
                )
                .await
                .map_err(map_oauth_error)?;
            return Err(CanvasProviderReadError::ReauthorizationRequired);
        }
        let payload = read_json_response(response, COLLECTION_PAGE_BYTES).await?;
        validate_rest_record(&text(requirement.get("fact_type")), &payload)?;
        Ok(payload)
    }

    async fn lti_access_token(
        &self,
        resources: &CanvasSyncResources,
        kind: LtiCollectionKind,
    ) -> Result<String, CanvasProviderReadError> {
        let expected = self.expected_lti_trust(resources)?;
        let endpoint = validate_canvas_lti_service_url(
            &expected.token_endpoint,
            &self.policy.private_origin_allowlist,
        )
        .await
        .map_err(|_| CanvasProviderReadError::InvalidConfiguration)?;
        if resources.platform.lti_client_id.trim().is_empty() {
            return Err(CanvasProviderReadError::InvalidConfiguration);
        }
        // Preserve trust/endpoint/client checks even on a cache hit. Published
        // application/roster processors keep successful token.value for their
        // whole invocation; they do not inspect expires_in or evict on a later
        // collection error. The next invocation always receives a fresh cache.
        if let Some(tokens) = &self.run_tokens {
            return tokens
                .get_or_request(LtiTokenKey::new(resources, &endpoint, kind), || {
                    self.acquire_lti_token(resources, &endpoint, kind.scope())
                })
                .await;
        }
        self.acquire_lti_token(resources, &endpoint, kind.scope())
            .await
    }

    async fn acquire_lti_token(
        &self,
        resources: &CanvasSyncResources,
        endpoint: &str,
        scope: &str,
    ) -> Result<String, CanvasProviderReadError> {
        let now = Utc::now().timestamp();
        let assertion = self
            .signer
            .sign_jwt(&json!({
                "iss": resources.platform.lti_client_id,
                "sub": resources.platform.lti_client_id,
                "aud": endpoint,
                "iat": now,
                "exp": now + 300,
                "jti": Uuid::new_v4().to_string(),
            }))
            .await
            .map_err(|_| CanvasProviderReadError::Unavailable)?;
        let endpoint_url =
            Url::parse(endpoint).map_err(|_| CanvasProviderReadError::InvalidConfiguration)?;
        let origin = origin_url(&endpoint_url)?;
        let (client, _) = client_for_canvas_origin(origin.as_str(), &self.policy)
            .await
            .map_err(|_| CanvasProviderReadError::InvalidConfiguration)?;
        request_lti_token(
            &client,
            endpoint_url,
            &resources.platform.lti_client_id,
            &assertion,
            scope,
        )
        .await
    }

    async fn lti_collection(
        &self,
        resources: &CanvasSyncResources,
        url: &str,
        kind: LtiCollectionKind,
        user_id: Option<&str>,
        limit: usize,
        limit_error: CanvasProviderReadError,
    ) -> Result<Vec<Value>, CanvasProviderReadError> {
        let validated = validate_canvas_lti_service_url(url, &self.policy.private_origin_allowlist)
            .await
            .map_err(|_| CanvasProviderReadError::InvalidConfiguration)?;
        self.enforce_lti_service_trust(resources, &validated)?;
        let token = self.lti_access_token(resources, kind).await?;
        let mut next =
            Url::parse(&validated).map_err(|_| CanvasProviderReadError::InvalidConfiguration)?;
        if let Some(user_id) = user_id {
            next.query_pairs_mut().append_pair("user_id", user_id);
        }
        self.collection(
            next,
            &token,
            kind.accept(),
            limit,
            limit_error,
            CollectionProtocol::Lti,
        )
        .await
    }

    async fn collection(
        &self,
        mut next: Url,
        token: &str,
        accept: &str,
        limit: usize,
        limit_error: CanvasProviderReadError,
        protocol: CollectionProtocol,
    ) -> Result<Vec<Value>, CanvasProviderReadError> {
        let expected_origin = origin_url(&next)?;
        reject_embedded_credentials(&next)?;
        let (client, _) = client_for_canvas_origin(expected_origin.as_str(), &self.policy)
            .await
            .map_err(|_| CanvasProviderReadError::InvalidConfiguration)?;
        let mut output = Vec::new();
        let mut visited = BTreeSet::new();
        next = protocol.first_page(next, limit);
        for _page in 0..COLLECTION_MAX_PAGES {
            if !visited.insert(next.to_string()) {
                return Err(CanvasProviderReadError::InvalidConfiguration);
            }
            if origin_url(&next)? != expected_origin {
                return Err(CanvasProviderReadError::InvalidConfiguration);
            }
            let (payload, link) =
                request_collection_page(&client, next.clone(), token, accept, protocol).await?;
            let rows = protocol
                .rows(&payload)
                .ok_or(CanvasProviderReadError::Unavailable)?;
            if rows.iter().any(|row| !valid_collection_item(row)) {
                return Err(CanvasProviderReadError::Unavailable);
            }
            let remaining = limit.saturating_sub(output.len());
            if rows.len() > remaining {
                return Err(limit_error);
            }
            output.extend(rows.iter().cloned());
            let Some(candidate) = next_link(&link)? else {
                return Ok(output);
            };
            if output.len() >= limit {
                return Err(limit_error);
            }
            next = Url::parse(&candidate)
                .map_err(|_| CanvasProviderReadError::InvalidConfiguration)?;
            reject_embedded_credentials(&next)?;
        }
        Err(limit_error)
    }
}

#[async_trait]
impl CanvasAuthoritativeProvider for HttpCanvasAuthoritativeProvider {
    fn for_run(self: Arc<Self>) -> Arc<dyn CanvasAuthoritativeProvider> {
        Arc::new(self.fresh_run())
    }

    async fn read_requirement(
        &self,
        resources: &CanvasSyncResources,
        requirement: &Value,
        canvas_user_id: Option<&str>,
        lti_subject: Option<&str>,
    ) -> Result<CanvasAuthoritativeObservation, CanvasProviderReadError> {
        if text(requirement.get("source")) == "ags_result" {
            let scope = requirement
                .get("scope")
                .and_then(Value::as_object)
                .ok_or(CanvasProviderReadError::InvalidConfiguration)?;
            let line_item = text(scope.get("line_item_url"));
            let subject = lti_subject
                .filter(|value| !value.is_empty())
                .ok_or(CanvasProviderReadError::Unavailable)?;
            let results = self
                .lti_collection(
                    resources,
                    &format!("{}/results", line_item.trim_end_matches('/')),
                    LtiCollectionKind::AgsResult,
                    Some(subject),
                    100,
                    CanvasProviderReadError::Unavailable,
                )
                .await?;
            let record = results.first().cloned().unwrap_or_else(|| json!({}));
            validate_ags_record(&record)?;
            let source_payload = selected_payload(
                &record,
                &[
                    "id",
                    "resultScore",
                    "resultMaximum",
                    "resultStatus",
                    "timestamp",
                ],
            );
            return Ok(CanvasAuthoritativeObservation {
                assertion: ags_assertion(&record),
                effective_at: timestamp(record.get("timestamp")),
                source_payload,
                verification_method: "LTI_AGS_RESULT_READ",
            });
        }
        let user = canvas_user_id
            .filter(|value| !value.is_empty())
            .ok_or(CanvasProviderReadError::Unavailable)?;
        let record = self.rest_record(resources, requirement, user).await?;
        let effective_at = ["updated_at", "graded_at", "completed_at"]
            .iter()
            .find_map(|key| timestamp(record.get(*key)));
        Ok(CanvasAuthoritativeObservation {
            assertion: rest_assertion(&text(requirement.get("fact_type")), &record),
            source_payload: normalized_rest_payload(&record),
            verification_method: "CANVAS_OAUTH_API_READ",
            effective_at,
        })
    }

    async fn roster(
        &self,
        target: &CanvasSyncTarget,
        resources: &CanvasSyncResources,
        requirements: &[Value],
        limit: usize,
    ) -> Result<CanvasRosterSnapshot, CanvasProviderReadError> {
        let has_rest = requirements
            .iter()
            .any(|value| text(value.get("source")) == "canvas_rest");
        let has_ags = requirements
            .iter()
            .any(|value| text(value.get("source")) == "ags_result");
        // Published roster setup performs OAuth lookup even for AGS-only
        // bindings. Preserve its audit/refresh side effects before NRPS setup.
        let token = self.oauth_token(resources).await;
        let mut snapshot = CanvasRosterSnapshot::default();
        if has_rest {
            let token = token.map_err(|error| match error {
                CanvasProviderReadError::RateLimited { .. } => error,
                _ => CanvasProviderReadError::RosterOAuthUnavailable,
            })?;
            let (_, base) =
                client_for_canvas_origin(&resources.platform.canvas_base_url, &self.policy)
                    .await
                    .map_err(|_| CanvasProviderReadError::InvalidConfiguration)?;
            let courses = requirements
                .iter()
                .filter(|value| text(value.get("source")) == "canvas_rest")
                .filter_map(|value| value.get("scope").and_then(Value::as_object))
                .map(|scope| text(scope.get("course_id")))
                .filter(|value| !value.is_empty())
                .collect::<BTreeSet<_>>();
            for course in courses {
                let mut url = api_url(&base, &format!("courses/{}/users", encoded(course)?))?;
                url.query_pairs_mut()
                    .append_pair("enrollment_type[]", "student");
                for user in self
                    .collection(
                        url,
                        &token,
                        "application/json",
                        limit,
                        CanvasProviderReadError::RosterCollectionTooLarge,
                        CollectionProtocol::CanvasRest,
                    )
                    .await?
                {
                    if let Some(id) = user.get("id").and_then(value_identifier) {
                        snapshot.canvas_user_ids.push(id);
                    }
                }
            }
            let completion_requirements = requirements
                .iter()
                .filter(|requirement| {
                    text(requirement.get("source")) == "canvas_rest"
                        && text(requirement.get("fact_type")) == "canvas.course_completion"
                })
                .collect::<Vec<_>>();
            for requirement in completion_requirements {
                let requirement_id = text(requirement.get("requirement_id"));
                let course = requirement
                    .get("scope")
                    .and_then(Value::as_object)
                    .map(|scope| text(scope.get("course_id")))
                    .unwrap_or_default();
                let url = api_url(
                    &base,
                    &format!("courses/{}/bulk_user_progress", encoded(course)?),
                )?;
                let rows = self
                    .collection(
                        url,
                        &token,
                        "application/json",
                        limit,
                        CanvasProviderReadError::RosterCollectionTooLarge,
                        CollectionProtocol::CanvasRest,
                    )
                    .await?;
                let by_user = validated_course_completion_by_user(rows)?;
                for user in &snapshot.canvas_user_ids {
                    let record = by_user.get(user).cloned().unwrap_or_else(|| json!({}));
                    snapshot.preloaded_observations.insert(
                        (requirement_id.clone(), user.clone()),
                        CanvasAuthoritativeObservation {
                            assertion: rest_assertion("canvas.course_completion", &record),
                            source_payload: normalized_rest_payload(&record),
                            verification_method: "CANVAS_OAUTH_API_READ",
                            effective_at: timestamp(record.get("updated_at")),
                        },
                    );
                }
            }
        } else if let Err(error) = token {
            if error != CanvasProviderReadError::ReauthorizationRequired {
                return Err(error);
            }
        }
        if has_ags {
            let binding_id = text(resources.binding.get("id"));
            let verified = target
                .metadata
                .get("verified_binding_id")
                .and_then(Value::as_str)
                == Some(binding_id.as_str())
                && target
                    .metadata
                    .get("verified_binding_config_version")
                    .and_then(Value::as_i64)
                    == resources
                        .binding
                        .get("config_version")
                        .and_then(Value::as_i64);
            let memberships = verified
                .then(|| text(target.metadata.get("nrps_context_memberships_url")))
                .filter(|value| !value.is_empty())
                .ok_or(CanvasProviderReadError::NrpsRosterUnavailable)?;
            for member in self
                .lti_collection(
                    resources,
                    &memberships,
                    LtiCollectionKind::NrpsMembership,
                    None,
                    limit,
                    CanvasProviderReadError::RosterCollectionTooLarge,
                )
                .await?
            {
                let active = member
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("active")
                    .eq_ignore_ascii_case("active");
                if active {
                    if let Some(subject) = member
                        .get("user_id")
                        .or_else(|| member.get("userId"))
                        .and_then(value_identifier)
                    {
                        snapshot.lti_subjects.push(subject);
                    }
                }
            }
        }
        Ok(snapshot)
    }
}

impl HttpCanvasAuthoritativeProvider {
    fn expected_lti_trust(
        &self,
        resources: &CanvasSyncResources,
    ) -> Result<marty_oid4vci::lti::CanvasLtiTrustProfile, CanvasProviderReadError> {
        expected_lti_trust(&resources.platform, &self.self_managed_origin_allowlist)
    }

    fn enforce_lti_service_trust(
        &self,
        resources: &CanvasSyncResources,
        service_url: &str,
    ) -> Result<(), CanvasProviderReadError> {
        let _expected = self.expected_lti_trust(resources)?;
        enforce_persisted_lti_service_origin(
            &resources.platform.canvas_base_url,
            &resources.platform.lti_trust_profile,
            service_url,
        )
    }
}

fn expected_lti_trust(
    platform: &crate::canvas_sync_processor::CanvasSyncPlatformSnapshot,
    self_managed_origin_allowlist: &[String],
) -> Result<marty_oid4vci::lti::CanvasLtiTrustProfile, CanvasProviderReadError> {
    let expected = canvas_lti_trust_profile(
        &platform.canvas_base_url,
        &platform.lti_trust_profile,
        self_managed_origin_allowlist,
    )
    .map_err(|_| CanvasProviderReadError::InvalidConfiguration)?;
    if platform.lti_issuer.trim() != expected.issuer
        || platform.lti_auth_token_url.trim() != expected.token_endpoint
    {
        return Err(CanvasProviderReadError::InvalidConfiguration);
    }
    Ok(expected)
}

async fn request_lti_token(
    client: &reqwest::Client,
    endpoint_url: Url,
    client_id: &str,
    assertion: &str,
    scope: &str,
) -> Result<String, CanvasProviderReadError> {
    let response = client
        .post(endpoint_url)
        .header("Accept", "application/json")
        .form(&[
            ("grant_type", "client_credentials"),
            (
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ),
            ("client_assertion", assertion),
            ("client_id", client_id),
            ("scope", scope),
        ])
        .send()
        .await
        .map_err(|_| CanvasProviderReadError::Unavailable)?;
    let payload = read_json_response(response, TOKEN_RESPONSE_BYTES).await?;
    payload
        .get("access_token")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or(CanvasProviderReadError::Unavailable)
}

async fn request_collection_page(
    client: &reqwest::Client,
    url: Url,
    token: &str,
    accept: &str,
    protocol: CollectionProtocol,
) -> Result<(Value, Vec<String>), CanvasProviderReadError> {
    let response = client
        .get(url)
        .bearer_auth(token)
        .header("Accept", accept)
        .send()
        .await
        .map_err(|_| CanvasProviderReadError::Unavailable)?;
    // The REST collection helper wraps ordinary HTTP status failures in
    // HTTPException; LTI and the existing 401/403/429 classifications differ.
    if protocol == CollectionProtocol::CanvasRest
        && (response.status().is_client_error() || response.status().is_server_error())
        && !matches!(response.status().as_u16(), 401 | 403 | 429)
    {
        return Err(CanvasProviderReadError::RosterHttpStatusFailure);
    }
    let link = link_header_values(response.headers());
    let payload = read_json_response(response, COLLECTION_PAGE_BYTES).await?;
    Ok((payload, link?))
}

async fn read_json_response(
    mut response: Response,
    maximum_bytes: usize,
) -> Result<Value, CanvasProviderReadError> {
    if response.status().is_redirection() {
        return Err(CanvasProviderReadError::InvalidConfiguration);
    }
    if matches!(response.status().as_u16(), 401 | 403) {
        return Err(CanvasProviderReadError::Unavailable);
    }
    if response.status().as_u16() == 429 {
        return Err(CanvasProviderReadError::RateLimited {
            retry_after_seconds: canvas_retry_after_seconds(&response).unwrap_or(0),
        });
    }
    if !response.status().is_success() {
        return Err(CanvasProviderReadError::Unavailable);
    }
    let length = response
        .content_length()
        .and_then(|value| usize::try_from(value).ok());
    if length.is_some_and(|value| value > maximum_bytes) {
        return Err(CanvasProviderReadError::Unavailable);
    }
    let mut bytes = Vec::with_capacity(length.unwrap_or(0).min(maximum_bytes));
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| CanvasProviderReadError::Unavailable)?
    {
        if bytes.len().saturating_add(chunk.len()) > maximum_bytes {
            return Err(CanvasProviderReadError::Unavailable);
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| CanvasProviderReadError::Unavailable)
}

fn reject_embedded_credentials(url: &Url) -> Result<(), CanvasProviderReadError> {
    if !url.username().is_empty() || url.password().is_some() {
        return Err(CanvasProviderReadError::InvalidConfiguration);
    }
    Ok(())
}

fn enforce_persisted_lti_service_origin(
    canvas_url: &str,
    trust_profile: &str,
    service_url: &str,
) -> Result<(), CanvasProviderReadError> {
    let canvas =
        Url::parse(canvas_url).map_err(|_| CanvasProviderReadError::InvalidConfiguration)?;
    let canvas_origin = origin_url(&canvas)?;
    if trust_profile.trim() == CANVAS_LTI_TRUST_SELF_MANAGED_SAME_ORIGIN {
        let service =
            Url::parse(service_url).map_err(|_| CanvasProviderReadError::InvalidConfiguration)?;
        if origin_url(&service)? != canvas_origin {
            return Err(CanvasProviderReadError::InvalidConfiguration);
        }
    }
    Ok(())
}

fn validate_ags_record(record: &Value) -> Result<(), CanvasProviderReadError> {
    record
        .as_object()
        .map(|_| ())
        .ok_or(CanvasProviderReadError::Unavailable)
}

fn validate_rest_record(fact_type: &str, record: &Value) -> Result<(), CanvasProviderReadError> {
    if !matches!(
        fact_type,
        "canvas.assignment_score"
            | "canvas.quiz_score"
            | "canvas.module_completion"
            | "canvas.course_completion"
    ) {
        return Err(CanvasProviderReadError::InvalidConfiguration);
    }
    record
        .as_object()
        .map(|_| ())
        .ok_or(CanvasProviderReadError::Unavailable)
}

fn validated_course_completion_by_user(
    rows: Vec<Value>,
) -> Result<std::collections::BTreeMap<String, Value>, CanvasProviderReadError> {
    let mut by_user = std::collections::BTreeMap::new();
    for row in rows {
        row.as_object()
            .ok_or(CanvasProviderReadError::Unavailable)?;
        let user = row
            .get("user_id")
            .or_else(|| row.get("userId"))
            .and_then(value_identifier);
        if let Some(user) = user {
            by_user.insert(user, row);
        }
    }
    Ok(by_user)
}

fn valid_collection_item(value: &Value) -> bool {
    value.is_object()
}

fn api_url(base: &Url, path: &str) -> Result<Url, CanvasProviderReadError> {
    base.join(&format!("/api/v1/{path}"))
        .map_err(|_| CanvasProviderReadError::InvalidConfiguration)
}

fn encoded(value: String) -> Result<String, CanvasProviderReadError> {
    if value.is_empty() {
        return Err(CanvasProviderReadError::InvalidConfiguration);
    }
    Ok(
        percent_encoding::utf8_percent_encode(&value, percent_encoding::NON_ALPHANUMERIC)
            .to_string(),
    )
}

fn origin_url(url: &Url) -> Result<Url, CanvasProviderReadError> {
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(CanvasProviderReadError::InvalidConfiguration);
    }
    Url::parse(&format!("{}/", url.origin().ascii_serialization()))
        .map_err(|_| CanvasProviderReadError::InvalidConfiguration)
}

fn link_header_values(
    headers: &reqwest::header::HeaderMap,
) -> Result<Vec<String>, CanvasProviderReadError> {
    headers
        .get_all(LINK)
        .iter()
        .map(|value| {
            value
                .to_str()
                .map(str::to_owned)
                .map_err(|_| CanvasProviderReadError::InvalidConfiguration)
        })
        .collect()
}

fn next_link(headers: &[String]) -> Result<Option<String>, CanvasProviderReadError> {
    let mut next = None;
    for header in headers {
        parse_link_header(header, &mut next)?;
    }
    Ok(next)
}

fn parse_link_header(
    header: &str,
    next: &mut Option<String>,
) -> Result<(), CanvasProviderReadError> {
    if header.is_empty() || !header.is_ascii() {
        return Err(CanvasProviderReadError::InvalidConfiguration);
    }
    let bytes = header.as_bytes();
    let mut cursor = 0;
    skip_optional_whitespace(bytes, &mut cursor);
    if cursor == bytes.len() {
        return Err(CanvasProviderReadError::InvalidConfiguration);
    }
    loop {
        if bytes.get(cursor) != Some(&b'<') {
            return Err(CanvasProviderReadError::InvalidConfiguration);
        }
        cursor += 1;
        let target_start = cursor;
        while bytes.get(cursor).is_some_and(|value| *value != b'>') {
            if bytes[cursor].is_ascii_whitespace() || matches!(bytes[cursor], b'<' | b'"' | b'\\') {
                return Err(CanvasProviderReadError::InvalidConfiguration);
            }
            cursor += 1;
        }
        if cursor == target_start || bytes.get(cursor) != Some(&b'>') {
            return Err(CanvasProviderReadError::InvalidConfiguration);
        }
        let target = &header[target_start..cursor];
        cursor += 1;
        let mut relations = None;

        loop {
            skip_optional_whitespace(bytes, &mut cursor);
            if cursor == bytes.len() || bytes[cursor] == b',' {
                break;
            }
            if bytes[cursor] != b';' {
                return Err(CanvasProviderReadError::InvalidConfiguration);
            }
            cursor += 1;
            skip_optional_whitespace(bytes, &mut cursor);
            let name_start = cursor;
            while bytes.get(cursor).is_some_and(|value| is_token(*value)) {
                cursor += 1;
            }
            if cursor == name_start {
                return Err(CanvasProviderReadError::InvalidConfiguration);
            }
            let name = &header[name_start..cursor];
            skip_optional_whitespace(bytes, &mut cursor);
            if bytes.get(cursor) != Some(&b'=') {
                return Err(CanvasProviderReadError::InvalidConfiguration);
            }
            cursor += 1;
            skip_optional_whitespace(bytes, &mut cursor);
            let value = parse_link_parameter_value(header, bytes, &mut cursor)?;
            if name.eq_ignore_ascii_case("rel") {
                if relations.is_some() {
                    return Err(CanvasProviderReadError::InvalidConfiguration);
                }
                let parsed = value
                    .split_ascii_whitespace()
                    .map(str::to_owned)
                    .collect::<Vec<_>>();
                if parsed.is_empty() {
                    return Err(CanvasProviderReadError::InvalidConfiguration);
                }
                relations = Some(parsed);
            }
        }

        if relations.is_some_and(|relations| {
            relations
                .iter()
                .any(|relation| relation.eq_ignore_ascii_case("next"))
        }) && next.replace(target.to_owned()).is_some()
        {
            return Err(CanvasProviderReadError::InvalidConfiguration);
        }

        skip_optional_whitespace(bytes, &mut cursor);
        if cursor == bytes.len() {
            return Ok(());
        }
        if bytes[cursor] != b',' {
            return Err(CanvasProviderReadError::InvalidConfiguration);
        }
        cursor += 1;
        skip_optional_whitespace(bytes, &mut cursor);
        if cursor == bytes.len() {
            return Err(CanvasProviderReadError::InvalidConfiguration);
        }
    }
}

fn parse_link_parameter_value(
    header: &str,
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<String, CanvasProviderReadError> {
    if bytes.get(*cursor) == Some(&b'"') {
        *cursor += 1;
        let mut output = String::new();
        loop {
            let Some(value) = bytes.get(*cursor).copied() else {
                return Err(CanvasProviderReadError::InvalidConfiguration);
            };
            *cursor += 1;
            match value {
                b'"' => return Ok(output),
                b'\\' => {
                    let Some(escaped) = bytes.get(*cursor).copied() else {
                        return Err(CanvasProviderReadError::InvalidConfiguration);
                    };
                    if escaped.is_ascii_control() && escaped != b'\t' {
                        return Err(CanvasProviderReadError::InvalidConfiguration);
                    }
                    output.push(char::from(escaped));
                    *cursor += 1;
                }
                value if value.is_ascii_control() && value != b'\t' => {
                    return Err(CanvasProviderReadError::InvalidConfiguration);
                }
                value => output.push(char::from(value)),
            }
        }
    }
    let start = *cursor;
    while bytes
        .get(*cursor)
        .is_some_and(|value| is_parameter_token(*value))
    {
        *cursor += 1;
    }
    if *cursor == start {
        return Err(CanvasProviderReadError::InvalidConfiguration);
    }
    Ok(header[start..*cursor].to_owned())
}

fn skip_optional_whitespace(bytes: &[u8], cursor: &mut usize) {
    while bytes
        .get(*cursor)
        .is_some_and(|value| matches!(value, b' ' | b'\t'))
    {
        *cursor += 1;
    }
}

fn is_token(value: u8) -> bool {
    value.is_ascii_alphanumeric()
        || matches!(
            value,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn is_parameter_token(value: u8) -> bool {
    value.is_ascii_alphanumeric()
        || matches!(
            value,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'/'
                | b':'
                | b'<'
                | b'='
                | b'>'
                | b'?'
                | b'@'
                | b'['
                | b']'
                | b'^'
                | b'_'
                | b'`'
                | b'{'
                | b'|'
                | b'}'
                | b'~'
        )
}

fn selected_payload(value: &Value, keys: &[&str]) -> Map<String, Value> {
    let mut output = Map::new();
    for key in keys {
        if let Some(value) = value.get(*key).filter(|value| !value.is_null()) {
            output.insert((*key).to_owned(), value.clone());
        }
    }
    output
}

fn timestamp(value: Option<&Value>) -> Option<DateTime<Utc>> {
    value
        .and_then(Value::as_str)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc))
}

fn value_identifier(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.trim().to_owned()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
    .filter(|value| !value.is_empty())
}

fn text(value: Option<&Value>) -> String {
    value
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_owned()
}

fn map_oauth_error(error: CanvasOAuthError) -> CanvasProviderReadError {
    match error {
        CanvasOAuthError::RefreshRateLimited {
            retry_after_seconds,
        } => CanvasProviderReadError::RateLimited {
            retry_after_seconds,
        },
        _ => CanvasProviderReadError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Exercise the unchanged token/collection HTTP adapters on synthetic local
    // transport. Public-provider HTTPS/trust parity remains a separate gate.
    #[derive(Default)]
    struct RunTokenTraffic {
        grants: usize,
        fail_next_grant: bool,
        collection_status: u16,
        authorizations: Vec<String>,
    }

    struct RunTokenServer {
        traffic: Arc<std::sync::Mutex<RunTokenTraffic>>,
        client: reqwest::Client,
        origin: String,
        task: tokio::task::JoinHandle<std::io::Result<()>>,
    }

    impl Drop for RunTokenServer {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    impl RunTokenServer {
        async fn start() -> Self {
            use axum::{
                extract::State,
                http::{HeaderMap, StatusCode},
                response::IntoResponse,
                routing::{get, post},
                Json, Router,
            };

            async fn grant(
                State(traffic): State<Arc<std::sync::Mutex<RunTokenTraffic>>>,
            ) -> axum::response::Response {
                let mut traffic = traffic.lock().unwrap();
                traffic.grants += 1;
                if std::mem::take(&mut traffic.fail_next_grant) {
                    return StatusCode::SERVICE_UNAVAILABLE.into_response();
                }
                Json(json!({
                    "access_token": format!(" synthetic-run-token-{} ", traffic.grants),
                    // Published callers retain token.value, without TTL refresh.
                    "expires_in": 0,
                }))
                .into_response()
            }

            async fn collection(
                State(traffic): State<Arc<std::sync::Mutex<RunTokenTraffic>>>,
                headers: HeaderMap,
            ) -> axum::response::Response {
                let mut traffic = traffic.lock().unwrap();
                traffic.authorizations.push(
                    headers
                        .get("authorization")
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .to_owned(),
                );
                if traffic.collection_status != 0 {
                    return StatusCode::from_u16(traffic.collection_status)
                        .unwrap()
                        .into_response();
                }
                Json(json!([])).into_response()
            }

            let traffic = Arc::new(std::sync::Mutex::new(RunTokenTraffic::default()));
            let app = Router::new()
                .route("/token", post(grant))
                .route("/collection", get(collection))
                .with_state(traffic.clone());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let origin = format!("http://{}", listener.local_addr().unwrap());
            let task = tokio::spawn(async move { axum::serve(listener, app).await });
            Self {
                traffic,
                client: reqwest::Client::builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .no_proxy()
                    .timeout(std::time::Duration::from_secs(5))
                    .build()
                    .unwrap(),
                origin,
                task,
            }
        }

        async fn token(
            &self,
            run: &RunLtiTokens,
            key: LtiTokenKey,
        ) -> Result<String, CanvasProviderReadError> {
            let client_id = key.client_id.clone();
            let scope = key.kind.scope();
            run.get_or_request(key, || {
                request_lti_token(
                    &self.client,
                    Url::parse(&format!("{}/token", self.origin)).unwrap(),
                    &client_id,
                    "synthetic-assertion",
                    scope,
                )
            })
            .await
        }

        async fn collection(&self, token: &str) -> Result<Value, CanvasProviderReadError> {
            request_collection_page(
                &self.client,
                Url::parse(&format!("{}/collection", self.origin)).unwrap(),
                token,
                AGS_RESULT_ACCEPT,
                CollectionProtocol::Lti,
            )
            .await
            .map(|(payload, _)| payload)
        }
    }

    fn run_token_resources() -> CanvasSyncResources {
        use crate::canvas_sync_processor::CanvasSyncPlatformSnapshot;

        CanvasSyncResources {
            platform: CanvasSyncPlatformSnapshot {
                id: "synthetic-platform".into(),
                organization_id: "synthetic-tenant".into(),
                config_version: 1,
                canvas_base_url: "https://canvas.example.invalid".into(),
                lti_trust_profile: CANVAS_LTI_TRUST_SELF_MANAGED_SAME_ORIGIN.into(),
                lti_issuer: "https://canvas.example.invalid".into(),
                lti_client_id: "synthetic-client".into(),
                lti_deployment_id: "synthetic-deployment".into(),
                lti_auth_token_url: "https://canvas.example.invalid/login/oauth2/token".into(),
            },
            binding: Map::new(),
            application: None,
            application_template: None,
        }
    }

    fn run_token_key() -> LtiTokenKey {
        let resources = run_token_resources();
        LtiTokenKey::new(
            &resources,
            &resources.platform.lti_auth_token_url,
            LtiCollectionKind::AgsResult,
        )
    }

    fn run_provider_without_database_io() -> (HttpCanvasAuthoritativeProvider, sqlx::PgPool) {
        use crate::{
            canvas_lti_tool_signing::CanvasLtiToolSigningError,
            canvas_oauth::CanvasOAuthServiceConfig,
            canvas_oauth_http::HttpCanvasOAuthProvider,
            canvas_oauth_postgres::{
                PostgresCanvasOAuthRepository, PostgresIntegrationSecretVault,
            },
            integration_secret::IntegrationSecretCipher,
        };

        struct UnusedSigner;
        #[async_trait]
        impl CanvasLtiToolJwtSigner for UnusedSigner {
            async fn sign_jwt(&self, _: &Value) -> Result<String, CanvasLtiToolSigningError> {
                panic!("factory and rejected-trust tests must not sign")
            }

            async fn public_jwks(&self) -> Result<Value, CanvasLtiToolSigningError> {
                panic!("factory tests must not resolve signing keys")
            }
        }

        // Lazy, zero-minimum pool: constructing this adapter performs no DB I/O.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .min_connections(0)
            .connect_lazy("postgres://synthetic:synthetic@127.0.0.1:1/synthetic")
            .unwrap();
        let oauth = CanvasOAuthService::new(
            Arc::new(PostgresCanvasOAuthRepository::new(pool.clone())),
            Arc::new(PostgresIntegrationSecretVault::new(
                pool.clone(),
                IntegrationSecretCipher::from_base64(
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                )
                .unwrap(),
            )),
            Arc::new(HttpCanvasOAuthProvider::new_with_policy(
                std::time::Duration::from_secs(2),
                Vec::new(),
                false,
                false,
            )),
            Some("synthetic-management-key"),
            CanvasOAuthServiceConfig {
                issuer_base_url: "https://issuer.example.invalid".into(),
                completion_base_url: "https://ui.example.invalid".into(),
                portable_enabled: true,
                pilot_organizations: BTreeSet::new(),
                allow_private_networks: false,
                allow_http_localhost: false,
            },
        )
        .unwrap();
        (
            HttpCanvasAuthoritativeProvider::new(
                Arc::new(oauth),
                "synthetic-private-oauth-key",
                Arc::new(UnusedSigner),
                CanvasHttpClientPolicy {
                    timeout: std::time::Duration::from_secs(2),
                    private_origin_allowlist: Vec::new(),
                    allow_private_networks: false,
                    allow_http_localhost: false,
                },
                vec!["https://canvas.example.invalid".into()],
            ),
            pool,
        )
    }

    #[tokio::test]
    async fn run_provider_factory_resets_scoped_instances_and_keeps_templates_uncached() {
        let (template, pool) = run_provider_without_database_io();
        assert!(template.run_tokens.is_none());
        let first = template.fresh_run();
        let first_cache = first.run_tokens.as_ref().unwrap();
        first_cache
            .get_or_request(run_token_key(), || async {
                Ok("synthetic-private-access-token".into())
            })
            .await
            .unwrap();
        // A caller cannot extend a previous job's token lifetime by scoping an
        // already-scoped instance. Cloning the stateless template also stays uncached.
        let second = first.fresh_run();
        let second_cache = second.run_tokens.as_ref().unwrap();
        assert!(!Arc::ptr_eq(first_cache, second_cache));
        assert!(second_cache.tokens.lock().await.is_empty());
        assert!(template.clone().run_tokens.is_none());
        let object: Arc<dyn CanvasAuthoritativeProvider> = Arc::new(first.clone());
        let left = object.clone().for_run();
        let right = object.clone().for_run();
        let nested = left.clone().for_run();
        assert!(!Arc::ptr_eq(&object, &left));
        assert!(!Arc::ptr_eq(&left, &right));
        assert!(!Arc::ptr_eq(&left, &nested));
        for debug in [format!("{first:?}"), format!("{first_cache:?}")] {
            for private in [
                "synthetic-private-access-token",
                "synthetic-private-oauth-key",
            ] {
                assert!(!debug.contains(private));
            }
        }
        pool.close().await;
    }

    #[tokio::test]
    async fn run_provider_rechecks_trust_before_considering_a_cached_grant() {
        let (template, pool) = run_provider_without_database_io();
        let run = template.fresh_run();
        let mut resources = run_token_resources();
        let key = run_token_key();
        run.run_tokens
            .as_ref()
            .unwrap()
            .get_or_request(key, || async { Ok("synthetic-cached-token".into()) })
            .await
            .unwrap();
        // The token cache key uses the validated endpoint, not this untrusted
        // input. Corrupting it must reject before any network/signing or cache hit.
        resources.platform.lti_auth_token_url = "https://untrusted.example.invalid/token".into();
        assert_eq!(
            run.lti_access_token(&resources, LtiCollectionKind::AgsResult)
                .await,
            Err(CanvasProviderReadError::InvalidConfiguration)
        );
        assert_eq!(
            run.run_tokens.as_ref().unwrap().tokens.lock().await.len(),
            1
        );
        pool.close().await;
    }

    #[tokio::test]
    async fn run_tokens_reuse_success_without_ttl_refresh_and_coalesce_concurrent_reads() {
        let server = RunTokenServer::start().await;
        let run = RunLtiTokens::default();
        let (first, concurrent) = tokio::join!(
            server.token(&run, run_token_key()),
            server.token(&run, run_token_key())
        );
        assert_eq!(first.unwrap(), "synthetic-run-token-1");
        assert_eq!(concurrent.unwrap(), "synthetic-run-token-1");
        assert_eq!(
            server.token(&run, run_token_key()).await.unwrap(),
            "synthetic-run-token-1"
        );
        assert_eq!(server.traffic.lock().unwrap().grants, 1);
    }

    #[tokio::test]
    async fn run_tokens_never_share_grants_between_concurrent_or_subsequent_runs() {
        let server = RunTokenServer::start().await;
        let first = RunLtiTokens::default();
        let second = RunLtiTokens::default();
        let (left, right) = tokio::join!(
            server.token(&first, run_token_key()),
            server.token(&second, run_token_key())
        );
        let left = left.unwrap();
        let right = right.unwrap();
        assert_ne!(left, right);
        assert_eq!(server.token(&first, run_token_key()).await.unwrap(), left);
        assert_eq!(server.token(&second, run_token_key()).await.unwrap(), right);
        let next = RunLtiTokens::default();
        assert_eq!(
            server.token(&next, run_token_key()).await.unwrap(),
            "synthetic-run-token-3"
        );
        assert_eq!(server.traffic.lock().unwrap().grants, 3);
    }

    #[tokio::test]
    async fn run_tokens_separate_every_resource_identity_dimension_and_scope() {
        let server = RunTokenServer::start().await;
        let run = RunLtiTokens::default();
        let baseline = run_token_resources();
        let mut keys = vec![run_token_key()];
        for dimension in 0..8 {
            let mut resources = baseline.clone();
            let platform = &mut resources.platform;
            match dimension {
                0 => platform.organization_id.push_str("-other"),
                1 => platform.id.push_str("-other"),
                2 => platform.config_version += 1,
                3 => platform.canvas_base_url.push_str("/other"),
                4 => platform.lti_trust_profile.push_str("-other"),
                5 => platform.lti_issuer.push_str("/other"),
                6 => platform.lti_client_id.push_str("-other"),
                7 => platform.lti_deployment_id.push_str("-other"),
                _ => unreachable!(),
            }
            keys.push(LtiTokenKey::new(
                &resources,
                &baseline.platform.lti_auth_token_url,
                LtiCollectionKind::AgsResult,
            ));
        }
        keys.push(LtiTokenKey::new(
            &baseline,
            "https://canvas.example.invalid/other-token",
            LtiCollectionKind::AgsResult,
        ));
        keys.push(LtiTokenKey::new(
            &baseline,
            &baseline.platform.lti_auth_token_url,
            LtiCollectionKind::NrpsMembership,
        ));
        assert_eq!(keys.iter().collect::<BTreeSet<_>>().len(), 11);
        let mut acquired = BTreeSet::new();
        for key in keys {
            let token = server.token(&run, key.clone()).await.unwrap();
            assert!(acquired.insert(token.clone()));
            assert_eq!(server.token(&run, key).await.unwrap(), token);
        }
        assert_eq!(server.traffic.lock().unwrap().grants, 11);
    }

    #[tokio::test]
    async fn run_tokens_retry_failed_acquisition_but_retain_success_after_collection_errors() {
        let server = RunTokenServer::start().await;
        let run = RunLtiTokens::default();
        server.traffic.lock().unwrap().fail_next_grant = true;
        assert_eq!(
            server.token(&run, run_token_key()).await,
            Err(CanvasProviderReadError::Unavailable)
        );
        let token = server.token(&run, run_token_key()).await.unwrap();
        for status in [503, 401] {
            server.traffic.lock().unwrap().collection_status = status;
            assert!(server.collection(&token).await.is_err());
            assert_eq!(server.token(&run, run_token_key()).await.unwrap(), token);
        }
        server.traffic.lock().unwrap().collection_status = 0;
        assert_eq!(server.collection(&token).await.unwrap(), json!([]));
        let traffic = server.traffic.lock().unwrap();
        assert_eq!(traffic.grants, 2);
        assert_eq!(traffic.authorizations, vec![format!("Bearer {token}"); 3]);
    }

    #[tokio::test]
    async fn run_tokens_cancelled_acquisition_releases_lock_without_caching_partial_token() {
        let run = Arc::new(RunLtiTokens::default());
        let started = Arc::new(tokio::sync::Notify::new());
        let task = {
            let run = run.clone();
            let started = started.clone();
            tokio::spawn(async move {
                run.get_or_request(run_token_key(), || async {
                    started.notify_one();
                    std::future::pending::<Result<String, CanvasProviderReadError>>().await
                })
                .await
            })
        };
        tokio::time::timeout(std::time::Duration::from_secs(2), started.notified())
            .await
            .unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                run.get_or_request(run_token_key(), || async { Ok("synthetic-retry".into()) })
            )
            .await
            .unwrap()
            .unwrap(),
            "synthetic-retry"
        );
        assert_eq!(run.tokens.lock().await.len(), 1);
        let debug = format!("{run:?}");
        for private in ["synthetic-retry", "synthetic-client", "synthetic-tenant"] {
            assert!(!debug.contains(private));
        }
    }

    #[test]
    fn pagination_accepts_standard_next_relation_forms_across_all_headers() {
        assert_eq!(TOKEN_RESPONSE_BYTES, 65_536);
        assert_eq!(COLLECTION_PAGE_BYTES, 8_388_608);
        assert_eq!(COLLECTION_MAX_PAGES, 200);
        assert_eq!(
            next_link(&[
                "<https://canvas.test/one>; rel=\"current\"".to_owned(),
                "<https://canvas.test/two?cursor=a,b>; title=\"page, two\"; REL=\"prev NEXT\""
                    .to_owned(),
            ]),
            Ok(Some("https://canvas.test/two?cursor=a,b".to_owned())),
        );
        assert_eq!(
            next_link(&["<https://canvas.test/two>; rel=next".to_owned()]),
            Ok(Some("https://canvas.test/two".to_owned())),
        );
        assert_eq!(
            next_link(&[
                "<https://canvas.test/one>; title=\"rel=\\\"next\\\"\"; rel=current".to_owned(),
                "<https://canvas.test/two>; rel=\"last\"".to_owned(),
            ]),
            Ok(None),
        );
    }

    #[test]
    fn pagination_link_parsing_fails_closed_on_malformed_or_ambiguous_headers() {
        for malformed in [
            "",
            "garbage",
            "<https://canvas.test/two; rel=next",
            "<https://canvas.test/two>; rel",
            "<https://canvas.test/two>; rel=\"next",
            "<https://canvas.test/two>; rel=next,",
            "<https://canvas.test/two>; rel=next; rel=last",
            "<https://canvas.test/two bad>; rel=next",
        ] {
            assert_eq!(
                next_link(&[malformed.to_owned()]),
                Err(CanvasProviderReadError::InvalidConfiguration),
                "{malformed}",
            );
        }
        assert_eq!(
            next_link(&[
                "<https://canvas.test/two>; rel=next".to_owned(),
                "<https://canvas.test/three>; rel=\"NEXT\"".to_owned(),
            ]),
            Err(CanvasProviderReadError::InvalidConfiguration),
        );
    }

    #[test]
    fn pagination_header_capture_preserves_all_values_and_rejects_non_text() {
        use reqwest::header::{HeaderMap, HeaderValue};

        let mut headers = HeaderMap::new();
        headers.append(
            LINK,
            HeaderValue::from_static("<https://canvas.test/one>; rel=current"),
        );
        headers.append(
            LINK,
            HeaderValue::from_static("<https://canvas.test/two>; rel=next"),
        );
        assert_eq!(
            link_header_values(&headers),
            Ok(vec![
                "<https://canvas.test/one>; rel=current".to_owned(),
                "<https://canvas.test/two>; rel=next".to_owned(),
            ]),
        );

        let mut non_text = HeaderMap::new();
        non_text.insert(LINK, HeaderValue::from_bytes(&[0xff]).unwrap());
        assert_eq!(
            link_header_values(&non_text),
            Err(CanvasProviderReadError::InvalidConfiguration),
        );
    }

    #[tokio::test]
    async fn malformed_link_metadata_cannot_mask_rate_limit_classification() {
        use axum::{http::StatusCode, response::Response, routing::get, Router};

        async fn rate_limited() -> Response {
            Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .header(LINK, "malformed")
                .header(reqwest::header::RETRY_AFTER, "also-malformed")
                .body(axum::body::Body::empty())
                .unwrap()
        }

        let app = Router::new().route("/collection", get(rate_limited));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move { axum::serve(listener, app).await });
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .expect("client");

        assert_eq!(
            request_collection_page(
                &client,
                Url::parse(&format!("http://{address}/collection")).unwrap(),
                "token",
                NRPS_MEMBERSHIP_ACCEPT,
                CollectionProtocol::Lti,
            )
            .await,
            Err(CanvasProviderReadError::RateLimited {
                retry_after_seconds: 0,
            }),
        );
        server.abort();
    }

    #[test]
    fn rest_collection_setup_preserves_query_and_protocol_specific_envelopes() {
        let url =
            Url::parse("https://canvas.test/api/v1/courses/42/users?enrollment_type%5B%5D=student")
                .unwrap();
        for (limit, page) in [(0, "1"), (2, "2"), (5000, "100")] {
            let actual = CollectionProtocol::CanvasRest.first_page(url.clone(), limit);
            assert_eq!(
                actual.query(),
                Some(format!("enrollment_type%5B%5D=student&per_page={page}").as_str())
            );
            assert_eq!(CollectionProtocol::Lti.first_page(url.clone(), limit), url);
        }
        for payload in [json!([]), json!({"items": []})] {
            assert_eq!(
                CollectionProtocol::CanvasRest.rows(&payload),
                Some(&Vec::new())
            );
        }
        for payload in [json!({"members": []}), json!({"results": []})] {
            assert!(CollectionProtocol::CanvasRest.rows(&payload).is_none());
            assert_eq!(CollectionProtocol::Lti.rows(&payload), Some(&Vec::new()));
        }
        assert!(CollectionProtocol::Lti
            .rows(&json!({"items": []}))
            .is_none());
        assert!(CollectionProtocol::CanvasRest
            .rows(&json!({"items": {}}))
            .is_none());
    }

    #[tokio::test]
    async fn rest_collection_status_failure_is_distinct_without_changing_lti_or_rate_limits() {
        use axum::{extract::Path, http::StatusCode, response::Response, routing::get, Router};

        async fn status(Path(code): Path<u16>) -> Response {
            Response::builder()
                .status(StatusCode::from_u16(code).unwrap())
                .header("Retry-After", "37")
                .body(axum::body::Body::from(
                    "synthetic-provider-detail-never-persisted",
                ))
                .unwrap()
        }
        let app = Router::new().route("/{status}", get(status));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await });
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .unwrap();
        for code in [400, 401, 403, 429, 503] {
            for protocol in [CollectionProtocol::CanvasRest, CollectionProtocol::Lti] {
                let actual = request_collection_page(
                    &client,
                    Url::parse(&format!("http://{address}/{code}")).unwrap(),
                    "synthetic-token",
                    "application/json",
                    protocol,
                )
                .await;
                let expected = match code {
                    429 => CanvasProviderReadError::RateLimited {
                        retry_after_seconds: 37,
                    },
                    401 | 403 => CanvasProviderReadError::Unavailable,
                    _ if protocol == CollectionProtocol::CanvasRest => {
                        CanvasProviderReadError::RosterHttpStatusFailure
                    }
                    _ => CanvasProviderReadError::Unavailable,
                };
                assert_eq!(actual, Err(expected), "status {code}");
            }
        }
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
    }

    #[test]
    fn pagination_credentials_and_malformed_items_fail_closed() {
        let credentialed = Url::parse("https://user:secret@canvas.test/two").unwrap();
        assert_eq!(
            reject_embedded_credentials(&credentialed),
            Err(CanvasProviderReadError::InvalidConfiguration)
        );
        assert!(valid_collection_item(&json!({})));
        assert!(valid_collection_item(&json!({"name": "missing identity"})));
        assert!(valid_collection_item(&json!({"id": 7})));
        assert!(valid_collection_item(&json!({"userId": "opaque-subject"})));
        assert!(!valid_collection_item(&json!([])));
    }

    #[test]
    fn origin_reconstruction_preserves_ipv6_and_canonical_default_ports() {
        assert_eq!(
            origin_url(
                &Url::parse("https://[2001:4860:4860::8888]:8443/path?cursor=1")
                    .expect("public IPv6 URL"),
            )
            .expect("IPv6 origin")
            .as_str(),
            "https://[2001:4860:4860::8888]:8443/",
        );
        assert_eq!(
            origin_url(&Url::parse("https://canvas.example:443/path").expect("HTTPS URL"))
                .expect("canonical HTTPS origin")
                .as_str(),
            "https://canvas.example/",
        );
        assert_eq!(
            origin_url(&Url::parse("https://user@example.test/path").expect("credentialed URL")),
            Err(CanvasProviderReadError::InvalidConfiguration),
        );
    }

    #[test]
    fn successful_authoritative_objects_include_verified_empty_negatives() {
        assert!(validate_ags_record(&json!({})).is_ok());
        assert!(validate_ags_record(&json!({
            "id":"result-1",
            "userId":"canvas-user-7",
            "resultScore":92,
            "resultMaximum":100
        }))
        .is_ok());
        assert!(validate_ags_record(&json!({
            "id":"result-2",
            "resultStatus":null,
            "resultScore":null,
            "resultMaximum":null
        }))
        .is_ok());
        for fact_type in [
            "canvas.assignment_score",
            "canvas.quiz_score",
            "canvas.module_completion",
            "canvas.course_completion",
        ] {
            assert!(
                validate_rest_record(fact_type, &json!({})).is_ok(),
                "{fact_type}"
            );
            assert_eq!(
                rest_assertion(fact_type, &json!({})).get("completed"),
                Some(&Value::Bool(false)),
                "{fact_type}",
            );
        }
        assert_eq!(
            validate_ags_record(&json!([])),
            Err(CanvasProviderReadError::Unavailable),
        );
        assert_eq!(
            validate_rest_record("canvas.assignment_score", &json!(null)),
            Err(CanvasProviderReadError::Unavailable),
        );
        assert_eq!(
            validate_rest_record("unsupported", &json!({})),
            Err(CanvasProviderReadError::InvalidConfiguration),
        );
        assert_eq!(
            ags_assertion(&json!({})).get("completed"),
            Some(&Value::Bool(false)),
        );
    }

    #[test]
    fn bulk_course_completion_keeps_object_and_last_row_semantics() {
        let first = json!({"user_id":"7", "requirement_count":null});
        let last = json!({
            "userId":"7",
            "requirement_count":3,
            "requirement_completed_count":2
        });
        let indexed = validated_course_completion_by_user(vec![json!({}), first, last.clone()])
            .expect("object rows are valid and unidentified rows are skipped");
        assert_eq!(indexed.get("7"), Some(&last));
        assert_eq!(
            validated_course_completion_by_user(vec![json!([])]),
            Err(CanvasProviderReadError::Unavailable),
        );
    }

    #[derive(Clone, Debug)]
    struct CapturedRequest {
        path: String,
        accept: String,
        authorization: Option<String>,
        body: String,
    }

    #[tokio::test]
    async fn token_form_and_lti_collection_accept_types_match_frozen_contract() {
        use std::sync::{Arc, Mutex};

        use axum::{
            body::Bytes,
            extract::State,
            http::{HeaderMap, Uri},
            response::IntoResponse,
            routing::{get, post},
            Json, Router,
        };

        async fn capture(
            State(requests): State<Arc<Mutex<Vec<CapturedRequest>>>>,
            uri: Uri,
            headers: HeaderMap,
            body: Bytes,
        ) -> impl IntoResponse {
            requests.lock().expect("requests").push(CapturedRequest {
                path: uri.path().to_owned(),
                accept: headers
                    .get("accept")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default()
                    .to_owned(),
                authorization: headers
                    .get("authorization")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned),
                body: String::from_utf8(body.to_vec()).expect("form body"),
            });
            if uri.path() == "/token" {
                Json(json!({"access_token":"  bounded-token  "}))
            } else {
                Json(json!([]))
            }
        }

        let requests = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .route("/token", post(capture))
            .route("/ags", get(capture))
            .route("/nrps", get(capture))
            .with_state(requests.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move { axum::serve(listener, app).await });
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .expect("client");
        let token = request_lti_token(
            &client,
            Url::parse(&format!("http://{address}/token")).unwrap(),
            "client-123",
            "assertion-456",
            AGS_RESULT_READ_SCOPE,
        )
        .await
        .expect("token response");
        assert_eq!(token, "bounded-token");
        for (path, accept) in [("ags", AGS_RESULT_ACCEPT), ("nrps", NRPS_MEMBERSHIP_ACCEPT)] {
            let (payload, _) = request_collection_page(
                &client,
                Url::parse(&format!("http://{address}/{path}")).unwrap(),
                &token,
                accept,
                CollectionProtocol::Lti,
            )
            .await
            .expect("collection response");
            assert_eq!(payload, json!([]));
        }
        server.abort();

        let requests = requests.lock().expect("requests");
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0].path, "/token");
        assert_eq!(requests[0].accept, "application/json");
        let form = url::form_urlencoded::parse(requests[0].body.as_bytes())
            .into_owned()
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(
            form.get("client_id").map(String::as_str),
            Some("client-123")
        );
        assert_eq!(
            form.get("client_assertion").map(String::as_str),
            Some("assertion-456"),
        );
        assert_eq!(requests[1].accept, AGS_RESULT_ACCEPT);
        assert_eq!(requests[2].accept, NRPS_MEMBERSHIP_ACCEPT);
        assert_eq!(
            requests[1].authorization.as_deref(),
            Some("Bearer bounded-token"),
        );
        assert_eq!(
            requests[2].authorization.as_deref(),
            Some("Bearer bounded-token"),
        );
    }

    #[test]
    fn persisted_self_managed_trust_is_same_origin_only() {
        assert!(enforce_persisted_lti_service_origin(
            "https://canvas.example.edu",
            CANVAS_LTI_TRUST_SELF_MANAGED_SAME_ORIGIN,
            "https://canvas.example.edu/api/lti/token",
        )
        .is_ok());
        assert_eq!(
            enforce_persisted_lti_service_origin(
                "https://canvas.example.edu",
                CANVAS_LTI_TRUST_SELF_MANAGED_SAME_ORIGIN,
                "https://attacker.example/api/lti/token",
            ),
            Err(CanvasProviderReadError::InvalidConfiguration)
        );
        assert!(enforce_persisted_lti_service_origin(
            "https://school.instructure.com",
            "hosted_global",
            "https://canvas.instructure.com/login/oauth2/token",
        )
        .is_ok());
        assert!(canvas_lti_trust_profile(
            "https://canvas.example.edu",
            CANVAS_LTI_TRUST_SELF_MANAGED_SAME_ORIGIN,
            &[],
        )
        .is_err());
    }
}
