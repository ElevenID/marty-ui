//! Bounded, redirect-free Canvas REST, AGS, and NRPS provider adapter.

use std::{collections::BTreeSet, sync::Arc};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use marty_oid4vci::lti::validate_canvas_lti_service_url;
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

#[derive(Clone)]
pub struct HttpCanvasAuthoritativeProvider {
    oauth: Arc<CanvasOAuthService>,
    oauth_api_key: String,
    signer: Arc<dyn CanvasLtiToolJwtSigner>,
    policy: CanvasHttpClientPolicy,
    self_managed_origin_allowlist: Vec<String>,
}

impl std::fmt::Debug for HttpCanvasAuthoritativeProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpCanvasAuthoritativeProvider")
            .field("policy", &self.policy)
            .field("oauth_api_key_configured", &!self.oauth_api_key.is_empty())
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
        scope: &str,
    ) -> Result<String, CanvasProviderReadError> {
        let endpoint = validate_canvas_lti_service_url(
            &resources.platform.lti_auth_token_url,
            &self.policy.private_origin_allowlist,
        )
        .await
        .map_err(|_| CanvasProviderReadError::InvalidConfiguration)?;
        self.enforce_self_managed_same_origin(resources, &endpoint)?;
        if resources.platform.lti_client_id.trim().is_empty() {
            return Err(CanvasProviderReadError::InvalidConfiguration);
        }
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
            Url::parse(&endpoint).map_err(|_| CanvasProviderReadError::InvalidConfiguration)?;
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
        scope: &str,
        accept: &str,
        user_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<Value>, CanvasProviderReadError> {
        let validated = validate_canvas_lti_service_url(url, &self.policy.private_origin_allowlist)
            .await
            .map_err(|_| CanvasProviderReadError::InvalidConfiguration)?;
        self.enforce_self_managed_same_origin(resources, &validated)?;
        let token = self.lti_access_token(resources, scope).await?;
        let mut next =
            Url::parse(&validated).map_err(|_| CanvasProviderReadError::InvalidConfiguration)?;
        if let Some(user_id) = user_id {
            next.query_pairs_mut().append_pair("user_id", user_id);
        }
        self.collection(resources, next, &token, accept, limit)
            .await
    }

    async fn collection(
        &self,
        resources: &CanvasSyncResources,
        mut next: Url,
        token: &str,
        accept: &str,
        limit: usize,
    ) -> Result<Vec<Value>, CanvasProviderReadError> {
        let expected_origin = origin_url(&next)?;
        reject_embedded_credentials(&next)?;
        let (client, _) = client_for_canvas_origin(expected_origin.as_str(), &self.policy)
            .await
            .map_err(|_| CanvasProviderReadError::InvalidConfiguration)?;
        let mut output = Vec::new();
        let mut visited = BTreeSet::new();
        for _page in 0..COLLECTION_MAX_PAGES {
            if !visited.insert(next.to_string()) {
                return Err(CanvasProviderReadError::InvalidConfiguration);
            }
            if origin_url(&next)? != expected_origin {
                return Err(CanvasProviderReadError::InvalidConfiguration);
            }
            let (payload, link) =
                request_collection_page(&client, next.clone(), token, accept).await?;
            let rows = payload
                .as_array()
                .or_else(|| payload.get("members").and_then(Value::as_array))
                .or_else(|| payload.get("results").and_then(Value::as_array))
                .ok_or(CanvasProviderReadError::Unavailable)?;
            if rows.iter().any(|row| !valid_collection_item(row)) {
                return Err(CanvasProviderReadError::Unavailable);
            }
            let remaining = limit.saturating_sub(output.len());
            if rows.len() > remaining {
                return Err(CanvasProviderReadError::Unavailable);
            }
            output.extend(rows.iter().cloned());
            let Some(candidate) = link.as_deref().and_then(next_link) else {
                return Ok(output);
            };
            if output.len() >= limit {
                return Err(CanvasProviderReadError::Unavailable);
            }
            next =
                Url::parse(candidate).map_err(|_| CanvasProviderReadError::InvalidConfiguration)?;
            reject_embedded_credentials(&next)?;
        }
        let _ = resources;
        Err(CanvasProviderReadError::InvalidConfiguration)
    }
}

#[async_trait]
impl CanvasAuthoritativeProvider for HttpCanvasAuthoritativeProvider {
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
                    AGS_RESULT_READ_SCOPE,
                    AGS_RESULT_ACCEPT,
                    Some(subject),
                    100,
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
        let mut snapshot = CanvasRosterSnapshot::default();
        if has_rest {
            let token = self.oauth_token(resources).await?;
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
                    .collection(resources, url, &token, "application/json", limit)
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
                    .collection(resources, url, &token, "application/json", limit)
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
                .ok_or(CanvasProviderReadError::InvalidConfiguration)?;
            for member in self
                .lti_collection(
                    resources,
                    &memberships,
                    NRPS_MEMBERSHIP_READ_SCOPE,
                    NRPS_MEMBERSHIP_ACCEPT,
                    None,
                    limit,
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
    fn enforce_self_managed_same_origin(
        &self,
        resources: &CanvasSyncResources,
        service_url: &str,
    ) -> Result<(), CanvasProviderReadError> {
        enforce_self_managed_origin(
            &resources.platform.canvas_base_url,
            service_url,
            &self.self_managed_origin_allowlist,
        )
    }
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
) -> Result<(Value, Option<String>), CanvasProviderReadError> {
    let response = client
        .get(url)
        .bearer_auth(token)
        .header("Accept", accept)
        .send()
        .await
        .map_err(|_| CanvasProviderReadError::Unavailable)?;
    let link = response
        .headers()
        .get(LINK)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let payload = read_json_response(response, COLLECTION_PAGE_BYTES).await?;
    Ok((payload, link))
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

fn enforce_self_managed_origin(
    canvas_url: &str,
    service_url: &str,
    allowlist: &[String],
) -> Result<(), CanvasProviderReadError> {
    let canvas =
        Url::parse(canvas_url).map_err(|_| CanvasProviderReadError::InvalidConfiguration)?;
    let canvas_origin = origin_url(&canvas)?;
    let self_managed = allowlist.iter().any(|candidate| {
        Url::parse(candidate)
            .ok()
            .filter(|url| {
                url.scheme() == "https"
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.query().is_none()
                    && url.fragment().is_none()
                    && matches!(url.path(), "" | "/")
            })
            .and_then(|url| origin_url(&url).ok())
            .is_some_and(|origin| origin == canvas_origin)
    });
    if self_managed {
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
    let host = url
        .host_str()
        .ok_or(CanvasProviderReadError::InvalidConfiguration)?;
    let port = url
        .port()
        .map(|port| format!(":{port}"))
        .unwrap_or_default();
    Url::parse(&format!("{}://{host}{port}/", url.scheme()))
        .map_err(|_| CanvasProviderReadError::InvalidConfiguration)
}

fn next_link(header: &str) -> Option<&str> {
    header.split(',').find_map(|part| {
        let (url, attributes) = part.trim().split_once('>')?;
        attributes
            .contains("rel=\"next\"")
            .then(|| url.trim_start_matches('<'))
    })
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

    #[test]
    fn pagination_only_accepts_explicit_next_relation() {
        assert_eq!(TOKEN_RESPONSE_BYTES, 65_536);
        assert_eq!(COLLECTION_PAGE_BYTES, 8_388_608);
        assert_eq!(COLLECTION_MAX_PAGES, 200);
        let header =
            "<https://canvas.test/one>; rel=\"current\", <https://canvas.test/two>; rel=\"next\"";
        assert_eq!(next_link(header), Some("https://canvas.test/two"));
        assert_eq!(next_link("<https://canvas.test/two>; rel=\"last\""), None);
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
    fn self_managed_trust_is_independent_and_same_origin_only() {
        let self_managed = vec!["https://canvas.example.edu".to_owned()];
        assert!(enforce_self_managed_origin(
            "https://canvas.example.edu",
            "https://canvas.example.edu/api/lti/token",
            &self_managed,
        )
        .is_ok());
        for invalid in [
            "https://user:secret@canvas.example.edu",
            "https://canvas.example.edu/path",
            "http://canvas.example.edu",
        ] {
            assert!(enforce_self_managed_origin(
                "https://canvas.example.edu",
                "https://attacker.example/token",
                &[invalid.to_owned()],
            )
            .is_ok());
        }
        assert_eq!(
            enforce_self_managed_origin(
                "https://canvas.example.edu",
                "https://attacker.example/api/lti/token",
                &self_managed,
            ),
            Err(CanvasProviderReadError::InvalidConfiguration)
        );
        assert!(enforce_self_managed_origin(
            "https://school.instructure.com",
            "https://canvas.instructure.com/login/oauth2/token",
            &self_managed,
        )
        .is_ok());
    }
}
