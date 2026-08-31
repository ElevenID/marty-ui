//! Bounded, redirect-free Canvas REST, AGS, and NRPS provider adapter.

use std::{collections::BTreeSet, sync::Arc, time::Duration};

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
const PAGE_BYTES: usize = 1_048_576;

#[derive(Clone)]
pub struct HttpCanvasAuthoritativeProvider {
    oauth: Arc<CanvasOAuthService>,
    oauth_api_key: String,
    signer: Arc<dyn CanvasLtiToolJwtSigner>,
    policy: CanvasHttpClientPolicy,
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
        timeout: Duration,
        private_origin_allowlist: Vec<String>,
        allow_private_networks: bool,
        allow_http_localhost: bool,
    ) -> Self {
        Self {
            oauth,
            oauth_api_key: oauth_api_key.into(),
            signer,
            policy: CanvasHttpClientPolicy {
                timeout,
                private_origin_allowlist,
                allow_private_networks,
                allow_http_localhost,
            },
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
        read_json_response(response).await
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
        let response = client
            .post(endpoint_url)
            .form(&[
                ("grant_type", "client_credentials"),
                (
                    "client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                ),
                ("client_assertion", assertion.as_str()),
                ("scope", scope),
            ])
            .send()
            .await
            .map_err(|_| CanvasProviderReadError::Unavailable)?;
        let payload = read_json_response(response).await?;
        payload
            .get("access_token")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .filter(|value| !value.is_empty())
            .ok_or(CanvasProviderReadError::Unavailable)
    }

    async fn lti_collection(
        &self,
        resources: &CanvasSyncResources,
        url: &str,
        scope: &str,
        user_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<Value>, CanvasProviderReadError> {
        let validated = validate_canvas_lti_service_url(url, &self.policy.private_origin_allowlist)
            .await
            .map_err(|_| CanvasProviderReadError::InvalidConfiguration)?;
        let token = self.lti_access_token(resources, scope).await?;
        let mut next =
            Url::parse(&validated).map_err(|_| CanvasProviderReadError::InvalidConfiguration)?;
        if let Some(user_id) = user_id {
            next.query_pairs_mut().append_pair("user_id", user_id);
        }
        self.collection(resources, next, &token, limit).await
    }

    async fn collection(
        &self,
        resources: &CanvasSyncResources,
        mut next: Url,
        token: &str,
        limit: usize,
    ) -> Result<Vec<Value>, CanvasProviderReadError> {
        let expected_origin = origin_url(&next)?;
        let (client, _) = client_for_canvas_origin(expected_origin.as_str(), &self.policy)
            .await
            .map_err(|_| CanvasProviderReadError::InvalidConfiguration)?;
        let mut output = Vec::new();
        let mut visited = BTreeSet::new();
        while output.len() < limit && visited.insert(next.to_string()) {
            if origin_url(&next)? != expected_origin {
                return Err(CanvasProviderReadError::InvalidConfiguration);
            }
            let response = client
                .get(next.clone())
                .bearer_auth(token)
                .header("Accept", "application/json")
                .send()
                .await
                .map_err(|_| CanvasProviderReadError::Unavailable)?;
            let link = response
                .headers()
                .get(LINK)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            let payload = read_json_response(response).await?;
            let rows = payload
                .as_array()
                .or_else(|| payload.get("members").and_then(Value::as_array))
                .or_else(|| payload.get("results").and_then(Value::as_array))
                .ok_or(CanvasProviderReadError::Unavailable)?;
            output.extend(rows.iter().take(limit - output.len()).cloned());
            let Some(candidate) = link.as_deref().and_then(next_link) else {
                break;
            };
            next =
                Url::parse(candidate).map_err(|_| CanvasProviderReadError::InvalidConfiguration)?;
        }
        let _ = resources; // Tenant-bound token/resource snapshot is retained by the caller.
        Ok(output)
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
                    Some(subject),
                    100,
                )
                .await?;
            let record = results.first().cloned().unwrap_or_else(|| json!({}));
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
                for user in self.collection(resources, url, &token, limit).await? {
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
                let rows = self.collection(resources, url, &token, limit).await?;
                let by_user = rows
                    .into_iter()
                    .filter_map(|row| {
                        row.get("user_id")
                            .or_else(|| row.get("userId"))
                            .and_then(value_identifier)
                            .map(|user| (user, row))
                    })
                    .collect::<std::collections::BTreeMap<_, _>>();
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

async fn read_json_response(response: Response) -> Result<Value, CanvasProviderReadError> {
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
    if length.is_some_and(|value| value > PAGE_BYTES) {
        return Err(CanvasProviderReadError::Unavailable);
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|_| CanvasProviderReadError::Unavailable)?;
    if bytes.len() > PAGE_BYTES {
        return Err(CanvasProviderReadError::Unavailable);
    }
    serde_json::from_slice(&bytes).map_err(|_| CanvasProviderReadError::Unavailable)
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
        let header =
            "<https://canvas.test/one>; rel=\"current\", <https://canvas.test/two>; rel=\"next\"";
        assert_eq!(next_link(header), Some("https://canvas.test/two"));
        assert_eq!(next_link("<https://canvas.test/two>; rel=\"last\""), None);
    }
}
