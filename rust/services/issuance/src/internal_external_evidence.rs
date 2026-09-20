//! Declarative external-evidence API execution for internal Applications.
//!
//! Template interpretation is transport-independent. The production transport
//! reuses the DNS-pinned, no-proxy, no-redirect provider client so a template
//! cannot turn evidence collection into an SSRF or credential-forwarding path.

use std::sync::OnceLock;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use http::{HeaderMap, HeaderName, HeaderValue, Method};
use regex::{Captures, Regex};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

use crate::{
    application_template_domain::ApplicationTemplateRecord,
    canvas_award_candidate::python_canonical_json,
    canvas_network_timeout::CanvasNetworkTimeout,
    canvas_operation_http::CanvasOperationHttpClient,
    canvas_provider_http::{is_private_ip, CanvasOriginPolicy},
    internal_application_domain::{python_datetime, ApplicationRecord, EvidenceFactRecord},
    python_value::{python_string, python_truthy},
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ExternalEvidenceApiError {
    #[error("{0}")]
    InvalidConfiguration(String),
    #[error("External evidence API request failed")]
    Transport,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ExternalEvidenceApiCheckResult {
    pub evidence_fact: EvidenceFactRecord,
    pub requirement: Map<String, Value>,
    pub check_id: String,
    pub http_status_code: u16,
    pub expectation_satisfied: bool,
    pub verification_status: String,
    pub response_metadata: Map<String, Value>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ExternalEvidenceHttpRequest {
    pub method: Method,
    pub url: Url,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
    pub timeout_seconds: f64,
    pub allow_private_network: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ExternalEvidenceHttpResponse {
    pub status_code: u16,
    pub body: Vec<u8>,
}

#[async_trait]
pub trait ExternalEvidenceTransport: Send + Sync {
    async fn send(
        &self,
        request: ExternalEvidenceHttpRequest,
    ) -> Result<ExternalEvidenceHttpResponse, ExternalEvidenceApiError>;
}

pub trait ExternalEvidenceSecrets: Send + Sync {
    fn get(&self, name: &str) -> Option<String>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct EnvironmentExternalEvidenceSecrets;

impl ExternalEvidenceSecrets for EnvironmentExternalEvidenceSecrets {
    fn get(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SecureExternalEvidenceTransport;

#[async_trait]
impl ExternalEvidenceTransport for SecureExternalEvidenceTransport {
    async fn send(
        &self,
        request: ExternalEvidenceHttpRequest,
    ) -> Result<ExternalEvidenceHttpResponse, ExternalEvidenceApiError> {
        let policy = CanvasOriginPolicy {
            allow_private_networks: request.allow_private_network,
            allow_http_localhost: request.allow_private_network,
            ..Default::default()
        };
        let origin = request.url.origin().ascii_serialization();
        let (client, _) = CanvasOperationHttpClient::prepare(
            policy,
            CanvasNetworkTimeout::from_seconds(request.timeout_seconds),
            &origin,
        )
        .await
        .map_err(|_| ExternalEvidenceApiError::Transport)?;
        let response = client
            .send(request.method, request.url, request.headers, request.body)
            .await
            .map_err(|_| ExternalEvidenceApiError::Transport)?;
        let status_code = response.response.status().as_u16();
        let body = response
            .bytes()
            .await
            .map_err(|_| ExternalEvidenceApiError::Transport)?;
        Ok(ExternalEvidenceHttpResponse {
            status_code,
            body: body.to_vec(),
        })
    }
}

#[must_use]
pub fn requirement_check_id(requirement: &Map<String, Value>) -> String {
    ["evidence_id", "check_id", "id", "name"]
        .into_iter()
        .find_map(|name| {
            requirement
                .get(name)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
        })
        .unwrap_or_default()
}

#[must_use]
pub fn find_external_api_requirement(
    template: &ApplicationTemplateRecord,
    check_id: &str,
) -> Option<Map<String, Value>> {
    template.evidence_requirements.iter().find_map(|value| {
        let requirement = value.as_object()?;
        let evidence_type = requirement
            .get("evidence_type")
            .and_then(value_string)
            .unwrap_or_default()
            .to_uppercase();
        if !matches!(evidence_type.as_str(), "EXTERNAL_API" | "EXTERNAL_FACT") {
            return None;
        }
        if evidence_type != "EXTERNAL_API" && !requirement.contains_key("api") {
            return None;
        }
        (requirement_check_id(requirement) == check_id).then(|| requirement.clone())
    })
}

#[allow(clippy::too_many_arguments)]
pub async fn execute_external_evidence_api_check(
    application: &ApplicationRecord,
    requirement: &Map<String, Value>,
    inputs: &Map<String, Value>,
    transport: &dyn ExternalEvidenceTransport,
    secrets: &dyn ExternalEvidenceSecrets,
    now: DateTime<Utc>,
    fact_id: String,
) -> Result<ExternalEvidenceApiCheckResult, ExternalEvidenceApiError> {
    let api = requirement
        .get("api")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("External evidence requirement is missing api configuration"))?;
    let check_id = requirement_check_id(requirement);
    if check_id.is_empty() {
        return Err(invalid(
            "External evidence requirement is missing evidence_id",
        ));
    }

    let context = template_context(application, inputs);
    let method_name = api
        .get("method")
        .filter(|value| python_truthy(value))
        .and_then(value_string)
        .unwrap_or_else(|| "POST".to_owned())
        .to_uppercase();
    let method = match method_name.as_str() {
        "GET" => Method::GET,
        "POST" => Method::POST,
        "PUT" => Method::PUT,
        "PATCH" => Method::PATCH,
        _ => {
            return Err(invalid(format!(
                "Unsupported external evidence API method '{method_name}'"
            )))
        }
    };
    let rendered_url = render_template(api.get("url").unwrap_or(&Value::Null), &context);
    let url_text = rendered_url
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid("External evidence API URL is required"))?;
    let allow_private_network = api.get("allow_private_network").is_some_and(python_truthy);
    let mut url = validate_api_url(url_text, allow_private_network)?;

    let timeout_seconds = timeout_seconds(api.get("timeout_seconds"))?;
    let mut headers = mapped_headers(api.get("headers"), &context)?;
    if let Some(secret_headers) = api.get("secret_headers").and_then(Value::as_object) {
        for (header_name, environment_name) in secret_headers {
            if header_name.is_empty() || !python_truthy(environment_name) {
                continue;
            }
            let Some(environment_name) = value_string(environment_name) else {
                continue;
            };
            let Some(secret) = secrets.get(&environment_name) else {
                continue;
            };
            insert_header(&mut headers, header_name, &secret)?;
        }
    }

    let params = render_template(
        api.get("params")
            .filter(|value| python_truthy(value))
            .unwrap_or(&json!({})),
        &context,
    );
    append_query_params(&mut url, &params)?;
    let body_source = if api.contains_key("body") {
        api.get("body").unwrap_or(&Value::Null)
    } else {
        api.get("json").unwrap_or(&Value::Null)
    };
    let body_value = render_template(body_source, &context);
    let body = if method == Method::GET
        || body_value.is_null()
        || matches!(&body_value, Value::String(value) if value.is_empty())
    {
        Vec::new()
    } else if let Value::String(body) = body_value {
        body.into_bytes()
    } else {
        headers
            .entry(http::header::CONTENT_TYPE)
            .or_insert(HeaderValue::from_static("application/json"));
        serde_json::to_vec(&body_value).map_err(|_| ExternalEvidenceApiError::Transport)?
    };

    let response = transport
        .send(ExternalEvidenceHttpRequest {
            method,
            url: url.clone(),
            headers,
            body,
            timeout_seconds,
            allow_private_network,
        })
        .await?;
    let response_json = serde_json::from_slice::<Value>(&response.body)
        .unwrap_or_else(|_| json!({"text": String::from_utf8_lossy(&response.body).into_owned()}));
    let expectation = first_truthy([
        requirement.get("expected_response"),
        requirement.get("response_expectations"),
        requirement.get("expected"),
    ])
    .and_then(Value::as_object)
    .cloned()
    .unwrap_or_default();
    let expectation_satisfied =
        expectations_satisfied(&response_json, response.status_code, &expectation)?;
    let mapping = requirement
        .get("response_mapping")
        .filter(|value| python_truthy(value))
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();

    let provider = first_truthy_value([
        mapping_value(mapping.get("provider"), &response_json, &context),
        requirement.get("provider").cloned(),
        Some(Value::String("external_api".to_owned())),
    ])
    .and_then(|value| value_string(&value))
    .unwrap_or_else(|| "external_api".to_owned());
    let fact_type = first_truthy_value([
        mapping_value(mapping.get("fact_type"), &response_json, &context),
        requirement.get("fact_type").cloned(),
        Some(Value::String(format!("{provider}.external_check"))),
    ])
    .and_then(|value| value_string(&value))
    .unwrap_or_else(|| format!("{provider}.external_check"));
    let subject_from_path = mapping
        .get("subject_id_path")
        .and_then(Value::as_str)
        .and_then(|path| path_value(&response_json, path))
        .cloned();
    let subject_id = first_truthy_value([
        mapping_value(mapping.get("subject_id"), &response_json, &context),
        subject_from_path,
        Some(Value::String(application.applicant_identifier.clone())),
    ])
    .and_then(|value| value_string(&value))
    .unwrap_or_else(|| application.applicant_identifier.clone());

    let mut scope = requirement
        .get("scope")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    scope.extend(mapped_dict(mapping.get("scope"), &response_json, &context));
    let mut assertion = mapped_dict(
        first_truthy([mapping.get("assertion"), mapping.get("assertions")]),
        &response_json,
        &context,
    );
    if assertion.is_empty() {
        assertion.insert(
            "response_matched".to_owned(),
            Value::Bool(expectation_satisfied),
        );
    }

    let mapped_status = mapping
        .get("verification_status_path")
        .and_then(Value::as_str)
        .and_then(|path| path_value(&response_json, path));
    let default_verified_values = [
        json!("verified"),
        json!("valid"),
        json!("passed"),
        json!("pass"),
        Value::Bool(true),
    ];
    let verified_values: &[Value] = mapping
        .get("verification_verified_values")
        .filter(|value| python_truthy(value))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&default_verified_values);
    let verification_status = if let Some(mapped_status) = mapped_status {
        let matches = verified_values.iter().any(|candidate| {
            python_equal(mapped_status, candidate)
                || value_string(mapped_status)
                    .zip(value_string(candidate))
                    .is_some_and(|(left, right)| left.to_lowercase() == right.to_lowercase())
        });
        if expectation_satisfied && matches {
            "VERIFIED"
        } else {
            "UNVERIFIED"
        }
    } else if expectation_satisfied {
        "VERIFIED"
    } else {
        "UNVERIFIED"
    }
    .to_owned();

    let provider_event_path = first_truthy([
        mapping.get("provider_event_id_path"),
        mapping.get("source_event_id_path"),
    ])
    .and_then(Value::as_str);
    let provider_event_id = first_truthy_value([
        mapping_value(mapping.get("provider_event_id"), &response_json, &context),
        provider_event_path.and_then(|path| path_value(&response_json, path).cloned()),
    ])
    .and_then(|value| value_string(&value));
    let response_hash = sha256_hex(python_canonical_json(&response_json).as_bytes());
    let endpoint_host = endpoint_host(&url)?;
    let endpoint_path = url.path().to_owned();
    let verification_method = requirement
        .get("verification_method")
        .filter(|value| python_truthy(value))
        .and_then(value_string)
        .unwrap_or_else(|| "EXTERNAL_API_RESPONSE".to_owned());
    let verification = Map::from_iter([
        ("method".to_owned(), Value::String(verification_method)),
        (
            "status".to_owned(),
            Value::String(verification_status.clone()),
        ),
        (
            "verified_at".to_owned(),
            Value::String(python_datetime(now)),
        ),
        (
            "expectation_satisfied".to_owned(),
            Value::Bool(expectation_satisfied),
        ),
        (
            "http_status_code".to_owned(),
            Value::from(response.status_code),
        ),
    ]);
    let mut source = Map::from_iter([
        (
            "type".to_owned(),
            Value::String("USER_DEFINED_API".to_owned()),
        ),
        ("check_id".to_owned(), Value::String(check_id.clone())),
        (
            "endpoint_host".to_owned(),
            Value::String(endpoint_host.clone()),
        ),
        (
            "endpoint_path".to_owned(),
            Value::String(endpoint_path.clone()),
        ),
        ("http_method".to_owned(), Value::String(method_name)),
        (
            "http_status_code".to_owned(),
            Value::from(response.status_code),
        ),
        (
            "response_hash".to_owned(),
            Value::String(response_hash.clone()),
        ),
    ]);
    if let Some(provider_event_id) = provider_event_id {
        source.insert(
            "provider_event_id".to_owned(),
            Value::String(provider_event_id),
        );
    }
    let logical_key = sha256_hex(
        format!(
            "|{provider}|{fact_type}|{}|{subject_id}",
            python_canonical_json(&Value::Object(scope.clone()))
        )
        .as_bytes(),
    );
    let payload_hash = sha256_hex(
        python_canonical_json(&json!({
            "provider": provider,
            "fact_type": fact_type,
            "scope": scope,
            "assertion": assertion,
            "verification": verification,
        }))
        .as_bytes(),
    );
    let evidence_fact = EvidenceFactRecord {
        id: fact_id,
        organization_id: application.organization_id.clone(),
        application_id: application.id.clone(),
        subject_id,
        provider,
        fact_type,
        scope,
        assertion,
        verification,
        source,
        requirement_id: None,
        logical_key,
        source_revision: payload_hash.clone(),
        payload_hash,
        observed_at: now,
        effective_at: Some(now),
        superseded_fact_id: None,
        created_at: now,
    };
    let response_metadata = Map::from_iter([
        (
            "http_status_code".to_owned(),
            Value::from(response.status_code),
        ),
        ("response_hash".to_owned(), Value::String(response_hash)),
        ("endpoint_host".to_owned(), Value::String(endpoint_host)),
        ("endpoint_path".to_owned(), Value::String(endpoint_path)),
    ]);
    Ok(ExternalEvidenceApiCheckResult {
        evidence_fact,
        requirement: requirement.clone(),
        check_id,
        http_status_code: response.status_code,
        expectation_satisfied,
        verification_status,
        response_metadata,
    })
}

fn invalid(message: impl Into<String>) -> ExternalEvidenceApiError {
    ExternalEvidenceApiError::InvalidConfiguration(message.into())
}

fn placeholder() -> &'static Regex {
    static PLACEHOLDER: OnceLock<Regex> = OnceLock::new();
    PLACEHOLDER.get_or_init(|| Regex::new(r"\{\{\s*([^{}]+?)\s*\}\}").expect("placeholder regex"))
}

fn template_context(application: &ApplicationRecord, inputs: &Map<String, Value>) -> Value {
    json!({
        "organization_id": application.organization_id,
        "application": {
            "id": application.id,
            "organization_id": application.organization_id,
            "application_template_id": application.application_template_id,
            "applicant_identifier": application.applicant_identifier,
            "form_data": application.form_data,
            "integration_context": application.integration_context,
        },
        "inputs": inputs,
    })
}

fn render_template(value: &Value, context: &Value) -> Value {
    match value {
        Value::Object(values) => Value::Object(
            values
                .iter()
                .map(|(name, value)| (name.clone(), render_template(value, context)))
                .collect(),
        ),
        Value::Array(values) => Value::Array(
            values
                .iter()
                .map(|value| render_template(value, context))
                .collect(),
        ),
        Value::String(template) => {
            let expression = placeholder();
            if let Some(captures) = expression.captures(template) {
                if captures
                    .get(0)
                    .is_some_and(|matched| matched.as_str() == template)
                {
                    return captures
                        .get(1)
                        .and_then(|path| path_value(context, path.as_str()))
                        .cloned()
                        .unwrap_or_else(|| Value::String(String::new()));
                }
            }
            Value::String(
                expression
                    .replace_all(template, |captures: &Captures<'_>| {
                        captures
                            .get(1)
                            .and_then(|path| path_value(context, path.as_str()))
                            .and_then(python_string)
                            .unwrap_or_default()
                    })
                    .into_owned(),
            )
        }
        other => other.clone(),
    }
}

fn path_value<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    let original = path.trim();
    if original.is_empty() {
        return None;
    }
    let normalized = original
        .strip_prefix("$.")
        .or_else(|| {
            original
                .strip_prefix('$')
                .map(|value| value.trim_start_matches('.'))
        })
        .unwrap_or(original);
    let mut current = root;
    for segment in normalized.split('.').filter(|segment| !segment.is_empty()) {
        current = match current {
            Value::Object(values) => values.get(segment)?,
            Value::Array(values) => {
                let index = segment.parse::<isize>().ok()?;
                let index = if index < 0 {
                    isize::try_from(values.len()).ok()?.checked_add(index)?
                } else {
                    index
                };
                values.get(usize::try_from(index).ok()?)?
            }
            _ => return None,
        };
    }
    (!current.is_null()).then_some(current)
}

fn mapping_value(spec: Option<&Value>, response: &Value, context: &Value) -> Option<Value> {
    let spec = spec?;
    match spec {
        Value::Object(values) if values.contains_key("path") => {
            let path = values
                .get("path")
                .and_then(value_string)
                .unwrap_or_default();
            path_value(response, &path)
                .cloned()
                .or_else(|| values.get("default").cloned())
        }
        Value::Object(values) if values.contains_key("template") => values
            .get("template")
            .map(|template| render_template(template, context)),
        Value::Object(values) if values.contains_key("value") => values.get("value").cloned(),
        Value::Object(values) => Some(Value::Object(
            values
                .iter()
                .map(|(name, value)| {
                    (
                        name.clone(),
                        mapping_value(Some(value), response, context).unwrap_or(Value::Null),
                    )
                })
                .collect(),
        )),
        Value::Array(values) => Some(Value::Array(
            values
                .iter()
                .map(|value| mapping_value(Some(value), response, context).unwrap_or(Value::Null))
                .collect(),
        )),
        Value::String(path) if path.starts_with('$') => path_value(response, path).cloned(),
        Value::String(template) if template.contains("{{") => Some(render_template(spec, context)),
        _ => Some(spec.clone()),
    }
}

fn mapped_dict(mapping: Option<&Value>, response: &Value, context: &Value) -> Map<String, Value> {
    let Some(mapping) = mapping.and_then(Value::as_object) else {
        return Map::new();
    };
    mapping
        .iter()
        .filter_map(|(name, spec)| {
            mapping_value(Some(spec), response, context)
                .filter(|value| !value.is_null())
                .map(|value| (name.clone(), value))
        })
        .collect()
}

fn response_path_value(response: &Value, status_code: u16, path: &str) -> Option<Value> {
    let normalized = path.trim();
    if normalized == "status_code" {
        return Some(Value::from(status_code));
    }
    if normalized.starts_with("body.") || normalized.starts_with("$.body.") {
        return path_value(&json!({"body": response}), normalized).cloned();
    }
    path_value(response, normalized).cloned()
}

fn condition_satisfied(response: &Value, status_code: u16, condition: &Value) -> bool {
    let Some(condition) = condition.as_object() else {
        return python_truthy(condition);
    };
    if let Some(items) = condition.get("all") {
        return items.as_array().is_some_and(|items| {
            items
                .iter()
                .all(|item| condition_satisfied(response, status_code, item))
        });
    }
    if let Some(items) = condition.get("any") {
        return items.as_array().is_some_and(|items| {
            items
                .iter()
                .any(|item| condition_satisfied(response, status_code, item))
        });
    }
    if let Some(inner) = condition.get("not") {
        return !condition_satisfied(response, status_code, inner);
    }
    let Some(path) = condition
        .get("path")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    else {
        return false;
    };
    let actual = response_path_value(response, status_code, path);
    let operator = first_truthy([condition.get("op"), condition.get("operator")])
        .and_then(value_string)
        .unwrap_or_else(|| {
            if condition.contains_key("value") {
                "eq".to_owned()
            } else {
                "exists".to_owned()
            }
        })
        .to_lowercase();
    let expected = condition.get("value").unwrap_or(&Value::Null);
    match operator.as_str() {
        "exists" | "present" => actual.is_some(),
        "truthy" | "true" => actual.as_ref().is_some_and(python_truthy),
        "falsy" | "false" => !actual.as_ref().is_some_and(python_truthy),
        "eq" | "equals" | "==" => actual
            .as_ref()
            .is_some_and(|actual| python_equal(actual, expected)),
        "neq" | "not_equals" | "!=" => actual
            .as_ref()
            .is_none_or(|actual| !python_equal(actual, expected)),
        ">=" | "gte" | "gt_eq" | "min" => numeric_pair(actual.as_ref(), expected)
            .is_some_and(|(actual, expected)| actual >= expected),
        ">" | "gt" => numeric_pair(actual.as_ref(), expected)
            .is_some_and(|(actual, expected)| actual > expected),
        "<=" | "lte" | "lt_eq" | "max" => numeric_pair(actual.as_ref(), expected)
            .is_some_and(|(actual, expected)| actual <= expected),
        "<" | "lt" => numeric_pair(actual.as_ref(), expected)
            .is_some_and(|(actual, expected)| actual < expected),
        "in" => expected.as_array().is_some_and(|values| {
            actual
                .as_ref()
                .is_some_and(|actual| values.iter().any(|value| python_equal(actual, value)))
        }),
        "contains" => match actual.as_ref() {
            Some(Value::Array(values)) => values.iter().any(|value| python_equal(value, expected)),
            Some(Value::String(value)) => {
                value_string(expected).is_some_and(|expected| value.contains(&expected))
            }
            _ => false,
        },
        _ => false,
    }
}

fn expectations_satisfied(
    response: &Value,
    status_code: u16,
    expectation: &Map<String, Value>,
) -> Result<bool, ExternalEvidenceApiError> {
    let statuses = first_truthy([expectation.get("status_codes"), expectation.get("status")]);
    let status_matches = match statuses {
        None => (200..300).contains(&status_code),
        Some(Value::Array(values)) => values.iter().any(|value| {
            integer_value(value).is_some_and(|candidate| candidate == i64::from(status_code))
        }),
        Some(value) => {
            integer_value(value).is_some_and(|candidate| candidate == i64::from(status_code))
        }
    };
    if !status_matches {
        return Ok(false);
    }
    let condition = first_truthy([
        expectation.get("json"),
        expectation.get("conditions"),
        expectation.get("body"),
    ]);
    Ok(condition.is_none_or(|condition| condition_satisfied(response, status_code, condition)))
}

fn validate_api_url(
    value: &str,
    allow_private_network: bool,
) -> Result<Url, ExternalEvidenceApiError> {
    let url = Url::parse(value).map_err(|_| invalid("External evidence API URL must use https"))?;
    if !matches!(url.scheme(), "https" | "http") {
        return Err(invalid("External evidence API URL must use https"));
    }
    let host = url
        .host_str()
        .ok_or_else(|| invalid("External evidence API URL must include a host"))?;
    let local_http = url.scheme() == "http"
        && matches!(
            host.to_lowercase().as_str(),
            "localhost" | "127.0.0.1" | "::1"
        );
    if url.scheme() != "https" && !local_http {
        return Err(invalid(
            "External evidence API URL must use https outside localhost development",
        ));
    }
    if !allow_private_network
        && (host.eq_ignore_ascii_case("localhost")
            || host.to_lowercase().ends_with(".local")
            || host.parse::<std::net::IpAddr>().is_ok_and(is_private_ip))
    {
        return Err(invalid(
            "External evidence API URL cannot target local/private hosts",
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(invalid(
            "External evidence API URL cannot include user information",
        ));
    }
    Ok(url)
}

fn timeout_seconds(value: Option<&Value>) -> Result<f64, ExternalEvidenceApiError> {
    let seconds = value
        .filter(|value| python_truthy(value))
        .map(float_value)
        .transpose()?
        .unwrap_or(10.0);
    if seconds.is_nan() {
        return Ok(1.0);
    }
    Ok(seconds.clamp(1.0, 20.0))
}

fn float_value(value: &Value) -> Result<f64, ExternalEvidenceApiError> {
    match value {
        Value::Bool(value) => Ok(if *value { 1.0 } else { 0.0 }),
        Value::Number(value) => value
            .as_f64()
            .ok_or_else(|| invalid("External evidence API timeout is invalid")),
        Value::String(value) => value
            .parse()
            .map_err(|_| invalid("External evidence API timeout is invalid")),
        _ => Err(invalid("External evidence API timeout is invalid")),
    }
}

fn mapped_headers(
    value: Option<&Value>,
    context: &Value,
) -> Result<HeaderMap, ExternalEvidenceApiError> {
    let rendered = mapped_dict(value, &json!({}), context);
    let mut headers = HeaderMap::new();
    for (name, value) in rendered {
        let Some(value) = value_string(&value) else {
            return Err(ExternalEvidenceApiError::Transport);
        };
        insert_header(&mut headers, &name, &value)?;
    }
    Ok(headers)
}

fn insert_header(
    headers: &mut HeaderMap,
    name: &str,
    value: &str,
) -> Result<(), ExternalEvidenceApiError> {
    let name =
        HeaderName::from_bytes(name.as_bytes()).map_err(|_| ExternalEvidenceApiError::Transport)?;
    let value = HeaderValue::from_str(value).map_err(|_| ExternalEvidenceApiError::Transport)?;
    headers.insert(name, value);
    Ok(())
}

fn append_query_params(url: &mut Url, params: &Value) -> Result<(), ExternalEvidenceApiError> {
    let Some(params) = params.as_object() else {
        if params.is_null() {
            return Ok(());
        }
        return Err(ExternalEvidenceApiError::Transport);
    };
    if params.is_empty() {
        return Ok(());
    }
    let mut query = url.query_pairs_mut();
    for (name, value) in params {
        if let Value::Array(values) = value {
            for value in values {
                let rendered = value_string(value).ok_or(ExternalEvidenceApiError::Transport)?;
                query.append_pair(name, &rendered);
            }
        } else {
            let rendered = value_string(value).ok_or(ExternalEvidenceApiError::Transport)?;
            query.append_pair(name, &rendered);
        }
    }
    Ok(())
}

fn value_string(value: &Value) -> Option<String> {
    python_string(value)
}

fn first_truthy<const N: usize>(values: [Option<&Value>; N]) -> Option<&Value> {
    values
        .into_iter()
        .flatten()
        .find(|value| python_truthy(value))
}

fn first_truthy_value<const N: usize>(values: [Option<Value>; N]) -> Option<Value> {
    values.into_iter().flatten().find(python_truthy)
}

fn integer_value(value: &Value) -> Option<i64> {
    match value {
        Value::Bool(value) => Some(i64::from(*value)),
        Value::Number(value) => value
            .as_i64()
            .or_else(|| value.as_f64().map(|value| value as i64)),
        Value::String(value) => value.parse().ok(),
        _ => None,
    }
}

fn numeric_value(value: &Value) -> Option<f64> {
    match value {
        Value::Bool(_) => None,
        Value::Number(value) => value.as_f64(),
        Value::String(value) => value.parse().ok(),
        _ => None,
    }
}

fn numeric_pair(actual: Option<&Value>, expected: &Value) -> Option<(f64, f64)> {
    Some((numeric_value(actual?)?, numeric_value(expected)?))
}

fn python_equal(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Number(left), Value::Number(right)) => left.as_f64() == right.as_f64(),
        (Value::Bool(left), Value::Number(right)) => {
            Some(if *left { 1.0 } else { 0.0 }) == right.as_f64()
        }
        (Value::Number(left), Value::Bool(right)) => {
            left.as_f64() == Some(if *right { 1.0 } else { 0.0 })
        }
        _ => left == right,
    }
}

fn endpoint_host(url: &Url) -> Result<String, ExternalEvidenceApiError> {
    url.host_str()
        .ok_or_else(|| invalid("External evidence API URL must include a host"))?;
    Ok(url[url::Position::BeforeHost..url::Position::AfterPort].to_owned())
}

fn sha256_hex(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, sync::Mutex};

    use chrono::TimeZone;

    use super::*;

    #[derive(Debug)]
    struct FakeTransport {
        response: ExternalEvidenceHttpResponse,
        request: Mutex<Option<ExternalEvidenceHttpRequest>>,
    }

    #[async_trait]
    impl ExternalEvidenceTransport for FakeTransport {
        async fn send(
            &self,
            request: ExternalEvidenceHttpRequest,
        ) -> Result<ExternalEvidenceHttpResponse, ExternalEvidenceApiError> {
            *self.request.lock().expect("request lock") = Some(request);
            Ok(self.response.clone())
        }
    }

    #[derive(Debug)]
    struct FakeSecrets(BTreeMap<String, String>);

    impl ExternalEvidenceSecrets for FakeSecrets {
        fn get(&self, name: &str) -> Option<String> {
            self.0.get(name).cloned()
        }
    }

    fn application() -> ApplicationRecord {
        let now = Utc
            .with_ymd_and_hms(2026, 9, 20, 1, 2, 3)
            .single()
            .expect("timestamp");
        ApplicationRecord {
            id: "application-passport".to_owned(),
            organization_id: "org-passport".to_owned(),
            application_template_id: "application-template-passport".to_owned(),
            applicant_identifier: "ada@example.com".to_owned(),
            form_data: json!({
                "passport_number": "X1234567",
                "birth_date": "1990-01-01",
            })
            .as_object()
            .expect("object")
            .clone(),
            evidence_submissions: Vec::new(),
            integration_context: Map::new(),
            status: crate::internal_application_domain::ApplicationStatus::Pending,
            review_notes: None,
            reviewer_id: None,
            rejection_reason: None,
            derived_claims: Map::new(),
            created_at: now,
            updated_at: now,
            submitted_at: now,
            reviewed_at: None,
            expires_at: now,
            issuance_transaction_id: None,
            credential_id: None,
        }
    }

    fn requirement() -> Map<String, Value> {
        json!({
            "evidence_id": "passport-document-check",
            "evidence_type": "EXTERNAL_API",
            "provider": "passport_verifier",
            "fact_type": "passport.document_verified",
            "scope": {"document_type": "passport"},
            "api": {
                "method": "POST",
                "url": "https://verify.example.test/passports",
                "headers": {"content-type": "application/json"},
                "secret_headers": {"authorization": "PASSPORT_VERIFY_API_TOKEN"},
                "body": {
                    "passport_number": "{{application.form_data.passport_number}}",
                    "birth_date": "{{application.form_data.birth_date}}",
                },
            },
            "expected_response": {
                "status_codes": [200],
                "json": {"all": [
                    {"path": "$.status", "op": "eq", "value": "verified"},
                    {"path": "$.checks.passive_auth_valid", "op": "eq", "value": true},
                    {"path": "$.biometric.face_match_score", "op": ">=", "value": 0.85}
                ]}
            },
            "response_mapping": {
                "provider_event_id_path": "$.id",
                "verification_status_path": "$.status",
                "verification_verified_values": ["verified"],
                "scope": {"issuing_country": "$.document.issuing_country"},
                "assertion": {
                    "passive_auth_valid": "$.checks.passive_auth_valid",
                    "face_match_score": "$.biometric.face_match_score",
                    "document_not_expired": "$.document.not_expired"
                }
            },
            "verification_method": "EXTERNAL_API_RESPONSE",
            "auto_issue_on_permit": true
        })
        .as_object()
        .expect("object")
        .clone()
    }

    #[tokio::test]
    async fn executes_frozen_passport_mapping_without_exposing_secret_metadata() {
        let transport = FakeTransport {
            response: ExternalEvidenceHttpResponse {
                status_code: 200,
                body: serde_json::to_vec(&json!({
                    "id": "passport-event-1",
                    "status": "verified",
                    "checks": {"passive_auth_valid": true},
                    "biometric": {"face_match_score": 0.91},
                    "document": {"issuing_country": "US", "not_expired": true}
                }))
                .expect("response"),
            },
            request: Mutex::new(None),
        };
        let now = Utc
            .with_ymd_and_hms(2026, 9, 20, 2, 3, 4)
            .single()
            .expect("timestamp");
        let result = execute_external_evidence_api_check(
            &application(),
            &requirement(),
            &Map::new(),
            &transport,
            &FakeSecrets(BTreeMap::from([(
                "PASSPORT_VERIFY_API_TOKEN".to_owned(),
                "Bearer secret-token".to_owned(),
            )])),
            now,
            "fact-1".to_owned(),
        )
        .await
        .expect("check result");
        assert!(result.expectation_satisfied);
        assert_eq!(result.verification_status, "VERIFIED");
        assert_eq!(result.evidence_fact.provider, "passport_verifier");
        assert_eq!(
            result.evidence_fact.scope,
            json!({"document_type": "passport", "issuing_country": "US"})
                .as_object()
                .expect("scope")
                .clone()
        );
        assert_eq!(result.evidence_fact.assertion["face_match_score"], 0.91);
        assert_eq!(
            result.evidence_fact.source["provider_event_id"],
            "passport-event-1"
        );
        assert!(!serde_json::to_string(&result.response_metadata)
            .expect("metadata")
            .contains("secret-token"));

        let request = transport
            .request
            .lock()
            .expect("request lock")
            .clone()
            .expect("request");
        assert_eq!(request.method, Method::POST);
        assert_eq!(
            request.url.as_str(),
            "https://verify.example.test/passports"
        );
        assert_eq!(request.headers["authorization"], "Bearer secret-token");
        assert_eq!(
            serde_json::from_slice::<Value>(&request.body).expect("JSON request"),
            json!({"passport_number": "X1234567", "birth_date": "1990-01-01"})
        );
    }

    #[tokio::test]
    async fn failed_expectation_creates_an_unverified_fact() {
        let transport = FakeTransport {
            response: ExternalEvidenceHttpResponse {
                status_code: 200,
                body: serde_json::to_vec(&json!({
                    "status": "verified",
                    "checks": {"passive_auth_valid": true},
                    "biometric": {"face_match_score": 0.4},
                    "document": {"issuing_country": "US", "not_expired": true}
                }))
                .expect("response"),
            },
            request: Mutex::new(None),
        };
        let result = execute_external_evidence_api_check(
            &application(),
            &requirement(),
            &Map::new(),
            &transport,
            &FakeSecrets(BTreeMap::new()),
            Utc::now(),
            "fact-2".to_owned(),
        )
        .await
        .expect("check result");
        assert!(!result.expectation_satisfied);
        assert_eq!(result.verification_status, "UNVERIFIED");
        assert_eq!(result.evidence_fact.verification["status"], "UNVERIFIED");
    }

    #[test]
    fn template_paths_conditions_and_mapping_preserve_python_shapes() {
        let context = json!({"items": [1, {"value": true}], "missing": null});
        assert_eq!(render_template(&json!("{{items.1.value}}"), &context), true);
        assert_eq!(render_template(&json!("x={{items.0}}"), &context), "x=1");
        assert_eq!(render_template(&json!("{{missing}}"), &context), "");
        let response = json!({"values": ["a", "b"], "score": "0.9"});
        assert!(condition_satisfied(
            &response,
            201,
            &json!({"all": [
                {"path": "status_code", "op": "eq", "value": 201},
                {"path": "$.score", "op": ">=", "value": 0.85},
                {"path": "$.values", "op": "contains", "value": "b"}
            ]})
        ));
    }

    #[test]
    fn private_and_insecure_provider_urls_fail_closed() {
        assert!(validate_api_url("http://provider.example/check", true).is_err());
        assert!(validate_api_url("https://127.0.0.1/check", false).is_err());
        assert!(validate_api_url("http://localhost/check", false).is_err());
        assert!(validate_api_url("http://localhost/check", true).is_ok());
        assert!(validate_api_url("https://provider.example/check", false).is_ok());
    }
}
