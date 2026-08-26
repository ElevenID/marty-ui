//! Canonical signing-service registration validation.

use std::{env, fs};

use chrono::Utc;
use regex::Regex;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::domain::{service_capabilities, service_type};
use crate::kms::{self, ProviderRequest};

const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);
const SUPPORTED_ALGORITHMS: &[&str] = &["ES256", "ES384", "ES512", "RS256", "EdDSA"];
const KEY_PURPOSES: &[&str] = &[
    "vc_jwt_issuer",
    "mdoc_dsc",
    "x509_doc_signer",
    "holder_binding",
    "presentation_signing",
    "oid4vp_request_signing",
    "vdsnc_signing",
    "csca",
    "jwks_signing",
    "lti_tool_signing",
];

#[derive(Debug, Clone, Deserialize)]
pub struct ValidationRequest {
    #[serde(flatten)]
    pub service_config: serde_json::Map<String, Value>,
    #[serde(default = "default_live_probe")]
    pub live_probe: bool,
}

fn default_live_probe() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidationCheck {
    pub name: String,
    pub status: String,
    pub detail: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidationResult {
    pub ok: bool,
    pub checks: Vec<ValidationCheck>,
    pub validated_at: String,
}

pub async fn validate(request: ValidationRequest) -> ValidationResult {
    let body = Value::Object(request.service_config);
    let payload = normalize_payload(&body);
    let mut checks = Vec::new();
    append_baseline_checks(&payload, &mut checks);
    append_provider_checks(&payload, &mut checks);

    if request.live_probe {
        if payload["protocol"] == "vault-transit-compatible" {
            validate_custom_transit(&payload, &mut checks).await;
        } else if let Some(validator_url) = validator_url(string(&payload, "provider")) {
            validate_bridge(&payload, &validator_url, &mut checks).await;
        } else {
            validate_provider_adapter(&payload, &mut checks).await;
        }
    }

    ValidationResult {
        ok: !checks.iter().any(|check| check.status == "fail"),
        checks,
        validated_at: Utc::now().to_rfc3339(),
    }
}

fn normalize_payload(body: &Value) -> Value {
    let requested_type = trimmed(body.get("service_type")).unwrap_or("custom-transit-compatible");
    let definition = service_type(requested_type);
    let algorithms = string_list(body.get("algorithms"))
        .into_iter()
        .filter(|value| SUPPORTED_ALGORITHMS.contains(&value.as_str()))
        .collect::<Vec<_>>();
    let key_purposes = string_list(body.get("key_purposes"))
        .into_iter()
        .filter(|value| KEY_PURPOSES.contains(&value.as_str()))
        .collect::<Vec<_>>();
    json!({
        "service_type": definition.id,
        "provider": definition.provider,
        "protocol": definition.protocol,
        "connection_fields": definition.connection_fields,
        "name": trimmed(body.get("name")).unwrap_or_default(),
        "endpoint": trimmed(body.get("endpoint")).unwrap_or_default(),
        "region": trimmed(body.get("region")).unwrap_or_default(),
        "mount": trimmed(body.get("mount")).unwrap_or("transit"),
        "namespace": trimmed(body.get("namespace")).unwrap_or_default(),
        "auth_mode": trimmed(body.get("auth_mode")).unwrap_or_default(),
        "auth_reference": trimmed(body.get("auth_reference")).unwrap_or_default(),
        "key_reference": trimmed(body.get("key_reference")).unwrap_or_default(),
        "key_aliases": dedupe(string_list(body.get("key_aliases"))),
        "algorithms": algorithms,
        "key_purposes": key_purposes,
    })
}

fn append_baseline_checks(payload: &Value, checks: &mut Vec<ValidationCheck>) {
    let auth_mode = string(payload, "auth_mode");
    let auth_reference = string(payload, "auth_reference");
    if requires_auth_reference(auth_mode) && auth_reference.is_empty() {
        add(
            checks,
            "Authentication reference",
            "warning",
            "Provide a credential or secret reference for this auth mode.",
            "baseline",
        );
    } else {
        add(
            checks,
            "Authentication reference",
            "pass",
            "Authentication mode and reference look ready.",
            "baseline",
        );
    }

    if string(payload, "key_reference").is_empty() {
        add(
            checks,
            "Key reference",
            "fail",
            "Key reference is required.",
            "baseline",
        );
    } else {
        add(
            checks,
            "Key reference",
            "pass",
            "Key reference was provided.",
            "baseline",
        );
    }

    let algorithms = string_list(payload.get("algorithms"));
    if algorithms.is_empty() {
        add(
            checks,
            "Algorithm coverage",
            "fail",
            "Select at least one supported signing algorithm.",
            "baseline",
        );
    } else {
        add(
            checks,
            "Algorithm coverage",
            "pass",
            format!("Selected algorithms: {}", algorithms.join(", ")),
            "baseline",
        );
    }

    let key_purposes = string_list(payload.get("key_purposes"));
    if !key_purposes.is_empty() && !algorithms.is_empty() {
        let mut incompatible = Vec::new();
        for purpose in &key_purposes {
            for algorithm in &algorithms {
                if !purpose_algorithms(purpose).contains(&algorithm.as_str())
                    && !incompatible.contains(algorithm)
                {
                    incompatible.push(algorithm.clone());
                }
            }
        }
        if incompatible.is_empty() {
            add(
                checks,
                "Key purpose algorithm fit",
                "pass",
                "Selected algorithms are compatible with all declared key purposes.",
                "baseline",
            );
        } else {
            add(
                checks,
                "Key purpose algorithm fit",
                "warning",
                format!(
                    "Algorithm(s) {} may not be suitable for the declared key purpose(s) {}.",
                    incompatible.join(", "),
                    key_purposes.join(", ")
                ),
                "baseline",
            );
        }
    }
}

fn append_provider_checks(payload: &Value, checks: &mut Vec<ValidationCheck>) {
    let provider = string(payload, "provider");
    let service_type_id = string(payload, "service_type");
    let key_reference = string(payload, "key_reference");
    if !key_reference.is_empty() {
        let (pattern, pass, fail) = match provider {
            "aws" => (
                r"^arn:aws:kms:[a-z0-9-]+:\d{12}:key/[A-Za-z0-9-]+$",
                "AWS key reference looks like a valid KMS key ARN.",
                "AWS key reference should be a key ARN (arn:aws:kms:region:account:key/<id>).",
            ),
            "azure" => (
                r"^https://[a-z0-9-]+\.vault\.azure\.net/keys/[A-Za-z0-9-]+(/[A-Za-z0-9-]+)?$",
                "Azure key reference looks like a Key Vault key identifier.",
                "Azure key reference should look like https://<vault>.vault.azure.net/keys/<name>/<version?>.",
            ),
            "gcp" => (
                r"^projects/[a-z0-9-]+/locations/[a-z0-9-]+/keyRings/[A-Za-z0-9_-]+/cryptoKeys/[A-Za-z0-9_-]+(/cryptoKeyVersions/[0-9]+)?$",
                "GCP key reference looks like a Cloud KMS resource path.",
                "GCP key reference should look like projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>[/cryptoKeyVersions/<v>].",
            ),
            _ => ("", "", ""),
        };
        if !pattern.is_empty() {
            if Regex::new(pattern)
                .expect("static provider regex")
                .is_match(key_reference)
            {
                add(checks, "Provider key format", "pass", pass, "provider");
            } else {
                add(checks, "Provider key format", "fail", fail, "provider");
            }
        }
    }

    append_provider_auth(payload, checks);
    let algorithms = string_list(payload.get("algorithms"));
    let supported = service_capabilities()
        .into_iter()
        .find(|capability| capability.service_type_id == service_type_id)
        .map(|capability| capability.capabilities.supported_algorithms)
        .unwrap_or_default();
    if !algorithms.is_empty() && !supported.is_empty() {
        let unsupported = algorithms
            .iter()
            .filter(|algorithm| !supported.contains(&algorithm.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        if unsupported.is_empty() {
            add(checks, "Provider algorithm fit", "pass", format!("Selected algorithms are compatible with expected {provider} signer capabilities."), "provider");
        } else {
            add(
                checks,
                "Provider algorithm fit",
                "fail",
                format!(
                    "Selected algorithms are not supported by {provider}: {}.",
                    unsupported.join(", ")
                ),
                "provider",
            );
        }
    }
}

fn append_provider_auth(payload: &Value, checks: &mut Vec<ValidationCheck>) {
    let provider = string(payload, "provider");
    let auth_mode = string(payload, "auth_mode");
    let has_reference = !string(payload, "auth_reference").is_empty();
    let result = match (provider, auth_mode, has_reference) {
        ("aws", "iam_role", _) => Some(("pass", "IAM role mode selected; ensure gateway runtime identity has kms:Sign permissions.")),
        ("aws", "access_key" | "assume_role", true) => Some(("pass", "Credential reference provided for AWS auth mode.")),
        ("aws", "access_key" | "assume_role", false) => Some(("warning", "Provide an auth reference for access_key/assume_role modes.")),
        ("azure", "managed_identity", _) => Some(("pass", "Managed identity mode selected; ensure Key Vault sign permissions are granted.")),
        ("azure", "client_secret" | "certificate", true) => Some(("pass", "Credential reference provided for Azure auth mode.")),
        ("azure", "client_secret" | "certificate", false) => Some(("warning", "Provide an auth reference for client_secret/certificate modes.")),
        ("gcp", "workload_identity", _) => Some(("pass", "Workload identity selected; ensure cloudkms.cryptoKeyVersions.useToSign permission is granted.")),
        ("gcp", "service_account", true) => Some(("pass", "Service account reference provided for GCP auth mode.")),
        ("gcp", "service_account", false) => Some(("warning", "Provide a service account reference for GCP auth mode.")),
        _ => None,
    };
    if let Some((status, detail)) = result {
        add(checks, "Provider auth policy", status, detail, "provider");
    }
}

async fn validate_provider_adapter(payload: &Value, checks: &mut Vec<ValidationCheck>) {
    match kms::verify(ProviderRequest {
        service_config: payload.clone(),
    })
    .await
    {
        Ok(result) if result.checks.is_empty() => add(
            checks,
            "Provider connectivity",
            if result.ok { "pass" } else { "warning" },
            "Adapter live validation completed.",
            "adapter",
        ),
        Ok(result) => {
            for check in result.checks {
                add(
                    checks,
                    &check.name,
                    &check.status,
                    check.detail,
                    &check.source,
                );
            }
            if let Some(error) = result.error {
                add(
                    checks,
                    "Adapter error",
                    if result.ok { "warning" } else { "fail" },
                    error,
                    "adapter",
                );
            }
        }
        Err(error) => add(
            checks,
            "Provider connectivity",
            "warning",
            format!("Adapter live validation failed unexpectedly: {error}"),
            "adapter",
        ),
    }
}

async fn validate_custom_transit(payload: &Value, checks: &mut Vec<ValidationCheck>) {
    let endpoint = string(payload, "endpoint");
    if endpoint.is_empty() {
        add(
            checks,
            "Provider connectivity",
            "fail",
            "Transit endpoint is required for live validation.",
            "live",
        );
        add(
            checks,
            "Signer capability",
            "warning",
            "Skipped signer capability check because provider endpoint is missing.",
            "live",
        );
        return;
    }
    let mount = string(payload, "mount").trim_matches('/');
    let key_reference = string(payload, "key_reference");
    let token = transit_token(payload);
    let namespace = string(payload, "namespace");
    let mut health = Client::new()
        .get(format!("{}/v1/sys/health", endpoint.trim_end_matches('/')))
        .timeout(PROBE_TIMEOUT);
    if !token.is_empty() {
        health = health.header("X-Vault-Token", &token);
    }
    if !namespace.is_empty() {
        health = health.header("X-Vault-Namespace", namespace);
    }
    match health.send().await {
        Ok(response) => {
            let code = response.status().as_u16();
            if [200, 429, 472, 473, 501].contains(&code) {
                add(
                    checks,
                    "Provider connectivity",
                    "pass",
                    "Connected to transit-compatible provider health endpoint.",
                    "live",
                );
            } else {
                add(
                    checks,
                    "Provider connectivity",
                    "fail",
                    format!("Provider health check returned HTTP {code}."),
                    "live",
                );
            }
        }
        Err(error) => {
            add(
                checks,
                "Provider connectivity",
                "fail",
                format!("Unable to reach provider endpoint: {error}"),
                "live",
            );
            add(
                checks,
                "Provider auth",
                "warning",
                "Skipped provider auth check because connectivity failed.",
                "live",
            );
            add(
                checks,
                "Signer capability",
                "warning",
                "Skipped signer capability check because connectivity failed.",
                "live",
            );
            return;
        }
    }

    let client = Client::new();
    if token.is_empty() {
        add(
            checks,
            "Provider auth",
            "warning",
            "Live auth validation requires a token-based auth mode or managed service token.",
            "live",
        );
    } else {
        let request = client
            .get(format!(
                "{}/v1/auth/token/lookup-self",
                endpoint.trim_end_matches('/')
            ))
            .timeout(PROBE_TIMEOUT)
            .header("X-Vault-Token", &token);
        let request = if namespace.is_empty() {
            request
        } else {
            request.header("X-Vault-Namespace", namespace)
        };
        let status = request
            .send()
            .await
            .map(|response| response.status().as_u16());
        match status {
            Ok(200) => add(
                checks,
                "Provider auth",
                "pass",
                "Token authentication validated against provider.",
                "live",
            ),
            Ok(code) => add(
                checks,
                "Provider auth",
                "fail",
                format!("Provider rejected token authentication (HTTP {code})."),
                "live",
            ),
            Err(error) => add(
                checks,
                "Provider auth",
                "fail",
                format!("Provider auth check failed: {error}"),
                "live",
            ),
        }
    }

    if key_reference.is_empty() {
        add(
            checks,
            "Signer capability",
            "fail",
            "Key reference is required to verify signing capability.",
            "live",
        );
        return;
    }
    let request = client
        .post(format!(
            "{}/v1/{mount}/sign/{key_reference}",
            endpoint.trim_end_matches('/')
        ))
        .timeout(PROBE_TIMEOUT)
        .json(&json!({"input": "dGVzdA=="}));
    let request = if token.is_empty() {
        request
    } else {
        request.header("X-Vault-Token", &token)
    };
    let request = if namespace.is_empty() {
        request
    } else {
        request.header("X-Vault-Namespace", namespace)
    };
    let response = request.send().await;
    match response {
        Ok(response) if response.status().is_success() => {
            let has_signature = response
                .json::<Value>()
                .await
                .ok()
                .and_then(|value| {
                    value
                        .pointer("/data/signature")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                })
                .is_some_and(|value| !value.is_empty());
            add(
                checks,
                "Signer capability",
                if has_signature { "pass" } else { "warning" },
                if has_signature {
                    "Provider signed a test payload with the requested key reference."
                } else {
                    "Provider responded but did not return a signature payload."
                },
                "live",
            );
        }
        Ok(response) if response.status().as_u16() == 404 => add(
            checks,
            "Signer capability",
            "fail",
            "Provider could not find the referenced signing key.",
            "live",
        ),
        Ok(response) if matches!(response.status().as_u16(), 401 | 403) => add(
            checks,
            "Signer capability",
            "fail",
            "Provider denied signing operation for the configured identity.",
            "live",
        ),
        Ok(response) => add(
            checks,
            "Signer capability",
            "warning",
            format!(
                "Provider sign check returned HTTP {}.",
                response.status().as_u16()
            ),
            "live",
        ),
        Err(error) => add(
            checks,
            "Signer capability",
            "warning",
            format!("Provider sign check failed: {error}"),
            "live",
        ),
    }
}

async fn validate_bridge(payload: &Value, validator_url: &str, checks: &mut Vec<ValidationCheck>) {
    let client = Client::new();
    let auth_reference = string(payload, "auth_reference");
    let mut health_request = client
        .get(format!("{}/health", validator_url.trim_end_matches('/')))
        .timeout(PROBE_TIMEOUT)
        .header("Accept", "application/json");
    if !auth_reference.is_empty() {
        health_request = health_request.header("X-Auth-Reference", auth_reference);
    }
    let health = match health_request.send().await {
        Ok(response) => response,
        Err(error) => {
            add(
                checks,
                "Provider connectivity",
                "warning",
                format!("Could not reach provider validator bridge: {error}"),
                "live",
            );
            add(
                checks,
                "Provider auth",
                "warning",
                "Skipped provider auth check because validator probe failed.",
                "live",
            );
            add(
                checks,
                "Signer capability",
                "warning",
                "Skipped signer capability check because validator probe failed.",
                "live",
            );
            return;
        }
    };
    if health.status().as_u16() != 200 {
        let detail = format!(
            "Validator health probe returned HTTP {}.",
            health.status().as_u16()
        );
        append_bridge_failure(checks, &detail);
        return;
    }
    let validation_payload = json!({
        "service_type": payload.get("service_type"),
        "provider": payload.get("provider"),
        "region": payload.get("region"),
        "endpoint": payload.get("endpoint"),
        "auth_mode": payload.get("auth_mode"),
        "auth_reference": auth_reference,
        "key_reference": payload.get("key_reference"),
        "algorithms": payload.get("algorithms"),
    });
    let mut request = client
        .post(format!(
            "{}/v1/signing/validate",
            validator_url.trim_end_matches('/')
        ))
        .timeout(PROBE_TIMEOUT)
        .header("Accept", "application/json")
        .json(&validation_payload);
    if !auth_reference.is_empty() {
        request = request.header("X-Auth-Reference", auth_reference);
    }
    match request.send().await {
        Ok(response) if response.status().as_u16() == 200 => {
            let body = response.json::<Value>().await.unwrap_or_default();
            if body.get("ok").and_then(Value::as_bool) == Some(true) {
                add(
                    checks,
                    "Provider connectivity",
                    "pass",
                    "Connected to provider validator bridge.",
                    "live",
                );
                add(
                    checks,
                    "Provider auth",
                    "pass",
                    "Validator bridge reported provider authentication success.",
                    "live",
                );
                add(
                    checks,
                    "Signer capability",
                    "pass",
                    "Validator bridge completed a remote sign-capability probe.",
                    "live",
                );
            } else {
                append_bridge_failure(
                    checks,
                    body.get("detail")
                        .and_then(Value::as_str)
                        .unwrap_or("Validator returned a non-success response payload."),
                );
            }
        }
        Ok(response) => append_bridge_failure(
            checks,
            &format!(
                "Validator sign-capability probe returned HTTP {}.",
                response.status().as_u16()
            ),
        ),
        Err(error) => append_bridge_failure(
            checks,
            &format!("Could not reach provider validator bridge: {error}"),
        ),
    }
}

fn append_bridge_failure(checks: &mut Vec<ValidationCheck>, detail: &str) {
    add(
        checks,
        "Provider connectivity",
        "warning",
        "Provider validator bridge is reachable but validation did not succeed.",
        "live",
    );
    add(checks, "Provider auth", "warning", detail, "live");
    add(checks, "Signer capability", "warning", detail, "live");
}

fn validator_url(provider: &str) -> Option<String> {
    let name = match provider {
        "aws" => "AWS_KMS_VALIDATOR_URL",
        "azure" => "AZURE_KEY_VAULT_VALIDATOR_URL",
        "gcp" => "GCP_CLOUD_KMS_VALIDATOR_URL",
        _ => return None,
    };
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn transit_token(payload: &Value) -> String {
    match string(payload, "auth_mode") {
        "service_token" => secret_value("BAO_TOKEN")
            .or_else(|| secret_value("OPENBAO_SERVICE_TOKEN"))
            .unwrap_or_default(),
        "token" | "api_key" | "custom" => string(payload, "auth_reference").to_string(),
        _ => String::new(),
    }
}

fn secret_value(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .or_else(|| {
            let path = env::var(format!("{name}_FILE")).ok()?;
            fs::read_to_string(path)
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        })
}

fn add(
    checks: &mut Vec<ValidationCheck>,
    name: &str,
    status: &str,
    detail: impl Into<String>,
    source: &str,
) {
    checks.push(ValidationCheck {
        name: name.to_string(),
        status: status.to_string(),
        detail: detail.into(),
        source: source.to_string(),
    });
}

fn requires_auth_reference(mode: &str) -> bool {
    matches!(
        mode,
        "token"
            | "approle"
            | "access_key"
            | "client_secret"
            | "certificate"
            | "service_account"
            | "api_key"
    )
}

fn purpose_algorithms(purpose: &str) -> &'static [&'static str] {
    match purpose {
        "mdoc_dsc" | "vdsnc_signing" => &["ES256", "ES384", "EdDSA"],
        "holder_binding" | "presentation_signing" => &["ES256", "EdDSA"],
        "oid4vp_request_signing" => &["ES256"],
        "lti_tool_signing" => &["RS256"],
        _ => SUPPORTED_ALGORITHMS,
    }
}

fn trimmed(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn string<'a>(value: &'a Value, name: &str) -> &'a str {
    value.get(name).and_then(Value::as_str).unwrap_or_default()
}

fn string_list(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
}

fn dedupe(values: Vec<String>) -> Vec<String> {
    let mut result = Vec::new();
    for value in values {
        if !result.contains(&value) {
            result.push(value);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn malformed_provider_configuration_fails_closed() {
        let result = validate(ValidationRequest {
            service_config: serde_json::Map::from_iter([(
                "service_type".into(),
                Value::String("aws-kms".into()),
            )]),
            live_probe: false,
        })
        .await;
        assert!(!result.ok);
        assert!(result
            .checks
            .iter()
            .any(|check| check.name == "Key reference" && check.status == "fail"));
        assert!(result
            .checks
            .iter()
            .any(|check| check.name == "Algorithm coverage" && check.status == "fail"));
    }
}
