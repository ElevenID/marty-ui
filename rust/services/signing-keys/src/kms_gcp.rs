//! GCP remote KMS adapter.
use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GcpServiceAccount {
    pub(super) email: String,
}

pub(super) enum GcpAuth {
    WorkloadIdentity,
    ServiceAccount(GcpServiceAccount),
}

pub(super) fn parse_gcp_auth(config: &Value) -> Result<GcpAuth, KmsError> {
    let reference = string(config, "auth_reference").unwrap_or_default();
    match string(config, "auth_mode").unwrap_or("workload_identity") {
        "workload_identity" => {
            if !reference.is_empty() {
                return Err(KmsError::InvalidConfig(
                    "GCP workload identity does not accept a bearer token.".into(),
                ));
            }
            Ok(GcpAuth::WorkloadIdentity)
        }
        "service_account" => {
            if reference.len() > 4096 {
                return Err(KmsError::InvalidConfig(
                    "GCP service account reference is invalid.".into(),
                ));
            }
            let account: GcpServiceAccount = serde_json::from_str(reference).map_err(|_| {
                KmsError::InvalidConfig("GCP service account reference is invalid.".into())
            })?;
            if !valid_gcp_service_account(&account.email) {
                return Err(KmsError::InvalidConfig(
                    "GCP service account reference is invalid.".into(),
                ));
            }
            Ok(GcpAuth::ServiceAccount(account))
        }
        _ => Err(KmsError::InvalidConfig(
            "GCP authentication mode is unsupported.".into(),
        )),
    }
}

pub(super) fn valid_gcp_service_account(email: &str) -> bool {
    email.len() <= 256
        && email.ends_with(".gserviceaccount.com")
        && email.split_once('@').is_some_and(|(name, domain)| {
            !name.is_empty()
                && !domain.is_empty()
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
                && domain
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
        })
}

pub(crate) fn validate_gcp_auth_config(config: &Value) -> Result<(), KmsError> {
    parse_gcp_auth(config).map(|_| ())
}

pub(super) async fn gcp_metadata_token() -> Result<String, KmsError> {
    let host = env::var("GCE_METADATA_HOST")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "metadata.google.internal".into());
    if host
        .chars()
        .any(|character| matches!(character, '/' | '?' | '#' | '@') || character.is_whitespace())
    {
        return Err(KmsError::InvalidConfig(
            "GCP metadata endpoint is invalid.".into(),
        ));
    }
    let endpoint =
        format!("http://{host}/computeMetadata/v1/instance/service-accounts/default/token");
    let parsed = reqwest::Url::parse(&endpoint)
        .map_err(|_| KmsError::InvalidConfig("GCP metadata endpoint is invalid.".into()))?;
    if !matches!(
        parsed.host_str(),
        Some("metadata.google.internal" | "169.254.169.254" | "127.0.0.1" | "localhost" | "::1")
    ) || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port().is_some_and(|port| {
            port != 80 && !matches!(parsed.host_str(), Some("127.0.0.1" | "localhost" | "::1"))
        })
    {
        return Err(KmsError::InvalidConfig(
            "GCP metadata endpoint is invalid.".into(),
        ));
    }
    let client = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| KmsError::Provider("GCP metadata HTTP client is unavailable.".into()))?;
    let response = send_json(
        client
            .get(endpoint)
            .timeout(HTTP_TIMEOUT)
            .header("Metadata-Flavor", "Google"),
    )
    .await
    .map_err(|_| KmsError::Provider("GCP workload token acquisition failed.".into()))?;
    gcp_token_value(response, "access_token")
}

pub(super) async fn gcp_service_account_token_at(
    endpoint: &str,
    account: &GcpServiceAccount,
    source_token: &str,
) -> Result<String, KmsError> {
    let email =
        percent_encoding::utf8_percent_encode(&account.email, percent_encoding::NON_ALPHANUMERIC);
    let response = send_json(
        cloud_http_client()?
            .post(format!(
                "{}/v1/projects/-/serviceAccounts/{email}:generateAccessToken",
                endpoint.trim_end_matches('/')
            ))
            .timeout(HTTP_TIMEOUT)
            .bearer_auth(source_token)
            .json(&json!({"scope": ["https://www.googleapis.com/auth/cloud-platform"]})),
    )
    .await
    .map_err(|_| KmsError::Provider("GCP service account token acquisition failed.".into()))?;
    gcp_token_value(response, "accessToken")
}

pub(super) fn gcp_token_value(response: Value, field: &str) -> Result<String, KmsError> {
    response
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            KmsError::InvalidResponse("GCP identity response omitted access token.".into())
        })
}

pub(super) async fn gcp_access_token(config: &Value) -> Result<String, KmsError> {
    match parse_gcp_auth(config)? {
        GcpAuth::WorkloadIdentity => gcp_metadata_token().await,
        GcpAuth::ServiceAccount(account) => {
            let source_token = gcp_metadata_token().await?;
            gcp_service_account_token_at(
                "https://iamcredentials.googleapis.com",
                &account,
                &source_token,
            )
            .await
        }
    }
}

pub(super) async fn gcp_bearer(
    builder: reqwest::RequestBuilder,
    config: &Value,
) -> Result<reqwest::RequestBuilder, KmsError> {
    Ok(builder.bearer_auth(gcp_access_token(config).await?))
}

pub(super) fn gcp_endpoint(config: &Value) -> &str {
    string(config, "endpoint")
        .filter(|value| !value.is_empty())
        .unwrap_or("https://cloudkms.googleapis.com")
}

pub(crate) fn gcp_key_version_reference(config: &Value) -> Result<&str, KmsError> {
    let reference = required(
        config,
        "key_reference",
        "GCP Cloud KMS requires a version-pinned key reference.",
    )?;
    let parts: Vec<_> = reference.split('/').collect();
    let valid = parts.len() == 10
        && parts[0] == "projects"
        && parts[2] == "locations"
        && parts[4] == "keyRings"
        && parts[6] == "cryptoKeys"
        && parts[8] == "cryptoKeyVersions"
        && [parts[1], parts[3]].iter().all(|value| {
            !value.is_empty()
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
        && [parts[5], parts[7]].iter().all(|value| {
            !value.is_empty()
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        })
        && parts[9].bytes().all(|byte| byte.is_ascii_digit())
        && parts[9].parse::<u64>().is_ok_and(|version| version > 0);
    if !valid {
        return Err(KmsError::InvalidConfig(
            "GCP Cloud KMS key reference must pin a CryptoKeyVersion.".into(),
        ));
    }
    Ok(reference)
}

pub(super) async fn sign_gcp(config: &Value, payload: &[u8]) -> Result<Vec<u8>, KmsError> {
    let endpoint = gcp_endpoint(config);
    let key_reference = gcp_key_version_reference(config)?;
    let algorithm = string(config, "algorithm").unwrap_or("ES256");
    let body = gcp_sign_body(algorithm, payload)?;
    let response = send_json(
        gcp_bearer(
            cloud_http_client()?.post(format!(
                "{}/v1/{key_reference}:asymmetricSign",
                endpoint.trim_end_matches('/')
            )),
            config,
        )
        .await?
        .timeout(HTTP_TIMEOUT)
        .json(&body),
    )
    .await?;
    require_gcp_response_name(&response, key_reference, true)?;
    let signature = response
        .get("signature")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            KmsError::InvalidResponse(
                "GCP Cloud KMS sign response did not include signature".to_string(),
            )
        })?;
    decode_standard(signature, "GCP signature")
}

pub(super) async fn public_key_gcp(config: &Value) -> Result<Value, KmsError> {
    let endpoint = gcp_endpoint(config);
    let key_reference = gcp_key_version_reference(config)?;
    let response = send_json(
        gcp_bearer(
            cloud_http_client()?.get(format!(
                "{}/v1/{key_reference}/publicKey",
                endpoint.trim_end_matches('/')
            )),
            config,
        )
        .await?
        .timeout(HTTP_TIMEOUT),
    )
    .await?;
    require_gcp_response_name(&response, key_reference, false)?;
    let pem = response.get("pem").and_then(Value::as_str).ok_or_else(|| {
        KmsError::InvalidResponse(
            "GCP Cloud KMS public key response did not include pem".to_string(),
        )
    })?;
    let public_jwk = jwk_value(
        public_key_pem_to_jwk(pem).map_err(|error| {
            KmsError::InvalidResponse(format!("GCP returned an invalid public key: {error}"))
        })?,
        key_reference,
    )?;
    Ok(json!({
        "provider": "gcp",
        "key_reference": key_reference,
        "public_key_pem": pem,
        "algorithm": response.get("algorithm").cloned().unwrap_or(Value::Null),
        "protection_level": response.get("protectionLevel").cloned().unwrap_or(Value::Null),
        "public_jwk": public_jwk,
    }))
}

pub(super) fn require_gcp_response_name(
    response: &Value,
    key_reference: &str,
    required: bool,
) -> Result<(), KmsError> {
    let name = response.get("name").and_then(Value::as_str);
    if name == Some(key_reference) || (!required && response.get("name").is_none()) {
        return Ok(());
    }
    Err(KmsError::InvalidResponse(
        "GCP Cloud KMS response key version did not match the pinned key.".to_string(),
    ))
}

pub(super) async fn verify_gcp(config: &Value) -> CapabilityResult {
    let endpoint = gcp_endpoint(config);
    let key_reference = match gcp_key_version_reference(config) {
        Ok(value) => value,
        Err(error) => return CapabilityResult::fail("Key reference", error.to_string()),
    };
    let client = match cloud_http_client() {
        Ok(client) => client,
        Err(error) => return CapabilityResult::fail("Connectivity", error.to_string()),
    };
    let builder = match gcp_bearer(
        client.get(format!(
            "{}/v1/{key_reference}",
            endpoint.trim_end_matches('/')
        )),
        config,
    )
    .await
    {
        Ok(builder) => builder,
        Err(error) => return CapabilityResult::fail("Authentication", error.to_string()),
    };
    verify_http_status(
        builder.timeout(PROBE_TIMEOUT),
        "GCP Cloud KMS",
        |status| match status {
            StatusCode::OK => (
                "Key exists",
                "pass",
                format!("GCP KMS key '{key_reference}' is reachable."),
            ),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => (
                "Authentication",
                "fail",
                "GCP token is invalid or unauthorized.".to_string(),
            ),
            StatusCode::NOT_FOUND => (
                "Key exists",
                "fail",
                "Configured GCP key reference was not found.".to_string(),
            ),
            other => (
                "Connectivity",
                "fail",
                format!("GCP returned HTTP {}.", other.as_u16()),
            ),
        },
    )
    .await
}
