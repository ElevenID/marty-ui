//! AZURE remote KMS adapter.
use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AzureManagedIdentity {
    pub(super) client_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AzureClientSecret {
    pub(super) tenant_id: String,
    pub(super) client_id: String,
    pub(super) client_secret: String,
}

pub(super) enum AzureAuth {
    ManagedIdentity(Option<String>),
    ClientSecret(AzureClientSecret),
}

pub(super) fn valid_azure_tenant(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.contains("..")
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
}

pub(super) fn parse_azure_auth(config: &Value) -> Result<AzureAuth, KmsError> {
    let reference = string(config, "auth_reference").unwrap_or_default();
    match string(config, "auth_mode").unwrap_or("managed_identity") {
        "managed_identity" => {
            if reference.is_empty() {
                return Ok(AzureAuth::ManagedIdentity(None));
            }
            let identity: AzureManagedIdentity = serde_json::from_str(reference).map_err(|_| {
                KmsError::InvalidConfig("Azure managed identity reference is invalid.".into())
            })?;
            if uuid::Uuid::parse_str(&identity.client_id).is_err() {
                return Err(KmsError::InvalidConfig(
                    "Azure managed identity client ID is invalid.".into(),
                ));
            }
            Ok(AzureAuth::ManagedIdentity(Some(identity.client_id)))
        }
        "client_secret" => {
            if reference.len() > 16_384 {
                return Err(KmsError::InvalidConfig(
                    "Azure client credential is invalid.".into(),
                ));
            }
            let credential: AzureClientSecret = serde_json::from_str(reference).map_err(|_| {
                KmsError::InvalidConfig("Azure client credential is invalid.".into())
            })?;
            if !valid_azure_tenant(&credential.tenant_id)
                || uuid::Uuid::parse_str(&credential.client_id).is_err()
                || credential.client_secret.is_empty()
            {
                return Err(KmsError::InvalidConfig(
                    "Azure client credential is invalid.".into(),
                ));
            }
            Ok(AzureAuth::ClientSecret(credential))
        }
        "certificate" => Err(KmsError::InvalidConfig(
            "Azure certificate authentication requires a remote client-assertion signer.".into(),
        )),
        _ => Err(KmsError::InvalidConfig(
            "Azure authentication mode is unsupported.".into(),
        )),
    }
}

pub(crate) fn validate_azure_auth_config(config: &Value) -> Result<(), KmsError> {
    parse_azure_auth(config).map(|_| ())
}

pub(super) async fn azure_access_token(config: &Value) -> Result<String, KmsError> {
    let resource = azure_token_resource(config)?;
    match parse_azure_auth(config)? {
        AzureAuth::ManagedIdentity(client_id) => {
            let endpoint = env::var("IDENTITY_ENDPOINT")
                .ok()
                .filter(|value| !value.is_empty());
            let header = env::var("IDENTITY_HEADER")
                .ok()
                .filter(|value| !value.is_empty());
            match (endpoint, header) {
                (Some(endpoint), Some(header)) => {
                    let parsed = reqwest::Url::parse(&endpoint).map_err(|_| {
                        KmsError::InvalidConfig(
                            "Azure managed identity endpoint is invalid.".into(),
                        )
                    })?;
                    if parsed.scheme() != "http"
                        || !matches!(
                            parsed.host_str(),
                            Some("127.0.0.1" | "localhost" | "::1" | "169.254.169.254")
                        )
                        || !parsed.username().is_empty()
                        || parsed.password().is_some()
                        || parsed.query().is_some()
                        || parsed.fragment().is_some()
                    {
                        return Err(KmsError::InvalidConfig(
                            "Azure managed identity endpoint is invalid.".into(),
                        ));
                    }
                    azure_managed_token(&endpoint, Some(&header), client_id.as_deref(), resource)
                        .await
                }
                (None, None) => {
                    azure_managed_token(
                        "http://169.254.169.254/metadata/identity/oauth2/token",
                        None,
                        client_id.as_deref(),
                        resource,
                    )
                    .await
                }
                _ => Err(KmsError::InvalidConfig(
                    "Azure managed identity environment is incomplete.".into(),
                )),
            }
        }
        AzureAuth::ClientSecret(credential) => {
            let endpoint = format!(
                "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
                credential.tenant_id
            );
            azure_client_secret_token(&endpoint, &credential, resource).await
        }
    }
}

pub(super) fn azure_token_resource(config: &Value) -> Result<&'static str, KmsError> {
    validate_cloud_endpoint(config, "azure")?;
    let endpoint = required(config, "endpoint", "Azure Key Vault endpoint is required.")?;
    let parsed = reqwest::Url::parse(endpoint)
        .map_err(|_| KmsError::InvalidConfig("Azure Key Vault endpoint is invalid.".into()))?;
    Ok(
        if parsed
            .host_str()
            .is_some_and(|host| host.ends_with(".managedhsm.azure.net"))
        {
            "https://managedhsm.azure.net"
        } else {
            "https://vault.azure.net"
        },
    )
}

pub(super) async fn azure_managed_token(
    endpoint: &str,
    header: Option<&str>,
    client_id: Option<&str>,
    resource: &str,
) -> Result<String, KmsError> {
    let client = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| KmsError::Provider("Azure identity HTTP client is unavailable.".into()))?;
    let version = if header.is_some() {
        "2019-08-01"
    } else {
        "2018-02-01"
    };
    let mut request = client
        .get(endpoint)
        .timeout(HTTP_TIMEOUT)
        .query(&[("api-version", version), ("resource", resource)]);
    if let Some(header) = header {
        request = request.header("X-IDENTITY-HEADER", header);
    } else {
        request = request.header("Metadata", "true");
    }
    if let Some(client_id) = client_id {
        request = request.query(&[("client_id", client_id)]);
    }
    azure_token_value(send_json(request).await.map_err(|_| {
        KmsError::Provider("Azure managed identity token acquisition failed.".into())
    })?)
}

pub(super) async fn azure_client_secret_token(
    endpoint: &str,
    credential: &AzureClientSecret,
    resource: &str,
) -> Result<String, KmsError> {
    let request =
        azure_client_secret_request(cloud_http_client()?, endpoint, credential, resource)?;
    let response = send_json(request)
        .await
        .map_err(|_| KmsError::Provider("Azure client token acquisition failed.".into()))?;
    azure_token_value(response)
}

pub(super) fn azure_client_secret_request(
    client: Client,
    endpoint: &str,
    credential: &AzureClientSecret,
    resource: &str,
) -> Result<reqwest::RequestBuilder, KmsError> {
    let url = reqwest::Url::parse(endpoint)
        .map_err(|_| KmsError::InvalidConfig("Azure token endpoint is invalid.".into()))?;
    let official_path = format!("/{}/oauth2/v2.0/token", credential.tenant_id);
    if url.scheme() != "https"
        || url.host_str() != Some("login.microsoftonline.com")
        || url.port().is_some()
        || url.path() != official_path
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(KmsError::InvalidConfig(
            "Azure token endpoint is invalid.".into(),
        ));
    }
    let scope = format!("{resource}/.default");
    Ok(client.post(url).timeout(HTTP_TIMEOUT).form(&[
        ("grant_type", "client_credentials"),
        ("client_id", credential.client_id.as_str()),
        ("client_secret", credential.client_secret.as_str()),
        ("scope", scope.as_str()),
    ]))
}

pub(super) fn azure_token_value(response: Value) -> Result<String, KmsError> {
    response
        .get("access_token")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            KmsError::InvalidResponse("Azure identity response omitted access token.".into())
        })
}

pub(super) async fn azure_bearer(
    builder: reqwest::RequestBuilder,
    config: &Value,
) -> Result<reqwest::RequestBuilder, KmsError> {
    Ok(builder.bearer_auth(azure_access_token(config).await?))
}

pub(super) async fn sign_azure(config: &Value, payload: &[u8]) -> Result<Vec<u8>, KmsError> {
    let endpoint = required(
        config,
        "endpoint",
        "azure-key-vault adapter requires 'endpoint' and 'key_reference' in service_config",
    )?;
    let key_path = azure_key_path(config)?;
    let algorithm = string(config, "algorithm").unwrap_or("ES256");
    if string(config, "azure_signing_algorithm").is_some_and(|configured| configured != algorithm) {
        return Err(KmsError::InvalidConfig(
            "Azure signing algorithm must match the service algorithm.".into(),
        ));
    }
    let (_, digest) = signing_digest(algorithm, payload)?;
    let response = send_json(
        azure_bearer(
            cloud_http_client()?.post(format!(
                "{}/keys/{key_path}/sign?api-version=7.4",
                endpoint.trim_end_matches('/')
            )),
            config,
        )
        .await?
        .timeout(HTTP_TIMEOUT)
        .json(&json!({
            "alg": algorithm,
            "value": URL_SAFE_NO_PAD.encode(digest),
        })),
    )
    .await?;
    require_azure_response_key(&response, endpoint, &key_path)?;
    let value = response
        .get("value")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            KmsError::InvalidResponse(
                "Azure Key Vault sign response did not include signature value".to_string(),
            )
        })?;
    let signature = decode_urlsafe(value, "Azure signature")?;
    if matches!(algorithm, "ES256" | "ES384" | "ES512") {
        // Key Vault's ES algorithms follow RFC 7518 (fixed-width r || s).
        // The service's ECDSA signature contract and certificate consumers use DER.
        marty_crypto::ecdsa::raw_signature_to_der(&signature, algorithm).map_err(|_| {
            KmsError::InvalidResponse("Azure Key Vault returned an invalid ECDSA signature.".into())
        })
    } else {
        Ok(signature)
    }
}

pub(super) fn require_azure_response_key(
    response: &Value,
    endpoint: &str,
    key_path: &str,
) -> Result<(), KmsError> {
    let expected = reqwest::Url::parse(&format!(
        "{}/keys/{key_path}",
        endpoint.trim_end_matches('/')
    ))
    .map_err(|_| KmsError::InvalidConfig("Azure Key Vault endpoint is invalid.".into()))?;
    let actual = response
        .get("kid")
        .and_then(Value::as_str)
        .and_then(|value| reqwest::Url::parse(value).ok());
    if !actual.is_some_and(|actual| {
        actual.origin() == expected.origin()
            && actual.path() == expected.path()
            && actual.username().is_empty()
            && actual.password().is_none()
            && actual.query().is_none()
            && actual.fragment().is_none()
    }) {
        return Err(KmsError::InvalidResponse(
            "Azure Key Vault sign response key identifier did not match the pinned key."
                .to_string(),
        ));
    }
    Ok(())
}

pub(super) async fn public_key_azure(config: &Value) -> Result<Value, KmsError> {
    let endpoint = required(
        config,
        "endpoint",
        "azure-key-vault adapter requires 'endpoint' and 'key_reference' in service_config",
    )?;
    let key_reference = required(
        config,
        "key_reference",
        "azure-key-vault adapter requires 'endpoint' and 'key_reference' in service_config",
    )?;
    let key_path = azure_key_path(config)?;
    let response = send_json(
        azure_bearer(
            cloud_http_client()?.get(format!(
                "{}/keys/{key_path}?api-version=7.4",
                endpoint.trim_end_matches('/')
            )),
            config,
        )
        .await?
        .timeout(HTTP_TIMEOUT),
    )
    .await?;
    let jwk = response
        .get("key")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    require_azure_response_key(&Value::Object(jwk.clone()), endpoint, &key_path)?;
    let public_jwk = canonical_provider_jwk(jwk, key_reference)?;
    let mut output = public_jwk.as_object().cloned().unwrap_or_default();
    output.insert("provider".to_string(), Value::String("azure".to_string()));
    output.insert(
        "key_reference".to_string(),
        Value::String(key_reference.to_string()),
    );
    output.insert("kid".to_string(), Value::String(key_reference.to_string()));
    Ok(Value::Object(output))
}

pub(super) async fn verify_azure(config: &Value) -> CapabilityResult {
    let endpoint = match string(config, "endpoint").filter(|value| !value.is_empty()) {
        Some(value) => value,
        None => return CapabilityResult::fail("Endpoint", "endpoint is required"),
    };
    let client = match cloud_http_client() {
        Ok(client) => client,
        Err(error) => return CapabilityResult::fail("Connectivity", error.to_string()),
    };
    let builder = match azure_bearer(
        client.get(format!(
            "{}/keys?api-version=7.4",
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
        "Azure Key Vault",
        |status| match status {
            StatusCode::OK => (
                "Connectivity",
                "pass",
                "Azure Key Vault endpoint is reachable.".to_string(),
            ),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => (
                "Authentication",
                "fail",
                "Azure token is invalid or unauthorized.".to_string(),
            ),
            other => (
                "Connectivity",
                "fail",
                format!("Azure returned HTTP {}.", other.as_u16()),
            ),
        },
    )
    .await
}
