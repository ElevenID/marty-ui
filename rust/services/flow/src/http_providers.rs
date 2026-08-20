use std::{collections::BTreeMap, time::Duration};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use reqwest::{Client, Method, StatusCode};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use url::Url;

use crate::{
    FlowKeyEnvelope, FlowKeyEnvelopeProvider, FlowKeyEnvelopeRequest, FlowProviderError,
    PhysicalDocumentOperation, PhysicalDocumentProvider, PhysicalDocumentRequest,
    PhysicalDocumentResult, SigningIdentity, SigningIdentityProvider, SigningRequest,
    SigningResult,
};

const MAXIMUM_RESPONSE_BYTES: usize = 1024 * 1024;

#[derive(Clone)]
struct BoundedHttpClient {
    client: Client,
    base_url: Url,
    api_key: String,
    provider: &'static str,
}

impl BoundedHttpClient {
    fn new(
        base_url: &str,
        api_key: &str,
        provider: &'static str,
        timeout: Duration,
    ) -> Result<Self, FlowProviderError> {
        let mut base_url = Url::parse(base_url).map_err(|_| invalid_config(provider))?;
        if !matches!(base_url.scheme(), "http" | "https")
            || base_url.host().is_none()
            || !base_url.username().is_empty()
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
            || api_key.trim().len() < 16
        {
            return Err(invalid_config(provider));
        }
        if !base_url.path().ends_with('/') {
            let path = format!("{}/", base_url.path());
            base_url.set_path(&path);
        }
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| FlowProviderError::Unavailable { provider })?;
        Ok(Self {
            client,
            base_url,
            api_key: api_key.into(),
            provider,
        })
    }

    async fn json<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, &str)],
        body: Option<Value>,
    ) -> Result<T, FlowProviderError> {
        let url = self
            .base_url
            .join(path)
            .map_err(|_| invalid_config(self.provider))?;
        let mut request = self
            .client
            .request(method, url)
            .query(query)
            .header("X-API-Key", &self.api_key);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let mut response = request
            .send()
            .await
            .map_err(|_| FlowProviderError::Unavailable {
                provider: self.provider,
            })?;
        if !response.status().is_success() {
            return Err(http_status(self.provider, response.status()));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) =
            response
                .chunk()
                .await
                .map_err(|_| FlowProviderError::Unavailable {
                    provider: self.provider,
                })?
        {
            if bytes.len().saturating_add(chunk.len()) > MAXIMUM_RESPONSE_BYTES {
                return Err(invalid_response(self.provider));
            }
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes).map_err(|_| invalid_response(self.provider))
    }
}

#[derive(Clone)]
pub struct HttpSigningProvider {
    signing: BoundedHttpClient,
    envelopes: BoundedHttpClient,
}

impl HttpSigningProvider {
    pub fn new(base_url: &str, api_key: &str) -> Result<Self, FlowProviderError> {
        Ok(Self {
            signing: BoundedHttpClient::new(
                base_url,
                api_key,
                "signing_identity",
                Duration::from_secs(10),
            )?,
            envelopes: BoundedHttpClient::new(
                base_url,
                api_key,
                "flow_key_envelope",
                Duration::from_secs(10),
            )?,
        })
    }

    pub async fn health_check(&self) -> Result<(), FlowProviderError> {
        let _: Value = self.signing.json(Method::GET, "/health", &[], None).await?;
        Ok(())
    }
}

#[async_trait]
impl SigningIdentityProvider for HttpSigningProvider {
    async fn resolve(
        &self,
        organization_id: &str,
        issuer_did: &str,
        key_purpose: &str,
        credential_format: &str,
        algorithm: Option<&str>,
    ) -> Result<SigningIdentity, FlowProviderError> {
        let mut query = vec![
            ("organization_id", organization_id),
            ("issuer_did", issuer_did),
            ("key_purpose", key_purpose),
            ("credential_format", credential_format),
        ];
        if let Some(algorithm) = algorithm {
            query.push(("algorithm", algorithm));
        }
        let mut identity: SigningIdentity = self
            .signing
            .json(Method::GET, "resolve-issuer-did", &query, None)
            .await?;
        if identity.credential_format.is_empty() {
            identity.credential_format = credential_format.into();
        }
        identity.validate_binding(
            organization_id,
            issuer_did,
            key_purpose,
            credential_format,
            algorithm,
        )?;
        Ok(identity)
    }

    async fn sign(&self, request: &SigningRequest) -> Result<SigningResult, FlowProviderError> {
        let body = json!({
            "issuer_did": request.issuer_did,
            "credential_format": request.credential_format,
            "key_purpose": request.key_purpose,
            "payload_b64": request.payload_b64url,
            "algorithm": request.algorithm
        });
        let response: Value = self
            .signing
            .json(
                Method::POST,
                "issuer-dids/sign",
                &[("organization_id", &request.organization_id)],
                Some(body),
            )
            .await?;
        let signature = raw_signature(&response)?;
        let result = SigningResult {
            issuer_did: required_string(&response, "issuer_did", "signing_identity")?,
            verification_method_id: required_string(
                &response,
                "verification_method_id",
                "signing_identity",
            )?,
            algorithm: required_string(&response, "algorithm", "signing_identity")?,
            signature_raw_b64url: signature.into(),
        };
        result.validate_binding(request)?;
        Ok(result)
    }
}

#[async_trait]
impl FlowKeyEnvelopeProvider for HttpSigningProvider {
    async fn wrap(
        &self,
        request: &FlowKeyEnvelopeRequest,
    ) -> Result<FlowKeyEnvelope, FlowProviderError> {
        let response: Value = self
            .envelopes
            .json(
                Method::POST,
                "flow-key-envelopes/wrap",
                &[("organization_id", &request.organization_id)],
                Some(json!({
                    "flow_instance_id": request.flow_instance_id,
                    "plaintext_b64": URL_SAFE_NO_PAD.encode(request.key_json.as_bytes())
                })),
            )
            .await?;
        let envelope = response
            .get("ciphertext")
            .and_then(Value::as_str)
            .filter(|value| value.starts_with("vault:"))
            .ok_or_else(|| invalid_response("flow_key_envelope"))?;
        Ok(FlowKeyEnvelope {
            organization_id: request.organization_id.clone(),
            flow_instance_id: request.flow_instance_id.clone(),
            purpose: request.purpose.clone(),
            envelope: envelope.into(),
        })
    }

    async fn unwrap(&self, envelope: &FlowKeyEnvelope) -> Result<String, FlowProviderError> {
        if !envelope.envelope.starts_with("vault:") {
            return Err(invalid_response("flow_key_envelope"));
        }
        let response: Value = self
            .envelopes
            .json(
                Method::POST,
                "flow-key-envelopes/unwrap",
                &[("organization_id", &envelope.organization_id)],
                Some(json!({
                    "flow_instance_id": envelope.flow_instance_id,
                    "ciphertext": envelope.envelope
                })),
            )
            .await?;
        let encoded = response
            .get("plaintext_b64")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_response("flow_key_envelope"))?;
        let decoded = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| invalid_response("flow_key_envelope"))?;
        String::from_utf8(decoded).map_err(|_| invalid_response("flow_key_envelope"))
    }
}

#[derive(Clone)]
pub struct HttpPhysicalDocumentProvider {
    http: BoundedHttpClient,
}

impl HttpPhysicalDocumentProvider {
    pub fn new(base_url: &str, api_key: &str) -> Result<Self, FlowProviderError> {
        Ok(Self {
            http: BoundedHttpClient::new(
                base_url,
                api_key,
                "physical_document",
                Duration::from_secs(30),
            )?,
        })
    }

    pub async fn health_check(&self) -> Result<(), FlowProviderError> {
        let _: Value = self.http.json(Method::GET, "/health", &[], None).await?;
        Ok(())
    }
}

#[async_trait]
impl PhysicalDocumentProvider for HttpPhysicalDocumentProvider {
    async fn execute(
        &self,
        request: &PhysicalDocumentRequest,
    ) -> Result<PhysicalDocumentResult, FlowProviderError> {
        let (method, path, body) = physical_operation(request)?;
        let data: BTreeMap<String, Value> = self.http.json(method, &path, &[], body).await?;
        let status = data
            .get("status")
            .and_then(Value::as_str)
            .filter(|status| !status.trim().is_empty())
            .ok_or_else(|| invalid_response("physical_document"))?
            .to_owned();
        Ok(PhysicalDocumentResult {
            operation: request.operation,
            status,
            data,
        })
    }
}

fn physical_operation(
    request: &PhysicalDocumentRequest,
) -> Result<(Method, String, Option<Value>), FlowProviderError> {
    if request.operation == PhysicalDocumentOperation::Initialize {
        let mut body = serde_json::to_value(&request.data)
            .map_err(|_| invalid_response("physical_document"))?;
        let object = body
            .as_object_mut()
            .ok_or_else(|| invalid_response("physical_document"))?;
        object.insert(
            "organization_id".into(),
            Value::String(request.organization_id.clone()),
        );
        object.insert(
            "flow_execution_id".into(),
            Value::String(request.flow_instance_id.clone()),
        );
        return Ok((Method::POST, "v1/passport/applications".into(), Some(body)));
    }
    let application_id = request
        .data
        .get("application_id")
        .and_then(Value::as_str)
        .filter(|id| {
            !id.is_empty()
                && id.len() <= 255
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
        })
        .ok_or_else(|| FlowProviderError::Rejected {
            provider: "physical_document",
            message: "application_id is required".into(),
        })?;
    let suffix = match request.operation {
        PhysicalDocumentOperation::GenerateDataGroups => "generate-data-groups",
        PhysicalDocumentOperation::SignSod => "generate-sod",
        PhysicalDocumentOperation::SubmitToPersonalization => "submit-personalization",
        PhysicalDocumentOperation::TrackProduction => "production-status",
        PhysicalDocumentOperation::QualityVerify => "quality-verify",
        PhysicalDocumentOperation::ActivateCredential => "activate",
        PhysicalDocumentOperation::Initialize => unreachable!(),
    };
    let method = if request.operation == PhysicalDocumentOperation::TrackProduction {
        Method::GET
    } else {
        Method::POST
    };
    let body = (request.operation == PhysicalDocumentOperation::QualityVerify).then(|| {
        json!({
            "passed": request.data.get("passed").and_then(Value::as_bool).unwrap_or(false),
            "failure_codes": request.data.get("failure_codes").cloned().unwrap_or_else(|| json!([]))
        })
    });
    Ok((
        method,
        format!("v1/passport/applications/{application_id}/{suffix}"),
        body,
    ))
}

fn invalid_config(provider: &'static str) -> FlowProviderError {
    FlowProviderError::InvalidResponse {
        provider,
        message: "provider URL or credential configuration is invalid".into(),
    }
}
fn required_string(
    value: &Value,
    field: &str,
    provider: &'static str,
) -> Result<String, FlowProviderError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .ok_or_else(|| invalid_response(provider))
}
fn raw_signature(value: &Value) -> Result<&str, FlowProviderError> {
    value
        .get("signature_raw_b64")
        .and_then(Value::as_str)
        .or_else(|| {
            (value.get("signature_encoding").and_then(Value::as_str) == Some("raw_ieee_p1363"))
                .then(|| value.get("signature_b64").and_then(Value::as_str))
                .flatten()
        })
        .filter(|signature| !signature.trim().is_empty())
        .ok_or_else(|| invalid_response("signing_identity"))
}
fn invalid_response(provider: &'static str) -> FlowProviderError {
    FlowProviderError::InvalidResponse {
        provider,
        message: "provider returned an invalid response".into(),
    }
}
fn http_status(provider: &'static str, status: StatusCode) -> FlowProviderError {
    match status.as_u16() {
        404 => FlowProviderError::NotFound {
            provider,
            resource: "resource".into(),
        },
        400 | 401 | 403 | 422 => FlowProviderError::Rejected {
            provider,
            message: "provider rejected the operation".into(),
        },
        409 => FlowProviderError::Conflict {
            provider,
            message: "provider reported a conflict".into(),
        },
        _ => FlowProviderError::Unavailable { provider },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(operation: PhysicalDocumentOperation) -> PhysicalDocumentRequest {
        PhysicalDocumentRequest {
            organization_id: "org-1".into(),
            flow_instance_id: "flow-1".into(),
            operation,
            data: BTreeMap::from([
                ("application_id".into(), json!("application-1")),
                ("passed".into(), json!(true)),
                ("failure_codes".into(), json!([])),
            ]),
        }
    }

    #[test]
    fn provider_configuration_rejects_credentials_and_weak_api_keys() {
        assert!(
            HttpSigningProvider::new("https://user@example.com/internal/", &"a".repeat(32))
                .is_err()
        );
        assert!(HttpSigningProvider::new("https://example.com/internal/", "short").is_err());
        assert!(HttpSigningProvider::new("https://example.com/internal/", &"a".repeat(32)).is_ok());
        let client = BoundedHttpClient::new(
            "https://example.com/internal/signing-keys",
            &"a".repeat(32),
            "test",
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(
            client.base_url.join("resolve-issuer-did").unwrap().as_str(),
            "https://example.com/internal/signing-keys/resolve-issuer-did"
        );
    }

    #[test]
    fn signature_fallback_must_be_raw_ieee_p1363() {
        let der = json!({
            "signature_b64": "der-signature",
            "signature_encoding": "der"
        });
        assert!(raw_signature(&der).is_err());
        assert_eq!(
            raw_signature(&json!({
                "signature_b64": "raw-signature",
                "signature_encoding": "raw_ieee_p1363"
            }))
            .unwrap(),
            "raw-signature"
        );
    }

    #[test]
    fn physical_document_adapter_preserves_every_python_operation() {
        let contract: Value = serde_json::from_slice(
            &std::fs::read(
                std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../../../contracts/flow-provider-behavior.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let routes = contract["physical_document_operations"]
            .as_object()
            .unwrap();
        let operations = [
            (
                "generate_data_groups",
                PhysicalDocumentOperation::GenerateDataGroups,
            ),
            ("sign_sod", PhysicalDocumentOperation::SignSod),
            (
                "submit_to_personalization",
                PhysicalDocumentOperation::SubmitToPersonalization,
            ),
            (
                "track_production",
                PhysicalDocumentOperation::TrackProduction,
            ),
            ("quality_verify", PhysicalDocumentOperation::QualityVerify),
            (
                "activate_credential",
                PhysicalDocumentOperation::ActivateCredential,
            ),
        ];
        for (name, operation) in operations {
            let (method, path, body) = physical_operation(&request(operation)).unwrap();
            let expected = routes[name].as_array().unwrap();
            assert_eq!(method.as_str(), expected[0].as_str().unwrap());
            assert_eq!(path, expected[1].as_str().unwrap());
            assert_eq!(
                body.is_some(),
                operation == PhysicalDocumentOperation::QualityVerify
            );
        }
        let (method, path, body) =
            physical_operation(&request(PhysicalDocumentOperation::Initialize)).unwrap();
        let expected = routes["initialize"].as_array().unwrap();
        assert_eq!(method.as_str(), expected[0].as_str().unwrap());
        assert_eq!(path, expected[1].as_str().unwrap());
        assert_eq!(body.unwrap()["organization_id"], "org-1");
    }
}
