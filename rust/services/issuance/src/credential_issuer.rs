use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use marty_verification::key_attestation::{
    route_proof_json, validate_attestation_json, validate_status_reference_json,
    validate_status_token_json, KeyAttestationPolicy,
};
use reqwest::{Certificate, Client, Url};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::credential::{
    CredentialIssuanceError, CredentialProofVerifier, CredentialTransaction, IssuerContext,
    IssuerContextResolver, VerifiedCredentialProof,
};
use crate::network_policy::is_public_ip;

const PROOF_MAX_AGE_SECONDS: i64 = 300;
const MAX_STATUS_LIST_BYTES: usize = 1_048_576;

#[derive(Clone)]
pub struct HttpIssuerContextResolver {
    client: Client,
    base_url: Url,
    api_key: Option<String>,
}

impl std::fmt::Debug for HttpIssuerContextResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpIssuerContextResolver")
            .field("base_url", &self.base_url)
            .field("has_api_key", &self.api_key.is_some())
            .finish_non_exhaustive()
    }
}

impl HttpIssuerContextResolver {
    pub fn new(
        base_url: Url,
        api_key: Option<&str>,
        timeout: Duration,
    ) -> Result<Self, CredentialIssuanceError> {
        let client = Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| {
                issuer_error(format!("Unable to configure issuer resolver: {error}"))
            })?;
        Ok(Self {
            client,
            base_url,
            api_key: api_key.map(str::to_owned),
        })
    }

    fn endpoint(&self) -> Result<Url, CredentialIssuanceError> {
        let path = format!(
            "{}/resolve-issuer-did",
            self.base_url.path().trim_end_matches('/')
        );
        let mut endpoint = self.base_url.clone();
        endpoint.set_path(&path);
        endpoint.set_query(None);
        endpoint.set_fragment(None);
        Ok(endpoint)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn resolve_raw(
        &self,
        organization_id: &str,
        issuer_did: &str,
        issuer_mode: Option<&str>,
        credential_format: &str,
        key_purpose: &str,
        algorithm: &str,
    ) -> Result<Value, CredentialIssuanceError> {
        let mut query = vec![
            ("organization_id", organization_id),
            ("issuer_did", issuer_did),
            ("credential_format", credential_format),
            ("key_purpose", key_purpose),
            ("algorithm", algorithm),
        ];
        if let Some(issuer_mode) = issuer_mode {
            query.push(("issuer_mode", issuer_mode));
        }
        let mut request = self.client.get(self.endpoint()?).query(&query);
        if let Some(api_key) = self.api_key.as_deref() {
            request = request.header("X-API-Key", api_key);
        }
        let response = request.send().await.map_err(|error| {
            issuer_error(format!("DID issuer context resolution failed: {error}"))
        })?;
        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(issuer_error(
                "Internal signing API rejected the service API key",
            ));
        }
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(issuer_error(
                "Unable to resolve the remote DID issuer profile for this organization",
            ));
        }
        let status = response.status();
        let context: Value = response.json().await.map_err(|error| {
            issuer_error(format!("DID issuer context returned invalid JSON: {error}"))
        })?;
        if !status.is_success() || context.get("ok").and_then(Value::as_bool) != Some(true) {
            return Err(issuer_error(format!(
                "DID issuer context resolution failed (HTTP {status})"
            )));
        }
        Ok(context)
    }
}

#[async_trait]
impl IssuerContextResolver for HttpIssuerContextResolver {
    async fn resolve(
        &self,
        transaction: &CredentialTransaction,
        credential_format: &str,
        _force: bool,
    ) -> Result<IssuerContext, CredentialIssuanceError> {
        let issuer_did = transaction.issuer_did.as_deref().ok_or_else(|| {
            issuer_error("The issuance transaction has no DID-mediated issuer identity")
        })?;
        let algorithm = transaction.issuer_algorithm.as_deref().ok_or_else(|| {
            issuer_error("The issuance transaction has no issuer signing algorithm")
        })?;
        let context = self
            .resolve_raw(
                &transaction.organization_id,
                issuer_did,
                Some(normalize_issuer_mode(&transaction.issuer_mode)),
                credential_format,
                key_purpose(credential_format),
                algorithm,
            )
            .await?;
        parse_issuer_context(context, issuer_did, algorithm)
    }
}

#[derive(Clone, Debug, Default)]
pub struct NativeCredentialProofVerifier;

#[async_trait]
impl CredentialProofVerifier for NativeCredentialProofVerifier {
    async fn verify(
        &self,
        proof_jwt: &str,
        expected_nonce: &str,
        organization_id: &str,
        issuer: &IssuerContext,
    ) -> Result<VerifiedCredentialProof, CredentialIssuanceError> {
        let route = native_json(
            route_proof_json,
            json!({
                "proof_jwt": proof_jwt,
                "issuer_context": issuer.raw_context,
                "organization_id": organization_id,
            }),
        )?;
        let verified = match route.get("action").and_then(Value::as_str) {
            Some("ordinary") => marty_oid4vci::proof::verify_jwt_proof(
                proof_jwt,
                "",
                Some(expected_nonce),
                PROOF_MAX_AGE_SECONDS,
            ),
            Some("bound") => {
                let attestation = route
                    .get("key_attestation")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid_proof("Key attestation route returned no JWT"))?;
                let policy: KeyAttestationPolicy =
                    serde_json::from_value(route.get("policy").cloned().ok_or_else(|| {
                        invalid_proof("Key attestation route returned no policy")
                    })?)
                    .map_err(|error| {
                        invalid_proof(format!("Invalid key attestation policy: {error}"))
                    })?;
                let validated = validate_attestation(attestation, &policy, expected_nonce).await?;
                let validated_jwt = validated
                    .get("jwt")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid_proof("Validated key attestation returned no JWT"))?;
                marty_oid4vci::proof::verify_key_attestation_bound_jwt_proof(
                    proof_jwt,
                    "",
                    Some(expected_nonce),
                    PROOF_MAX_AGE_SECONDS,
                    validated_jwt,
                )
            }
            _ => return Err(invalid_proof("Key attestation route returned no action")),
        }
        .map_err(|error| invalid_proof(error.to_string()))?;
        let holder_jwk = verified
            .holder_jwk
            .map(serde_json::to_value)
            .transpose()
            .map_err(|error| invalid_proof(format!("Holder JWK is invalid: {error}")))?;
        Ok(VerifiedCredentialProof {
            holder_did: verified.holder_id,
            holder_jwk,
        })
    }
}

async fn validate_attestation(
    jwt: &str,
    policy: &KeyAttestationPolicy,
    expected_nonce: &str,
) -> Result<Value, CredentialIssuanceError> {
    let validated = native_json(
        validate_attestation_json,
        json!({
            "jwt": jwt,
            "policy": policy,
            "expected_nonce": expected_nonce,
            "now": Utc::now().to_rfc3339(),
        }),
    )?;
    let statuses = validated
        .get("statuses")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_proof("Validated key attestation returned invalid statuses"))?;
    if policy.status_validation != "disabled" {
        for status in statuses {
            validate_status(status, policy).await?;
        }
    }
    Ok(validated)
}

#[derive(Deserialize)]
struct StatusReference {
    uri: String,
    hostname: String,
    port: u16,
    allow_private_hosts: bool,
    index: u64,
}

async fn validate_status(
    status: &Value,
    policy: &KeyAttestationPolicy,
) -> Result<(), CredentialIssuanceError> {
    let reference: StatusReference = serde_json::from_value(native_json(
        validate_status_reference_json,
        json!({"status": status, "policy": policy}),
    )?)
    .map_err(|error| invalid_proof(format!("Invalid status-list reference: {error}")))?;
    let addresses = tokio::net::lookup_host((reference.hostname.as_str(), reference.port))
        .await
        .map_err(|_| invalid_proof("Status-list hostname could not be resolved"))?
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err(invalid_proof(
            "Status-list hostname resolved to no addresses",
        ));
    }
    if !reference.allow_private_hosts && addresses.iter().any(|address| !is_public_ip(address.ip()))
    {
        return Err(invalid_proof(
            "Status-list hostname resolves to a non-public address",
        ));
    }
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .resolve_to_addrs(&reference.hostname, &addresses);
    for pem in &policy.status_list_tls_ca_certificates_pem {
        let certificate = Certificate::from_pem(pem.as_bytes())
            .map_err(|_| invalid_proof("Status-list TLS CA certificate is invalid"))?;
        builder = builder.add_root_certificate(certificate);
    }
    let client = builder
        .build()
        .map_err(|_| invalid_proof("Status-list HTTP client configuration is invalid"))?;
    let mut response = client
        .get(&reference.uri)
        .header("Accept", "application/statuslist+jwt")
        .send()
        .await
        .map_err(|_| invalid_proof("Status-list endpoint request failed"))?;
    if !response.status().is_success() {
        return Err(invalid_proof(format!(
            "Status-list endpoint returned HTTP {}",
            response.status()
        )));
    }
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    if content_type != Some("application/statuslist+jwt") {
        return Err(invalid_proof(
            "Status-list endpoint did not return application/statuslist+jwt",
        ));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_STATUS_LIST_BYTES as u64)
    {
        return Err(invalid_proof("Status List Token response is too large"));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| invalid_proof("Status-list endpoint request failed"))?
    {
        if body.len().saturating_add(chunk.len()) > MAX_STATUS_LIST_BYTES {
            return Err(invalid_proof("Status List Token response is too large"));
        }
        body.extend_from_slice(&chunk);
    }
    let token = std::str::from_utf8(&body)
        .map_err(|_| invalid_proof("Status List Token response is not ASCII"))?
        .trim();
    if !token.is_ascii() {
        return Err(invalid_proof("Status List Token response is not ASCII"));
    }
    let value = validate_status_token_json(
        &serde_json::to_string(&json!({
            "token": token,
            "uri": reference.uri,
            "index": reference.index,
            "policy": policy,
            "now": Utc::now().to_rfc3339(),
        }))
        .map_err(|error| invalid_proof(error.to_string()))?,
    )
    .map_err(invalid_proof)?;
    if value != 0 {
        return Err(invalid_proof(
            "Key attestation status is revoked or invalid",
        ));
    }
    Ok(())
}

fn parse_issuer_context(
    context: Value,
    expected_did: &str,
    expected_algorithm: &str,
) -> Result<IssuerContext, CredentialIssuanceError> {
    let profile = context
        .get("issuer_profile")
        .and_then(Value::as_object)
        .ok_or_else(|| issuer_error("Issuer DID resolver returned no active issuer profile"))?;
    let value = |name: &str| {
        context
            .get(name)
            .or_else(|| profile.get(name))
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
    };
    if !profile
        .get("status")
        .and_then(Value::as_str)
        .is_some_and(|status| status.eq_ignore_ascii_case("active"))
    {
        return Err(issuer_error("KMS issuer profile is not active"));
    }
    let issuer_did = value("issuer_did")
        .ok_or_else(|| issuer_error("KMS issuer context is missing issuer_did"))?;
    let algorithm = context
        .get("algorithm")
        .or_else(|| profile.get("algorithm"))
        .and_then(Value::as_str)
        .ok_or_else(|| issuer_error("KMS issuer context is missing issuer_algorithm"))?;
    if issuer_did != expected_did || algorithm != expected_algorithm {
        return Err(issuer_error(
            "Resolved issuer context changed during credential issuance",
        ));
    }
    let required = |name: &str| {
        value(name)
            .map(str::to_owned)
            .ok_or_else(|| issuer_error(format!("KMS issuer context is missing {name}")))
    };
    let issuer_profile_id = required("issuer_profile_id").or_else(|_| {
        profile
            .get("id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| issuer_error("KMS issuer context is missing issuer_profile_id"))
    })?;
    let signing_service_id = required("signing_service_id")?;
    required("signing_key_reference")?;
    let verification_method_id = Some(required("verification_method_id")?);
    let public_jwk = context.get("public_jwk").cloned().filter(Value::is_object);
    let certificate_chain = context
        .get("issuer_x5c")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .filter(|value| !value.is_empty())
                        .map(str::to_owned)
                        .ok_or_else(|| issuer_error("Issuer certificate chain is invalid"))
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();
    Ok(IssuerContext {
        issuer_profile_id,
        issuer_did: issuer_did.to_owned(),
        signing_service_id,
        algorithm: algorithm.to_owned(),
        verification_method_id,
        public_jwk,
        certificate_chain,
        raw_context: context,
    })
}

fn native_json(
    operation: fn(&str) -> Result<String, String>,
    request: Value,
) -> Result<Value, CredentialIssuanceError> {
    let request = serde_json::to_string(&request)
        .map_err(|error| invalid_proof(format!("Invalid native request: {error}")))?;
    let response = operation(&request).map_err(invalid_proof)?;
    serde_json::from_str(&response)
        .map_err(|error| invalid_proof(format!("Invalid native response: {error}")))
}

fn key_purpose(credential_format: &str) -> &'static str {
    if credential_format == "mso_mdoc" {
        "mdoc_dsc"
    } else {
        "vc_jwt_issuer"
    }
}

fn normalize_issuer_mode(mode: &str) -> &str {
    match mode.trim() {
        "" => "org_managed",
        value => value,
    }
}

fn invalid_proof(detail: impl Into<String>) -> CredentialIssuanceError {
    CredentialIssuanceError::InvalidProof(detail.into())
}

fn issuer_error(detail: impl Into<String>) -> CredentialIssuanceError {
    CredentialIssuanceError::IssuerUnavailable(detail.into())
}

#[cfg(test)]
mod tests {
    use super::NativeCredentialProofVerifier;
    use crate::credential::{CredentialProofVerifier, IssuerContext};
    use serde_json::json;

    #[tokio::test]
    async fn ordinary_proof_uses_the_canonical_rust_verifier() {
        let nonce = format!("proof-adapter-{}", uuid::Uuid::new_v4());
        let proof = marty_oid4vci::proof::create_proof_jwt("https://issuer.example", &nonce)
            .expect("proof fixture");
        let verified = NativeCredentialProofVerifier
            .verify(
                &proof,
                &nonce,
                "org-a",
                &IssuerContext {
                    issuer_profile_id: "profile-a".to_owned(),
                    issuer_did: "did:web:issuer.example".to_owned(),
                    signing_service_id: "service-a".to_owned(),
                    algorithm: "ES256".to_owned(),
                    verification_method_id: None,
                    public_jwk: None,
                    certificate_chain: Vec::new(),
                    raw_context: json!({}),
                },
            )
            .await
            .expect("valid ordinary proof");
        assert!(verified.holder_did.starts_with("did:key:"));
    }
}
