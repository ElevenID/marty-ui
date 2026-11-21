//! Network-only caller mechanics and independent bootstrap expectations.
//! No function below reads a retained challenge or receipt from owner storage.

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use axum::{http::HeaderMap, routing::get, Json, Router};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use marty_delegated_authority::{
    DelegationGrant, DelegationUseCommandResponse, DelegationUseCommandResult,
    DelegationUseOperation, RetainedUseChallenge, DELEGATION_COMMAND_PROFILE,
    DELEGATION_COMMAND_RESPONSE_PROFILE,
};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use reqwest::{Client, RequestBuilder, Response, StatusCode};
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::{json, Value};
use uuid::Uuid;

use super::live_support::{provider_calls, ISSUANCE_KEY, SERVICE_TOKEN};
use crate::support::{
    owned::{operation_digest, ACTION, AUDIENCE, OPERATION_PROFILE, RESOURCE, VERIFIER_CLIENT_ID},
    TestResult,
};

pub fn start(grant: &DelegationGrant) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "profile":DELEGATION_COMMAND_PROFILE,"command":"START_USE",
        "command_id":Uuid::new_v4(),
        "grant":{"id":grant.id,"revision":grant.revision,"terms_digest":grant.terms_digest},
        "operation":{"action":ACTION,"resource_id":RESOURCE,"audience":AUDIENCE,
            "request_profile":OPERATION_PROFILE,"request_digest":operation_digest()}
    }))
    .unwrap()
}

pub fn finalization(challenge: Uuid, proof: Uuid) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "profile":DELEGATION_COMMAND_PROFILE,"command":"FINALIZE_USE",
        "command_id":Uuid::new_v4(),"challenge_id":challenge,"proof_submission_id":proof
    }))
    .unwrap()
}

pub fn recovery(response: &DelegationUseCommandResponse) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "profile":DELEGATION_COMMAND_PROFILE,"command":"RECOVER_RESULT",
        "original_command_id":response.original_command_id,
        "expected_command_digest":response.command_digest
    }))
    .unwrap()
}

/// This DTO conveys bytes, not a verified receipt or proof of authorization.
/// Deliberately no Debug: failures must not print the original signed artifact.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptArtifact {
    pub original_response: DelegationUseCommandResponse,
    pub receipt_ref: String,
    pub receipt_digest: String,
    pub compact_jws: String,
    pub semantics: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofSubmission {
    pub submission_id: Uuid,
    pub challenge_id: Uuid,
    pub proof_digest: String,
    pub received_at: DateTime<Utc>,
    pub recovered: bool,
}

pub struct Network {
    pub client: Client,
    pub origin: String,
    pub organization: Uuid,
}
impl Network {
    pub fn command_request(&self, raw: &[u8]) -> RequestBuilder {
        self.client
            .post(format!(
                "{}/internal/v1/organizations/{}/delegated-use-commands",
                self.origin, self.organization
            ))
            .header("content-type", "application/json")
            .body(raw.to_vec())
    }
    pub fn receipt_request(&self, raw: &[u8]) -> RequestBuilder {
        self.client
            .post(format!(
                "{}/internal/v1/organizations/{}/delegated-use/receipts/recover",
                self.origin, self.organization
            ))
            .header("content-type", "application/json")
            .body(raw.to_vec())
    }
    pub fn request(&self, challenge: Uuid) -> RequestBuilder {
        self.client.get(format!(
            "{}/internal/v1/organizations/{}/delegated-use/challenges/{challenge}/request",
            self.origin, self.organization
        ))
    }
    pub fn proof_request(&self, challenge: Uuid, proof: &[u8]) -> RequestBuilder {
        self.client
            .post(format!(
                "{}/internal/v1/organizations/{}/delegated-use/challenges/{challenge}/proof",
                self.origin, self.organization
            ))
            .header("content-type", "application/octet-stream")
            .body(proof.to_vec())
    }
    pub async fn command(&self, raw: &[u8]) -> TestResult<DelegationUseCommandResponse> {
        let command: Option<Value> = serde_json::from_slice(raw).ok();
        let label = match command.as_ref().and_then(|value| value["command"].as_str()) {
            Some("START_USE") => "START_USE",
            Some("FINALIZE_USE") => "FINALIZE_USE",
            Some("RECOVER_RESULT") => "RECOVER_RESULT",
            _ => "delegated-use command",
        };
        let result: DelegationUseCommandResponse =
            json_response(self.command_request(raw), label).await?;
        assert_eq!(result.profile, DELEGATION_COMMAND_RESPONSE_PROFILE);
        Ok(result)
    }
    pub async fn receipt(&self, raw: &[u8]) -> TestResult<ReceiptArtifact> {
        json_response(self.receipt_request(raw), "original receipt recovery").await
    }
    pub async fn signed_request(&self, challenge: Uuid) -> TestResult<String> {
        let (response, context) = checked_response(
            self.request(challenge),
            StatusCode::OK,
            "signed request retrieval",
        )
        .await?;
        protected(&response, StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/oauth-authz-req+jwt"
        );
        let bytes = bounded_body(response, 262_144)
            .await
            .map_err(|_| format!("{context}: signed request body unavailable or oversized"))?;
        if bytes.is_empty() {
            return Err(format!("{context}: signed request body is empty").into());
        }
        String::from_utf8(bytes)
            .map_err(|_| format!("{context}: signed request is not UTF-8").into())
    }
    pub async fn submit(&self, challenge: Uuid, proof: &[u8]) -> TestResult<ProofSubmission> {
        json_response(
            self.proof_request(challenge, proof),
            "machine proof submission",
        )
        .await
    }
}

pub fn protected(response: &Response, status: StatusCode) {
    assert_eq!(
        response.status(),
        status,
        "protected HTTP response for {}",
        response.url().path()
    );
    assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
    assert_eq!(response.headers().get("pragma").unwrap(), "no-cache");
    assert_eq!(
        response.headers().get("x-content-type-options").unwrap(),
        "nosniff"
    );
}

async fn json_response<T: DeserializeOwned>(
    request: RequestBuilder,
    label: &'static str,
) -> TestResult<T> {
    let (response, context) = checked_response(request, StatusCode::OK, label).await?;
    protected(&response, StatusCode::OK);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "application/json"
    );
    let bytes = bounded_body(response, 262_144)
        .await
        .map_err(|_| format!("{context}: JSON body unavailable or oversized"))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| format!("{context}: invalid bounded response DTO").into())
}

pub async fn denied(request: RequestBuilder, status: StatusCode, code: &str) -> TestResult {
    denied_for(request, status, code, "expected denial").await
}

pub async fn denied_for(
    request: RequestBuilder,
    status: StatusCode,
    code: &str,
    label: &'static str,
) -> TestResult {
    let (response, context) = checked_response(request, status, label).await?;
    protected(&response, status);
    let actual = generic_detail(response).await;
    if actual != code {
        return Err(
            format!("{context}: HTTP {status}; expected detail {code}; got {actual}").into(),
        );
    }
    Ok(())
}

/// Report only a static operation label, HTTP method, route path, status and a
/// closed public detail code. Queries, headers, arbitrary upstream diagnostics
/// and request/proof/receipt bodies never enter an error or panic message.
async fn checked_response(
    builder: RequestBuilder,
    expected: StatusCode,
    label: &'static str,
) -> TestResult<(Response, String)> {
    let (client, request) = builder.build_split();
    let request = request.map_err(|_| format!("{label}: HTTP request construction failed"))?;
    let context = format!("{label}: {} {}", request.method(), request.url().path());
    let response = client
        .execute(request)
        .await
        .map_err(|_| format!("{context}: HTTP transport failed"))?;
    let status = response.status();
    if status != expected {
        let detail = generic_detail(response).await;
        return Err(format!(
            "{context}: expected HTTP {expected}; got HTTP {status}; detail {detail}"
        )
        .into());
    }
    Ok((response, context))
}

async fn bounded_body(mut response: Response, maximum: usize) -> Result<Vec<u8>, ()> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| ())? {
        if chunk.len() > maximum.saturating_sub(bytes.len()) {
            return Err(());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

async fn generic_detail(response: Response) -> &'static str {
    let Ok(bytes) = bounded_body(response, 4096).await else {
        return "unavailable-or-oversized-error-body";
    };
    let Ok(body) = serde_json::from_slice::<Value>(&bytes) else {
        return "unrecognized-error-body";
    };
    if body.as_object().is_none_or(|object| object.len() != 1) {
        return "unrecognized-error-body";
    }
    match body["detail"].as_str() {
        Some("invalid_delegation_use_command") => "invalid_delegation_use_command",
        Some("delegation_use_access_denied") => "delegation_use_access_denied",
        Some("delegation_use_service_authentication_required") => {
            "delegation_use_service_authentication_required"
        }
        Some("delegation_use_workload_denied") => "delegation_use_workload_denied",
        Some("delegation_use_conflict") => "delegation_use_conflict",
        Some("delegation_use_preparation_pending") => "delegation_use_preparation_pending",
        Some("delegation_use_result_not_found") => "delegation_use_result_not_found",
        Some("delegation_use_evidence_expired") => "delegation_use_evidence_expired",
        Some("delegation_use_unavailable") => "delegation_use_unavailable",
        Some("unsupported_delegation_use_command") => "unsupported_delegation_use_command",
        Some("delegation_use_json_required") => "delegation_use_json_required",
        Some("delegation_use_body_timeout") => "delegation_use_body_timeout",
        Some("delegation_use_body_too_large") => "delegation_use_body_too_large",
        Some("invalid_delegated_flow_request") => "invalid_delegated_flow_request",
        Some("delegated_flow_body_timeout") => "delegated_flow_body_timeout",
        Some("delegated_flow_request_body_forbidden") => "delegated_flow_request_body_forbidden",
        Some("delegated_flow_proof_bytes_required") => "delegated_flow_proof_bytes_required",
        Some("delegated_flow_body_too_large") => "delegated_flow_body_too_large",
        _ => "unrecognized-error-detail",
    }
}

pub fn original(
    received: &DelegationUseCommandResponse,
    expected: &DelegationUseCommandResponse,
) -> TestResult {
    assert!(received.recovered);
    assert_eq!(received.profile, DELEGATION_COMMAND_RESPONSE_PROFILE);
    assert_eq!(received.profile, expected.profile);
    assert_eq!(received.original_command_id, expected.original_command_id);
    assert_eq!(received.command_digest, expected.command_digest);
    assert_eq!(
        serde_json::to_value(&received.result)?,
        serde_json::to_value(&expected.result)?
    );
    Ok(())
}

/// Authenticate the request using the independently provisioned request key.
/// The wallet challenge comes from authenticated START_USE and this signature,
/// never a database snapshot or the receipt that will later be verified.
pub fn wallet_challenge(
    compact: &str,
    public_jwk: &Value,
    key_id: &str,
    grant: &DelegationGrant,
    started: &DelegationUseCommandResponse,
    public_base_url: &str,
    requirement_id: &str,
) -> TestResult<RetainedUseChallenge> {
    let parts = compact.split('.').collect::<Vec<_>>();
    assert_eq!(parts.len(), 3);
    let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0])?)?;
    assert_eq!(header.as_object().unwrap().len(), 3);
    assert_eq!(header["alg"], "ES256");
    assert_eq!(header["typ"], "oauth-authz-req+jwt");
    assert_eq!(header["kid"], key_id);
    assert_eq!(public_jwk["kty"], "EC");
    assert_eq!(public_jwk["crv"], "P-256");
    let x: [u8; 32] = URL_SAFE_NO_PAD
        .decode(public_jwk["x"].as_str().unwrap())?
        .try_into()
        .map_err(|_| "invalid independently selected request x coordinate")?;
    let y: [u8; 32] = URL_SAFE_NO_PAD
        .decode(public_jwk["y"].as_str().unwrap())?
        .try_into()
        .map_err(|_| "invalid independently selected request y coordinate")?;
    let mut point = [0u8; 65];
    point[0] = 4;
    point[1..33].copy_from_slice(&x);
    point[33..].copy_from_slice(&y);
    let verifier = VerifyingKey::from_sec1_bytes(&point)?;
    let signature = Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2])?)?;
    verifier.verify(
        format!("{}.{}", parts[0], parts[1]).as_bytes(),
        &signature.normalize_s(),
    )?;
    let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1])?)?;
    let DelegationUseCommandResult::Challenge {
        challenge_id,
        grant: reference,
        operation,
        created_at,
        expires_at,
    } = &started.result
    else {
        return Err("START_USE did not return a challenge".into());
    };
    assert_eq!(reference.id, grant.id);
    assert_eq!(reference.revision, grant.revision);
    assert_eq!(reference.terms_digest, grant.terms_digest);
    assert_eq!(
        operation,
        &DelegationUseOperation {
            action: ACTION.into(),
            resource_id: RESOURCE.into(),
            audience: AUDIENCE.into(),
            request_profile: OPERATION_PROFILE.into(),
            request_digest: operation_digest(),
        }
    );
    assert_eq!(claims["client_id"], VERIFIER_CLIENT_ID);
    assert_eq!(claims["iss"], VERIFIER_CLIENT_ID);
    assert_eq!(claims["aud"], "https://self-issued.me/v2");
    assert_eq!(claims["state"], challenge_id.to_string());
    assert_eq!(claims["response_type"], "vp_token");
    assert_eq!(claims["response_mode"], "direct_post");
    assert_eq!(
        claims["response_uri"],
        format!("{public_base_url}/v1/flows/instances/{challenge_id}/submit")
    );
    assert_eq!(claims["exp"].as_i64(), Some(expires_at.timestamp()));
    let issued_at = claims["iat"]
        .as_i64()
        .ok_or("missing signed request issuance time")?;
    assert!(issued_at >= created_at.timestamp() && issued_at <= Utc::now().timestamp());
    assert!(issued_at < expires_at.timestamp());
    let query =
        marty_oid4vp_contract::jwt_vc_profile::profiled_jwt_vc_query(&claims["dcql_query"])?
            .ok_or("signed request omitted the explicitly selected securing profile")?;
    assert_eq!(query.id, requirement_id);
    assert_eq!(
        query.binding.securing_profile(),
        marty_oid4vp_contract::jwt_vc_profile::JwtVcSecuringProfile::MartyNestedVc2JwtV1
    );
    assert_eq!(query.type_sets, vec![vec!["MachineCredential".to_owned()]]);
    assert_eq!(
        claims["dcql_query"]["credentials"][0]["meta"]["type_values"],
        json!([["VerifiableCredential", "MachineCredential"]])
    );
    assert_eq!(
        claims["dcql_query"]["credentials"][0]["require_cryptographic_holder_binding"],
        true
    );
    let nonce = claims["nonce"]
        .as_str()
        .ok_or("missing signed request nonce")?;
    assert!(!nonce.is_empty() && nonce.len() <= 256);
    Ok(RetainedUseChallenge {
        organization_id: grant.organization_id,
        challenge_id: *challenge_id,
        grant: grant.clone(),
        operation: operation.clone(),
        verifier_id: VERIFIER_CLIENT_ID.into(),
        nonce: nonce.into(),
        created_at: *created_at,
        expires_at: *expires_at,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SigningCounts {
    pub request_sign: usize,
    pub credential_sign: usize,
    pub receipt_sign: usize,
    pub request_grant: usize,
    pub credential_grant: usize,
    pub receipt_grant: usize,
}
impl SigningCounts {
    pub fn capture() -> TestResult<Self> {
        Ok(Self {
            request_sign: provider_calls("transit/sign/lifecycle-request-es256")?,
            credential_sign: provider_calls("transit/sign/lifecycle-machine-es256")?,
            receipt_sign: provider_calls("transit/sign/lifecycle-receipt-es256")?,
            request_grant: provider_calls("transit/hmac/marty-sign-grant-flow-wallet-v1/sha2-256")?,
            credential_grant: provider_calls(
                "transit/hmac/marty-sign-grant-issuance-credential-v1/sha2-256",
            )?,
            receipt_grant: provider_calls(
                "transit/hmac/marty-sign-grant-delegated-decision-v1/sha2-256",
            )?,
        })
    }
}

/// The four catalog origins are required by host readiness but unused by this
/// selected operation. This named fixture serves authenticated health only;
/// any attempted record resolution is counted and fails. Actual template and
/// policy RPCs, issuance, owner state and custody are provided elsewhere.
#[derive(Default)]
pub struct CatalogHealthFixture {
    pub health_reads: Arc<AtomicUsize>,
    pub attempted_record_reads: Arc<AtomicUsize>,
}
impl CatalogHealthFixture {
    pub fn router(&self) -> Router {
        let health_reads = self.health_reads.clone();
        let attempted = self.attempted_record_reads.clone();
        Router::new().route("/health", get(move |headers: HeaderMap| {
            let health_reads = health_reads.clone();
            async move {
                let service = headers.get("x-service-token").and_then(|v| v.to_str().ok());
                let issuance = headers.get("x-api-key").and_then(|v| v.to_str().ok());
                if (service == Some(SERVICE_TOKEN) && issuance.is_none())
                    || (issuance == Some(ISSUANCE_KEY) && service.is_none()) {
                    health_reads.fetch_add(1, Ordering::SeqCst);
                    (StatusCode::OK, Json(json!({"status":"healthy","fixture":"unused-catalog-health-only"})))
                } else {
                    (StatusCode::UNAUTHORIZED, Json(json!({"error":"fixture credential required"})))
                }
            }
        })).fallback(move || {
            let attempted = attempted.clone();
            async move {
                attempted.fetch_add(1, Ordering::SeqCst);
                StatusCode::NOT_FOUND
            }
        })
    }
}
