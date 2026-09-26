//! KMS-held MAC for tenant-bound passport bureau callbacks.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Deserialize;
use serde_json::{json, Value};
use subtle::ConstantTimeEq;

use crate::flow_envelope::OpenBaoEnvelopeProvider;

const SCHEMA: &str = "marty.passport-bureau-callback/v1";
const KEY_ID: &str = "passport-bureau-callback-marty-hmac";
const MAX_BODY_BYTES: usize = 64 * 1024;
const MAX_HMAC_BYTES: usize = 512;

fn valid_signature(signature: &str) -> bool {
    let Some((version, digest)) = signature
        .strip_prefix("vault:v")
        .and_then(|value| value.split_once(':'))
    else {
        return false;
    };
    !version.is_empty()
        && version.bytes().all(|byte| byte.is_ascii_digit())
        && signature.len() <= MAX_HMAC_BYTES
        && STANDARD.decode(digest).is_ok_and(|bytes| bytes.len() == 32)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignRequest {
    pub body_b64: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyRequest {
    pub body_b64: String,
    pub signature: String,
}

#[derive(Debug, thiserror::Error)]
pub enum CallbackKmsError {
    #[error("Invalid internal signing API key.")]
    Unauthorized,
    #[error("Passport bureau callback is invalid or does not match this organization.")]
    InvalidEvent,
    #[error("Passport bureau callback signature is invalid.")]
    InvalidSignature,
    #[error("KMS passport callback signer is unavailable.")]
    Unavailable,
}

impl IntoResponse for CallbackKmsError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::Unauthorized | Self::InvalidSignature => StatusCode::UNAUTHORIZED,
            Self::InvalidEvent => StatusCode::UNPROCESSABLE_ENTITY,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        };
        (status, Json(json!({"detail": self.to_string()}))).into_response()
    }
}

fn signed_input(organization_id: &str, body_b64: &str) -> Result<String, CallbackKmsError> {
    if organization_id.trim().is_empty()
        || organization_id.len() > 256
        || body_b64.len() > MAX_BODY_BYTES.div_ceil(3) * 4
    {
        return Err(CallbackKmsError::InvalidEvent);
    }
    let body = STANDARD
        .decode(body_b64)
        .map_err(|_| CallbackKmsError::InvalidEvent)?;
    if body.is_empty() || body.len() > MAX_BODY_BYTES {
        return Err(CallbackKmsError::InvalidEvent);
    }
    let event: Value = serde_json::from_slice(&body).map_err(|_| CallbackKmsError::InvalidEvent)?;
    if event.get("organization_id").and_then(Value::as_str) != Some(organization_id)
        || event
            .get("bureau_job_id")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || !matches!(
            event.get("status").and_then(Value::as_str),
            Some(
                "QUEUED"
                    | "PRINTING"
                    | "ENCODING"
                    | "QUALITY_CHECK"
                    | "SHIPPED"
                    | "DELIVERED"
                    | "FAILED"
                    | "CANCELLED"
            )
        )
    {
        return Err(CallbackKmsError::InvalidEvent);
    }
    let mut input = Vec::with_capacity(SCHEMA.len() + organization_id.len() + body.len() + 2);
    input.extend_from_slice(SCHEMA.as_bytes());
    input.push(0);
    input.extend_from_slice(organization_id.as_bytes());
    input.push(0);
    input.extend_from_slice(&body);
    Ok(STANDARD.encode(input))
}

pub async fn sign(
    provider: &OpenBaoEnvelopeProvider,
    organization_id: &str,
    request: SignRequest,
) -> Result<Value, CallbackKmsError> {
    let input = signed_input(organization_id, &request.body_b64)?;
    let response = provider
        .post(
            &format!("/v1/transit/hmac/{KEY_ID}"),
            json!({"input": input}),
        )
        .await
        .map_err(|_| CallbackKmsError::Unavailable)?;
    let signature = response
        .pointer("/data/hmac")
        .and_then(Value::as_str)
        .filter(|value| valid_signature(value))
        .ok_or(CallbackKmsError::Unavailable)?;
    Ok(json!({"signature": signature}))
}

pub async fn verify(
    provider: &OpenBaoEnvelopeProvider,
    organization_id: &str,
    request: VerifyRequest,
) -> Result<Value, CallbackKmsError> {
    let input = signed_input(organization_id, &request.body_b64)?;
    if !valid_signature(&request.signature) {
        return Err(CallbackKmsError::InvalidSignature);
    }
    let response = provider
        .post(
            &format!("/v1/transit/verify/{KEY_ID}"),
            json!({"input": input, "hmac": request.signature}),
        )
        .await
        .map_err(|_| CallbackKmsError::Unavailable)?;
    let valid = response
        .pointer("/data/valid")
        .and_then(Value::as_bool)
        .ok_or(CallbackKmsError::Unavailable)?;
    Ok(json!({"valid": valid}))
}

#[derive(Clone)]
struct SignerState {
    provider: OpenBaoEnvelopeProvider,
    internal_api_key: String,
}

/// The beta-only signer has no general signing, verification, or public routes.
/// Deploy it only on the dedicated callback-signing Compose network.
pub fn isolated_signer_router(
    provider: OpenBaoEnvelopeProvider,
    internal_api_key: String,
) -> Router {
    Router::new()
        .route("/health", get(|| async { StatusCode::OK }))
        .route(
            "/internal/documents/{organization_id}/passport-callbacks/sign",
            post(sign_callback),
        )
        .with_state(SignerState {
            provider,
            internal_api_key,
        })
}

async fn sign_callback(
    State(state): State<SignerState>,
    Path(organization_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<SignRequest>,
) -> Result<Json<Value>, CallbackKmsError> {
    let supplied = headers
        .get("x-api-key")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if supplied.len() != state.internal_api_key.len()
        || supplied
            .as_bytes()
            .ct_eq(state.internal_api_key.as_bytes())
            .unwrap_u8()
            != 1
    {
        return Err(CallbackKmsError::Unauthorized);
    }
    sign(&state.provider, &organization_id, request)
        .await
        .map(Json)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::{
        body::Body,
        extract::{Json, State},
        http::Request,
        routing::post,
        Router,
    };
    use tower::ServiceExt;

    use super::*;

    const SYNTHETIC_SIGNATURE: &str = "vault:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn body(organization_id: &str) -> String {
        STANDARD.encode(
            json!({"organization_id": organization_id, "bureau_job_id": "job-1", "status": "SHIPPED"})
                .to_string(),
        )
    }

    #[test]
    fn contract_rejects_invalid_or_cross_tenant_callback_before_kms_use() {
        let contract: Value = serde_json::from_str(include_str!(
            "../../../../contracts/passport-bureau-callback-kms-behavior.json"
        ))
        .unwrap();
        assert_eq!(contract["schema"], SCHEMA);
        assert_eq!(contract["maximum_body_bytes"], MAX_BODY_BYTES);
        assert!(signed_input("org-a", &body("org-a")).is_ok());
        assert!(signed_input("org-b", &body("org-a")).is_err());
        assert!(signed_input("org-a", "not-base64").is_err());
        assert!(signed_input("org-a", &STANDARD.encode(b"{}")).is_err());
        assert!(valid_signature(SYNTHETIC_SIGNATURE));
        assert!(!valid_signature("vault:v1:synthetic"));
    }

    #[tokio::test]
    async fn sign_and_verify_use_versioned_kms_hmac_without_exporting_a_key() {
        type SignedInput = Arc<Mutex<Option<String>>>;
        async fn hmac(State(signed): State<SignedInput>, Json(body): Json<Value>) -> Json<Value> {
            *signed.lock().unwrap() = body["input"].as_str().map(str::to_owned);
            Json(json!({"data": {"hmac": SYNTHETIC_SIGNATURE}}))
        }
        async fn verify_hmac(
            State(signed): State<SignedInput>,
            Json(body): Json<Value>,
        ) -> Json<Value> {
            Json(json!({"data": {"valid": body["hmac"] == SYNTHETIC_SIGNATURE
                && signed.lock().unwrap().as_deref() == body["input"].as_str()}}))
        }
        let signed = SignedInput::default();
        let app = Router::new()
            .route(
                "/v1/transit/hmac/passport-bureau-callback-marty-hmac",
                post(hmac),
            )
            .route(
                "/v1/transit/verify/passport-bureau-callback-marty-hmac",
                post(verify_hmac),
            )
            .with_state(signed);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let provider =
            OpenBaoEnvelopeProvider::new(format!("http://{address}"), "test-token").unwrap();
        let signed = sign(
            &provider,
            "org-a",
            SignRequest {
                body_b64: body("org-a"),
            },
        )
        .await
        .unwrap();
        assert_eq!(signed["signature"], SYNTHETIC_SIGNATURE);
        let verified = verify(
            &provider,
            "org-a",
            VerifyRequest {
                body_b64: body("org-a"),
                signature: signed["signature"].as_str().unwrap().into(),
            },
        )
        .await
        .unwrap();
        assert_eq!(verified["valid"], true);
        let tampered = verify(
            &provider,
            "org-a",
            VerifyRequest {
                body_b64: STANDARD.encode(json!({"organization_id": "org-a", "bureau_job_id": "job-1", "status": "FAILED"}).to_string()),
                signature: signed["signature"].as_str().unwrap().into(),
            },
        )
        .await
        .unwrap();
        assert_eq!(tampered["valid"], false);

        let ordinary = crate::http::router_with_dependencies(
            "internal-key".into(),
            None,
            None,
            None,
            None,
            Some(provider.clone()),
            None,
        );
        let endpoint = "/internal/documents/org-a/passport-callbacks/sign";
        let request_body = json!({"body_b64": body("org-a")}).to_string();
        let unavailable_on_ordinary_service = ordinary
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(endpoint)
                    .header("content-type", "application/json")
                    .header("x-api-key", "internal-key")
                    .body(Body::from(request_body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            unavailable_on_ordinary_service.status(),
            StatusCode::NOT_FOUND
        );
        let app = isolated_signer_router(provider, "internal-key".into());
        let unauthorized = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(endpoint)
                    .header("content-type", "application/json")
                    .body(Body::from(request_body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
        let signed = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(endpoint)
                    .header("content-type", "application/json")
                    .header("x-api-key", "internal-key")
                    .body(Body::from(request_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(signed.status(), StatusCode::OK);
        for isolated_path in [
            "/internal/documents/org-a/passport-callbacks/verify",
            "/internal/documents/org-a/passport-artifacts/decrypt",
            "/v1/signing-keys",
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(isolated_path)
                        .header("x-api-key", "internal-key")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{isolated_path}");
        }
        server.abort();
    }
}
