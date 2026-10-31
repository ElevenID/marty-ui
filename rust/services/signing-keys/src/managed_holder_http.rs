//! Dedicated Device Registration authority for managed holder operations.

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use serde_json::json;
use subtle::ConstantTimeEq;

use crate::managed_holder_key::{
    CreateHolderKeyRequest, HolderKeyError, HolderKeyScope, OpenBaoManagedHolderKeys,
    SignHolderKeyRequest,
};

#[derive(Clone)]
struct HolderState {
    device_key: Arc<str>,
    provider: Option<OpenBaoManagedHolderKeys>,
}

pub fn router(device_key: String, provider: OpenBaoManagedHolderKeys) -> Router {
    router_with_optional_provider(device_key, Some(provider))
}

pub fn router_with_optional_provider(
    device_key: String,
    provider: Option<OpenBaoManagedHolderKeys>,
) -> Router {
    let state = HolderState {
        device_key: Arc::from(device_key),
        provider,
    };
    Router::new()
        .route(
            "/internal/device-registration/holder-keys/create",
            post(create),
        )
        .route("/internal/device-registration/holder-keys/sign", post(sign))
        .route(
            "/internal/device-registration/holder-keys/revoke",
            post(revoke),
        )
        .route_layer(middleware::from_fn_with_state(state.clone(), device_auth))
        .with_state(state)
}

async fn device_auth(State(state): State<HolderState>, request: Request, next: Next) -> Response {
    let headers: &HeaderMap = request.headers();
    let supplied = headers
        .get("x-device-registration-key")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if state.device_key.len() < 32
        || supplied
            .as_bytes()
            .ct_eq(state.device_key.as_bytes())
            .unwrap_u8()
            != 1
    {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"detail":"Device Registration authentication is required"})),
        )
            .into_response();
    }
    next.run(request).await
}

fn capability_unavailable() -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({
            "code":"capability_unavailable", "capability":"managed_holder_key_lifecycle",
            "detail":"Managed holder keys require a configured compatible remote provider"
        })),
    )
        .into_response()
}

fn operation_error(error: HolderKeyError) -> Response {
    let status = match error {
        HolderKeyError::Invalid => StatusCode::UNPROCESSABLE_ENTITY,
        HolderKeyError::Unavailable | HolderKeyError::Provider => StatusCode::SERVICE_UNAVAILABLE,
    };
    (status, Json(json!({"detail":error.to_string()}))).into_response()
}

async fn create(
    State(state): State<HolderState>,
    Json(request): Json<CreateHolderKeyRequest>,
) -> Response {
    let Some(provider) = state.provider.as_ref() else {
        return capability_unavailable();
    };
    match provider.create(request).await {
        Ok(metadata) => (StatusCode::OK, Json(metadata)).into_response(),
        Err(error) => operation_error(error),
    }
}

async fn sign(
    State(state): State<HolderState>,
    Json(request): Json<SignHolderKeyRequest>,
) -> Response {
    let Some(provider) = state.provider.as_ref() else {
        return capability_unavailable();
    };
    match provider.sign(request).await {
        Ok(signature) => (StatusCode::OK, Json(signature)).into_response(),
        Err(error) => operation_error(error),
    }
}

async fn revoke(State(state): State<HolderState>, Json(scope): Json<HolderKeyScope>) -> Response {
    let Some(provider) = state.provider.as_ref() else {
        return capability_unavailable();
    };
    match provider.revoke(scope).await {
        Ok(()) => (StatusCode::OK, Json(json!({"ok":true}))).into_response(),
        Err(error) => operation_error(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    #[tokio::test]
    async fn absent_holder_capability_requires_device_authority() {
        let key = "dedicated-device-registration-key-32-chars";
        let app = router_with_optional_provider(key.into(), None);
        let body = json!({
            "scope": {"organization_id":"org-a", "registration_id":"reg-a",
                "purpose":"holder_binding", "provider_reference":"cred-holder-unavailable"},
            "algorithm":"ES256"
        });
        for authorized in [false, true] {
            let mut request = Request::builder()
                .method("POST")
                .uri("/internal/device-registration/holder-keys/create")
                .header("content-type", "application/json");
            if authorized {
                request = request.header("x-device-registration-key", key);
            }
            let response = app
                .clone()
                .oneshot(request.body(Body::from(body.to_string())).unwrap())
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                if authorized {
                    StatusCode::UNPROCESSABLE_ENTITY
                } else {
                    StatusCode::UNAUTHORIZED
                }
            );
            if authorized {
                let bytes = axum::body::to_bytes(response.into_body(), 2048)
                    .await
                    .unwrap();
                let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(value["code"], "capability_unavailable");
                assert_eq!(value["capability"], "managed_holder_key_lifecycle");
            }
        }
    }

    #[tokio::test]
    async fn dedicated_credential_and_scope_fail_before_openbao() {
        let provider = OpenBaoManagedHolderKeys::new("https://127.0.0.1:1".into()).unwrap();
        let app = router(
            "dedicated-device-registration-key-32-chars".into(),
            provider,
        );
        let body = json!({
            "scope": {"organization_id":"org-a", "registration_id":"reg-a",
                "purpose":"holder_binding", "provider_reference":"cred-holder-other"},
            "algorithm":"EdDSA"
        });
        let request = Request::builder()
            .method("POST")
            .uri("/internal/device-registration/holder-keys/create")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let request = Request::builder()
            .method("POST")
            .uri("/internal/device-registration/holder-keys/create")
            .header("content-type", "application/json")
            .header(
                "x-device-registration-key",
                "dedicated-device-registration-key-32-chars",
            )
            .body(Body::from(body.to_string()))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }
}
