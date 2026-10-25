//! Gateway domain operations; transport authorization remains in runtime.
use super::*;

pub(super) async fn internal_signing_compatibility_handler(
    state: Arc<GatewayRuntimeState>,
    request: Request,
) -> Response {
    let expected = if request.method() == axum::http::Method::POST
        && request.uri().path() == "/internal/signing-keys/issuer-dids/sign"
    {
        let Some(key) = state.issuer_sign_key.as_ref() else {
            return detail_response(401, "Invalid internal API key");
        };
        key
    } else {
        &state.signing_service_api_key
    };
    if !constant_time_header_matches(request.headers().get("x-api-key"), expected) {
        return detail_response(401, "Invalid internal API key");
    }
    let Some(method) = http_method(request.method().as_str()) else {
        return detail_response(405, "Method not allowed");
    };
    let Some(operation) = signing_compat::operation(method, request.uri().path()) else {
        return detail_response(404, "Not found");
    };
    let query = query_pairs(request.uri().query());
    let Some(organization_id) = first_query(&query, "organization_id")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
    else {
        return detail_response(422, "organization_id is required.");
    };
    if matches!(
        &operation,
        SigningCompatibilityOperation::PassportArtifactEncrypt
            | SigningCompatibilityOperation::PassportArtifactDecrypt
            | SigningCompatibilityOperation::PassportCallbackVerify
    ) {
        return forward_bound_envelope(&state, &operation, &organization_id, request).await;
    }
    if operation == SigningCompatibilityOperation::IssuerContext {
        return forward_issuer_context(&state, &organization_id, &query).await;
    }
    if operation == SigningCompatibilityOperation::ResolveIssuerDid {
        return forward_resolve_issuer_did(&state, &organization_id, &query).await;
    }
    if operation == SigningCompatibilityOperation::CscaTrustAnchors {
        let path = format!(
            "/internal/documents/{}/csca-trust-anchors",
            utf8_percent_encode(&organization_id, NON_ALPHANUMERIC)
        );
        return match signing_service_request(&state, HttpMethod::Get, &path, None).await {
            Ok(response) => upstream_response(response),
            Err(response) => response,
        };
    }
    if let SigningCompatibilityOperation::ProfileIdentity { profile_id } = &operation {
        return forward_profile_identity(&state, &organization_id, profile_id, false).await;
    }
    if let SigningCompatibilityOperation::ProfilePublicIdentity { profile_id } = &operation {
        return forward_profile_identity(&state, &organization_id, profile_id, true).await;
    }
    if operation == SigningCompatibilityOperation::IssuerDidSign {
        return forward_signing_body(
            &state,
            &organization_id,
            "/internal/compat/issuer-dids/sign",
            request,
        )
        .await;
    }
    if operation == SigningCompatibilityOperation::CreateProfile {
        return forward_profile_write(
            &state,
            &organization_id,
            "/internal/compat/issuer-profiles",
            request,
        )
        .await;
    }
    if let SigningCompatibilityOperation::UpdateProfile { profile_id } = &operation {
        let path = format!(
            "/internal/compat/issuer-profiles/{}",
            utf8_percent_encode(profile_id, NON_ALPHANUMERIC)
        );
        return forward_profile_write(&state, &organization_id, &path, request).await;
    }
    if let SigningCompatibilityOperation::ProfileCertificate { profile_id } = &operation {
        let path = format!(
            "/internal/compat/issuer-profiles/{}/certificate",
            utf8_percent_encode(profile_id, NON_ALPHANUMERIC)
        );
        return forward_profile_write(&state, &organization_id, &path, request).await;
    }
    let organization_id = utf8_percent_encode(&organization_id, NON_ALPHANUMERIC);
    let (method, path, transform_delete) = match operation {
        SigningCompatibilityOperation::ListProfiles => (
            HttpMethod::Get,
            format!("/internal/profiles/{organization_id}"),
            false,
        ),
        SigningCompatibilityOperation::GetProfile { profile_id } => (
            HttpMethod::Get,
            format!(
                "/internal/profiles/{organization_id}/{}",
                utf8_percent_encode(&profile_id, NON_ALPHANUMERIC)
            ),
            false,
        ),
        SigningCompatibilityOperation::DeleteProfile { profile_id } => (
            HttpMethod::Delete,
            format!(
                "/internal/profiles/{organization_id}/{}",
                utf8_percent_encode(&profile_id, NON_ALPHANUMERIC)
            ),
            true,
        ),
        _ => {
            return error_response(
                501,
                MipError::new(
                    "not_implemented",
                    "Internal signing compatibility operation has not completed Rust migration",
                ),
            );
        }
    };
    let response = match signing_service_request(&state, method, &path, None).await {
        Ok(response) => response,
        Err(response) => return response,
    };
    if !transform_delete || response.status_code != 200 {
        return upstream_response(response);
    }
    let Some(deleted) = response_json(&response)
        .and_then(|body| body.get("deleted").cloned())
        .and_then(|value| value.as_str().map(str::to_owned))
    else {
        return detail_response(503, "Native issuer-profile backend is unavailable.");
    };
    Json(json!({"ok": true, "deleted": deleted})).into_response()
}

pub(super) async fn forward_resolve_issuer_did(
    state: &Arc<GatewayRuntimeState>,
    organization_id: &str,
    query: &BTreeMap<String, Vec<String>>,
) -> Response {
    if query.contains_key("issuer_profile_id") {
        return detail_response(
            422,
            "issuer_profile_id is not accepted; resolve the issuer by issuer_did.",
        );
    }
    let Some(issuer_did) = first_query(query, "issuer_did") else {
        return detail_response(422, "issuer_did is required.");
    };
    let body = json!({
        "organization_id": organization_id,
        "issuer_did": issuer_did,
        "verification_method_id": first_query(query, "verification_method_id"),
        "credential_format": first_query(query, "credential_format"),
        "key_purpose": first_query(query, "key_purpose"),
        "algorithm": first_query(query, "algorithm")
    });
    forward_signing_compatibility_json(state, "/internal/compat/resolve-issuer-did", body).await
}

pub(super) async fn forward_profile_identity(
    state: &Arc<GatewayRuntimeState>,
    organization_id: &str,
    profile_id: &str,
    public_projection: bool,
) -> Response {
    let suffix = if public_projection {
        "public-identity"
    } else {
        "identity"
    };
    let path = format!(
        "/internal/compat/issuer-profiles/{}/{suffix}",
        utf8_percent_encode(profile_id, NON_ALPHANUMERIC)
    );
    forward_signing_compatibility_json(state, &path, json!({"organization_id": organization_id}))
        .await
}

pub(super) async fn forward_signing_compatibility_json(
    state: &Arc<GatewayRuntimeState>,
    path: &str,
    body: Value,
) -> Response {
    forward_signing_compatibility_json_with_grant(state, path, body, None).await
}

pub(super) async fn forward_signing_compatibility_json_with_grant(
    state: &Arc<GatewayRuntimeState>,
    path: &str,
    body: Value,
    grant_header: Option<&str>,
) -> Response {
    match signing_service_request_with_grant(
        state,
        HttpMethod::Post,
        path,
        Some(serde_json::to_vec(&body).expect("compatibility request serializes")),
        grant_header,
    )
    .await
    {
        Ok(response) => upstream_response(response),
        Err(response) => response,
    }
}

pub(super) async fn forward_signing_body(
    state: &Arc<GatewayRuntimeState>,
    organization_id: &str,
    path: &str,
    request: Request,
) -> Response {
    let grant_header = match request.headers().get(marty_signing_grant::HEADER_NAME) {
        Some(value) => {
            let Ok(value) = value.to_str() else {
                return detail_response(422, "Signing grant header is malformed.");
            };
            if marty_signing_grant::GrantEnvelope::from_header_value(value).is_err() {
                return detail_response(422, "Signing grant header is malformed.");
            }
            Some(value.to_owned())
        }
        None => None,
    };
    let mut body = match request_json_object(request, state.maximum_body_bytes).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    body["organization_id"] = Value::String(organization_id.into());
    forward_signing_compatibility_json_with_grant(state, path, body, grant_header.as_deref()).await
}

pub(super) async fn forward_profile_write(
    state: &Arc<GatewayRuntimeState>,
    organization_id: &str,
    path: &str,
    request: Request,
) -> Response {
    let body = match request_json_object(request, state.maximum_body_bytes).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    forward_signing_compatibility_json(
        state,
        path,
        json!({"organization_id": organization_id, "body": body}),
    )
    .await
}

pub(super) async fn forward_issuer_context(
    state: &Arc<GatewayRuntimeState>,
    organization_id: &str,
    query: &BTreeMap<String, Vec<String>>,
) -> Response {
    if query.contains_key("issuer_profile_id") {
        return detail_response(
            422,
            "issuer_profile_id is not accepted; resolve the issuer by issuer_did.",
        );
    }
    let body = json!({
        "organization_id": organization_id,
        "issuer_did": first_query(query, "issuer_did")
            .map(str::trim)
            .filter(|value| !value.is_empty()),
        "issuer_mode": first_query(query, "issuer_mode")
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("org_managed"),
        "credential_format": first_query(query, "credential_format"),
        "key_purpose": first_query(query, "key_purpose"),
        "algorithm": first_query(query, "algorithm")
    });
    let response = signing_service_request(
        state,
        HttpMethod::Post,
        "/internal/compat/issuer-context",
        Some(serde_json::to_vec(&body).expect("issuer context request serializes")),
    )
    .await;
    match response {
        Ok(response) => upstream_response(response),
        Err(response) => response,
    }
}

pub(super) async fn forward_bound_envelope(
    state: &Arc<GatewayRuntimeState>,
    operation: &SigningCompatibilityOperation,
    organization_id: &str,
    request: Request,
) -> Response {
    let body = match request_json_object(request, state.maximum_body_bytes).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let path = match operation {
        SigningCompatibilityOperation::PassportArtifactEncrypt => format!(
            "/internal/documents/{}/passport-artifacts/encrypt",
            utf8_percent_encode(organization_id, NON_ALPHANUMERIC)
        ),
        SigningCompatibilityOperation::PassportArtifactDecrypt => format!(
            "/internal/documents/{}/passport-artifacts/decrypt",
            utf8_percent_encode(organization_id, NON_ALPHANUMERIC)
        ),
        SigningCompatibilityOperation::PassportCallbackVerify => format!(
            "/internal/documents/{}/passport-callbacks/verify",
            utf8_percent_encode(organization_id, NON_ALPHANUMERIC)
        ),
        _ => unreachable!("caller restricts bound-envelope operations"),
    };
    let response = signing_service_request(
        state,
        HttpMethod::Post,
        &path,
        Some(serde_json::to_vec(&body).expect("flow envelope request serializes")),
    )
    .await;
    match response {
        Ok(response) => upstream_response(response),
        Err(response) => response,
    }
}
