use super::*;
use crate::didcomm_remote_kms::{RemoteDidcommKms, RemoteDidcommKmsError};
use marty_signing_grant::didcomm::{
    public_key_bytes, DidcommKeyReference, DidcommOperationBinding, DidcommPackRequest,
    DidcommResolveRequest,
};

enum DidcommOperationError {
    Unauthorized,
    CapabilityUnavailable,
    Unavailable,
    BindingChanged,
    Invalid,
    Registry(registry::RegistryError),
    Identity(PublicSigningError),
}

impl IntoResponse for DidcommOperationError {
    fn into_response(self) -> Response {
        let (status, detail) = match self {
            Self::Registry(error) => return registry_error(error).into_response(),
            Self::Identity(error) => return error.into_response(),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "DIDComm operation authorization is invalid."),
            Self::CapabilityUnavailable => return (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({
                "code": "capability_unavailable", "capability": "didcomm_authcrypt",
                "detail": "DIDComm authcrypt requires a registered and bound OpenBao extension.",
            }))).into_response(),
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "DIDComm operation provider is unavailable."),
            Self::BindingChanged => (StatusCode::CONFLICT, "DIDComm operation binding or public key has changed."),
            Self::Invalid => (StatusCode::UNPROCESSABLE_ENTITY, "DIDComm operation request is invalid."),
        };
        public_error(status, detail)
    }
}

impl From<RemoteDidcommKmsError> for DidcommOperationError {
    fn from(error: RemoteDidcommKmsError) -> Self {
        match error {
            RemoteDidcommKmsError::CapabilityUnavailable => Self::CapabilityUnavailable,
            RemoteDidcommKmsError::Unauthorized => Self::Unauthorized,
            RemoteDidcommKmsError::BindingMismatch => Self::BindingChanged,
            _ => Self::Unavailable,
        }
    }
}

fn binding_public_jwk(binding: &DidcommOperationBinding) -> Value {
    json!({"kty": "OKP", "crv": "X25519", "x": binding.public_key})
}

fn document_matches_binding(
    document: &Value,
    issuer_did: &str,
    binding: &DidcommOperationBinding,
) -> bool {
    let expected = binding_public_jwk(binding);
    document.get("id").and_then(Value::as_str) == Some(issuer_did)
        && document
            .get("keyAgreement")
            .and_then(Value::as_array)
            .is_some_and(|relationships| relationships.contains(&json!(binding.sender_key_id)))
        && document
            .get("verificationMethod")
            .and_then(Value::as_array)
            .is_some_and(|methods| {
                methods.iter().any(|method| {
                    method.get("id").and_then(Value::as_str) == Some(binding.sender_key_id.as_str())
                        && method.get("controller").and_then(Value::as_str) == Some(issuer_did)
                        && method.get("type").and_then(Value::as_str) == Some("JsonWebKey2020")
                        && method.get("publicKeyJwk") == Some(&expected)
                })
            })
}

fn operation_service<'a>(
    registry: &'a Value,
    service_id: &str,
) -> Result<&'a Value, DidcommOperationError> {
    registry
        .get("services")
        .and_then(Value::as_array)
        .and_then(|services| {
            services
                .iter()
                .find(|service| service.get("id").and_then(Value::as_str) == Some(service_id))
        })
        .filter(|service| {
            service.get("service_type").and_then(Value::as_str) == Some("openbao-transit")
                && !matches!(
                    service.get("status").and_then(Value::as_str),
                    Some("disabled" | "inactive" | "retired")
                )
        })
        .ok_or(DidcommOperationError::CapabilityUnavailable)
}

async fn resolved_operation(
    state: &AppState,
    organization_id: &str,
    issuer_did: &str,
) -> Result<(DidcommOperationBinding, RemoteDidcommKms), DidcommOperationError> {
    let registry = state
        .registry_store
        .as_ref()
        .ok_or(DidcommOperationError::Unavailable)?
        .load(organization_id)
        .await
        .map_err(DidcommOperationError::Registry)?;
    let binding = registry::didcomm_binding(&registry, organization_id, issuer_did)
        .map_err(DidcommOperationError::Registry)?
        .ok_or(DidcommOperationError::CapabilityUnavailable)?;
    let service = operation_service(&registry, &binding.service_id)?;
    if registry::didcomm_service_config_sha256(service) != binding.service_config_sha256 {
        return Err(DidcommOperationError::BindingChanged);
    }
    let profiles = state
        .profile_store
        .as_ref()
        .ok_or(DidcommOperationError::Unavailable)?
        .list(organization_id)
        .await
        .map_err(|_| DidcommOperationError::Unavailable)?;
    if !profiles
        .get("profiles")
        .and_then(Value::as_array)
        .is_some_and(|profiles| {
            profiles.iter().any(|profile| {
                profile.get("issuer_did").and_then(Value::as_str) == Some(issuer_did)
                    && profile.get("status").and_then(Value::as_str) == Some("active")
            })
        })
    {
        return Err(DidcommOperationError::BindingChanged);
    }
    let stored = state
        .document_store
        .as_ref()
        .ok_or(DidcommOperationError::Unavailable)?
        .load_did(
            organization_id,
            LoadDidRequest {
                did_id: Some(issuer_did.into()),
                fallback_did: None,
            },
        )
        .await
        .map_err(|_| DidcommOperationError::Unavailable)?;
    if !stored.found || !document_matches_binding(&stored.document, issuer_did, &binding) {
        return Err(DidcommOperationError::BindingChanged);
    }
    let provider = RemoteDidcommKms::from_registered_service(service)?;
    let reference = binding
        .validate(organization_id, issuer_did)
        .map_err(|_| DidcommOperationError::BindingChanged)?;
    let public = provider.public_key(&reference, issuer_did).await?;
    if public.sender_key_id != binding.sender_key_id
        || public_key_bytes(&binding.public_key)
            .map_err(|_| DidcommOperationError::BindingChanged)?
            != public.public_key
    {
        return Err(DidcommOperationError::BindingChanged);
    }
    Ok((binding, provider))
}

pub(super) async fn resolve_registered_didcomm(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<DidcommResolveRequest>,
) -> Response {
    if !authorize_issuer_sign(&state, &headers) {
        return DidcommOperationError::Unauthorized.into_response();
    }
    if request.organization_id.is_empty()
        || request.organization_id.len() > 128
        || request.issuer_did.len() > 512
        || !request.issuer_did.starts_with("did:")
    {
        return DidcommOperationError::Invalid.into_response();
    }
    match resolved_operation(&state, &request.organization_id, &request.issuer_did).await {
        Ok((binding, _)) => Json(binding).into_response(),
        Err(error) => error.into_response(),
    }
}

pub(super) async fn pack_registered_didcomm(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<DidcommPackRequest>,
) -> Response {
    if !authorize_issuer_sign(&state, &headers) {
        return DidcommOperationError::Unauthorized.into_response();
    }
    let result = async {
        let payload = request
            .bound_payload()
            .map_err(|_| DidcommOperationError::Invalid)?;
        let header = headers
            .get(HEADER_NAME)
            .and_then(|header| header.to_str().ok())
            .ok_or(DidcommOperationError::Unauthorized)?;
        // The exact fixed Issuance origin is derived from the operation, never the header.
        // Consume before any registry inventory/plugin read or private operation.
        let consumed =
            consume_bound_signing_grant(&state, header, &request.grant_binding(&payload))
                .await
                .map_err(|error| match error {
                    GrantAuthorizationError::Denied => DidcommOperationError::Unauthorized,
                    GrantAuthorizationError::Unavailable => DidcommOperationError::Unavailable,
                })?;
        let store = state
            .registry_store
            .as_ref()
            .ok_or(DidcommOperationError::Unavailable)?;
        let lease = store
            .acquire_rotation_lease(&request.organization_id)
            .await
            .map_err(DidcommOperationError::Registry)?
            .ok_or(DidcommOperationError::Registry(
                registry::RegistryError::Conflict,
            ))?;
        let packed = async {
            let (binding, provider) =
                resolved_operation(&state, &request.organization_id, &request.issuer_did).await?;
            if binding != request.binding {
                return Err(DidcommOperationError::BindingChanged);
            }
            provider
                .pack_authorized(&request, consumed)
                .await
                .map_err(Into::into)
        }
        .await;
        let release = lease
            .release()
            .await
            .map_err(DidcommOperationError::Registry);
        let jwe = packed?;
        release?;
        Ok::<_, DidcommOperationError>(jwe)
    }
    .await;
    match result {
        Ok(jwe) => Json(json!({"jwe": jwe})).into_response(),
        Err(error) => error.into_response(),
    }
}

pub(super) async fn publish_public_issuer_didcomm_key_agreement(
    State(state): State<AppState>,
    Query(scope): Query<OrganizationScope>,
    headers: HeaderMap,
    Json(input): Json<DidcommKeyAgreementRequest>,
) -> Response {
    let identity = input.identity();
    if let Err(error) = validate_identity_scope(&scope.organization_id, &identity) {
        return error.into_response();
    }
    if let Err(error) = validate_identity_operation_fields(&identity, false, false) {
        return error.into_response();
    }
    if let Err(error) = documents::validate_x25519_public_jwk(&input.public_jwk) {
        return public_publication_error(error);
    }
    let expected_revision = match strong_config_if_match(&headers) {
        Ok(revision) => revision,
        Err(()) => {
            return public_error(
                StatusCode::BAD_REQUEST,
                "If-Match must be one strong registry revision.",
            )
        }
    };
    let reference = match DidcommKeyReference::parse(&input.key_reference) {
        Ok(reference) if reference.tenant() == scope.organization_id => reference,
        _ => return DidcommOperationError::Invalid.into_response(),
    };
    let Some(public_domain) = state.public_domain.as_deref() else {
        return DidcommOperationError::Invalid.into_response();
    };
    let Some(org_slug) = documents::did_web_org_slug(&input.issuer_did, Some(public_domain)) else {
        return DidcommOperationError::Invalid.into_response();
    };
    let Some(registry_store) = state.registry_store.as_ref() else {
        return DidcommOperationError::Unavailable.into_response();
    };
    let Some(documents) = state.document_store.as_ref() else {
        return DidcommOperationError::Unavailable.into_response();
    };
    let lease = match registry_store
        .acquire_rotation_lease(&scope.organization_id)
        .await
    {
        Ok(Some(lease)) => lease,
        Ok(None) => return registry_error(registry::RegistryError::Conflict).into_response(),
        Err(error) => return registry_error(error).into_response(),
    };
    let result = async {
        let snapshot = registry_store.load_with_revision_snapshot(&scope.organization_id).await.map_err(DidcommOperationError::Registry)?;
        if expected_revision.as_deref().is_some_and(|expected| expected != snapshot.etag) {
            return Err(DidcommOperationError::Registry(registry::RegistryError::PreconditionFailed));
        }
        if !input.enabled {
            if let Some(binding) = registry::didcomm_binding(&snapshot.registry, &scope.organization_id, &input.issuer_did).map_err(DidcommOperationError::Registry)? {
                if binding.service_id != input.service_id || binding.key_reference != input.key_reference { return Err(DidcommOperationError::BindingChanged); }
            }
            let revision = registry_store.set_didcomm_binding_with_lease(&scope.organization_id, &input.issuer_did, None, &snapshot, &lease).await.map_err(DidcommOperationError::Registry)?;
            return Ok(json!({"issuer_did": input.issuer_did, "enabled": false, "config_revision": revision}));
        }
        let profile = one_matching_profile(&state, &scope.organization_id, &identity).await.map_err(DidcommOperationError::Identity)?;
        validated_issuer_service(&state, &scope.organization_id, &profile, &input.credential_format, &input.key_purpose, &input.algorithm)
            .await.map_err(DidcommOperationError::Identity)?;
        let service = operation_service(&snapshot.registry, &input.service_id)?;
        let provider = RemoteDidcommKms::from_registered_service(service)?;
        let sender = provider.public_key(&reference, &input.issuer_did).await?;
        let binding = DidcommOperationBinding {
            service_id: input.service_id.clone(), service_config_sha256: registry::didcomm_service_config_sha256(service),
            key_reference: input.key_reference.clone(), sender_key_id: sender.sender_key_id,
            public_key: URL_SAFE_NO_PAD.encode(sender.public_key),
        };
        binding.validate(&scope.organization_id, &input.issuer_did).map_err(|_| DidcommOperationError::Invalid)?;
        if binding_public_jwk(&binding) != input.public_jwk { return Err(DidcommOperationError::BindingChanged); }
        let fragment = binding.sender_key_id.strip_prefix(&format!("{}#", input.issuer_did)).filter(|fragment| !fragment.is_empty()).ok_or(DidcommOperationError::Invalid)?;
        let publication = documents.publish_did_with_lease(&scope.organization_id, "didcomm-authcrypt", PublishDidRequest {
            jwk: input.public_jwk.clone(), public_domain: public_domain.into(), did_id: Some(input.issuer_did.clone()),
            org_slug: Some(org_slug), fragment: Some(fragment.into()), key_reference: None,
            cert_pem: None, cert_chain_pem: None, relationship: DidVerificationRelationship::KeyAgreement,
        }, &lease).await.map_err(|_| DidcommOperationError::Unavailable)?;
        if !valid_didcomm_publication(&publication, &input.issuer_did, &binding.sender_key_id, &input.public_jwk) { return Err(DidcommOperationError::BindingChanged); }
        let revision = registry_store.set_didcomm_binding_with_lease(&scope.organization_id, &input.issuer_did, Some(&binding), &snapshot, &lease).await.map_err(DidcommOperationError::Registry)?;
        // A publication-only or registry-only partial write is never reported as usable.
        let (stored, _) = resolved_operation(&state, &scope.organization_id, &input.issuer_did).await?;
        if stored != binding { return Err(DidcommOperationError::BindingChanged); }
        Ok::<_, DidcommOperationError>(json!({"issuer_did": input.issuer_did, "key_agreement_method_id": binding.sender_key_id, "enabled": true, "config_revision": revision}))
    }.await;
    let release = lease.release().await;
    match (result, release) {
        (Ok(response), Ok(())) => Json(response).into_response(),
        (Err(error), _) => error.into_response(),
        (_, Err(error)) => registry_error(error).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use tower::ServiceExt;

    fn binding() -> DidcommOperationBinding {
        DidcommOperationBinding {
            service_id: "service-a".into(),
            service_config_sha256: "a".repeat(64),
            key_reference: format!("didcomm/keys/org-a/sender/versions/{}", "b".repeat(32)),
            sender_key_id: "did:example:issuer#sender".into(),
            public_key: URL_SAFE_NO_PAD.encode([7; 32]),
        }
    }

    #[test]
    fn didcomm_requires_both_private_binding_and_exact_published_relationship() {
        let binding = binding();
        let mut doc = json!({"id":"did:example:issuer", "verificationMethod":[{
            "id":binding.sender_key_id,"controller":"did:example:issuer","type":"JsonWebKey2020",
            "publicKeyJwk":binding_public_jwk(&binding)
        }],"keyAgreement":[binding.sender_key_id]});
        assert!(document_matches_binding(
            &doc,
            "did:example:issuer",
            &binding
        ));
        doc["keyAgreement"] = json!([]);
        assert!(!document_matches_binding(
            &doc,
            "did:example:issuer",
            &binding
        ));
        doc["keyAgreement"] = json!([binding.sender_key_id]);
        doc["verificationMethod"][0]["publicKeyJwk"]["x"] = json!(URL_SAFE_NO_PAD.encode([8; 32]));
        assert!(!document_matches_binding(
            &doc,
            "did:example:issuer",
            &binding
        ));
        let registry = json!({"services":[{"id":"aws", "service_type":"aws-kms", "discovered_capabilities":{"didcomm_authcrypt":true}}]});
        assert!(matches!(
            operation_service(&registry, "aws"),
            Err(DidcommOperationError::CapabilityUnavailable)
        ));
    }

    #[tokio::test]
    async fn didcomm_pack_requires_issuer_api_authentication_and_a_separate_grant() {
        let app = router_with_all_keys_and_grants(
            "internal-key".into(),
            None,
            Some("dedicated-issuer-key".into()),
            None,
            None,
            None,
            false,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let request = DidcommPackRequest {
            organization_id: "org-a".into(),
            issuer_did: "did:example:issuer".into(),
            operation_id: "transaction-a".into(),
            phase: marty_signing_grant::didcomm::DidcommPackPhase::Preflight,
            binding: binding(),
            recipient_did: "did:example:holder".into(),
            recipients: vec![marty_signing_grant::didcomm::RemoteRecipientPublic::new(
                "did:example:holder#key".into(),
                &[8; 32],
            )],
            plaintext: "private fixture".into(),
        };
        for key in ["", "internal-key", "dedicated-issuer-key"] {
            let response = app
                .clone()
                .oneshot(
                    Request::post(marty_signing_grant::didcomm::PACK_ROUTE)
                        .header("content-type", "application/json")
                        .header("x-api-key", key)
                        .body(Body::from(serde_json::to_vec(&request).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            let body = to_bytes(response.into_body(), 4096).await.unwrap();
            assert!(!String::from_utf8_lossy(&body).contains("private fixture"));
        }
    }
}
