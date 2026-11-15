use super::*;
use axum::{body::Body, http::Request};
use tower::ServiceExt;

fn check(name: &str, status: &str) -> validation::ValidationCheck {
    validation::ValidationCheck {
        name: name.into(),
        status: status.into(),
        detail: String::new(),
        source: "live".into(),
    }
}

#[test]
fn sign_and_read_prove_ready_even_when_sign_only_token_cannot_lookup_self() {
    assert!(current_issuer_service_readiness(&[
        check("Key exists", "pass"),
        check("Provider auth", "fail"),
        check("Signer capability", "pass"),
    ]));
    assert!(!current_issuer_service_readiness(&[
        check("Key exists", "pass"),
        check("Provider auth", "pass"),
        check("Signer capability", "fail"),
    ]));
    assert!(current_issuer_service_readiness(&[
        check("Key exists", "pass"),
        check("Provider auth", "fail"),
    ]));
    assert!(!current_issuer_service_readiness(&[
        check("Key exists", "pass"),
        check("Provider connectivity", "fail"),
    ]));
    assert!(!current_issuer_service_readiness(&[check(
        "Signer capability",
        "pass"
    )]));
    // Fixed public ECDSA vector for the server-owned challenge; tests never sign.
    let jwk = json!({"kty":"EC", "crv":"P-256",
            "x":"jlM7b6C_e0YluzBmfAH7YH75-LioD-9bMAYocDGHsqM",
            "y":"c-sdveAzGDZtBp-DpvWQAFPHNjPLBBshxV4ahsH0ALQ"});
    let payload = b"marty-current-issuer-service-readiness-v1";
    let signature = hex::decode(concat!(
        "3045022018c28b956d1557b85154a8e9bd077adb21f4df0f9876f12f97fd9373a4d72f0f",
        "022100bbab5fba0e276f3026e344c0b16aebd56db96fd1d756375cac3086745f52e6f5"
    ))
    .expect("fixed public DER signature");
    assert!(verify_current_issuer_signature(
        &jwk,
        payload,
        signature.as_slice()
    ));
    assert!(!verify_current_issuer_signature(
        &jwk,
        payload,
        b"not-a-signature"
    ));
    let wrong_jwk = json!({"kty":"EC", "crv":"P-256",
            "x":"Ytl3nb7psFNAQnQtOrVMrcHSOJgPzpfbtN2dwdtvs5M",
            "y":"rVrMvZHp2CRP8V13EWfO4KLtUfa752p42lQKag8JlX4"});
    assert!(!verify_current_issuer_signature(
        &wrong_jwk,
        payload,
        signature.as_slice()
    ));
    assert!(!verify_current_issuer_signature(
        &json!({"kty":"EC","crv":"P-256","x":"AA","y":"AA"}),
        payload,
        signature.as_slice()
    ));
}

#[test]
fn only_unique_active_vc_issuer_tuple_can_be_probed() {
    let document = json!({"profiles": [
        {"status":"active", "issuer_did":"did:web:issuer.example", "credential_format":"SD_JWT_VC",
         "key_purpose":"vc_jwt_issuer", "algorithm":"ES256", "signing_service_id":"svc-a"},
        {"status":"active", "issuer_did":"did:web:issuer.example", "credential_format":"SD_JWT_VC",
         "key_purpose":"mdoc_dsc", "algorithm":"ES256", "signing_service_id":"svc-b"},
        {"status":"revoked", "issuer_did":"did:web:issuer.example", "credential_format":"SD_JWT_VC",
         "key_purpose":"vc_jwt_issuer", "algorithm":"ES256", "signing_service_id":"svc-c"},
    ]});
    assert_eq!(
        current_issuer_profiles(&document, "did:web:issuer.example", "SD_JWT_VC").len(),
        1
    );
    assert!(current_issuer_profiles(&document, "did:web:foreign.example", "SD_JWT_VC").is_empty());
    assert!(current_issuer_profiles(&document, "did:web:issuer.example", "VC_JWT").is_empty());
    assert!(validate_service_scope("org-a", Some("org-b")).is_err());
    assert!(supported_current_issuer_service(&json!({
        "service_type":"openbao-transit", "auth_mode":"token"
    })));
    assert!(!supported_current_issuer_service(&json!({
        "service_type":"openbao-transit", "auth_mode":"approle"
    })));
    assert!(!supported_current_issuer_service(&json!({
        "service_type":"managed-openbao-transit", "auth_mode":"service_token"
    })));
    assert!(serde_json::from_value::<CurrentIssuerServiceValidationRequest>(json!({
            "issuer_did":"did:web:issuer.example", "credential_format":"SD_JWT_VC", "payload_b64":"dGVzdA=="
        })).is_err());
}

#[test]
fn selected_issuer_binding_reuses_service_and_ceremony_authority() {
    let service = json!({"id":"svc-a", "service_type":"openbao-transit",
            "auth_mode":"token", "key_reference":"vc-key", "algorithms":["ES256"],
            "key_purposes":["vc_jwt_issuer","oid4vp_request_signing","jwks_signing",
                "mdoc_iaca","lti_tool_signing"]});
    let fields = service.as_object().unwrap();
    let profile = json!({"organization_id":"org-a", "issuer_did":"did:web:issuer.example",
            "credential_format":"SD_JWT_VC", "signing_service_id":"svc-a",
            "signing_key_reference":"vc-key", "key_purpose":"vc_jwt_issuer", "algorithm":"ES256"});
    let allowed = |registry: Value| {
        crate::compat::authorize_current_issuer_binding(
            &registry, fields, &profile, "org-a", "svc-a", "vc-key",
        )
        .is_ok()
    };
    assert!(allowed(json!({"key_reference_purposes": {}})));
    for purposes in [
        json!(["vc_jwt_issuer"]),
        json!(["vc_jwt_issuer", "oid4vp_request_signing"]),
        json!(["vc_jwt_issuer", "jwks_signing"]),
    ] {
        assert!(allowed(
            json!({"key_reference_purposes": {"svc-a": {"vc-key": purposes}}})
        ));
    }
    for purposes in [
        json!([]),
        json!(["oid4vp_request_signing"]),
        json!(["vc_jwt_issuer", "mdoc_iaca"]),
        json!(["vc_jwt_issuer", "lti_tool_signing"]),
        json!(["vc_jwt_issuer", "vc_jwt_issuer"]),
        json!(["vc_jwt_issuer", "unknown"]),
        json!("malformed"),
    ] {
        assert!(!allowed(
            json!({"key_reference_purposes": {"svc-a": {"vc-key": purposes}}})
        ));
    }
    let managed_ref = crate::registry::managed_key_reference_for_fields(
        "org-a",
        "did:web:issuer.example",
        "vc_jwt_issuer",
        "SD_JWT_VC",
        "ES256",
    );
    let mut managed_profile = profile.clone();
    managed_profile["signing_service_id"] = json!("managed-openbao-transit");
    managed_profile["signing_key_reference"] = json!(managed_ref);
    let managed_service = json!({"id":"managed-openbao-transit",
            "key_purposes":["vc_jwt_issuer"], "algorithms":["ES256"]});
    assert!(crate::compat::authorize_current_issuer_binding(
        &json!({"key_reference_purposes": {}}),
        managed_service.as_object().unwrap(),
        &managed_profile,
        "org-a",
        "managed-openbao-transit",
        &managed_ref,
    )
    .is_ok());
    assert!(crate::compat::authorize_current_issuer_binding(
        &json!({"key_reference_purposes": {}}),
        managed_service.as_object().unwrap(),
        &managed_profile,
        "org-b",
        "managed-openbao-transit",
        &managed_ref,
    )
    .is_err());
    let no_vc = json!({"id":"svc-a", "key_purposes":["oid4vp_request_signing"],
            "algorithms":["ES256"]});
    assert!(crate::compat::authorize_current_issuer_binding(
        &json!({"key_reference_purposes": {}}),
        no_vc.as_object().unwrap(),
        &profile,
        "org-a",
        "svc-a",
        "vc-key",
    )
    .is_err());
}

#[tokio::test]
async fn current_validation_denies_unauthenticated_cross_tenant_and_arbitrary_signing() {
    let app = router_with_all_keys(
        "shared-internal-signing-key-32-chars".into(),
        Some("dedicated-service-sign-key-32-chars".into()),
        Some("dedicated-issuer-sign-key-32-chars".into()),
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
    );
    let route = "/v1/signing-keys/config/validate-current?organization_id=org-a";
    let body = json!({"organization_id":"org-a", "issuer_did":"did:web:issuer.example",
            "credential_format":"SD_JWT_VC"});
    let request = |body: Value, key: Option<&str>| {
        let mut builder = Request::post(route).header("content-type", "application/json");
        if let Some(key) = key {
            builder = builder.header("x-api-key", key);
        }
        builder.body(Body::from(body.to_string())).unwrap()
    };
    let key = "dedicated-service-sign-key-32-chars";
    assert_eq!(
        app.clone()
            .oneshot(request(body.clone(), None))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let mut foreign = body.clone();
    foreign["organization_id"] = json!("org-b");
    assert_eq!(
        app.clone()
            .oneshot(request(foreign, Some(key)))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        app.clone()
            .oneshot(request(
                json!({"organization_id":"org-a", "issuer_did":"did:web:issuer.example",
            "credential_format":"mso_mdoc"}),
                Some(key)
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    // Caller-selected protected purposes cannot be smuggled into the
    // fixed VC issuer probe, even when the requested format is VC_JWT.
    assert_eq!(
        app.clone()
            .oneshot(request(
                json!({"organization_id":"org-a", "issuer_did":"did:web:issuer.example",
                        "credential_format":"VC_JWT", "key_purpose":"mdoc_dsc"}),
                Some(key)
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        app.clone()
            .oneshot(request(
                json!({"organization_id":"org-a", "issuer_did":"did:web:issuer.example",
            "credential_format":"SD_JWT_VC", "payload_b64":"dGVzdA=="}),
                Some(key)
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    // A valid authenticated request reaches storage; the bare test router
    // has none and must not claim signer readiness.
    assert_eq!(
        app.oneshot(request(body, Some(key)))
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}
