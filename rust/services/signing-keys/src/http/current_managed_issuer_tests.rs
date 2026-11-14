use super::*;
use axum::body::to_bytes;
use std::sync::Mutex;

fn fixture() -> (Value, Value, Value) {
    let profile = json!({"id":"profile-a", "signing_service_id":"service-a", "signing_key_reference":"key-a"});
    let jwk = json!({"kty":"EC", "crv":"P-256", "x":"public-x", "y":"public-y"});
    let resolved = json!({"issuer_profile":profile, "public_jwk":jwk});
    (profile, resolved, jwk)
}

async fn response_value(response: Response) -> (StatusCode, Value) {
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn current_managed_identity_preserves_readbacks_and_provider_call_order() {
    let (profile, resolved, jwk) = fixture();
    let calls = Mutex::new(Vec::new());
    let current = resolve_current_managed_issuer_identity(
        &profile,
        async {
            calls.lock().unwrap().push("resolve");
            Ok(resolved.clone())
        },
        async {
            calls.lock().unwrap().push("provider");
            Ok(jwk.clone())
        },
    )
    .await
    .unwrap();
    assert_eq!(*calls.lock().unwrap(), ["resolve", "provider"]);
    assert_eq!(current.resolved, resolved);
    assert_eq!(current.current_jwk, jwk);
}

#[tokio::test]
async fn stale_or_incomplete_profile_never_polls_the_provider() {
    let (profile, resolved, _) = fixture();
    for field in ["id", "signing_service_id", "signing_key_reference"] {
        for replacement in [Value::Null, json!(""), json!("different")] {
            let mut stale = profile.clone();
            stale[field] = replacement;
            let error = resolve_current_managed_issuer_identity(
                &stale,
                async { Ok(resolved.clone()) },
                async { panic!("stale profile must fail before provider lookup") },
            )
            .await
            .err()
            .expect("stale profile refused");
            assert_eq!(
                response_value(error).await,
                (
                    StatusCode::CONFLICT,
                    json!({"detail":"Resolved issuer identity does not match its active managed profile."})
                )
            );
        }
    }
    let error = resolve_current_managed_issuer_identity(
        &profile,
        async { Ok(json!({"public_jwk":{}})) },
        async { panic!("missing resolved profile must fail before provider lookup") },
    )
    .await
    .err()
    .expect("missing profile refused");
    assert_eq!(error.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn missing_or_rotated_public_key_keeps_the_current_key_conflict() {
    let (profile, resolved, jwk) = fixture();
    for published in [
        Value::Null,
        json!({}),
        json!({"kty":"EC", "crv":"P-256", "x":"rotated-x", "y":"public-y"}),
    ] {
        let mut stale = resolved.clone();
        stale["public_jwk"] = published;
        let error = resolve_current_managed_issuer_identity(&profile, async { Ok(stale) }, async {
            Ok(jwk.clone())
        })
        .await
        .err()
        .expect("stale published key refused");
        assert_eq!(
            response_value(error).await,
            (
                StatusCode::CONFLICT,
                json!({"detail":"Published issuer identity does not match its current managed KMS key."})
            )
        );
    }
}

#[tokio::test]
async fn resolution_and_provider_errors_keep_their_complete_native_responses() {
    let (profile, resolved, _) = fixture();
    let failures: [fn() -> CompatibilityError; 11] = [
        || CompatibilityError::Unauthorized,
        || CompatibilityError::ProfileNotFound,
        || CompatibilityError::AmbiguousProfile,
        || CompatibilityError::ServiceNotFound,
        || CompatibilityError::NotFound("absent".into()),
        || CompatibilityError::BadRequest("bad request".into()),
        || CompatibilityError::Unavailable,
        || CompatibilityError::SecretCapabilityUnavailable,
        || CompatibilityError::Invalid("invalid".into()),
        || CompatibilityError::Conflict("changed".into()),
        || CompatibilityError::PreconditionFailed,
    ];
    for failure in failures {
        let expected = response_value(failure().into_response()).await;
        let error =
            resolve_current_managed_issuer_identity(&profile, async { Err(failure()) }, async {
                panic!("resolution failure must not poll the provider")
            })
            .await
            .err()
            .expect("resolution failure forwarded");
        assert_eq!(response_value(error).await, expected);
        let error = resolve_current_managed_issuer_identity(
            &profile,
            async { Ok(resolved.clone()) },
            async { Err(failure()) },
        )
        .await
        .err()
        .expect("provider failure forwarded");
        assert_eq!(response_value(error).await, expected);
    }
}
