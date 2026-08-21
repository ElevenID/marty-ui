use std::{sync::Arc, time::Duration};

use axum::{
    extract::{Path, State},
    http::HeaderMap,
    routing::get,
    Json, Router,
};
use marty_presentation_policy::{
    CredentialStatusResolver, NativePresentationControlPlane, PresentationTrustResolver,
    PresentationVerificationError,
};
use serde_json::Value;
use tokio::net::TcpListener;
use uuid::Uuid;

#[derive(Clone)]
struct Fixture {
    profile: Value,
    status: Value,
}

async fn trust_profile(
    State(fixture): State<Arc<Fixture>>,
    Path(_profile_id): Path<String>,
    headers: HeaderMap,
) -> Json<Value> {
    assert_eq!(
        headers
            .get("x-service-token")
            .and_then(|value| value.to_str().ok()),
        Some("behavioral-service-token")
    );
    Json(fixture.profile.clone())
}

async fn credential_status(
    State(fixture): State<Arc<Fixture>>,
    Path(_credential_id): Path<String>,
    headers: HeaderMap,
) -> Json<Value> {
    assert_eq!(
        headers
            .get("x-api-key")
            .and_then(|value| value.to_str().ok()),
        Some("behavioral-issuance-key")
    );
    Json(fixture.status.clone())
}

#[tokio::test]
async fn fresh_trust_and_status_reads_match_the_language_neutral_contract() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/presentation-control-plane-behavior.json"
    ))
    .unwrap();
    let fixture = Arc::new(Fixture {
        profile: contract["trust_profile"].clone(),
        status: contract["status_response"].clone(),
    });
    let app = Router::new()
        .route(
            "/internal/v1/trust-profiles/{profile_id}",
            get(trust_profile),
        )
        .route("/status/{credential_id}", get(credential_status))
        .with_state(fixture);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let base = format!("http://{address}");
    let issuer = contract["issuer_id"].as_str().unwrap();
    let control = NativePresentationControlPlane::connect_lazy(
        "http://127.0.0.1:9",
        &base,
        &format!("{base}/status/{{credential_id}}"),
        Some("behavioral-service-token"),
        Some("behavioral-issuance-key"),
        [issuer.to_owned()],
        Duration::from_secs(2),
    )
    .unwrap();
    let profile_id = contract["profile_id"].as_str().unwrap().parse().unwrap();
    let organization_id = contract["organization_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let profile = control
        .load_profile(profile_id, organization_id)
        .await
        .unwrap();
    assert_eq!(
        profile.document["resolved_verification_methods"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let trust = control.evaluate_issuer(&profile, issuer).await.unwrap();
    assert!(trust.verified);
    assert_eq!(trust.trust_level, Some(90));
    assert_eq!(trust.compliance_statuses, ["ACCREDITED"]);
    assert_eq!(trust.accreditations, ["example-accreditation"]);

    let status = control
        .resolve(
            organization_id,
            issuer,
            &[contract["credential_id"].as_str().unwrap().into()],
        )
        .await
        .unwrap();
    assert_eq!(status.not_revoked, Some(true));
    assert_eq!(status.credential_status.as_deref(), Some("active"));

    let mismatch = control
        .load_profile(profile_id, Uuid::from_u128(999))
        .await
        .expect_err("cross-tenant profile must fail closed");
    assert!(matches!(mismatch, PresentationVerificationError::Failed(_)));
    server.abort();
}

#[test]
fn invalid_native_control_plane_configuration_fails_before_startup() {
    let result = NativePresentationControlPlane::connect_lazy(
        "http://127.0.0.1:9",
        "file:///trust",
        "http://status.example/no-placeholder",
        None,
        None,
        [],
        Duration::ZERO,
    );
    assert!(matches!(
        result,
        Err(PresentationVerificationError::Failed(_))
    ));
}
