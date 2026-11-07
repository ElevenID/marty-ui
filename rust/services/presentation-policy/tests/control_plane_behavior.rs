use std::{collections::BTreeMap, sync::Arc, time::Duration};

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use marty_presentation_policy::{
    CredentialStatusResolver, NativePresentationControlPlane, PresentationTrustResolver,
    PresentationVerificationError,
};
use marty_verification::credential_format::DetectedCredentialFormat;
use serde_json::Value;
use tokio::net::TcpListener;
use uuid::Uuid;

#[derive(Clone)]
struct Fixture {
    profile: Value,
    organization_id: String,
    statuses: BTreeMap<String, Value>,
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
    Path(credential_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    assert_eq!(
        headers
            .get("x-api-key")
            .and_then(|value| value.to_str().ok()),
        Some("behavioral-issuance-key")
    );
    assert_eq!(
        headers
            .get("x-organization-id")
            .and_then(|value| value.to_str().ok()),
        Some(fixture.organization_id.as_str())
    );
    fixture.statuses.get(&credential_id).map_or_else(
        || StatusCode::NOT_FOUND.into_response(),
        |status| Json(status.clone()).into_response(),
    )
}

#[tokio::test]
async fn fresh_trust_and_status_reads_match_the_language_neutral_contract() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/presentation-control-plane-behavior.json"
    ))
    .unwrap();
    let organization_id = contract["organization_id"].as_str().unwrap();
    let fixture = Arc::new(Fixture {
        profile: contract["trust_profile"].clone(),
        organization_id: organization_id.into(),
        statuses: BTreeMap::from([
            (
                contract["credential_id"].as_str().unwrap().into(),
                contract["status_response"].clone(),
            ),
            (
                "suspended".into(),
                serde_json::json!({"issuer_did": contract["issuer_id"], "status": "suspended"}),
            ),
            (
                "revoked".into(),
                serde_json::json!({"issuer_did": contract["issuer_id"], "status": "revoked"}),
            ),
            (
                "mismatched-issuer".into(),
                serde_json::json!({"issuer_did": "did:web:issuer.example:orgs:other", "status": "active"}),
            ),
            (
                "missing-issuer".into(),
                serde_json::json!({"status": "active"}),
            ),
            (
                "url-case-match".into(),
                serde_json::json!({"issuer_did": "https://ISSUER.EXAMPLE/Org/Acme/", "status": "active"}),
            ),
            (
                "url-path-case-mismatch".into(),
                serde_json::json!({"issuer_did": "https://issuer.example/org/acme", "status": "active"}),
            ),
        ]),
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
        Duration::from_secs(2),
    )
    .unwrap();
    let profile_id = contract["profile_id"].as_str().unwrap().parse().unwrap();
    let organization_id = organization_id.parse().unwrap();
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
    let trust = control
        .evaluate_issuer(&profile, issuer, DetectedCredentialFormat::W3cVc)
        .await
        .unwrap();
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

    for (credential_id, expected_status) in [("suspended", "suspended"), ("revoked", "revoked")] {
        let status = control
            .resolve(organization_id, issuer, &[credential_id.into()])
            .await
            .unwrap();
        assert_eq!(status.not_revoked, Some(false));
        assert_eq!(status.credential_status.as_deref(), Some(expected_status));
    }
    for credential_id in ["mismatched-issuer", "missing-issuer", "not-found"] {
        let status = control
            .resolve(organization_id, issuer, &[credential_id.into()])
            .await
            .unwrap();
        assert_eq!(status, Default::default());
    }
    let normalized_url_status = control
        .resolve(
            organization_id,
            "https://issuer.example/Org/Acme",
            &["url-case-match".into()],
        )
        .await
        .unwrap();
    assert_eq!(normalized_url_status.not_revoked, Some(true));
    let path_case_mismatch = control
        .resolve(
            organization_id,
            "https://issuer.example/Org/Acme",
            &["url-path-case-mismatch".into()],
        )
        .await
        .unwrap();
    assert_eq!(path_case_mismatch, Default::default());
    assert_eq!(
        contract["status_resolution"]["issuer_binding"],
        "exact_normalized_identifier"
    );
    assert_eq!(contract["status_resolution"]["dynamic_issuers"], true);

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
        Duration::ZERO,
    );
    assert!(matches!(
        result,
        Err(PresentationVerificationError::Failed(_))
    ));
}

#[tokio::test]
async fn ca_verified_organization_client_rejects_plaintext() {
    let result = NativePresentationControlPlane::connect_with_ca(
        "http://organization:9002",
        std::path::Path::new("unused-public-ca.pem"),
        "http://trust-profile:8004",
        "http://issuance:8005/v1/issuance/credentials/{credential_id}/status",
        Some(&"s".repeat(32)),
        None,
        Duration::from_secs(1),
    )
    .await;
    assert!(matches!(
        result,
        Err(PresentationVerificationError::Failed(_))
    ));
}

#[tokio::test]
async fn authenticated_mdoc_status_requires_exact_reference_and_certificate_then_reports_active_or_revoked(
) {
    let organization_id = Uuid::from_u128(2);
    let issuer = format!("x509-sha256:{}", "a".repeat(64));
    let refs = (0..5)
        .map(|i| {
            format!(
                "urn:mdoc-status:v1:{}:{}",
                "a".repeat(64),
                format!("{i:x}").repeat(64)
            )
        })
        .collect::<Vec<_>>();
    let fixture = Arc::new(Fixture {
        profile: Value::Null,
        organization_id: organization_id.to_string(),
        statuses: BTreeMap::from([
            (
                refs[0].clone(),
                serde_json::json!({"id":"owned","mdoc_status_reference":refs[0],"issuer_did":"did:web:issuer.invalid","status":"active"}),
            ),
            (
                refs[1].clone(),
                serde_json::json!({"id":"owned","mdoc_status_reference":refs[1],"status":"revoked"}),
            ),
            (
                refs[2].clone(),
                serde_json::json!({"id":"owned","mdoc_status_reference":refs[0],"status":"active"}),
            ),
            (
                refs[3].clone(),
                serde_json::json!({"id":"owned","issuer_did":issuer,"status":"active"}),
            ),
            (
                refs[4].clone(),
                serde_json::json!({"id":"","mdoc_status_reference":refs[4],"status":"active"}),
            ),
        ]),
    });
    let app = Router::new()
        .route("/status/{credential_id}", get(credential_status))
        .with_state(fixture);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let control = NativePresentationControlPlane::connect_lazy(
        "http://127.0.0.1:9",
        &format!("http://{address}"),
        &format!("http://{address}/status/{{credential_id}}"),
        None,
        Some("behavioral-issuance-key"),
        Duration::from_secs(2),
    )
    .unwrap();
    let active = control
        .resolve(organization_id, &issuer, &[refs[0].clone()])
        .await
        .unwrap();
    assert_eq!(active.not_revoked, Some(true));
    assert!(active.checked_at_epoch_seconds.is_some());
    let revoked = control
        .resolve(organization_id, &issuer, &[refs[1].clone()])
        .await
        .unwrap();
    assert_eq!(revoked.not_revoked, Some(false));
    assert_eq!(revoked.credential_status.as_deref(), Some("revoked"));
    for reference in &refs[2..] {
        assert_eq!(
            control
                .resolve(organization_id, &issuer, std::slice::from_ref(reference))
                .await
                .unwrap(),
            Default::default()
        );
    }
    assert_eq!(
        control
            .resolve(
                organization_id,
                &format!("x509-sha256:{}", "c".repeat(64)),
                &[refs[0].clone()]
            )
            .await
            .unwrap(),
        Default::default()
    );
    let unknown = format!("urn:mdoc-status:v1:{}:{}", "a".repeat(64), "f".repeat(64));
    assert_eq!(
        control
            .resolve(organization_id, &issuer, &[unknown])
            .await
            .unwrap(),
        Default::default()
    );
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn configured_dependency_redirects_never_receive_service_or_tenant_credentials() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let redirected = Arc::new(AtomicUsize::new(0));
    let observed = redirected.clone();
    let app = Router::new()
        .route(
            "/internal/v1/trust-profiles/{profile_id}",
            get(|| async { axum::response::Redirect::temporary("/redirect-target") }),
        )
        .route(
            "/status/{credential_id}",
            get(|| async { axum::response::Redirect::temporary("/redirect-target") }),
        )
        .route(
            "/redirect-target",
            get(move || {
                observed.fetch_add(1, Ordering::SeqCst);
                async { Json(serde_json::json!({"status":"active"})) }
            }),
        );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let control = NativePresentationControlPlane::connect_lazy(
        "http://127.0.0.1:9",
        &base,
        &format!("{base}/status/{{credential_id}}"),
        Some("service-secret"),
        Some("tenant-secret"),
        Duration::from_secs(2),
    )
    .unwrap();
    assert!(matches!(
        control.load_profile(Uuid::new_v4(), Uuid::new_v4()).await,
        Err(PresentationVerificationError::Unavailable)
    ));
    assert!(matches!(
        control
            .resolve(
                Uuid::new_v4(),
                "did:web:issuer.example",
                &["credential".into()]
            )
            .await,
        Err(PresentationVerificationError::Unavailable)
    ));
    assert_eq!(redirected.load(Ordering::SeqCst), 0);
    server.abort();
}

#[tokio::test]
async fn configured_dependency_bodies_are_bounded_with_and_without_content_length() {
    use axum::body::{Body, Bytes};
    let profile_id = Uuid::new_v4();
    let organization_id = Uuid::new_v4();
    for chunked in [false, true] {
        let oversized_profile = serde_json::json!({
            "id":profile_id, "organization_id":organization_id, "status":"active",
            "issuer_relationships":[], "padding":"x".repeat(2 * 1024 * 1024),
        })
        .to_string();
        let oversized_status = serde_json::json!({
            "issuer_did":"did:web:issuer.example", "status":"active", "padding":"x".repeat(64 * 1024),
        }).to_string();
        let response = move |body: String| {
            let body = if chunked {
                Body::from_stream(tokio_stream::iter(
                    body.as_bytes()
                        .chunks(4096)
                        .map(|chunk| {
                            Ok::<_, std::convert::Infallible>(Bytes::copy_from_slice(chunk))
                        })
                        .collect::<Vec<_>>(),
                ))
            } else {
                Body::from(body)
            };
            Response::builder()
                .header("content-type", "application/json")
                .body(body)
                .unwrap()
        };
        let app = Router::new()
            .route(
                "/internal/v1/trust-profiles/{profile_id}",
                get(move || {
                    let body = oversized_profile.clone();
                    async move { response(body) }
                }),
            )
            .route(
                "/status/{credential_id}",
                get(move || {
                    let body = oversized_status.clone();
                    async move { response(body) }
                }),
            );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let control = NativePresentationControlPlane::connect_lazy(
            "http://127.0.0.1:9",
            &base,
            &format!("{base}/status/{{credential_id}}"),
            Some("service-secret"),
            Some("tenant-secret"),
            Duration::from_secs(2),
        )
        .unwrap();
        assert!(
            matches!(
                control.load_profile(profile_id, organization_id).await,
                Err(PresentationVerificationError::Unavailable)
            ),
            "chunked={chunked}"
        );
        assert!(
            matches!(
                control
                    .resolve(
                        organization_id,
                        "did:web:issuer.example",
                        &["credential".into()]
                    )
                    .await,
                Err(PresentationVerificationError::Unavailable)
            ),
            "chunked={chunked}"
        );
        server.abort();
    }
}

#[tokio::test]
async fn configured_dependency_timeout_is_enforced_for_trust_and_status_reads() {
    let pending = || async {
        std::future::pending::<()>().await;
        Json(serde_json::json!({}))
    };
    let app = Router::new()
        .route("/internal/v1/trust-profiles/{profile_id}", get(pending))
        .route("/status/{credential_id}", get(pending));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let control = NativePresentationControlPlane::connect_lazy(
        "http://127.0.0.1:9",
        &base,
        &format!("{base}/status/{{credential_id}}"),
        None,
        None,
        Duration::from_millis(50),
    )
    .unwrap();
    assert!(matches!(
        control.load_profile(Uuid::new_v4(), Uuid::new_v4()).await,
        Err(PresentationVerificationError::Unavailable)
    ));
    assert!(matches!(
        control
            .resolve(
                Uuid::new_v4(),
                "did:web:issuer.example",
                &["credential".into()]
            )
            .await,
        Err(PresentationVerificationError::Unavailable)
    ));
    server.abort();
}

#[tokio::test]
async fn configured_endpoints_reject_credentials_fragments_and_identifier_host_templates() {
    for (trust, status) in [
        (
            "http://user:secret@127.0.0.1",
            "http://127.0.0.1/status/{credential_id}",
        ),
        (
            "http://127.0.0.1#fragment",
            "http://127.0.0.1/status/{credential_id}",
        ),
        (
            "http://127.0.0.1?query=true",
            "http://127.0.0.1/status/{credential_id}",
        ),
        ("http://127.0.0.1", "http://{credential_id}.example/status"),
        (
            "http://127.0.0.1",
            "http://user:secret@127.0.0.1/status/{credential_id}",
        ),
        (
            "http://127.0.0.1",
            "http://127.0.0.1/status/{credential_id}#fragment",
        ),
        (
            "http://127.0.0.1",
            "http://127.0.0.1/status/{credential_id}/{credential_id}",
        ),
    ] {
        assert!(
            NativePresentationControlPlane::connect_lazy(
                "http://127.0.0.1:9",
                trust,
                status,
                None,
                None,
                Duration::from_secs(1),
            )
            .is_err(),
            "{trust} {status}"
        );
    }
}

#[tokio::test]
async fn credential_dot_segments_never_change_the_configured_status_route() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let requests = Arc::new(AtomicUsize::new(0));
    let observed = requests.clone();
    let app = Router::new().fallback(get(move |uri: axum::http::Uri| {
        observed.fetch_add(1, Ordering::SeqCst);
        assert_eq!(uri.path(), "/status/known-credential");
        async {
            Json(serde_json::json!({"issuer_did":"did:web:issuer.example", "status":"active"}))
        }
    }));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let control = NativePresentationControlPlane::connect_lazy(
        "http://127.0.0.1:9",
        &base,
        &format!("{base}/status/{{credential_id}}"),
        None,
        Some("tenant-secret"),
        Duration::from_secs(2),
    )
    .unwrap();
    let organization_id = Uuid::new_v4();
    let unavailable = control
        .resolve(
            organization_id,
            "did:web:issuer.example",
            &[".".into(), "..".into()],
        )
        .await
        .unwrap();
    assert_eq!(unavailable, Default::default());
    assert_eq!(requests.load(Ordering::SeqCst), 0);
    let status = control
        .resolve(
            organization_id,
            "did:web:issuer.example",
            &[".".into(), "..".into(), "known-credential".into()],
        )
        .await
        .unwrap();
    assert_eq!(status.not_revoked, Some(true));
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    server.abort();
}
