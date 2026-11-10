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

#[tokio::test]
async fn verification_sources_require_service_auth_and_exact_active_tenant_metadata() {
    let organization_id = Uuid::from_u128(1);
    let app = Router::new()
        .route("/internal/v1/organizations/{org}/credential-templates/{id}/verification-type", get(
            move |Path((org, id)): Path<(Uuid, String)>, headers: HeaderMap| async move {
                assert_eq!(org, organization_id);
                assert_eq!(headers.get("x-service-token").unwrap(), "verification-service-token");
                Json(serde_json::json!({"id":id,"organization_id":if id == "foreign" { Uuid::from_u128(99) } else { org },
                    "credential_type":"EmployeeCredential","vct":"https://issuer.example/employee","doctype":null,"status":"ACTIVE"}))
            }
        ))
        .route("/internal/v1/organizations/{org}/policy-sets/{id}", get(
            move |Path((org, id)): Path<(Uuid, Uuid)>, headers: HeaderMap| async move {
                assert_eq!(org, organization_id);
                assert_eq!(headers.get("x-service-token").unwrap(), "verification-service-token");
                let mut document = serde_json::json!({"id":id,"organization_id":org,"status":"ACTIVE","policy_type":"CREDENTIAL_VERIFICATION","cedar_schema_version":"MIP/1.0", "cedar_policies":[
                    {"policy_id":"allowed","enabled":true,"cedar_text":"permit(principal, action, resource);"},
                    {"policy_id":"disabled","enabled":false,"cedar_text":"forbid(principal, action, resource);"}
                ]});
                match id.as_u128() {
                    3 => document["organization_id"] = serde_json::json!(Uuid::from_u128(99)),
                    4 => document["status"] = "ARCHIVED".into(),
                    5 => document["policy_type"] = "CUSTOM".into(),
                    6 => document["cedar_schema_version"] = "MIP/99".into(),
                    7 => document["id"] = serde_json::json!(Uuid::from_u128(99)),
                    8 => document["cedar_policies"] = serde_json::json!([]),
                    9 => document["cedar_policies"][1]["policy_id"] = "allowed".into(),
                    10 => document["cedar_policies"][0]["enabled"] = Value::Null,
                    _ => {},
                }
                Json(document)
            }
        ));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let control = |token| {
        NativePresentationControlPlane::connect_lazy(
            "http://127.0.0.1:9",
            &base,
            &format!("{base}/status/{{credential_id}}"),
            token,
            None,
            Duration::from_secs(2),
        )
        .unwrap()
        .with_verification_sources(&base, &base)
        .unwrap()
    };
    let unauthenticated = control(None);
    assert!(unauthenticated
        .load_credential_template("employee", organization_id)
        .await
        .is_err());
    assert!(unauthenticated
        .load_verification_policy(Uuid::from_u128(2), organization_id)
        .await
        .is_err());
    let control = control(Some("verification-service-token"));
    let template = control
        .load_credential_template("employee", organization_id)
        .await
        .unwrap();
    assert_eq!(
        template.vct.as_deref(),
        Some("https://issuer.example/employee")
    );
    assert!(control
        .load_credential_template("foreign", organization_id)
        .await
        .is_err());
    assert!(control
        .load_credential_template("..", organization_id)
        .await
        .is_err());
    let policy = control
        .load_verification_policy(Uuid::from_u128(2), organization_id)
        .await
        .unwrap();
    assert_eq!(
        policy.cedar_policies,
        "permit(principal, action, resource);"
    );
    assert!(policy.revision.starts_with("sha256:"));
    for id in 3..=10 {
        assert!(
            control
                .load_verification_policy(Uuid::from_u128(id), organization_id)
                .await
                .is_err(),
            "source case {id}"
        );
    }
    server.abort();
}

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

mod managed_authority_http {
    use super::*;
    use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

    use chrono::Utc;
    use marty_oid4vp_contract::{
        digest_domain_json,
        managed_status::{
            digest_managed_status_observation, ManagedCredentialStatusObservationV1,
            ManagedCredentialStatusRequestV1, ManagedCredentialStatusState,
            MANAGED_STATUS_AUTHORITY, MANAGED_STATUS_CONTRACT, MANAGED_STATUS_OBSERVATION_PATH,
        },
        trust_authority::{
            credential_authority_basis_digest, credential_authority_snapshot_digest,
            credential_trust_evaluation_digest, issuer_public_key_thumbprint,
            CredentialAuthoritySnapshotV1, CredentialTrustEvaluationRequestV1,
            CredentialTrustEvaluationResponseV1, CREDENTIAL_AUTHORITY_SNAPSHOT_CONTRACT,
            CREDENTIAL_TRUST_EVALUATION_CONTRACT,
        },
        EvidenceCheckOutcome,
    };
    use serde_json::json;

    const TOKEN: &str = "loopback-authority-service-token";
    const API_KEY: &str = "loopback-issuance-management-key";

    struct AuthorityFixture {
        snapshot: CredentialAuthoritySnapshotV1,
        selection: CredentialTrustEvaluationRequestV1,
        status_request: ManagedCredentialStatusRequestV1,
        // 0: exact; 1: revision conflict; 2: valid but crossed scope; 3: expired.
        mode: AtomicU8,
        reads: AtomicUsize,
    }

    impl AuthorityFixture {
        fn new() -> Self {
            let organization_id = Uuid::from_u128(101).to_string();
            let profile_id = Uuid::from_u128(102).to_string();
            let issuer_id = "https://issuer.example.test/Tenant-A";
            let vct = "https://credentials.example.test/Employee";
            let key = json!({"kty":"OKP","crv":"Ed25519","alg":"EdDSA","use":"sig",
                "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"});
            let basis = serde_json::from_value(json!({
                "id":profile_id,"organization_id":organization_id,"status":"active","compliance_status":"COMPLIANT",
                "trust_purposes":["CREDENTIAL_ISSUER"],"supported_formats":["SD_JWT_VC"],"allowed_algorithms":["EdDSA"],
                "allowed_issuers":null,"denied_issuers":[],"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z",
                "policy_controls":{
                    "validation_rules":{"min_key_size_rsa":2048,"min_key_size_ec":256,"require_key_usage":true,"max_chain_depth":5,"allow_self_signed":false},
                    "time_policy":{"max_clock_skew_seconds":300,"credential_freshness_hours":null,"require_not_before":true,"require_expiration":true},
                    "revocation_policy":{"check_mode":"HARD_FAIL","check_ocsp":false,"check_crl":false,"check_status_list":false,"offline_grace_period_hours":0,"cache_duration_hours":0},
                    "trusted_assertion_formats":["JWT"],"unsupported_configuration_fields":[],
                    "unsupported_configuration_digest":digest_domain_json("marty.trust-profile/unsupported-credential-authority-configuration/v1", &json!({})).unwrap()
                },
                "issuer_relationships":[{
                    "relationship_id":Uuid::from_u128(103),"issuer_entity_id":Uuid::from_u128(104),"issuer_id":issuer_id,
                    "issuer_organization_id":organization_id,"is_system_issuer":false,"relationship_status":"TRUSTED",
                    "trust_level":80,"compliance_status":"COMPLIANT","accreditations":["example-accreditation"],
                    "valid_from":"2026-01-01T00:00:00Z","valid_until":null,"revoked_at":null,"verification_keys":[key],
                    "credential_authorizations":[{"format":"SD_JWT_VC","vct":vct}],
                    "issuer_created_at":"2026-01-01T00:00:00Z","issuer_updated_at":"2026-01-01T00:00:00Z",
                    "relationship_created_at":"2026-01-01T00:00:00Z","relationship_updated_at":"2026-01-01T00:00:00Z"
                }]
            })).unwrap();
            let mut snapshot = CredentialAuthoritySnapshotV1 {
                contract: CREDENTIAL_AUTHORITY_SNAPSHOT_CONTRACT.into(),
                organization_id: organization_id.clone(),
                profile: marty_oid4vp_contract::EvidenceProfileReference {
                    id: profile_id,
                    version: 7,
                    content_digest: credential_authority_basis_digest(&basis).unwrap(),
                },
                basis,
                response_digest: String::new(),
            };
            snapshot.response_digest = credential_authority_snapshot_digest(&snapshot).unwrap();
            snapshot.validate().unwrap();
            let selection = CredentialTrustEvaluationRequestV1 {
                organization_id: organization_id.clone(),
                expected_profile: snapshot.profile.clone(),
                issuer_id: issuer_id.into(),
                format: "SD_JWT_VC".into(),
                vct: vct.into(),
                issuer_algorithm: "EdDSA".into(),
                issuer_key_thumbprint: issuer_public_key_thumbprint(&key).unwrap(),
                request_binding_digest: format!("sha256:{}", "a".repeat(64)),
            };
            let status_request = ManagedCredentialStatusRequestV1 {
                organization_id,
                issuer_id: issuer_id.into(),
                credential_id: "urn:uuid:managed-credential-1".into(),
                credential_template_id: Uuid::from_u128(105).to_string(),
                issuer_jwt_digest: format!("sha256:{}", "b".repeat(64)),
                request_binding_digest: selection.request_binding_digest.clone(),
                max_age_seconds: 60,
            };
            Self {
                snapshot,
                selection,
                status_request,
                mode: AtomicU8::new(0),
                reads: AtomicUsize::new(0),
            }
        }

        fn trust_response(&self) -> CredentialTrustEvaluationResponseV1 {
            let request = &self.selection;
            let checked = Utc::now().timestamp()
                - if self.mode.load(Ordering::SeqCst) == 3 {
                    120
                } else {
                    0
                };
            let mut response = CredentialTrustEvaluationResponseV1 {
                contract: CREDENTIAL_TRUST_EVALUATION_CONTRACT.into(),
                organization_id: request.organization_id.clone(),
                profile: request.expected_profile.clone(),
                issuer_id: request.issuer_id.clone(),
                format: request.format.clone(),
                vct: request.vct.clone(),
                issuer_algorithm: request.issuer_algorithm.clone(),
                issuer_key_thumbprint: request.issuer_key_thumbprint.clone(),
                request_binding_digest: request.request_binding_digest.clone(),
                outcome: EvidenceCheckOutcome::Passed,
                reason_code: "TRUST_PROFILE.CREDENTIAL_AUTHORIZED".into(),
                trust_level: Some(80),
                compliance_statuses: vec!["COMPLIANT".into()],
                accreditations: vec!["example-accreditation".into()],
                checked_at_epoch_seconds: checked,
                valid_until_epoch_seconds: checked + 60,
                evidence_digest: String::new(),
            };
            if self.mode.load(Ordering::SeqCst) == 2 {
                response.issuer_id = "https://issuer.example.test/tenant-a".into();
            }
            response.evidence_digest = credential_trust_evaluation_digest(&response).unwrap();
            response.validate().unwrap();
            response
        }
    }

    fn request_headers(headers: &HeaderMap, fixture: &AuthorityFixture, trust: bool) {
        assert_eq!(headers["accept"], "application/json");
        assert_eq!(headers["content-type"], "application/json");
        if trust {
            assert_eq!(headers["x-service-token"], TOKEN);
            assert!(!headers.contains_key("x-api-key"));
            assert!(!headers.contains_key("x-organization-id"));
        } else {
            assert_eq!(headers["x-api-key"], API_KEY);
            assert_eq!(
                headers["x-organization-id"],
                fixture.status_request.organization_id
            );
            assert!(!headers.contains_key("x-service-token"));
        }
        fixture.reads.fetch_add(1, Ordering::SeqCst);
    }

    async fn freeze(
        State(fixture): State<Arc<AuthorityFixture>>,
        Path(id): Path<String>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> Json<CredentialAuthoritySnapshotV1> {
        request_headers(&headers, &fixture, true);
        assert_eq!(id, fixture.snapshot.profile.id);
        assert_eq!(
            body,
            json!({"organization_id":fixture.snapshot.organization_id})
        );
        let mut snapshot = fixture.snapshot.clone();
        if fixture.mode.load(Ordering::SeqCst) == 2 {
            snapshot.organization_id = Uuid::from_u128(999).to_string();
            snapshot
                .basis
                .organization_id
                .clone_from(&snapshot.organization_id);
            snapshot.basis.issuer_relationships[0].issuer_organization_id =
                Some(snapshot.organization_id.clone());
            snapshot.profile.content_digest =
                credential_authority_basis_digest(&snapshot.basis).unwrap();
            snapshot.response_digest = credential_authority_snapshot_digest(&snapshot).unwrap();
        }
        snapshot.validate().unwrap();
        Json(snapshot)
    }

    async fn assess(
        State(fixture): State<Arc<AuthorityFixture>>,
        Path(id): Path<String>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> Response {
        request_headers(&headers, &fixture, true);
        assert_eq!(id, fixture.selection.expected_profile.id);
        assert_eq!(body, json!(fixture.selection));
        if fixture.mode.load(Ordering::SeqCst) == 1 {
            return StatusCode::CONFLICT.into_response();
        }
        Json(fixture.trust_response()).into_response()
    }

    async fn status(
        State(fixture): State<Arc<AuthorityFixture>>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> Json<ManagedCredentialStatusObservationV1> {
        request_headers(&headers, &fixture, false);
        assert_eq!(body, json!(fixture.status_request));
        let checked = Utc::now().timestamp()
            - if fixture.mode.load(Ordering::SeqCst) == 3 {
                120
            } else {
                0
            };
        let mut observation = ManagedCredentialStatusObservationV1 {
            contract: MANAGED_STATUS_CONTRACT.into(),
            authority: MANAGED_STATUS_AUTHORITY.into(),
            request: fixture.status_request.clone(),
            state: ManagedCredentialStatusState::Active,
            status_updated_at_epoch_seconds: checked - 1,
            checked_at_epoch_seconds: checked,
            valid_until_epoch_seconds: checked + 60,
            credential_expires_at_epoch_seconds: checked + 3600,
            evidence_digest: String::new(),
        };
        if fixture.mode.load(Ordering::SeqCst) == 2 {
            observation.request.credential_id = "urn:uuid:different-managed-credential".into();
        }
        observation.evidence_digest = digest_managed_status_observation(&observation).unwrap();
        observation
            .validate_for_request(&observation.request, checked)
            .unwrap();
        Json(observation)
    }

    async fn serve() -> (Arc<AuthorityFixture>, String, tokio::task::JoinHandle<()>) {
        let fixture = Arc::new(AuthorityFixture::new());
        let app = Router::new()
            .route(
                "/internal/v1/trust-profiles/{profile_id}/credential-authority-snapshot",
                axum::routing::post(freeze),
            )
            .route(
                "/internal/v1/trust-profiles/{profile_id}/credential-trust-evaluations",
                axum::routing::post(assess),
            )
            .route(MANAGED_STATUS_OBSERVATION_PATH, axum::routing::post(status))
            .with_state(fixture.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (fixture, base, server)
    }

    fn control(
        base: &str,
        token: Option<&str>,
        api_key: Option<&str>,
    ) -> NativePresentationControlPlane {
        NativePresentationControlPlane::connect_lazy(
            "http://127.0.0.1:9",
            base,
            &format!("{base}/v1/issuance/credentials/{{credential_id}}/status"),
            token,
            api_key,
            Duration::from_secs(2),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn authority_posts_preserve_owner_routes_credentials_and_exact_scoped_bodies() {
        let (fixture, base, server) = serve().await;
        let client = control(&base, Some(TOKEN), Some(API_KEY));
        let frozen = client
            .freeze_credential_authority(
                fixture.snapshot.organization_id.parse().unwrap(),
                fixture.snapshot.profile.id.parse().unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(frozen, fixture.snapshot);
        let trust = client
            .evaluate_credential_authority(&fixture.selection)
            .await
            .unwrap();
        assert_eq!(trust.outcome, EvidenceCheckOutcome::Passed);
        assert_eq!(trust.profile, frozen.profile);
        assert_eq!(trust.trust_level, Some(80));
        assert_eq!(trust.accreditations, ["example-accreditation"]);
        let observed = client
            .observe_managed_status(&fixture.status_request)
            .await
            .unwrap();
        assert_eq!(observed.request, fixture.status_request);
        assert_eq!(observed.state, ManagedCredentialStatusState::Active);
        assert_eq!(fixture.reads.load(Ordering::SeqCst), 3);
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn authority_posts_reject_conflicts_crossed_scope_expiry_and_missing_local_credentials() {
        let (fixture, base, server) = serve().await;
        let client = control(&base, Some(TOKEN), Some(API_KEY));
        fixture.mode.store(1, Ordering::SeqCst);
        assert!(matches!(
            client
                .evaluate_credential_authority(&fixture.selection)
                .await,
            Err(PresentationVerificationError::CredentialAuthorityChanged)
        ));
        fixture.mode.store(2, Ordering::SeqCst);
        assert!(matches!(
            client
                .freeze_credential_authority(
                    fixture.snapshot.organization_id.parse().unwrap(),
                    fixture.snapshot.profile.id.parse().unwrap()
                )
                .await,
            Err(PresentationVerificationError::Failed(_))
        ));
        assert!(matches!(
            client
                .evaluate_credential_authority(&fixture.selection)
                .await,
            Err(PresentationVerificationError::Failed(_))
        ));
        assert!(matches!(
            client.observe_managed_status(&fixture.status_request).await,
            Err(PresentationVerificationError::Failed(_))
        ));
        fixture.mode.store(3, Ordering::SeqCst);
        assert!(matches!(
            client
                .evaluate_credential_authority(&fixture.selection)
                .await,
            Err(PresentationVerificationError::Failed(_))
        ));
        assert!(matches!(
            client.observe_managed_status(&fixture.status_request).await,
            Err(PresentationVerificationError::Failed(_))
        ));
        assert_eq!(fixture.reads.load(Ordering::SeqCst), 6);

        let unconfigured = control(&base, None, None);
        assert!(matches!(
            unconfigured
                .freeze_credential_authority(
                    fixture.snapshot.organization_id.parse().unwrap(),
                    fixture.snapshot.profile.id.parse().unwrap()
                )
                .await,
            Err(PresentationVerificationError::Unavailable)
        ));
        assert!(matches!(
            unconfigured
                .evaluate_credential_authority(&fixture.selection)
                .await,
            Err(PresentationVerificationError::Unavailable)
        ));
        assert!(matches!(
            unconfigured
                .observe_managed_status(&fixture.status_request)
                .await,
            Err(PresentationVerificationError::Unavailable)
        ));
        assert_eq!(
            fixture.reads.load(Ordering::SeqCst),
            6,
            "missing credentials must fail before owner reads"
        );
        server.abort();
        let _ = server.await;
    }
}
