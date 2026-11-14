use super::*;
use axum::{extract::Path, http::HeaderMap, response::IntoResponse, routing::post, Json, Router};
use std::sync::{Arc, Mutex};

const DID: &str = "did:web:203.0.113.42%3A8443:orgs:retained-issuer";

fn document() -> Value {
    json!({
        "id": DID,
        "verificationMethod": [
            {"id": format!("{DID}#assertion"), "controller": DID, "type": "JsonWebKey2020",
                "publicKeyJwk": {"kty":"EC", "crv":"P-256", "x":"public-x", "y":"public-y"}},
            {"id": format!("{DID}#authentication"), "controller": DID, "type": "JsonWebKey2020",
                "publicKeyJwk": {"kty":"EC", "crv":"P-256", "x":"other-x", "y":"other-y"}}
        ],
        "assertionMethod": [format!("{DID}#assertion")],
        "authentication": [format!("{DID}#authentication")]
    })
}

type Observations = Arc<Mutex<Vec<(String, Value)>>>;

async fn server(
    status: StatusCode,
    raw: String,
) -> (String, Observations, tokio::task::JoinHandle<()>) {
    let calls: Observations = Arc::default();
    let received = Arc::clone(&calls);
    let redirected = Arc::clone(&calls);
    let app = Router::new()
        .route(
            "/internal/documents/{organization}/did/load",
            post(
                move |Path(organization): Path<String>,
                      headers: HeaderMap,
                      Json(body): Json<Value>| {
                    let received = Arc::clone(&received);
                    let raw = raw.clone();
                    async move {
                        assert_eq!(headers["x-api-key"], "private-test-credential");
                        received.lock().unwrap().push((organization, body));
                        (
                            status,
                            [
                                ("content-type", "application/json"),
                                ("location", "/redirected"),
                            ],
                            raw,
                        )
                            .into_response()
                    }
                },
            ),
        )
        .fallback(move || {
            let redirected = Arc::clone(&redirected);
            async move {
                redirected
                    .lock()
                    .unwrap()
                    .push(("redirect-followed".into(), json!(null)));
                StatusCode::OK
            }
        });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (base, calls, task)
}

#[tokio::test]
async fn exact_scoped_publication_preserves_old_ipv4_identity_without_public_network_lookup() {
    let doc = document();
    let (base, calls, task) = server(
        StatusCode::OK,
        json!({"found":true,"document":doc}).to_string(),
    )
    .await;
    let resolver =
        HttpScopedIssuerKeyResolver::new(&base, "private-test-credential", Duration::from_secs(2))
            .unwrap();
    let resolution = resolver.resolve("org-a", DID).await.unwrap().unwrap();
    assert_eq!(
        calls.lock().unwrap().as_slice(),
        &[("org-a".into(), json!({"did_id":DID}))]
    );
    assert_eq!(resolution.verification_keys.len(), 1);
    assert_eq!(
        resolution.verification_keys[0]["kid"],
        format!("{DID}#assertion")
    );
    assert_eq!(resolution.source, "organization_published_did_document");
    assert_eq!(
        resolution.content_sha256,
        format!("{:x}", Sha256::digest(serde_json::to_vec(&doc).unwrap()))
    );
    assert!(chrono::DateTime::parse_from_rfc3339(&resolution.retrieved_at).is_ok());
    assert!(!format!("{resolver:?} {resolution:?}").contains("private-test-credential"));
    task.abort();
}

#[tokio::test]
async fn only_explicit_authenticated_missing_document_is_a_miss() {
    let (base, calls, task) = server(
        StatusCode::OK,
        json!({"found":false,"document":{}}).to_string(),
    )
    .await;
    let resolver =
        HttpScopedIssuerKeyResolver::new(&base, "private-test-credential", Duration::from_secs(2))
            .unwrap();
    assert_eq!(resolver.resolve("org-a", DID).await.unwrap(), None);
    assert_eq!(calls.lock().unwrap().len(), 1);
    task.abort();
}

#[tokio::test]
async fn invalid_scope_is_rejected_before_contacting_the_configured_owner() {
    let (base, calls, task) = server(
        StatusCode::OK,
        json!({"found":true,"document":document()}).to_string(),
    )
    .await;
    let resolver =
        HttpScopedIssuerKeyResolver::new(&base, "private-test-credential", Duration::from_secs(2))
            .unwrap();
    for (organization, did) in [
        ("", DID),
        (" org-a", DID),
        ("..", DID),
        ("other/org", DID),
        ("%2E%2E", DID),
        ("org-a", "https://untrusted.test"),
        ("org-a", "did:web:issuer.test#key"),
    ] {
        assert_eq!(
            resolver.resolve(organization, did).await,
            Err(IssuerKeyResolutionError::Invalid)
        );
    }
    assert!(calls.lock().unwrap().is_empty());
    task.abort();
}

#[tokio::test]
async fn failed_or_redirected_owner_is_never_treated_as_an_absent_document() {
    for status in [
        StatusCode::UNAUTHORIZED,
        StatusCode::FORBIDDEN,
        StatusCode::NOT_FOUND,
        StatusCode::FOUND,
        StatusCode::SERVICE_UNAVAILABLE,
    ] {
        let (base, calls, task) = server(
            status,
            json!({"found":false,"document":{"id":DID}}).to_string(),
        )
        .await;
        let resolver = HttpScopedIssuerKeyResolver::new(
            &base,
            "private-test-credential",
            Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(
            resolver.resolve("org-a", DID).await,
            Err(if status.is_server_error() {
                IssuerKeyResolutionError::Unavailable
            } else {
                IssuerKeyResolutionError::Invalid
            })
        );
        assert_eq!(
            calls.lock().unwrap().len(),
            1,
            "must never follow a redirect"
        );
        task.abort();
    }
}

#[tokio::test]
async fn malformed_or_wrong_identity_publication_never_falls_back() {
    let mut cases = vec![
        json!({}),
        json!({"found":true}),
        json!({"found":"false","document":{"id":DID}}),
        json!({"found":true,"document":document(),"unexpected":true}),
    ];
    for failure in [
        "wrong-id",
        "no-assertion",
        "foreign-controller",
        "foreign-key-id",
        "private-key",
        "private-custody",
        "missing-coordinate",
        "duplicate-method",
        "conflicting-inline",
        "empty-inline-type",
        "ambiguous-material",
    ] {
        let mut doc = document();
        match failure {
            "wrong-id" => doc["id"] = json!("did:web:203.0.113.43%3A8443:orgs:retained-issuer"),
            "no-assertion" => doc["assertionMethod"] = json!([]),
            "foreign-controller" => {
                doc["verificationMethod"][0]["controller"] = json!("did:web:other.test")
            }
            "foreign-key-id" => {
                doc["verificationMethod"][0]["id"] = json!("did:web:other.test#key")
            }
            "private-key" => {
                doc["verificationMethod"][1]["publicKeyJwk"]["d"] = json!("not-public")
            }
            "private-custody" => doc["signing_key_reference"] = json!("private-coordinate"),
            "missing-coordinate" => {
                doc["verificationMethod"][0]["publicKeyJwk"]
                    .as_object_mut()
                    .unwrap()
                    .remove("x");
            }
            "duplicate-method" => {
                let method = doc["verificationMethod"][0].clone();
                doc["verificationMethod"]
                    .as_array_mut()
                    .unwrap()
                    .push(method);
            }
            "conflicting-inline" => {
                let mut method = doc["verificationMethod"][0].clone();
                method["publicKeyJwk"]["x"] = json!("conflicting-x");
                doc["assertionMethod"].as_array_mut().unwrap().push(method);
            }
            "empty-inline-type" => {
                let mut method = doc["verificationMethod"][0].clone();
                method["type"] = json!("");
                doc["assertionMethod"] = json!([method]);
            }
            "ambiguous-material" => {
                doc["verificationMethod"][0]["publicKeyMultibase"] = json!("zDifferentKey")
            }
            _ => unreachable!(),
        }
        cases.push(json!({"found":true,"document":doc}));
    }
    for body in cases {
        let (base, _, task) = server(StatusCode::OK, body.to_string()).await;
        let resolver = HttpScopedIssuerKeyResolver::new(
            &base,
            "private-test-credential",
            Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(
            resolver.resolve("org-a", DID).await,
            Err(IssuerKeyResolutionError::Invalid)
        );
        task.abort();
    }
}

#[tokio::test]
async fn malformed_and_oversized_response_bodies_are_bounded() {
    for body in ["not-json".to_owned(), " ".repeat(MAX_DOCUMENT_BYTES + 1)] {
        let (base, _, task) = server(StatusCode::OK, body).await;
        let resolver = HttpScopedIssuerKeyResolver::new(
            &base,
            "private-test-credential",
            Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(
            resolver.resolve("org-a", DID).await,
            Err(IssuerKeyResolutionError::Invalid)
        );
        task.abort();
    }
}

#[test]
fn owner_origin_and_credentials_are_strictly_configured() {
    for base in [
        "file:///tmp/document",
        "http://user:secret@issuer.test",
        "https://issuer.test/path",
        "https://issuer.test/?query",
        "https://issuer.test/#fragment",
    ] {
        assert!(
            HttpScopedIssuerKeyResolver::new(base, "credential", Duration::from_secs(1)).is_err()
        );
    }
    assert!(
        HttpScopedIssuerKeyResolver::new("https://issuer.test", " ", Duration::from_secs(1))
            .is_err()
    );
    assert!(
        HttpScopedIssuerKeyResolver::new("https://issuer.test", "credential", Duration::ZERO)
            .is_err()
    );
}
