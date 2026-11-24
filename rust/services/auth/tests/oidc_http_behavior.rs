use std::sync::{Arc, Mutex};

use axum::{
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use base64::Engine as _;
use marty_auth::{OidcHttpClient, ReqwestOidcHttpClient};
use serde_json::json;

async fn serve(router: Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (origin, task)
}

fn client() -> ReqwestOidcHttpClient {
    marty_service_runtime::install_tls_crypto_provider();
    ReqwestOidcHttpClient::new().unwrap()
}

#[tokio::test]
async fn native_revocation_scopes_the_client_and_always_attempts_local_cleanup() {
    for grant_status in [
        StatusCode::NO_CONTENT,
        StatusCode::INTERNAL_SERVER_ERROR,
        StatusCode::TEMPORARY_REDIRECT,
    ] {
        let observations = Arc::new(Mutex::new(Vec::new()));
        let grants = observations.clone();
        let logout = observations.clone();
        let (origin, server) = serve(
            Router::new()
                .route(
                    "/auth/v1/user/oauth/grants",
                    delete(move |headers: HeaderMap, uri: axum::http::Uri| {
                        let grants = grants.clone();
                        async move {
                            assert_eq!(headers["apikey"], "sb_publishable_synthetic");
                            assert_eq!(
                                headers[header::AUTHORIZATION],
                                "Bearer synthetic-native-token"
                            );
                            assert_eq!(uri.query(), Some("client_id=fixture-client"));
                            grants.lock().unwrap().push("grant");
                            (
                                grant_status,
                                [(header::LOCATION, "https://attacker.invalid/")],
                            )
                        }
                    }),
                )
                .route(
                    "/auth/v1/logout",
                    post(move |headers: HeaderMap, uri: axum::http::Uri| {
                        let logout = logout.clone();
                        async move {
                            assert_eq!(
                                headers[header::AUTHORIZATION],
                                "Bearer synthetic-native-token"
                            );
                            assert_eq!(uri.query(), Some("scope=local"));
                            logout.lock().unwrap().push("local");
                            StatusCode::NO_CONTENT
                        }
                    }),
                ),
        )
        .await;
        let result = client()
            .revoke_supabase_bootstrap(
                &format!("{origin}/auth/v1"),
                "sb_publishable_synthetic",
                "fixture-client",
                "synthetic-native-token",
            )
            .await;
        assert_eq!(result.is_ok(), grant_status == StatusCode::NO_CONTENT);
        assert_eq!(*observations.lock().unwrap(), ["grant", "local"]);
        server.abort();
    }
}

#[tokio::test]
async fn basic_credentials_are_form_encoded_before_header_encoding_and_absent_from_body() {
    let observed = Arc::new(Mutex::new(None));
    let capture = observed.clone();
    let (origin, server) = serve(Router::new().route(
        "/token",
        post(move |headers: HeaderMap, body: String| {
            let capture = capture.clone();
            async move {
                *capture.lock().unwrap() = Some((headers, body));
                Json(json!({"access_token": "synthetic-access"}))
            }
        }),
    ))
    .await;
    client()
        .post_form_json_object_basic(
            &format!("{origin}/token"),
            &[
                ("grant_type".into(), "authorization_code".into()),
                ("code_verifier".into(), "synthetic-verifier".into()),
            ],
            "client:id with+space",
            "synthetic:secret with+space",
            1024,
            "token response",
        )
        .await
        .unwrap();
    let (headers, body) = observed.lock().unwrap().take().unwrap();
    let expected = base64::engine::general_purpose::STANDARD
        .encode("client%3Aid+with%2Bspace:synthetic%3Asecret+with%2Bspace");
    assert_eq!(headers[header::AUTHORIZATION], format!("Basic {expected}"));
    assert_eq!(
        headers[header::CONTENT_TYPE],
        "application/x-www-form-urlencoded"
    );
    assert!(!body.contains("client_id"));
    assert!(!body.contains("secret"));
    assert!(body.contains("code_verifier=synthetic-verifier"));
    server.abort();
}

#[tokio::test]
async fn authenticated_requests_never_follow_redirects_or_forward_credentials() {
    let forwarded = Arc::new(Mutex::new(0_u32));
    let capture = forwarded.clone();
    let destination = get(move || {
        let capture = capture.clone();
        async move {
            *capture.lock().unwrap() += 1;
            Json(json!({}))
        }
    })
    .post({
        let capture = forwarded.clone();
        move || {
            let capture = capture.clone();
            async move {
                *capture.lock().unwrap() += 1;
                Json(json!({}))
            }
        }
    });
    let (destination_origin, destination_server) =
        serve(Router::new().route("/collect", destination)).await;
    let location = format!("{destination_origin}/collect");
    let redirect = move || {
        let location = location.clone();
        async move {
            (
                StatusCode::TEMPORARY_REDIRECT,
                [(header::LOCATION, location)],
            )
                .into_response()
        }
    };
    let (origin, server) =
        serve(Router::new().route("/redirect", get(redirect.clone()).post(redirect))).await;
    let client = client();
    assert!(client
        .get_userinfo_json_object(&format!("{origin}/redirect"), "synthetic-bearer", 1024)
        .await
        .is_err());
    assert!(client
        .post_form_json_object_basic(
            &format!("{origin}/redirect"),
            &[],
            "client",
            "synthetic-secret",
            1024,
            "token response"
        )
        .await
        .is_err());
    assert_eq!(*forwarded.lock().unwrap(), 0);
    server.abort();
    destination_server.abort();
}

#[tokio::test]
async fn userinfo_uses_only_bearer_header_and_enforces_response_bounds_and_shape() {
    let observed = Arc::new(Mutex::new(None));
    let capture = observed.clone();
    let (origin, server) = serve(
        Router::new()
            .route(
                "/profile",
                get(move |headers: HeaderMap| {
                    let capture = capture.clone();
                    async move {
                        *capture.lock().unwrap() = Some(headers);
                        Json(json!({"sub": "user-1"}))
                    }
                }),
            )
            .route(
                "/large",
                get(|| async { Json(json!({"data": "x".repeat(2048)})) }),
            )
            .route("/array", get(|| async { Json(json!([{"sub": "user-1"}])) })),
    )
    .await;
    let client = client();
    assert_eq!(
        client
            .get_userinfo_json_object(&format!("{origin}/profile"), "synthetic-bearer", 1024)
            .await
            .unwrap()["sub"],
        "user-1"
    );
    assert_eq!(
        observed.lock().unwrap().as_ref().unwrap()[header::AUTHORIZATION],
        "Bearer synthetic-bearer"
    );
    for path in ["large", "array"] {
        assert!(client
            .get_userinfo_json_object(&format!("{origin}/{path}"), "synthetic-bearer", 128)
            .await
            .is_err());
    }
    server.abort();
}
