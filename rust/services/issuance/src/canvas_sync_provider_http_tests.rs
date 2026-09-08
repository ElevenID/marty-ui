//! Independent scoped-adapter controls, not whole-worker roster body qualification.

use super::tests::{run_provider_without_database_io, run_token_key};
use super::*;
use crate::{
    canvas_network_timeout::CanvasNetworkTimeout,
    canvas_operation_http::CanvasOperationHttpClient,
    canvas_provider_http::{validate_canvas_origin, CanvasOriginPolicy},
    canvas_sync_processor::CanvasProviderRunScope,
    canvas_sync_worker::CanvasSyncTargetType,
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[test]
fn target_scope_is_explicit_and_does_not_infer_roster_candidates_from_resources() {
    for (target, expected) in [
        (
            CanvasSyncTargetType::LearnerApplication,
            Some(CanvasProviderRunScope::Application),
        ),
        (
            CanvasSyncTargetType::IssuedDrift,
            Some(CanvasProviderRunScope::Application),
        ),
        (
            CanvasSyncTargetType::BackgroundRoster,
            Some(CanvasProviderRunScope::BackgroundRoster),
        ),
        (CanvasSyncTargetType::AwardCandidate, None),
    ] {
        assert_eq!(CanvasProviderRunScope::from_target_type(target), expected);
    }
}

#[tokio::test]
async fn nested_scope_selection_starts_fresh_cache_without_reconfiguring_lti_policy() {
    let (mut template, pool) = run_provider_without_database_io();
    template.policy.timeout = Duration::from_secs(20);
    assert!(template.run_scope.is_none());
    assert!(template.run_tokens.is_none());
    for scope in [
        CanvasProviderRunScope::Application,
        CanvasProviderRunScope::BackgroundRoster,
    ] {
        let first = template.fresh_run(scope);
        assert_eq!(first.run_scope, Some(scope));
        assert_eq!(first.policy.timeout, Duration::from_secs(20));
        let first_cache = first.run_tokens.as_ref().unwrap();
        first_cache
            .get_or_request(run_token_key(), || async {
                Ok("synthetic-private-run-token".to_owned())
            })
            .await
            .unwrap();
        for nested_scope in [
            CanvasProviderRunScope::Application,
            CanvasProviderRunScope::BackgroundRoster,
        ] {
            let nested = first.fresh_run(nested_scope);
            assert_eq!(nested.run_scope, Some(nested_scope));
            assert_eq!(nested.policy.timeout, Duration::from_secs(20));
            let nested_cache = nested.run_tokens.as_ref().unwrap();
            assert!(!Arc::ptr_eq(first_cache, nested_cache));
            assert!(nested_cache.tokens.lock().await.is_empty());
            assert!(!format!("{nested:?}").contains("synthetic-private-run-token"));
        }
        assert_eq!(first_cache.tokens.lock().await.len(), 1);
        let object: Arc<dyn CanvasAuthoritativeProvider> = Arc::new(first);
        let left = object.clone().for_run(scope);
        let right = object.clone().for_run(scope);
        let nested = left.clone().for_run(scope);
        assert!(!Arc::ptr_eq(&object, &left));
        assert!(!Arc::ptr_eq(&left, &right));
        assert!(!Arc::ptr_eq(&left, &nested));
    }
    assert!(template.run_tokens.is_none());
    pool.close().await;
}

#[test]
fn persisted_origins_keep_path_query_fragment_and_credential_rejections() {
    let policy = CanvasOriginPolicy::default();
    let origin = validate_canvas_origin("https://canvas.example.invalid", &policy).unwrap();
    assert_eq!(origin.as_str(), "https://canvas.example.invalid/");
    for rejected in [
        "https://canvas.example.invalid/persisted/base",
        "https://canvas.example.invalid/?query=secret",
        "https://canvas.example.invalid/#fragment",
        "https://user@canvas.example.invalid/",
        "https://user:secret@canvas.example.invalid/",
        "http://canvas.example.invalid/",
    ] {
        assert!(validate_canvas_origin(rejected, &policy).is_err());
    }
    let exact_local = CanvasOriginPolicy {
        allow_http_localhost: true,
        ..CanvasOriginPolicy::default()
    };
    assert!(validate_canvas_origin("http://127.0.0.1:1234", &exact_local).is_ok());
    assert!(validate_canvas_origin("http://127.0.0.1:1234/base", &exact_local).is_err());
    assert_eq!(
        api_url(&origin, "courses/42/assignments/9/submissions/7")
            .unwrap()
            .as_str(),
        "https://canvas.example.invalid/api/v1/courses/42/assignments/9/submissions/7"
    );
}

#[tokio::test]
async fn only_explicit_application_scope_selects_operation_transport() {
    let (mut template, pool) = run_provider_without_database_io();
    pool.close().await;
    template.policy.allow_http_localhost = true;
    template.policy.timeout = Duration::from_secs(20);
    assert_eq!(APPLICATION_REST_TIMEOUT_SECONDS, 15.0);
    let (default_client, _) = template.rest_client("http://127.0.0.1:1").await.unwrap();
    assert!(matches!(default_client, RestReadClient::Total(_)));
    for scope in [
        CanvasProviderRunScope::Application,
        CanvasProviderRunScope::BackgroundRoster,
    ] {
        let provider = template.fresh_run(scope);
        let (client, _) = provider.rest_client("http://127.0.0.1:1").await.unwrap();
        assert_eq!(
            matches!(client, RestReadClient::Operation(_)),
            scope == CanvasProviderRunScope::Application
        );
        // Retaining this policy does not qualify roster inactivity semantics.
        assert_eq!(provider.policy.timeout, Duration::from_secs(20));
        for base in [
            "http://127.0.0.1:1/base",
            "http://127.0.0.1:1/?q=secret",
            "http://127.0.0.1:1/#fragment",
            "http://private:secret@127.0.0.1:1",
        ] {
            assert!(matches!(
                provider.rest_client(base).await,
                Err(CanvasProviderReadError::InvalidConfiguration)
            ));
        }
    }
}

#[tokio::test]
async fn malformed_bearer_and_rejected_origin_keep_closed_errors_without_connecting() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("https://{}", listener.local_addr().unwrap());
    let url = Url::parse(&format!("{origin}/owned")).unwrap();
    let (mut template, pool) = run_provider_without_database_io();
    pool.close().await;
    template.policy.timeout = Duration::from_secs(20);

    // Existing total-client setup resolves/rejects this private origin before
    // any request header is built. Keep that behavior for templates and roster.
    assert!(matches!(
        template.rest_client(&origin).await,
        Err(CanvasProviderReadError::InvalidConfiguration)
    ));
    let roster = template.fresh_run(CanvasProviderRunScope::BackgroundRoster);
    assert!(matches!(
        roster.rest_client(&origin).await,
        Err(CanvasProviderReadError::InvalidConfiguration)
    ));

    // The application operation owner resolves once at send, after validating
    // the persisted root and constructing headers. Both-invalid inputs thus
    // report the header failure first; this is an explicit adapter edge, not
    // claimed frozen Python precedence or permission to contact the origin.
    let application = template.fresh_run(CanvasProviderRunScope::Application);
    let (client, _) = application.rest_client(&origin).await.unwrap();
    assert!(matches!(client, RestReadClient::Operation(_)));
    for malformed in [
        "synthetic\nheader",
        "synthetic\r\nheader",
        "synthetic\0header",
    ] {
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), client.get(url.clone(), malformed))
                .await
                .expect("Malformed synthetic header must fail promptly"),
            Err(CanvasProviderReadError::Unavailable)
        ));
    }
    assert!(matches!(
        tokio::time::timeout(
            Duration::from_secs(1),
            client.get(url, "synthetic-valid-token")
        )
        .await
        .expect("Rejected synthetic origin must fail promptly"),
        Err(CanvasProviderReadError::InvalidConfiguration)
    ));
    // A bound listener is an executable negative control, not a process/network
    // mock: none of the invalid combinations may reach TCP connection setup.
    assert!(
        tokio::time::timeout(Duration::from_millis(25), listener.accept())
            .await
            .is_err()
    );
}

struct ResponseServer {
    origin: String,
    request: Option<tokio::sync::oneshot::Receiver<Vec<u8>>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for ResponseServer {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

impl ResponseServer {
    async fn start(response: Vec<u8>) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let (sender, request) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(3), async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    assert!(
                        request.len() < 8192,
                        "Synthetic request header exceeded its bound"
                    );
                    request.push(stream.read_u8().await.unwrap());
                }
                let _ = sender.send(request);
                // A rejected status/length can legitimately close before the
                // synthetic responder's final write. It never starts another request.
                let _ = stream.write_all(&response).await;
            })
            .await
            .expect("Synthetic response server exceeded its bound");
        });
        Self {
            origin,
            request: Some(request),
            task: Some(task),
        }
    }

    async fn fetch(&mut self, operation: bool) -> ProviderResponse {
        let client = if operation {
            RestReadClient::Operation(CanvasOperationHttpClient::new(
                CanvasOriginPolicy {
                    allow_http_localhost: true,
                    ..CanvasOriginPolicy::default()
                },
                CanvasNetworkTimeout::from_seconds(2.0),
            ))
        } else {
            RestReadClient::Total(
                reqwest::Client::builder()
                    .no_proxy()
                    .redirect(reqwest::redirect::Policy::none())
                    .timeout(Duration::from_secs(2))
                    .build()
                    .unwrap(),
            )
        };
        let url = Url::parse(&format!("{}/owned?include%5B%5D=assignment", self.origin)).unwrap();
        let response = client.get(url, "synthetic-operation-token").await.unwrap();
        let request = tokio::time::timeout(Duration::from_secs(1), self.request.take().unwrap())
            .await
            .unwrap()
            .unwrap();
        let request = String::from_utf8(request).unwrap();
        assert!(request.starts_with("GET /owned?include%5B%5D=assignment HTTP/1.1\r\n"));
        let headers = request.to_ascii_lowercase();
        assert!(headers.contains("\r\nauthorization: bearer synthetic-operation-token\r\n"));
        assert!(headers.contains("\r\naccept: application/json\r\n"));
        response
    }

    async fn finish(mut self) {
        tokio::time::timeout(Duration::from_secs(3), self.task.take().unwrap())
            .await
            .unwrap()
            .unwrap();
    }
}

fn wire_response(status: u16, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut bytes = format!("HTTP/1.1 {status} Synthetic\r\nConnection: close\r\nContent-Type: application/json\r\n{headers}\r\n").into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

#[tokio::test]
async fn both_response_adapters_preserve_status_and_bounded_json_classification() {
    let cases = [
        (
            200,
            "Content-Length: 2\r\n",
            b"{}".as_slice(),
            2,
            Ok(json!({})),
        ),
        (
            302,
            "Content-Length: 2\r\nLocation: /other\r\n",
            b"{}".as_slice(),
            64,
            Err(CanvasProviderReadError::InvalidConfiguration),
        ),
        (
            401,
            "Content-Length: 2\r\nWWW-Authenticate: Bearer\r\n",
            b"{}".as_slice(),
            64,
            Err(CanvasProviderReadError::Unavailable),
        ),
        (
            403,
            "Content-Length: 2\r\n",
            b"{}".as_slice(),
            64,
            Err(CanvasProviderReadError::Unavailable),
        ),
        (
            429,
            "Content-Length: 2\r\nRetry-After: 3\r\n",
            b"{}".as_slice(),
            64,
            Err(CanvasProviderReadError::RateLimited {
                retry_after_seconds: 3,
            }),
        ),
        (
            500,
            "Content-Length: 2\r\n",
            b"{}".as_slice(),
            64,
            Err(CanvasProviderReadError::Unavailable),
        ),
        (
            200,
            "Content-Length: 100\r\n",
            b"{}".as_slice(),
            4,
            Err(CanvasProviderReadError::Unavailable),
        ),
        (
            200,
            "Content-Length: 3\r\n",
            b"{}".as_slice(),
            64,
            Err(CanvasProviderReadError::Unavailable),
        ),
        (
            200,
            "Content-Length: 2\r\n",
            b"{]".as_slice(),
            64,
            Err(CanvasProviderReadError::Unavailable),
        ),
        (
            200,
            "Transfer-Encoding: chunked\r\n",
            b"2\r\n{}\r\n0\r\n\r\n".as_slice(),
            2,
            Ok(json!({})),
        ),
        (
            200,
            "Transfer-Encoding: chunked\r\n",
            b"2\r\n{}\r\n1\r\n \r\n0\r\n\r\n".as_slice(),
            2,
            Err(CanvasProviderReadError::Unavailable),
        ),
    ];
    for operation in [false, true] {
        for (status, headers, body, limit, expected) in &cases {
            let mut server = ResponseServer::start(wire_response(*status, headers, body)).await;
            let response = server.fetch(operation).await;
            assert_eq!(response.response().status().as_u16(), *status);
            if *status == 401 {
                assert!(response.response().headers().contains_key(WWW_AUTHENTICATE));
            }
            assert_eq!(read_json_response(response, *limit).await, *expected);
            server.finish().await;
        }
    }
}

#[tokio::test]
async fn operation_response_keeps_decoded_body_byte_limit_attached() {
    use std::io::Write;
    for deflate in [false, true] {
        let body = format!("{{\"value\":\"{}\"}}", "x".repeat(200));
        let (encoding, compressed) = if deflate {
            let mut encoder =
                flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(body.as_bytes()).unwrap();
            ("deflate", encoder.finish().unwrap())
        } else {
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(body.as_bytes()).unwrap();
            ("gzip", encoder.finish().unwrap())
        };
        assert!(compressed.len() < 64 && body.len() > 64);
        for limit in [64, body.len()] {
            let headers = format!(
                "Content-Encoding: {encoding}\r\nContent-Length: {}\r\n",
                compressed.len()
            );
            let mut server = ResponseServer::start(wire_response(200, &headers, &compressed)).await;
            let response = server.fetch(true).await;
            let actual = read_json_response(response, limit).await;
            if limit == 64 {
                assert_eq!(actual, Err(CanvasProviderReadError::Unavailable));
            } else {
                assert_eq!(
                    actual.unwrap(),
                    serde_json::from_str::<Value>(&body).unwrap()
                );
            }
            server.finish().await;
        }
    }
}
