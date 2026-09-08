use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use mmf_platform::{
    GatewayRequest, GatewayResponse, HttpMethod, PlatformError, ServiceInstance, UpstreamClient,
};

pub struct ReqwestUpstream {
    client: reqwest::Client,
    maximum_response_bytes: usize,
}

impl ReqwestUpstream {
    pub fn new(maximum_response_bytes: usize) -> Result<Self, PlatformError> {
        Self::validate_response_limit(maximum_response_bytes)?;
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(|error| PlatformError::ProviderUnavailable(error.to_string()))?;
        Self::with_client(maximum_response_bytes, client)
    }

    /// Supply explicit connection, proxy and redirect policy while retaining the
    /// gateway's per-request deadlines and bounded response handling.
    pub fn with_client(
        maximum_response_bytes: usize,
        client: reqwest::Client,
    ) -> Result<Self, PlatformError> {
        Self::validate_response_limit(maximum_response_bytes)?;
        Ok(Self {
            client,
            maximum_response_bytes,
        })
    }

    fn validate_response_limit(maximum_response_bytes: usize) -> Result<(), PlatformError> {
        if maximum_response_bytes == 0 {
            return Err(PlatformError::InvalidConfiguration(
                "maximum response bytes must be nonzero".into(),
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl UpstreamClient for ReqwestUpstream {
    async fn send(
        &self,
        instance: &ServiceInstance,
        request: GatewayRequest,
    ) -> Result<GatewayResponse, PlatformError> {
        let started = Instant::now();
        let raw_url = format!(
            "{}{}",
            instance.endpoint.url().trim_end_matches('/'),
            if request.path.starts_with('/') {
                request.path.clone()
            } else {
                format!("/{}", request.path)
            }
        );
        let mut url = url::Url::parse(&raw_url)
            .map_err(|error| PlatformError::Operation(error.to_string()))?;
        {
            let mut query = url.query_pairs_mut();
            for (key, values) in &request.query {
                for value in values {
                    query.append_pair(key, value);
                }
            }
        }
        let mut builder =
            self.client
                .request(method(request.method), url)
                .timeout(Duration::from_millis(
                    instance.endpoint.read_timeout_ms.max(1),
                ));
        for (name, value) in request.headers {
            // Every request reaching this transport owns an in-memory body. In
            // particular, gateway contract handlers can replace the public
            // body with canonical JSON before proxying it. Never forward the
            // client's framing for a body whose length may have changed;
            // reqwest will derive correct framing from the bytes below.
            if is_body_framing_header(&name) {
                continue;
            }
            builder = builder.header(name, value);
        }
        if let Some(body) = request.body {
            builder = builder.body(body);
        }
        let mut response = builder.send().await.map_err(map_reqwest_error)?;
        let status_code = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| {
                Ok((
                    name.as_str().to_owned(),
                    value
                        .to_str()
                        .map_err(|error| PlatformError::Operation(error.to_string()))?
                        .to_owned(),
                ))
            })
            .collect::<Result<BTreeMap<_, _>, PlatformError>>()?;
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(map_reqwest_error)? {
            if body.len().saturating_add(chunk.len()) > self.maximum_response_bytes {
                body.resize(self.maximum_response_bytes.saturating_add(1), 0);
                break;
            }
            body.extend_from_slice(&chunk);
        }
        Ok(GatewayResponse {
            status_code,
            headers,
            body: Some(body),
            response_time_ms: Some(
                u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            ),
            upstream_service: Some(instance.service_name.clone()),
        })
    }
}

fn is_body_framing_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("content-length") || name.eq_ignore_ascii_case("transfer-encoding")
}

fn method(method: HttpMethod) -> reqwest::Method {
    match method {
        HttpMethod::Get => reqwest::Method::GET,
        HttpMethod::Post => reqwest::Method::POST,
        HttpMethod::Put => reqwest::Method::PUT,
        HttpMethod::Delete => reqwest::Method::DELETE,
        HttpMethod::Patch => reqwest::Method::PATCH,
        HttpMethod::Head => reqwest::Method::HEAD,
        HttpMethod::Options => reqwest::Method::OPTIONS,
        HttpMethod::Trace => reqwest::Method::TRACE,
        HttpMethod::Connect => reqwest::Method::CONNECT,
    }
}

fn map_reqwest_error(error: reqwest::Error) -> PlatformError {
    if error.is_timeout() {
        PlatformError::UpstreamTimeout(error.to_string())
    } else if error.is_connect() || error.is_request() || error.is_body() {
        PlatformError::UpstreamTransport(error.to_string())
    } else {
        PlatformError::Operation(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use axum::{body::Bytes, extract::State, http::HeaderMap, routing::post, Json, Router};
    use mmf_platform::{
        EndpointProtocol, GatewayRequest, HttpMethod, ServiceEndpoint, ServiceInstance,
        UpstreamClient,
    };
    use serde_json::{json, Value};
    use tokio::{net::TcpListener, time::sleep};

    use super::*;

    fn isolated_client() -> reqwest::Client {
        reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_millis(250))
            .timeout(Duration::from_secs(2))
            .build()
            .expect("isolated loopback client")
    }

    struct OwnedLoopbacks {
        tasks: tokio::task::JoinSet<()>,
        shutdown: tokio::sync::watch::Sender<bool>,
    }

    impl OwnedLoopbacks {
        fn new() -> Self {
            Self {
                tasks: tokio::task::JoinSet::new(),
                shutdown: tokio::sync::watch::channel(false).0,
            }
        }

        async fn serve(&mut self, app: Router) -> u16 {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("owned bind");
            let port = listener.local_addr().expect("owned address").port();
            let mut shutdown = self.shutdown.subscribe();
            self.tasks.spawn(async move {
                axum::serve(listener, app)
                    .with_graceful_shutdown(async move {
                        while !*shutdown.borrow_and_update() {
                            if shutdown.changed().await.is_err() {
                                break;
                            }
                        }
                    })
                    .await
                    .expect("owned serve");
            });
            port
        }

        async fn close(&mut self) {
            self.shutdown.send_replace(true);
            tokio::time::timeout(Duration::from_secs(2), async {
                while let Some(result) = self.tasks.join_next().await {
                    result.expect("owned server joined");
                }
            })
            .await
            .expect("bounded owned server cleanup");
        }
    }

    impl Drop for OwnedLoopbacks {
        fn drop(&mut self) {
            self.shutdown.send_replace(true);
            self.tasks.abort_all();
        }
    }

    #[test]
    fn both_upstream_constructors_reject_zero_response_limits() {
        for result in [
            ReqwestUpstream::new(0),
            ReqwestUpstream::with_client(0, isolated_client()),
        ] {
            assert!(
                matches!(result, Err(PlatformError::InvalidConfiguration(message))
                if message == "maximum response bytes must be nonzero")
            );
        }
        assert!(ReqwestUpstream::new(1).is_ok());
        assert!(ReqwestUpstream::with_client(1, isolated_client()).is_ok());
    }

    #[tokio::test]
    async fn injected_client_preserves_no_redirect_policy_without_target_requests() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
        let mut servers = OwnedLoopbacks::new();
        let target_calls = Arc::new(AtomicUsize::new(0));
        let observed_target = target_calls.clone();
        let target = servers
            .serve(Router::new().route(
                "/target",
                post(move || {
                    let calls = observed_target.clone();
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Json(json!({"owned_target": true}))
                    }
                }),
            ))
            .await;
        let location = format!("http://127.0.0.1:{target}/target");
        let redirect_calls = Arc::new(AtomicUsize::new(0));
        let observed_redirect = redirect_calls.clone();
        let redirect_location = location.clone();
        let origin = servers
            .serve(Router::new().route(
                "/redirect",
                post(move || {
                    observed_redirect.fetch_add(1, Ordering::SeqCst);
                    let location = redirect_location.clone();
                    async move { axum::response::Redirect::temporary(&location) }
                }),
            ))
            .await;
        let upstream = ReqwestUpstream::with_client(1_024, isolated_client()).unwrap();
        let control = upstream
            .send(
                &instance(target, 1_000),
                GatewayRequest::new(HttpMethod::Post, "/target", 0),
            )
            .await
            .unwrap();
        assert_eq!(control.status_code, 200);
        assert_eq!(target_calls.swap(0, Ordering::SeqCst), 1);
        let response = tokio::time::timeout(
            Duration::from_secs(2),
            upstream.send(
                &instance(origin, 1_000),
                GatewayRequest::new(HttpMethod::Post, "/redirect", 0),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response.status_code, 307);
        assert_eq!(response.headers.get("location"), Some(&location));
        assert_eq!(redirect_calls.load(Ordering::SeqCst), 1);
        servers.close().await;
        assert_eq!(target_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn injected_client_keeps_exact_response_cap_and_overflow_sentinel() {
        let mut servers = OwnedLoopbacks::new();
        let port = servers
            .serve(Router::new().route("/echo", post(echo)))
            .await;
        let expected = serde_json::to_vec(&json!({
            "body": "synthetic", "content_length": "9", "transfer_encoding": null,
        }))
        .unwrap();
        for limit in [1, expected.len() - 1, expected.len(), expected.len() + 1] {
            let mut request = GatewayRequest::new(HttpMethod::Post, "/echo", 0);
            request.body = Some(b"synthetic".to_vec());
            let upstream = ReqwestUpstream::with_client(limit, isolated_client()).unwrap();
            let response = tokio::time::timeout(
                Duration::from_secs(2),
                upstream.send(&instance(port, 1_000), request),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(response.status_code, 200);
            assert_eq!(response.upstream_service.as_deref(), Some("test-upstream"));
            let bytes = response.body.expect("bounded body");
            if limit < expected.len() {
                // Preserve the existing max+1 overflow signal to GatewayProxy;
                // this transport does not itself turn overflow into an error.
                assert_eq!(bytes.len(), limit + 1);
            } else {
                assert_eq!(bytes, expected);
            }
        }
        servers.close().await;
    }

    #[tokio::test]
    async fn injected_client_keeps_discovered_deadline_over_client_default() {
        let mut servers = OwnedLoopbacks::new();
        let port = servers
            .serve(
                Router::new()
                    .route("/delayed", post(delayed))
                    .with_state(Duration::from_millis(250)),
            )
            .await;
        let upstream = ReqwestUpstream::with_client(1_024, isolated_client()).unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            upstream.send(
                &instance(port, 25),
                GatewayRequest::new(HttpMethod::Post, "/delayed", 0),
            ),
        )
        .await
        .expect("bounded request");
        assert!(matches!(result, Err(PlatformError::UpstreamTimeout(_))));
        // A longer endpoint budget permits the same delayed handler/client.
        let response = tokio::time::timeout(
            Duration::from_secs(2),
            upstream.send(
                &instance(port, 1_000),
                GatewayRequest::new(HttpMethod::Post, "/delayed", 0),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response.status_code, 200);
        servers.close().await;
    }

    fn instance(port: u16, read_timeout_ms: u64) -> ServiceInstance {
        ServiceInstance::new(
            "test-upstream",
            ServiceEndpoint {
                host: "127.0.0.1".into(),
                port,
                protocol: EndpointProtocol::Http,
                path: String::new(),
                verify_tls: true,
                connect_timeout_ms: 5_000,
                read_timeout_ms,
            },
            0,
        )
        .expect("service instance")
    }

    async fn echo(headers: HeaderMap, body: Bytes) -> Json<Value> {
        Json(json!({
            "body": String::from_utf8(body.to_vec()).expect("UTF-8 request"),
            "content_length": headers
                .get("content-length")
                .and_then(|value| value.to_str().ok()),
            "transfer_encoding": headers
                .get("transfer-encoding")
                .and_then(|value| value.to_str().ok()),
        }))
    }

    async fn delayed(State(delay): State<Duration>) -> Json<Value> {
        sleep(delay).await;
        Json(json!({"completed": true}))
    }

    #[tokio::test]
    async fn proxy_recomputes_framing_after_gateway_body_replacement() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("local address").port();
        let server = tokio::spawn(async move {
            axum::serve(listener, Router::new().route("/echo", post(echo)))
                .await
                .expect("serve");
        });
        let canonical = br#"{"canonical":"body is a different length"}"#.to_vec();
        let mut request = GatewayRequest::new(HttpMethod::Post, "/echo", 0);
        request
            .headers
            .insert("content-type".into(), "application/json".into());
        request
            .headers
            .insert("Content-Length".into(), "9999".into());
        request
            .headers
            .insert("Transfer-Encoding".into(), "chunked".into());
        request.body = Some(canonical.clone());

        let response = ReqwestUpstream::new(1_024)
            .expect("upstream")
            .send(&instance(port, 1_000), request)
            .await
            .expect("proxy response");
        let response: Value =
            serde_json::from_slice(response.body.as_deref().expect("body")).expect("JSON response");
        assert_eq!(response["body"], String::from_utf8(canonical).unwrap());
        assert_eq!(
            response["content_length"],
            response["body"].as_str().unwrap().len().to_string()
        );
        assert!(response["transfer_encoding"].is_null());
        server.abort();
    }

    #[tokio::test]
    async fn proxy_enforces_the_discovered_upstream_read_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("local address").port();
        let server = tokio::spawn(async move {
            let app = Router::new()
                .route("/delayed", post(delayed))
                .with_state(Duration::from_millis(250));
            axum::serve(listener, app).await.expect("serve");
        });
        let mut request = GatewayRequest::new(HttpMethod::Post, "/delayed", 0);
        request.body = Some(b"{}".to_vec());

        let error = ReqwestUpstream::new(1_024)
            .expect("upstream")
            .send(&instance(port, 25), request)
            .await
            .expect_err("slow upstream must time out");
        assert!(matches!(error, PlatformError::UpstreamTimeout(_)));
        server.abort();
    }
}
