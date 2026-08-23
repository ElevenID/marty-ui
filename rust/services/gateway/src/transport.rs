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
        if maximum_response_bytes == 0 {
            return Err(PlatformError::InvalidConfiguration(
                "maximum response bytes must be nonzero".into(),
            ));
        }
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(|error| PlatformError::ProviderUnavailable(error.to_string()))?;
        Ok(Self {
            client,
            maximum_response_bytes,
        })
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
