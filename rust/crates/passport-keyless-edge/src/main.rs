//! HTTPS edge for the disposable passport acceptance project. TLS signing is
//! delegated to a versioned, non-exportable OpenBao Transit key.

use std::{error::Error, net::SocketAddr, time::Duration};

use axum::{
    body::{to_bytes, Body},
    extract::{ConnectInfo, State},
    http::{header, HeaderMap, HeaderValue, Method, Request, Response, StatusCode},
    routing::any,
    Router,
};
use futures_util::StreamExt;
use marty_passport_keyless_edge::{
    caller_forwarding_header, hop_by_hop, keyless_tls_config, required,
};

const MAX_BODY_BYTES: usize = 32 * 1024 * 1024;
const UPSTREAM: &str = "http://gateway:8000";

#[derive(Clone)]
struct EdgeState {
    client: reqwest::Client,
    upstream: String,
}

fn error_response(status: StatusCode) -> Response<Body> {
    Response::builder()
        .status(status)
        .body(Body::empty())
        .expect("static HTTP status")
}

async fn callback(method: Method) -> Response<Body> {
    let status = if method == Method::POST {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::METHOD_NOT_ALLOWED
    };
    Response::builder()
        .status(status)
        .header("x-marty-synthetic-only", "true")
        .body(Body::empty())
        .expect("static callback response")
}

async fn proxy(
    State(state): State<EdgeState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response<Body> {
    let (parts, body) = request.into_parts();
    let Some(host) = parts.headers.get(header::HOST).cloned() else {
        return error_response(StatusCode::BAD_REQUEST);
    };
    let path = parts
        .uri
        .path_and_query()
        .map_or("/", |value| value.as_str());
    let destination = format!("{}{path}", state.upstream);
    let connection = parts
        .headers
        .get(header::CONNECTION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let mut headers = HeaderMap::new();
    for (name, value) in &parts.headers {
        if !hop_by_hop(name, connection)
            && name != header::HOST
            && name != header::CONTENT_LENGTH
            && !caller_forwarding_header(name)
        {
            headers.append(name, value.clone());
        }
    }
    headers.insert(header::HOST, host.clone());
    headers.insert("x-forwarded-host", host);
    headers.insert(
        "x-forwarded-proto",
        "https".parse().expect("static HTTPS scheme"),
    );
    let peer_ip: HeaderValue = peer.ip().to_string().parse().expect("socket IP header");
    headers.insert("x-real-ip", peer_ip.clone());
    headers.insert("x-forwarded-for", peer_ip);
    let payload = match to_bytes(body, MAX_BODY_BYTES).await {
        Ok(payload) => payload,
        Err(_) => return error_response(StatusCode::PAYLOAD_TOO_LARGE),
    };
    let upstream = match state
        .client
        .request(parts.method, destination)
        .headers(headers)
        .body(payload)
        .send()
        .await
    {
        Ok(response) => response,
        Err(_) => return error_response(StatusCode::BAD_GATEWAY),
    };
    let status = upstream.status();
    let response_connection = upstream
        .headers()
        .get(header::CONNECTION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let mut response = Response::builder().status(status);
    for (name, value) in upstream.headers() {
        if !hop_by_hop(name, &response_connection) && name != header::CONTENT_LENGTH {
            response = response.header(name, value);
        }
    }
    let mut stream = upstream.bytes_stream();
    let mut bytes = Vec::new();
    while let Some(next) = stream.next().await {
        let Ok(chunk) = next else {
            return error_response(StatusCode::BAD_GATEWAY);
        };
        if bytes.len().saturating_add(chunk.len()) > MAX_BODY_BYTES {
            return error_response(StatusCode::BAD_GATEWAY);
        }
        bytes.extend_from_slice(&chunk);
    }
    response
        .body(Body::from(bytes))
        .unwrap_or_else(|_| error_response(StatusCode::BAD_GATEWAY))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let tls = keyless_tls_config("PASSPORT_EDGE").await?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()?;
    let router = Router::new()
        .route("/__disposable/flow-callback", any(callback))
        .fallback(proxy)
        .with_state(EdgeState {
            client,
            upstream: UPSTREAM.into(),
        });
    axum_server::bind_rustls(required("PASSPORT_EDGE_BIND")?.parse::<SocketAddr>()?, tls)
        .serve(router.into_make_service_with_connect_info::<SocketAddr>())
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;

    #[tokio::test]
    async fn edge_preserves_public_host_and_https_origin_and_synthetic_callback() {
        let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_address = upstream.local_addr().unwrap();
        let upstream_app = Router::new().route(
            "/identity",
            get(|headers: HeaderMap| async move {
                format!(
                    "{}|{}|{}|{}|{}|{}|{}",
                    headers[header::HOST].to_str().unwrap(),
                    headers["x-forwarded-host"].to_str().unwrap(),
                    headers["x-forwarded-proto"].to_str().unwrap(),
                    headers["x-real-ip"].to_str().unwrap(),
                    headers["x-forwarded-for"].to_str().unwrap(),
                    headers.get("forwarded").is_none(),
                    headers.get("x-injected").is_none(),
                )
            }),
        );
        let upstream_task = tokio::spawn(async move {
            axum::serve(upstream, upstream_app).await.unwrap();
        });
        let edge = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let edge_address = edge.local_addr().unwrap();
        let edge_app = Router::new()
            .route("/__disposable/flow-callback", any(callback))
            .fallback(proxy)
            .with_state(EdgeState {
                client: reqwest::Client::new(),
                upstream: format!("http://{upstream_address}"),
            });
        let edge_task = tokio::spawn(async move {
            axum::serve(
                edge,
                edge_app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        let client = reqwest::Client::new();
        let base = format!("http://{edge_address}");
        let forwarded = client
            .get(format!("{base}/identity"))
            .header(header::HOST, "localhost:29877")
            .header("forwarded", "for=198.51.100.7;proto=http")
            .header("x-real-ip", "198.51.100.7")
            .header("x-forwarded-for", "198.51.100.7")
            .header("x-forwarded-proto", "http")
            .header(header::CONNECTION, "x-injected")
            .header("x-injected", "spoofed")
            .send()
            .await
            .unwrap();
        assert_eq!(forwarded.status(), StatusCode::OK);
        assert_eq!(
            forwarded.text().await.unwrap(),
            "localhost:29877|localhost:29877|https|127.0.0.1|127.0.0.1|true|true"
        );
        let callback = client
            .post(format!("{base}/__disposable/flow-callback"))
            .send()
            .await
            .unwrap();
        assert_eq!(callback.status(), StatusCode::NO_CONTENT);
        assert_eq!(callback.headers()["x-marty-synthetic-only"], "true");
        let other_method = client
            .get(format!("{base}/__disposable/flow-callback"))
            .send()
            .await
            .unwrap();
        assert_eq!(other_method.status(), StatusCode::METHOD_NOT_ALLOWED);
        upstream_task.abort();
        edge_task.abort();
    }
}
