//! OIDF public HTTPS edge. The certificate is public; OpenBao performs every
//! TLS private-key operation through the shared keyless identity boundary.

use std::{error::Error, net::SocketAddr};

use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode, Uri},
    routing::any,
    Router,
};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use marty_passport_keyless_edge::{keyless_tls_config, required};
use tokio::{
    io::copy_bidirectional,
    net::TcpStream,
    time::{timeout, Duration},
};

const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
struct EdgeState {
    gateway: String,
    keycloak: String,
    ui: String,
}

impl Default for EdgeState {
    fn default() -> Self {
        Self {
            gateway: "gateway:8000".into(),
            keycloak: "keycloak:8080".into(),
            ui: "ui:80".into(),
        }
    }
}

fn ui_path(path: &str) -> bool {
    if path == "/" || path == "/console" || path.starts_with("/console/") {
        return true;
    }
    if ["/assets/", "/locales/", "/images/", "/blog/", "/demos/"]
        .iter()
        .any(|prefix| path.starts_with(prefix))
    {
        return true;
    }
    if [
        "/runtime-config.js",
        "/startup.js",
        "/config.json",
        "/apple-touch-icon.png",
        "/manifest.json",
        "/llms.txt",
        "/openapi.yaml",
    ]
    .contains(&path)
    {
        return true;
    }
    ["/favicon", "/logo"].iter().any(|prefix| {
        path.strip_prefix(prefix)
            .is_some_and(|suffix| !suffix.contains('/'))
    })
}

fn target<'a>(path: &str, state: &'a EdgeState) -> &'a str {
    if path.starts_with("/realms/") {
        &state.keycloak
    } else if ui_path(path) {
        &state.ui
    } else {
        &state.gateway
    }
}

fn hop_by_hop(name: &HeaderName, connection: &str) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    ) || connection
        .split(',')
        .any(|item| item.trim().eq_ignore_ascii_case(name.as_str()))
}

fn forwarded(name: &HeaderName) -> bool {
    name.as_str() == "forwarded"
        || name.as_str() == "x-real-ip"
        || name.as_str().starts_with("x-forwarded-")
}

fn failure(status: StatusCode) -> Response<Body> {
    Response::builder()
        .status(status)
        .body(Body::empty())
        .expect("static HTTP response")
}

async fn proxy(
    State(state): State<EdgeState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    mut request: Request<Body>,
) -> Response<Body> {
    let Some(host) = request.headers().get(header::HOST).cloned() else {
        return failure(StatusCode::BAD_REQUEST);
    };
    let Ok(authority) = host
        .to_str()
        .ok()
        .unwrap_or("")
        .parse::<http::uri::Authority>()
    else {
        return failure(StatusCode::BAD_REQUEST);
    };
    if authority.as_str().contains('@') || authority.host().is_empty() {
        return failure(StatusCode::BAD_REQUEST);
    }
    let port = authority.port_u16().unwrap_or(443);
    let path = request.uri().path();
    let upstream = target(path, &state);
    let connection = request
        .headers()
        .get(header::CONNECTION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let upgrade = upstream == state.gateway
        && connection
            .split(',')
            .any(|item| item.trim().eq_ignore_ascii_case("upgrade"))
        && request.headers().contains_key(header::UPGRADE);
    let upgrade_value = if upgrade {
        request.headers().get(header::UPGRADE).cloned()
    } else {
        None
    };
    let downstream_upgrade = upgrade.then(|| hyper::upgrade::on(&mut request));
    let (mut parts, body) = request.into_parts();
    let original_connection = parts
        .headers
        .get(header::CONNECTION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let mut headers = HeaderMap::new();
    for (name, value) in &parts.headers {
        if name != header::HOST && !hop_by_hop(name, original_connection) && !forwarded(name) {
            headers.append(name, value.clone());
        }
    }
    headers.insert(header::HOST, host.clone());
    headers.insert("x-forwarded-host", host);
    headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
    headers.insert(
        "x-forwarded-port",
        HeaderValue::from_str(&port.to_string()).expect("validated port"),
    );
    let client_ip = HeaderValue::from_str(&peer.ip().to_string()).expect("socket IP");
    headers.insert("x-real-ip", client_ip.clone());
    headers.insert("x-forwarded-for", client_ip);
    if let Some(value) = upgrade_value {
        headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
        headers.insert(header::UPGRADE, value);
    }
    parts.headers = headers;
    let path_and_query = parts.uri.path_and_query().map_or("/", |p| p.as_str());
    parts.uri = path_and_query
        .parse::<Uri>()
        .expect("incoming origin-form path");
    let upstream_request = Request::from_parts(parts, body);
    let Ok(Ok(stream)) = timeout(UPSTREAM_CONNECT_TIMEOUT, TcpStream::connect(upstream)).await
    else {
        return failure(StatusCode::BAD_GATEWAY);
    };
    let Ok(Ok((mut sender, connection))) = timeout(
        UPSTREAM_CONNECT_TIMEOUT,
        http1::handshake(TokioIo::new(stream)),
    )
    .await
    else {
        return failure(StatusCode::BAD_GATEWAY);
    };
    tokio::spawn(async move {
        let _ = connection.with_upgrades().await;
    });
    let Ok(mut response) = sender.send_request(upstream_request).await else {
        return failure(StatusCode::BAD_GATEWAY);
    };
    if let Some(downstream) = downstream_upgrade {
        if response.status() == StatusCode::SWITCHING_PROTOCOLS {
            let upstream = hyper::upgrade::on(&mut response);
            tokio::spawn(async move {
                if let (Ok(client), Ok(server)) = (downstream.await, upstream.await) {
                    let mut client = TokioIo::new(client);
                    let mut server = TokioIo::new(server);
                    let _ = copy_bidirectional(&mut client, &mut server).await;
                }
            });
        }
    }
    let (mut parts, body) = response.into_parts();
    let connection = parts
        .headers
        .get(header::CONNECTION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let mut headers = HeaderMap::new();
    for (name, value) in &parts.headers {
        if !hop_by_hop(name, connection) {
            headers.append(name, value.clone());
        }
    }
    if parts.status == StatusCode::SWITCHING_PROTOCOLS && upgrade {
        if let Some(value) = parts.headers.get(header::UPGRADE) {
            headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
            headers.insert(header::UPGRADE, value.clone());
        }
    }
    parts.headers = headers;
    Response::from_parts(parts, Body::new(body))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let bind: SocketAddr = required("OIDF_EDGE_BIND")?.parse()?;
    let tls = keyless_tls_config("OIDF_EDGE").await?;
    let app = Router::new()
        .fallback(any(proxy))
        .with_state(EdgeState::default());
    axum_server::bind_rustls(bind, tls)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn oidf_route_map_matches_public_origin_contract() {
        let state = EdgeState::default();
        assert_eq!(target("/realms/11id", &state), "keycloak:8080");
        for path in [
            "/",
            "/console",
            "/console/",
            "/assets/app.js",
            "/locales/en",
            "/images/icon.png",
            "/blog/post",
            "/demos/demo",
            "/runtime-config.js",
            "/startup.js",
            "/config.json",
            "/favicon.ico",
            "/logo.svg",
            "/apple-touch-icon.png",
            "/manifest.json",
            "/llms.txt",
            "/openapi.yaml",
        ] {
            assert_eq!(target(path, &state), "ui:80", "{path}");
        }
        for path in [
            "/v1/auth/callback",
            "/realms",
            "/assets",
            "/favicon/a",
            "/api/ws",
        ] {
            assert_eq!(target(path, &state), "gateway:8000", "{path}");
        }
    }

    #[tokio::test]
    async fn proxy_forwards_body_and_replaces_untrusted_forwarding_headers() {
        async fn upstream(request: Request<Body>) -> Response<Body> {
            let headers = request.headers().clone();
            let body = to_bytes(request.into_body(), 1024).await.unwrap();
            let summary = format!(
                "{}|{}|{}|{}|{}|{}|{}|{}|{}",
                String::from_utf8(body.to_vec()).unwrap(),
                headers[header::HOST].to_str().unwrap(),
                headers["x-forwarded-host"].to_str().unwrap(),
                headers["x-forwarded-port"].to_str().unwrap(),
                headers["x-forwarded-proto"].to_str().unwrap(),
                headers["x-forwarded-for"].to_str().unwrap(),
                headers["x-real-ip"].to_str().unwrap(),
                headers.get("forwarded").is_none(),
                headers.get("x-injected").is_none(),
            );
            Response::new(Body::from(summary))
        }
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_address = upstream_listener.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            axum::serve(upstream_listener, Router::new().fallback(any(upstream)))
                .await
                .unwrap();
        });
        let edge_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let edge_address = edge_listener.local_addr().unwrap();
        let state = EdgeState {
            gateway: upstream_address.to_string(),
            keycloak: upstream_address.to_string(),
            ui: upstream_address.to_string(),
        };
        let edge_task = tokio::spawn(async move {
            axum::serve(
                edge_listener,
                Router::new()
                    .fallback(any(proxy))
                    .with_state(state)
                    .into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        let response = reqwest::Client::new()
            .post(format!("http://{edge_address}/v1/accept"))
            .header(header::HOST, "example.test:8443")
            .header("forwarded", "for=198.51.100.1;proto=http")
            .header("x-forwarded-for", "198.51.100.1")
            .header("x-forwarded-host", "spoofed.invalid")
            .header("x-forwarded-proto", "http")
            .header(header::CONNECTION, "x-injected")
            .header("x-injected", "spoofed")
            .body("protocol payload")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.text().await.unwrap(),
            "protocol payload|example.test:8443|example.test:8443|8443|https|127.0.0.1|127.0.0.1|true|true"
        );
        edge_task.abort();
        upstream_task.abort();
    }

    #[tokio::test]
    async fn gateway_upgrade_tunnels_bidirectional_bytes() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_address = upstream_listener.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream_listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0_u8];
                stream.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
                assert!(request.len() < 8192);
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with("GET /api/ws HTTP/1.1\r\n"), "{request}");
            assert!(request
                .to_ascii_lowercase()
                .contains("upgrade: websocket\r\n"));
            stream
                .write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
                .await
                .unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });
        let edge_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let edge_address = edge_listener.local_addr().unwrap();
        let edge_task = tokio::spawn(async move {
            axum::serve(
                edge_listener,
                Router::new()
                    .fallback(any(proxy))
                    .with_state(EdgeState {
                        gateway: upstream_address.to_string(),
                        keycloak: "127.0.0.1:1".into(),
                        ui: "127.0.0.1:1".into(),
                    })
                    .into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        timeout(Duration::from_secs(3), async {
            let mut client = TcpStream::connect(edge_address).await.unwrap();
            client
                .write_all(b"GET /api/ws HTTP/1.1\r\nHost: example.test:8443\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
                .await
                .unwrap();
            let mut response = Vec::new();
            while !response.ends_with(b"\r\n\r\n") {
                let mut byte = [0_u8];
                client.read_exact(&mut byte).await.unwrap();
                response.push(byte[0]);
                assert!(response.len() < 8192);
            }
            assert!(String::from_utf8(response).unwrap().starts_with("HTTP/1.1 101"));
            client.write_all(b"ping").await.unwrap();
            let mut reply = [0_u8; 4];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"pong");
            upstream_task.await.unwrap();
        })
        .await
        .unwrap();
        edge_task.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "requires a disposable HTTPS OpenBao signer and public certificate"]
    async fn oidf_https_handshake_signs_with_versioned_remote_key() {
        async fn upstream(request: Request<Body>) -> Response<Body> {
            let host = request.headers()[header::HOST].to_str().unwrap();
            Response::new(Body::from(format!("{host}|{}", request.uri().path())))
        }
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_address = upstream_listener.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            axum::serve(upstream_listener, Router::new().fallback(any(upstream)))
                .await
                .unwrap();
        });
        let tls = keyless_tls_config("OIDF_EDGE").await.unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let edge_task = tokio::spawn(async move {
            axum_server::from_tcp_rustls(listener, tls)
                .unwrap()
                .serve(
                    Router::new()
                        .fallback(any(proxy))
                        .with_state(EdgeState {
                            gateway: upstream_address.to_string(),
                            keycloak: upstream_address.to_string(),
                            ui: upstream_address.to_string(),
                        })
                        .into_make_service_with_connect_info::<SocketAddr>(),
                )
                .await
                .unwrap();
        });
        let ca = std::fs::read(required("MARTY_TEST_OIDF_EDGE_CA").unwrap()).unwrap();
        let ca = reqwest::Certificate::from_pem(&ca).unwrap();
        let client = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .tls_certs_only([ca])
            .build()
            .unwrap();
        let response = client
            .get(format!("https://localhost:{}/v1/ready", address.port()))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.text().await.unwrap(),
            format!("localhost:{}|/v1/ready", address.port())
        );
        edge_task.abort();
        upstream_task.abort();
    }
}
