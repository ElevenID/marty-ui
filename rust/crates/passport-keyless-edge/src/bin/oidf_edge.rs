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
    installer_authority: Option<(String, u16)>,
}

impl Default for EdgeState {
    fn default() -> Self {
        Self {
            gateway: "gateway:8000".into(),
            keycloak: "keycloak:8080".into(),
            ui: "ui:80".into(),
            installer_authority: None,
        }
    }
}

impl EdgeState {
    /// Explicit installer mode has one fixed upstream and one exact public
    /// authority. Unset mode retains the existing OIDF route contract.
    fn configured(profile: Option<&str>, origin: Option<&str>) -> Result<Self, &'static str> {
        match (profile, origin) {
            (None, None) => Ok(Self::default()),
            (Some("installer"), Some(origin)) => {
                let port_text = origin
                    .strip_prefix("https://localhost:")
                    .ok_or("invalid installer origin")?;
                let port: u16 = port_text.parse().map_err(|_| "invalid installer origin")?;
                if port < 1024 || port_text != port.to_string() {
                    return Err("invalid installer origin");
                }
                Ok(Self {
                    gateway: "edge:80".into(),
                    keycloak: "edge:80".into(),
                    ui: "edge:80".into(),
                    installer_authority: Some((format!("localhost:{port}"), port)),
                })
            }
            _ => Err("invalid edge profile or missing installer origin"),
        }
    }
}

fn accepted_authority(
    state: &EdgeState,
    headers: &HeaderMap,
    uri: &Uri,
) -> Option<(HeaderValue, u16)> {
    let host = headers.get(header::HOST)?.clone();
    if let Some((expected, port)) = &state.installer_authority {
        if headers.get_all(header::HOST).iter().count() != 1
            || host.as_bytes() != expected.as_bytes()
            || uri
                .authority()
                .is_some_and(|authority| authority.as_str() != expected)
            || uri.scheme_str().is_some_and(|scheme| scheme != "https")
        {
            return None;
        }
        return Some((HeaderValue::from_str(expected).ok()?, *port));
    }
    let authority = host.to_str().ok()?.parse::<http::uri::Authority>().ok()?;
    if authority.as_str().contains('@') || authority.host().is_empty() {
        return None;
    }
    Some((host, authority.port_u16().unwrap_or(443)))
}

fn ui_path(path: &str) -> bool {
    if path == "/applicant/preview" || path.starts_with("/applicant/preview/") {
        return true;
    }
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
    let Some((host, port)) = accepted_authority(&state, request.headers(), request.uri()) else {
        return failure(StatusCode::BAD_REQUEST);
    };
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
    let optional = |name| match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(error),
    };
    let profile = optional("OIDF_EDGE_PROFILE")?;
    let origin = optional("OIDF_EDGE_PUBLIC_ORIGIN")?;
    let state = EdgeState::configured(profile.as_deref(), origin.as_deref())?;
    let bind: SocketAddr = required("OIDF_EDGE_BIND")?.parse()?;
    let tls = keyless_tls_config("OIDF_EDGE").await?;
    let app = Router::new().fallback(any(proxy)).with_state(state);
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
    fn installer_profile_requires_explicit_canonical_local_https_origin() {
        assert!(EdgeState::configured(None, None)
            .unwrap()
            .installer_authority
            .is_none());
        for port in [1024, 18443, 65535] {
            let origin = format!("https://localhost:{port}");
            assert_eq!(
                EdgeState::configured(Some("installer"), Some(&origin))
                    .unwrap()
                    .installer_authority,
                Some((format!("localhost:{port}"), port))
            );
        }
        for origin in [
            "http://localhost:18443",
            "https://localhost:443",
            "https://localhost:0",
            "https://localhost:65536",
            "https://localhost:018443",
            "https://localhost:+18443",
            "https://LOCALHOST:18443",
            "https://127.0.0.1:18443",
            "https://localhost:18443/",
            "https://localhost:18443?query",
            "https://localhost:18443#fragment",
            "https://user@localhost:18443",
            "https://localhost:18443\n",
            "https://elsewhere:18443",
        ] {
            assert!(
                EdgeState::configured(Some("installer"), Some(origin)).is_err(),
                "accepted {origin:?}"
            );
        }
        for (mode, origin) in [
            (None, Some("https://localhost:18443")),
            (Some("installer"), None),
            (Some(""), None),
            (Some("unknown"), Some("https://localhost:18443")),
        ] {
            assert!(EdgeState::configured(mode, origin).is_err());
        }
    }

    #[test]
    fn installer_routes_every_path_to_nginx_including_login_assets_and_upgrades() {
        let state =
            EdgeState::configured(Some("installer"), Some("https://localhost:18443")).unwrap();
        for path in [
            "/",
            "/console",
            "/realms/11id",
            "/resources/theme/login.css",
            "/assets/app.js",
            "/v1/auth/callback?code=public",
            "/api/ws",
            "/events",
            "/unrecognized-route",
        ] {
            assert_eq!(target(path, &state), "edge:80");
            // Existing proxy upgrade path is enabled for this fixed upstream.
            assert_eq!(target(path, &state), state.gateway);
        }
    }

    #[test]
    fn installer_rejects_foreign_duplicate_and_conflicting_authority() {
        let state =
            EdgeState::configured(Some("installer"), Some("https://localhost:18443")).unwrap();
        let uri: Uri = "/v1/auth/callback?code=public".parse().unwrap();
        let mut headers = HeaderMap::new();
        assert!(accepted_authority(&state, &headers, &uri).is_none());
        for bad in [
            "localhost",
            "localhost:443",
            "LOCALHOST:18443",
            "127.0.0.1:18443",
            "foreign:18443",
            "localhost:018443",
        ] {
            headers.insert(header::HOST, HeaderValue::from_str(bad).unwrap());
            assert!(accepted_authority(&state, &headers, &uri).is_none());
        }
        headers.insert(header::HOST, HeaderValue::from_static("localhost:18443"));
        headers.insert("x-forwarded-host", HeaderValue::from_static("foreign:443"));
        assert_eq!(
            accepted_authority(&state, &headers, &uri).unwrap(),
            (HeaderValue::from_static("localhost:18443"), 18443)
        );
        for bad_uri in ["https://foreign:18443/", "http://localhost:18443/"] {
            assert!(accepted_authority(&state, &headers, &bad_uri.parse().unwrap()).is_none());
        }
        assert!(accepted_authority(
            &state,
            &headers,
            &"https://localhost:18443/".parse().unwrap()
        )
        .is_some());
        headers.append(header::HOST, HeaderValue::from_static("localhost:18443"));
        assert!(accepted_authority(&state, &headers, &uri).is_none());
    }

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
    async fn installer_proxy_forwards_login_assets_with_pinned_origin_headers() {
        async fn upstream(request: Request<Body>) -> String {
            let headers = request.headers();
            format!(
                "{}|{}|{}|{}|{}|{}",
                request.uri(),
                headers[header::HOST].to_str().unwrap(),
                headers["x-forwarded-host"].to_str().unwrap(),
                headers["x-forwarded-proto"].to_str().unwrap(),
                headers["x-forwarded-port"].to_str().unwrap(),
                headers.get("forwarded").is_none()
            )
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_address = listener.local_addr().unwrap().to_string();
        let upstream_task = tokio::spawn(async move {
            axum::serve(listener, Router::new().fallback(any(upstream)))
                .await
                .unwrap();
        });
        let mut state =
            EdgeState::configured(Some("installer"), Some("https://localhost:18443")).unwrap();
        // Test-only substitution; production configured() fixes all targets to edge:80.
        state.gateway = upstream_address.clone();
        state.keycloak = upstream_address.clone();
        state.ui = upstream_address;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let edge_task = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new()
                    .fallback(any(proxy))
                    .with_state(state)
                    .into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let url = format!("http://{address}/resources/theme/login.css?v=1");
        assert_eq!(
            client
                .get(&url)
                .header(header::HOST, "foreign:18443")
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
        let response = client
            .get(&url)
            .header(header::HOST, "localhost:18443")
            .header("x-forwarded-host", "foreign:443")
            .header("x-forwarded-proto", "http")
            .header("x-forwarded-port", "443")
            .header("forwarded", "host=foreign;proto=http")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.text().await.unwrap(),
            "/resources/theme/login.css?v=1|localhost:18443|localhost:18443|https|18443|true"
        );
        edge_task.abort();
        upstream_task.abort();
    }

    #[tokio::test]
    async fn preview_navigation_reaches_ui_while_template_api_stays_on_gateway() {
        async fn ui(request: Request<Body>) -> String {
            format!("ui|{}", request.uri())
        }
        async fn api(request: Request<Body>) -> String {
            format!("api|{}", request.uri())
        }
        let ui_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ui_address = ui_listener.local_addr().unwrap();
        let ui_task = tokio::spawn(async move {
            axum::serve(ui_listener, Router::new().fallback(any(ui)))
                .await
                .unwrap();
        });
        let api_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api_address = api_listener.local_addr().unwrap();
        let api_task = tokio::spawn(async move {
            axum::serve(api_listener, Router::new().fallback(any(api)))
                .await
                .unwrap();
        });
        let edge_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let edge_address = edge_listener.local_addr().unwrap();
        let edge_task = tokio::spawn(async move {
            axum::serve(
                edge_listener,
                Router::new()
                    .fallback(any(proxy))
                    .with_state(EdgeState {
                        installer_authority: None,
                        gateway: api_address.to_string(),
                        keycloak: api_address.to_string(),
                        ui: ui_address.to_string(),
                    })
                    .into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        for (path, expected) in [
            (
                "/applicant/preview/applications/template-1?organization_id=org-1",
                "ui",
            ),
            ("/applicant/preview/credentials/template-1", "ui"),
            ("/applicant/preview-elsewhere/template-1", "api"),
            (
                "/v1/application-templates/template-1?organization_id=org-1",
                "api",
            ),
            ("/v1/applicants/me", "api"),
        ] {
            let response = client
                .get(format!("http://{edge_address}{path}"))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.text().await.unwrap(), format!("{expected}|{path}"));
        }
        edge_task.abort();
        ui_task.abort();
        api_task.abort();
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
            installer_authority: None,
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
                        installer_authority: None,
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
                            installer_authority: None,
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
