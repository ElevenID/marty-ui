//! Prepared-origin transport controls using owned loopback only. No TLS/SNI or
//! complete worker-parity claim; existing HTTPS qualification owns those gates.
use super::*;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::{timeout, Duration},
};

fn local_policy() -> CanvasOriginPolicy {
    CanvasOriginPolicy {
        allow_http_localhost: true,
        ..Default::default()
    }
}

fn request_headers() -> http::HeaderMap {
    http::HeaderMap::from_iter([
        (
            http::header::AUTHORIZATION,
            http::HeaderValue::from_static("Bearer synthetic-prepared-token"),
        ),
        (
            http::header::ACCEPT,
            http::HeaderValue::from_static("application/json"),
        ),
        // The validated origin, not caller input, must provide Host.
        (
            http::header::HOST,
            http::HeaderValue::from_static("wrong-host.invalid"),
        ),
    ])
}

async fn serve(listener: &TcpListener, count: usize) -> Vec<String> {
    let mut requests = Vec::new();
    for _ in 0..count {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut bytes = Vec::new();
        let mut byte = [0];
        while !bytes.ends_with(b"\r\n\r\n") {
            socket.read_exact(&mut byte).await.unwrap();
            bytes.push(byte[0]);
            assert!(
                bytes.len() <= 8192,
                "owned prepared request exceeded header bound"
            );
        }
        requests.push(String::from_utf8(bytes).unwrap());
        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n[]").await.unwrap();
        socket.shutdown().await.unwrap();
    }
    requests
}

async fn no_connection(listener: &TcpListener) {
    assert!(
        timeout(Duration::from_millis(30), listener.accept())
            .await
            .is_err(),
        "rejected prepared request must not connect"
    );
}

async fn get(
    client: &CanvasOperationHttpClient,
    url: Url,
) -> Result<Bytes, CanvasOperationHttpError> {
    client
        .send(http::Method::GET, url, request_headers(), Vec::new())
        .await?
        .bytes()
        .await
}

#[tokio::test]
async fn prepared_origin_and_clones_reuse_validated_pin_without_reapplying_lazy_policy() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let base = format!("http://localhost:{}", address.port());
    let budget = CanvasNetworkTimeout::from_seconds(0.5);
    let (mut prepared, origin) = CanvasOperationHttpClient::prepare(local_policy(), budget, &base)
        .await
        .unwrap();
    assert_eq!(origin, Url::parse(&base).unwrap());
    assert_eq!(prepared.prepared.as_ref().unwrap().address, address);
    assert_eq!(prepared.prepared.as_ref().unwrap().origin, origin);
    no_connection(&listener).await;

    // A lazy resolution using this deliberately closed policy would reject the
    // HTTP origin. Prepared sends must retain their already-validated pin.
    prepared.policy = CanvasOriginPolicy::default();
    let cloned = prepared.clone();
    let first = origin
        .join("/api/v1/courses/42?include%5B%5D=assignment")
        .unwrap();
    let second = origin.join("/api/v1/courses/43?per_page=10").unwrap();
    let (requests, ()) = timeout(Duration::from_secs(3), async {
        tokio::join!(serve(&listener, 2), async {
            assert_eq!(get(&prepared, first).await.unwrap().as_ref(), b"[]");
            assert_eq!(get(&cloned, second).await.unwrap().as_ref(), b"[]");
        })
    })
    .await
    .unwrap();
    for (request, path) in requests.iter().zip([
        "/api/v1/courses/42?include%5B%5D=assignment",
        "/api/v1/courses/43?per_page=10",
    ]) {
        let lower = request.to_ascii_lowercase();
        assert!(request.starts_with(&format!("GET {path} HTTP/1.1\r\n")));
        assert!(lower.contains(&format!("\r\nhost: localhost:{}\r\n", address.port())));
        assert!(lower.contains("\r\nauthorization: bearer synthetic-prepared-token\r\n"));
        assert!(lower.contains("\r\naccept: application/json\r\n"));
        assert!(!lower.contains("wrong-host.invalid"));
    }
    let lazy = CanvasOperationHttpClient::new(CanvasOriginPolicy::default(), budget);
    assert!(lazy.prepared.is_none());
    assert_eq!(
        get(&lazy, origin).await.unwrap_err(),
        CanvasOperationHttpError::Origin
    );
    no_connection(&listener).await;
}

#[tokio::test]
async fn prepared_cross_origin_port_scheme_and_credentials_fail_before_connect() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let other = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let (prepared, origin) = CanvasOperationHttpClient::prepare(
        local_policy(),
        CanvasNetworkTimeout::from_seconds(0.25),
        &base,
    )
    .await
    .unwrap();
    let mut port = origin.clone();
    port.set_port(Some(other.local_addr().unwrap().port()))
        .unwrap();
    let mut host = origin.clone();
    host.set_host(Some("localhost")).unwrap();
    let mut scheme = origin.clone();
    scheme.set_scheme("https").unwrap();
    let mut user = origin.clone();
    user.set_username("private-user-sentinel").unwrap();
    let mut password = origin.clone();
    password
        .set_password(Some("private-password-sentinel"))
        .unwrap();
    for rejected in [port, host, scheme, user, password] {
        let error = timeout(Duration::from_secs(1), get(&prepared, rejected))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(error, CanvasOperationHttpError::Origin);
        assert_eq!(
            error.to_string(),
            "Provider origin is unavailable or disallowed"
        );
    }
    no_connection(&listener).await;
    no_connection(&other).await;
}

#[tokio::test]
async fn prepare_rejects_invalid_persisted_roots_and_private_policy_before_connect() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let base = format!("http://{address}");
    let budget = CanvasNetworkTimeout::from_seconds(0.25);
    for invalid in [
        format!("{base}/api/v1"),
        format!("{base}/?private-query-sentinel=1"),
        format!("{base}/?"),
        format!("{base}/#private-fragment-sentinel"),
        format!("http://private-user-sentinel@{address}/"),
        format!("http://user:private-password-sentinel@{address}/"),
        format!("ftp://{address}/"),
        "not a provider URL".into(),
    ] {
        let error = timeout(
            Duration::from_secs(1),
            CanvasOperationHttpClient::prepare(local_policy(), budget, &invalid),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert_eq!(error, CanvasOperationHttpError::Origin);
        assert!(!error.to_string().contains("sentinel"));
    }
    assert_eq!(
        CanvasOperationHttpClient::prepare(CanvasOriginPolicy::default(), budget, &base)
            .await
            .unwrap_err(),
        CanvasOperationHttpError::Origin
    );
    assert_eq!(
        CanvasOperationHttpClient::prepare(
            CanvasOriginPolicy::default(),
            budget,
            &format!("https://{address}")
        )
        .await
        .unwrap_err(),
        CanvasOperationHttpError::Origin
    );
    no_connection(&listener).await;
}

#[tokio::test]
async fn prepared_debug_redacts_the_pin_origin_and_policy_contents() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let base = format!("http://{address}");
    let mut policy = local_policy();
    policy
        .private_origin_allowlist
        .push("https://private-prepared-policy-sentinel.invalid".into());
    let (client, _) =
        CanvasOperationHttpClient::prepare(policy, CanvasNetworkTimeout::from_seconds(0.5), &base)
            .await
            .unwrap();
    let private_address = address.to_string();
    for description in [
        format!("{client:?}"),
        format!("{:?}", client.prepared.as_ref().unwrap()),
    ] {
        assert!(description.contains("PreparedOrigin([redacted])"));
        for private in [
            base.as_str(),
            private_address.as_str(),
            "127.0.0.1",
            "private-prepared-policy-sentinel",
        ] {
            assert!(
                !description.contains(private),
                "prepared Debug exposed origin or policy contents"
            );
        }
    }
    no_connection(&listener).await;
}

#[tokio::test]
async fn lazy_client_still_resolves_each_independently_allowed_request_origin() {
    let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let second = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let one = Url::parse(&format!("http://{}/one", first.local_addr().unwrap())).unwrap();
    let two = Url::parse(&format!("http://{}/two", second.local_addr().unwrap())).unwrap();
    let client =
        CanvasOperationHttpClient::new(local_policy(), CanvasNetworkTimeout::from_seconds(0.5));
    assert!(client.prepared.is_none());
    let (first_requests, second_requests, ()) = timeout(Duration::from_secs(3), async {
        tokio::join!(serve(&first, 1), serve(&second, 1), async {
            assert_eq!(get(&client, one).await.unwrap().as_ref(), b"[]");
            assert_eq!(get(&client, two).await.unwrap().as_ref(), b"[]");
        })
    })
    .await
    .unwrap();
    assert_eq!(first_requests.len(), 1);
    assert_eq!(second_requests.len(), 1);
    assert!(first_requests[0].starts_with("GET /one HTTP/1.1\r\n"));
    assert!(second_requests[0].starts_with("GET /two HTTP/1.1\r\n"));
    assert!(
        client.prepared.is_none(),
        "lazy client must not acquire a cross-request pin"
    );
}
