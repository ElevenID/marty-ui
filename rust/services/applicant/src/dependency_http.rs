//! HTTP policy for configured internal service owners.

use reqwest::{redirect::Policy, Client};
use std::time::Duration;

pub const DEFAULT_DEPENDENCY_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Bound the complete response and keep service credentials at the configured
/// owner. A redirect is a dependency failure, not permission to forward them.
pub fn client(timeout: Duration) -> Result<Client, reqwest::Error> {
    Client::builder()
        .redirect(Policy::none())
        .connect_timeout(CONNECT_TIMEOUT.min(timeout))
        .timeout(timeout)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::StatusCode, response::Response, routing::any, Router};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    #[tokio::test]
    async fn redirects_do_not_forward_service_credentials() {
        let received = Arc::new(AtomicUsize::new(0));
        let observed = received.clone();
        let target = Router::new().route(
            "/",
            any(move || {
                let observed = observed.clone();
                async move {
                    observed.fetch_add(1, Ordering::SeqCst);
                    StatusCode::OK
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_url = format!("http://{}/", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, target).await.unwrap() });
        let http = client(DEFAULT_DEPENDENCY_TIMEOUT).unwrap();
        assert_eq!(
            http.get(&target_url).send().await.unwrap().status(),
            StatusCode::OK
        );
        received.store(0, Ordering::SeqCst);

        for status in [301, 302, 303, 307, 308] {
            let location = target_url.clone();
            let redirect = Router::new().route(
                "/",
                any(move || {
                    let location = location.clone();
                    async move {
                        Response::builder()
                            .status(status)
                            .header("location", location)
                            .body(Body::empty())
                            .unwrap()
                    }
                }),
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let origin = format!("http://{}/", listener.local_addr().unwrap());
            let redirect_server =
                tokio::spawn(async move { axum::serve(listener, redirect).await.unwrap() });
            let response = http
                .post(origin)
                .header("x-service-token", "synthetic-service-token")
                .header("x-api-key", "synthetic-api-key")
                .body("private event")
                .send()
                .await
                .unwrap();
            assert_eq!(response.status().as_u16(), status);
            assert_eq!(received.load(Ordering::SeqCst), 0);
            redirect_server.abort();
        }
        server.abort();
    }

    #[tokio::test]
    async fn stalled_response_headers_are_bounded() {
        let app = Router::new().route(
            "/",
            any(|| async { std::future::pending::<StatusCode>().await }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}/", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let error = tokio::time::timeout(
            Duration::from_secs(2),
            client(Duration::from_millis(50))
                .unwrap()
                .get(origin)
                .send(),
        )
        .await
        .expect("dependency request remained unbounded")
        .unwrap_err();
        assert!(error.is_timeout());
        server.abort();
    }

    #[tokio::test]
    async fn stalled_response_body_is_bounded() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}/", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            assert_ne!(
                socket.read(&mut request).await.unwrap(),
                0,
                "client closed before sending its request"
            );
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n")
                .await
                .unwrap();
            std::future::pending::<()>().await;
        });
        let error = tokio::time::timeout(Duration::from_secs(2), async {
            client(Duration::from_millis(100))
                .unwrap()
                .get(origin)
                .send()
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap_err()
        })
        .await
        .expect("dependency body remained unbounded");
        assert!(error.is_timeout());
        server.abort();
    }
}
