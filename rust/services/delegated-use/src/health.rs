//! Optional container-local readiness transport. This listener has no business
//! route, identity mapping, credential output, or authority-changing operation.
use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use async_trait::async_trait;
use axum::{
    body::to_bytes,
    extract::{Request, State},
    http::{header, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use tokio::{net::TcpListener, sync::watch};

use crate::runtime::DelegatedUseRuntime;

#[async_trait]
trait Readiness: Send + Sync {
    async fn ready(&self) -> bool;
}

#[async_trait]
impl Readiness for DelegatedUseRuntime {
    async fn ready(&self) -> bool {
        self.readiness().await.is_ok()
    }
}

pub struct LoopbackHealthServer {
    listener: TcpListener,
    router: Router,
}

impl LoopbackHealthServer {
    pub async fn bind(address: SocketAddr, runtime: Arc<DelegatedUseRuntime>) -> io::Result<Self> {
        Self::bind_probe(address, runtime).await
    }

    async fn bind_probe(address: SocketAddr, readiness: Arc<dyn Readiness>) -> io::Result<Self> {
        // Repeat the boundary at the socket owner, even for a direct library
        // caller that did not construct DelegatedUseHostConfig.
        if !address.ip().is_loopback() || address.port() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "health listener must be loopback with a nonzero port",
            ));
        }
        Ok(Self {
            listener: TcpListener::bind(address).await?,
            router: router(readiness),
        })
    }

    pub async fn serve(self, mut shutdown: watch::Receiver<bool>) -> io::Result<()> {
        axum::serve(self.listener, self.router)
            .with_graceful_shutdown(async move {
                marty_service_runtime::wait_for_shutdown(&mut shutdown).await;
            })
            .await
    }
}

fn router(readiness: Arc<dyn Readiness>) -> Router {
    Router::new()
        .route("/health", get(probe))
        .route("/ready", get(probe))
        .with_state(readiness)
}

fn response(status: StatusCode) -> Response {
    let mut result = status.into_response();
    result
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    result
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    result.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    result
}

async fn probe(State(readiness): State<Arc<dyn Readiness>>, request: Request) -> Response {
    if request.method() != Method::GET {
        return response(StatusCode::METHOD_NOT_ALLOWED);
    }
    if request.uri().query().is_some()
        || request.headers().contains_key(header::TRANSFER_ENCODING)
        || request
            .headers()
            .get(header::CONTENT_LENGTH)
            .is_some_and(|value| value != "0")
    {
        return response(StatusCode::BAD_REQUEST);
    }
    if !matches!(
        tokio::time::timeout(Duration::from_secs(1), to_bytes(request.into_body(), 0)).await,
        Ok(Ok(_))
    ) {
        return response(StatusCode::BAD_REQUEST);
    }
    response(if readiness.ready().await {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tower::ServiceExt;

    struct Probe {
        available: AtomicBool,
        calls: AtomicUsize,
    }
    #[async_trait]
    impl Readiness for Probe {
        async fn ready(&self) -> bool {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.available.load(Ordering::SeqCst)
        }
    }

    #[tokio::test]
    async fn both_routes_report_current_readiness_without_data_or_business_routes() {
        let probe = Arc::new(Probe {
            available: AtomicBool::new(true),
            calls: AtomicUsize::new(0),
        });
        let app = router(probe.clone());
        for available in [true, false, true] {
            probe.available.store(available, Ordering::SeqCst);
            for path in ["/health", "/ready"] {
                let result = app
                    .clone()
                    .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                assert_eq!(
                    result.status(),
                    if available {
                        StatusCode::OK
                    } else {
                        StatusCode::SERVICE_UNAVAILABLE
                    }
                );
                assert_eq!(result.headers()[header::CACHE_CONTROL], "no-store");
                assert!(to_bytes(result.into_body(), 1).await.unwrap().is_empty());
            }
        }
        assert_eq!(probe.calls.load(Ordering::SeqCst), 6);
        for (method, path, body, expected) in [
            (
                "GET",
                "/ready?verbose=true",
                Body::empty(),
                StatusCode::BAD_REQUEST,
            ),
            (
                "GET",
                "/ready",
                Body::from("payload"),
                StatusCode::BAD_REQUEST,
            ),
            (
                "POST",
                "/ready",
                Body::empty(),
                StatusCode::METHOD_NOT_ALLOWED,
            ),
            (
                "HEAD",
                "/ready",
                Body::empty(),
                StatusCode::METHOD_NOT_ALLOWED,
            ),
            (
                "GET",
                "/internal/v1/delegated-use/commands",
                Body::empty(),
                StatusCode::NOT_FOUND,
            ),
            (
                "GET",
                "/v1/delegated-use/receipts",
                Body::empty(),
                StatusCode::NOT_FOUND,
            ),
        ] {
            let result = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .body(body)
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(result.status(), expected);
        }
        assert_eq!(
            probe.calls.load(Ordering::SeqCst),
            6,
            "invalid input must not query any owner"
        );
    }

    #[tokio::test]
    async fn socket_owner_refuses_public_wildcard_and_ephemeral_addresses() {
        let probe = Arc::new(Probe {
            available: AtomicBool::new(true),
            calls: AtomicUsize::new(0),
        });
        for raw in [
            "0.0.0.0:8022",
            "192.0.2.1:8022",
            "[::]:8022",
            "[2001:db8::1]:8022",
            "127.0.0.1:0",
        ] {
            let result =
                LoopbackHealthServer::bind_probe(raw.parse().unwrap(), probe.clone()).await;
            assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::InvalidInput));
        }
        assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
    }
}
