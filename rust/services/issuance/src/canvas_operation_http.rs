//! Single-request, DNS-pinned HTTP/1 provider transport with operation deadlines.
//! The client owns no shared pool, proxy or redirect mechanism. Hyper handles HTTP
//! framing; rustls retains platform certificate verification and original SNI.

use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc,
    },
    task::{Context, Poll},
};

use bytes::Bytes;
use futures_core::Stream;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use rustls_platform_verifier::BuilderVerifierExt;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use url::Url;

use crate::{
    canvas_content_decoder::CanvasContentDecoder,
    canvas_network_timeout::{CanvasNetworkBudget, CanvasNetworkPhase, CanvasNetworkTimeout},
    canvas_provider_http::{resolve_canvas_origin, CanvasOriginPolicy},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CanvasOperationHttpError {
    #[error("Provider origin is unavailable or disallowed")]
    Origin,
    #[error("Provider connection unavailable")]
    Connect,
    #[error("Provider TLS connection unavailable")]
    Tls,
    #[error("Provider request unavailable")]
    Request,
    #[error("Provider response unavailable")]
    Response,
    #[error("Provider response content decoding failed")]
    Decoding,
    #[cfg(test)]
    #[error(transparent)]
    Text(#[from] crate::canvas_response_text::CanvasResponseTextError),
    #[error("Provider {0:?} operation timed out")]
    Timeout(CanvasNetworkPhase),
}

fn failed(phase: &AtomicU8, fallback: CanvasOperationHttpError) -> CanvasOperationHttpError {
    match phase.load(Ordering::Relaxed) {
        1 => CanvasOperationHttpError::Timeout(CanvasNetworkPhase::Read),
        2 => CanvasOperationHttpError::Timeout(CanvasNetworkPhase::Write),
        _ => fallback,
    }
}

trait Socket: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Socket for T {}

struct OperationSocket {
    inner: Box<dyn Socket>,
    timeout: CanvasNetworkTimeout,
    read_budget: Option<CanvasNetworkBudget>,
    write_budget: Option<CanvasNetworkBudget>,
    phase: Arc<AtomicU8>,
    header_tail: u32,
    headers_written: bool,
    body_remaining: usize,
    request_flushed: bool,
}

impl OperationSocket {
    fn check(
        budget: &mut Option<CanvasNetworkBudget>,
        timeout: CanvasNetworkTimeout,
        cx: &mut Context<'_>,
    ) -> bool {
        Pin::new(budget.get_or_insert_with(|| timeout.budget()))
            .poll(cx)
            .is_ready()
    }

    fn expired(&self, phase: u8) -> io::Error {
        let _ = self
            .phase
            .compare_exchange(0, phase, Ordering::Relaxed, Ordering::Relaxed);
        io::Error::new(
            io::ErrorKind::TimedOut,
            "Canvas provider operation timed out",
        )
    }

    fn wrote(&mut self, bytes: &[u8]) {
        let mut body_offset = 0;
        if !self.headers_written {
            body_offset = bytes.len();
            for (index, byte) in bytes.iter().enumerate() {
                self.header_tail = (self.header_tail << 8) | u32::from(*byte);
                if self.header_tail == 0x0d0a0d0a {
                    self.headers_written = true;
                    body_offset = index + 1;
                    // HTTPX emits headers and the single JSON body as separate
                    // write operations. Keep that boundary across partial I/O.
                    self.write_budget = None;
                    break;
                }
            }
        }
        if self.headers_written {
            self.body_remaining = self
                .body_remaining
                .saturating_sub(bytes.len() - body_offset);
        }
    }
}

impl AsyncRead for OperationSocket {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // Hyper can poll for an early response while request writes are still
        // pending. HTTPX's response-read deadline starts only after those writes.
        if !this.request_flushed {
            return Poll::Pending;
        }
        if Self::check(&mut this.read_budget, this.timeout, cx) {
            return Poll::Ready(Err(this.expired(1)));
        }
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if result.is_ready() {
            this.read_budget = None;
        }
        result
    }
}

impl AsyncWrite for OperationSocket {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if Self::check(&mut this.write_budget, this.timeout, cx) {
            return Poll::Ready(Err(this.expired(2)));
        }
        let result = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(count)) = &result {
            this.wrote(&buf[..*count]);
        }
        result
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if Self::check(&mut this.write_budget, this.timeout, cx) {
            return Poll::Ready(Err(this.expired(2)));
        }
        let result = Pin::new(&mut this.inner).poll_flush(cx);
        if matches!(&result, Poll::Ready(Ok(()))) {
            this.write_budget = None;
            if !this.request_flushed && this.headers_written && this.body_remaining == 0 {
                this.request_flushed = true;
                cx.waker().wake_by_ref();
            }
        }
        result
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

struct Driver(tokio::task::JoinHandle<()>);
impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct ResponseStream {
    stream: Pin<Box<dyn Stream<Item = Result<Bytes, hyper::Error>> + Send>>,
    _driver: Driver,
}
impl Stream for ResponseStream {
    type Item = Result<Bytes, hyper::Error>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().stream.as_mut().poll_next(cx)
    }
}

pub(crate) struct CanvasOperationResponse {
    pub response: reqwest::Response,
    phase: Arc<AtomicU8>,
    decoders: Vec<CanvasContentDecoder>,
    finished: bool,
}
impl CanvasOperationResponse {
    pub fn content_type(&self) -> Option<String> {
        let values = self
            .response
            .headers()
            .get_all(http::header::CONTENT_TYPE)
            .iter()
            .map(|value| {
                value
                    .as_bytes()
                    .iter()
                    .map(|byte| char::from(*byte))
                    .collect::<String>()
            })
            .collect::<Vec<_>>();
        if values.is_empty() {
            None
        } else {
            Some(values.join(", "))
        }
    }
    pub async fn chunk(&mut self) -> Result<Option<Bytes>, CanvasOperationHttpError> {
        if self.finished {
            return Ok(None);
        }
        let chunk = self
            .response
            .chunk()
            .await
            .map_err(|_| failed(&self.phase, CanvasOperationHttpError::Response))?;
        self.finished = chunk.is_none();
        if self.decoders.is_empty() {
            return Ok(chunk);
        }
        let mut decoded = chunk.unwrap_or_default().to_vec();
        for decoder in &mut self.decoders {
            decoded = decoder.decode(&decoded)?;
        }
        if self.finished && decoded.is_empty() {
            Ok(None)
        } else {
            Ok(Some(Bytes::from(decoded)))
        }
    }
    pub async fn bytes(mut self) -> Result<Bytes, CanvasOperationHttpError> {
        let mut bytes = Vec::new();
        while let Some(chunk) = self.chunk().await? {
            bytes.extend_from_slice(&chunk);
        }
        Ok(Bytes::from(bytes))
    }
    #[cfg(test)]
    pub async fn text(self) -> Result<String, CanvasOperationHttpError> {
        let content_type = self.content_type();
        Ok(crate::canvas_response_text::response_text(
            &self.bytes().await?,
            content_type.as_deref(),
        )?)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct CanvasOperationHttpClient {
    policy: CanvasOriginPolicy,
    timeout: CanvasNetworkTimeout,
    tls: Option<Arc<rustls::ClientConfig>>,
}

impl CanvasOperationHttpClient {
    pub fn new(policy: CanvasOriginPolicy, timeout: CanvasNetworkTimeout) -> Self {
        Self {
            policy,
            timeout,
            tls: None,
        }
    }

    pub async fn send(
        &self,
        method: http::Method,
        url: Url,
        headers: http::HeaderMap,
        body: Vec<u8>,
    ) -> Result<CanvasOperationResponse, CanvasOperationHttpError> {
        if !url.username().is_empty() || url.password().is_some() {
            return Err(CanvasOperationHttpError::Origin);
        }
        let (origin, pinned) =
            resolve_canvas_origin(&url.origin().ascii_serialization(), &self.policy)
                .await
                .map_err(|_| CanvasOperationHttpError::Origin)?;
        let tcp = self
            .timeout
            .run(
                CanvasNetworkPhase::Connect,
                tokio::net::TcpStream::connect(pinned),
            )
            .await
            .map_err(|error| CanvasOperationHttpError::Timeout(error.phase))?
            .map_err(|_| CanvasOperationHttpError::Connect)?;
        tcp.set_nodelay(true)
            .map_err(|_| CanvasOperationHttpError::Connect)?;
        let socket: Box<dyn Socket> = if origin.scheme() == "https" {
            let config = match &self.tls {
                Some(config) => config.clone(),
                None => Arc::new(
                    rustls::ClientConfig::builder_with_provider(Arc::new(
                        rustls::crypto::aws_lc_rs::default_provider(),
                    ))
                    .with_safe_default_protocol_versions()
                    .map_err(|_| CanvasOperationHttpError::Tls)?
                    .with_platform_verifier()
                    .map_err(|_| CanvasOperationHttpError::Tls)?
                    .with_no_client_auth(),
                ),
            };
            let name = rustls::pki_types::ServerName::try_from(
                origin
                    .host_str()
                    .ok_or(CanvasOperationHttpError::Origin)?
                    .to_owned(),
            )
            .map_err(|_| CanvasOperationHttpError::Origin)?;
            Box::new(
                self.timeout
                    .run(
                        CanvasNetworkPhase::Tls,
                        tokio_rustls::TlsConnector::from(config).connect(name, tcp),
                    )
                    .await
                    .map_err(|error| CanvasOperationHttpError::Timeout(error.phase))?
                    .map_err(|_| CanvasOperationHttpError::Tls)?,
            )
        } else {
            Box::new(tcp)
        };
        let phase = Arc::new(AtomicU8::new(0));
        let io = OperationSocket {
            inner: socket,
            timeout: self.timeout,
            read_budget: None,
            write_budget: None,
            phase: phase.clone(),
            header_tail: 0,
            headers_written: false,
            body_remaining: body.len(),
            request_flushed: false,
        };
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(io))
            .await
            .map_err(|_| CanvasOperationHttpError::Request)?;
        let driver = Driver(tokio::spawn(async move {
            let _ = connection.await;
        }));
        let mut request = http::Request::builder()
            .method(method)
            .uri(&url[url::Position::BeforePath..url::Position::AfterQuery])
            .body(Full::new(Bytes::from(body)))
            .map_err(|_| CanvasOperationHttpError::Request)?;
        *request.headers_mut() = headers;
        request
            .headers_mut()
            .entry(http::header::ACCEPT_ENCODING)
            .or_insert(http::HeaderValue::from_static("gzip, deflate"));
        let authority = &origin[url::Position::BeforeHost..url::Position::AfterPort];
        request.headers_mut().insert(
            http::header::HOST,
            http::HeaderValue::from_str(authority)
                .map_err(|_| CanvasOperationHttpError::Request)?,
        );
        let response = sender
            .send_request(request)
            .await
            .map_err(|_| failed(&phase, CanvasOperationHttpError::Request))?;
        let (parts, body) = response.into_parts();
        let decoders = CanvasContentDecoder::from_headers(&parts.headers);
        let stream = ResponseStream {
            stream: Box::pin(body.into_data_stream()),
            _driver: driver,
        };
        let response = http::Response::from_parts(parts, reqwest::Body::wrap_stream(stream));
        Ok(CanvasOperationResponse {
            response: reqwest::Response::from(response),
            phase,
            decoders,
            finished: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{pem::PemObject, CertificateDer};
    use serde_json::{json, Value};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn split_headers_and_body_do_not_start_a_response_deadline_early() {
        let (io, _peer) = tokio::io::duplex(64);
        let mut socket = OperationSocket {
            inner: Box::new(io),
            timeout: CanvasNetworkTimeout::from_seconds(0.01),
            read_budget: None,
            write_budget: None,
            phase: Arc::new(AtomicU8::new(0)),
            header_tail: 0,
            headers_written: false,
            body_remaining: 3,
            request_flushed: false,
        };
        socket.wrote(b"POST / HTTP/1.1\r\nContent-Length: 3\r\n\r");
        assert!(!socket.headers_written);
        socket.wrote(b"\na");
        assert!(socket.headers_written);
        assert_eq!(socket.body_remaining, 2);
        let mut byte = [0];
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(30), socket.read(&mut byte))
                .await
                .is_err()
        );
        assert!(socket.read_budget.is_none());
        assert_eq!(socket.phase.load(Ordering::Relaxed), 0);
        socket.wrote(b"bc");
        socket.flush().await.unwrap();
        assert!(socket.request_flushed);
        let failure = socket.read(&mut byte).await.unwrap_err();
        assert_eq!(failure.kind(), io::ErrorKind::TimedOut);
        assert_eq!(socket.phase.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn cancellation_and_response_drop_close_the_owned_connection() {
        for response_started in [false, true] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let origin = format!("http://{}", listener.local_addr().unwrap());
            let (ready, started) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut headers = Vec::new();
                let mut byte = [0];
                while !headers.ends_with(b"\r\n\r\n") {
                    socket.read_exact(&mut byte).await.unwrap();
                    headers.push(byte[0]);
                    assert!(headers.len() < 8192);
                }
                if response_started {
                    socket
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\na")
                        .await
                        .unwrap();
                }
                let _ = ready.send(());
                tokio::time::timeout(std::time::Duration::from_secs(3), socket.read(&mut byte))
                    .await
                    .unwrap()
                    .unwrap()
            });
            let client = CanvasOperationHttpClient::new(
                CanvasOriginPolicy {
                    allow_http_localhost: true,
                    ..Default::default()
                },
                CanvasNetworkTimeout::from_seconds(f64::INFINITY),
            );
            let task = tokio::spawn(async move {
                client
                    .send(
                        http::Method::GET,
                        Url::parse(&origin).unwrap(),
                        http::HeaderMap::new(),
                        Vec::new(),
                    )
                    .await
            });
            started.await.unwrap();
            if response_started {
                drop(task.await.unwrap().unwrap());
            } else {
                task.abort();
                assert!(matches!(task.await, Err(error) if error.is_cancelled()));
            }
            assert_eq!(
                server.await.unwrap(),
                0,
                "connection must not outlive its request or response"
            );
        }
    }

    // Invoked only by the owned TLS fixture; the mandatory CI invocation verifies
    // its single observation for every frozen published socket case.
    #[tokio::test]
    async fn native_socket_case() {
        let Ok(raw) = std::env::var("MARTY_CANVAS_TIMEOUT_NATIVE_CASE") else {
            return;
        };
        let case: Value = serde_json::from_str(&raw).unwrap();
        let origin = std::env::var("MARTY_CANVAS_TIMEOUT_NATIVE_ORIGIN").unwrap();
        assert!(origin.starts_with("https://127.0.0.1:"));
        let path = case["response"].as_str().unwrap();
        assert!(matches!(
            path,
            "immediate"
                | "headers"
                | "body"
                | "progress"
                | "failure_json_exact"
                | "failure_json_large"
                | "failure_text_large"
                | "failure_stall"
                | "json_utf8_bom"
                | "json_utf16_le"
                | "json_utf16_be"
                | "json_utf16_le_bom"
                | "json_utf16_be_bom"
                | "json_utf32_le"
                | "json_utf32_be"
                | "json_utf32_le_bom"
                | "json_utf32_be_bom"
                | "text_utf8_bom"
                | "gzip_json"
                | "deflate_json"
                | "raw_deflate_json"
                | "stacked_json"
                | "double_gzip_json"
                | "mixed_case_gzip"
                | "unknown_encoding"
                | "unsupported_br"
                | "gzip_trailing_bytes"
                | "gzip_without_trailer"
                | "gzip_invalid"
                | "deflate_invalid"
                | "gzip_success_invalid"
                | "stacked_headers"
                | "gzip_progress"
                | "gzip_stall"
                | "text_ascii"
                | "text_ascii_alias"
                | "text_latin1"
                | "text_latin1_alias"
                | "text_latin1_spaces"
                | "text_quoted_charset"
                | "text_quoted_semicolon"
                | "text_first_charset"
                | "text_unknown_charset"
                | "text_empty_charset"
                | "text_without_charset"
                | "text_without_type"
                | "text_invalid_media_type"
                | "text_utf8_sig"
                | "text_ascii_bom"
                | "text_json_latin1"
                | "text_long_latin1"
                | "text_cp1252"
                | "text_cp037"
                | "text_koi8_r"
                | "text_mac_roman"
                | "text_multibyte_big5"
                | "text_multibyte_big5hkscs"
                | "text_multibyte_cp932"
                | "text_multibyte_cp949"
                | "text_multibyte_cp950"
                | "text_multibyte_gb2312"
                | "text_multibyte_gbk"
                | "text_multibyte_johab"
                | "text_multibyte_shift_jis"
                | "text_multibyte_shift_jis_2004"
                | "text_multibyte_shift_jisx0213"
                | "text_multibyte_euc_jp"
                | "text_multibyte_euc_jis_2004"
                | "text_multibyte_euc_jisx0213"
                | "text_multibyte_hz"
                | "text_gb18030"
                | "text_euc_kr"
                | "text_iso2022_kr"
                | "text_iso2022_jp"
                | "text_iso2022_jp_1"
                | "text_iso2022_jp_2"
                | "text_iso2022_jp_2004"
                | "text_iso2022_jp_3"
                | "text_iso2022_jp_ext"
                | "text_iso2022_internal"
                | "text_iso2022_pending"
                | "text_iso2022_label"
                | "text_iso2022_label_json"
        ));
        let config = crate::config::IssuanceServiceConfig::from_values([(
            "CANVAS_CREDENTIALS_STATUS_SYNC_TIMEOUT_SECONDS".to_owned(),
            case["seconds"].as_str().unwrap().to_owned(),
        )])
        .unwrap();
        let policy = CanvasOriginPolicy {
            private_origin_allowlist: vec![origin.clone()],
            allow_private_networks: false,
            allow_http_localhost: false,
        };
        let mut client =
            CanvasOperationHttpClient::new(policy, config.canvas_credentials_validation_timeout);
        if case["trusted"] != false {
            let cert = std::env::var("MARTY_CANVAS_TIMEOUT_NATIVE_CERT").unwrap();
            assert_eq!(
                std::path::Path::new(&cert).file_name().unwrap(),
                "synthetic.pem"
            );
            let mut roots = rustls::RootCertStore::empty();
            roots
                .add(CertificateDer::from_pem_file(cert).unwrap())
                .unwrap();
            client.tls = Some(Arc::new(
                rustls::ClientConfig::builder_with_provider(Arc::new(
                    rustls::crypto::aws_lc_rs::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth(),
            ));
        }
        let result = async {
            let mut response = client
                .send(
                    http::Method::GET,
                    Url::parse(&format!("{origin}/{path}")).unwrap(),
                    http::HeaderMap::new(),
                    Vec::new(),
                )
                .await?;
            let status = response.response.status().as_u16();
            let body = if case["projection"] == "discard" {
                while response.chunk().await?.is_some() {}
                Value::Null
            } else if case["projection"] == "excerpt" {
                let content_type = response.content_type();
                json!(crate::canvas_credentials_protocol::response_excerpt(
                    &response.bytes().await?,
                    content_type.as_deref()
                )?)
            } else {
                json!(response.text().await?)
            };
            Ok::<_, CanvasOperationHttpError>(json!({"status":status, "body":body}))
        }
        .await;
        let mut result = match result {
            Ok(value) => value,
            Err(error) => json!({"error_class": match error {
                CanvasOperationHttpError::Timeout(CanvasNetworkPhase::Connect | CanvasNetworkPhase::Tls) => "ConnectTimeout",
                CanvasOperationHttpError::Timeout(CanvasNetworkPhase::Read) => "ReadTimeout",
                CanvasOperationHttpError::Timeout(CanvasNetworkPhase::Write) => "WriteTimeout",
                CanvasOperationHttpError::Connect | CanvasOperationHttpError::Tls => "ConnectError",
                CanvasOperationHttpError::Decoding => "DecodingError",
                CanvasOperationHttpError::Text(error) => error.diagnostic_class(),
                _ => panic!("unexpected fixture outcome: {error:?}"),
            }}),
        };
        result["name"] = case["name"].clone();
        println!("\nCANVAS_TIMEOUT_NATIVE={result}");
    }
}
