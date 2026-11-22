//! Opt-in, certificate-authenticated transport for the internal use surfaces.
//!
//! Only the verified leaf from a mandatory mutual-TLS handshake can construct
//! the private peer extension. Configuration pins its exact URI SAN and SHA-256
//! certificate digest to one full-machine principal. No HTTP header can create
//! that identity. Current Organization use access remains independently required.

use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use axum::{http::StatusCode, middleware::AddExtension, Extension, Router};
use axum_server::{
    accept::Accept,
    tls_rustls::{RustlsAcceptor, RustlsConfig},
    Handle,
};
use chrono::{DateTime, Utc};
use marty_crypto::certificate::get_certificate_info;
use marty_service_runtime::RemoteTlsIdentityFiles;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::watch,
};
use tokio_rustls::server::TlsStream;
use tower::Layer;
use uuid::Uuid;

use crate::{
    use_http::UseHttpError, DelegationCommandCaller, DelegationUseCommandError, Principal,
    PrincipalType,
};

/// Deployment configuration, never command JSON or forwarded headers. Leaf
/// replacement requires an explicitly reviewed new pin, even under the same CA.
#[derive(Clone, Debug)]
pub struct DelegatedUseWorkloadBinding {
    workload_uri: String,
    leaf_sha256: String,
    principal_id: String,
}

impl DelegatedUseWorkloadBinding {
    pub fn new(
        workload_uri: String,
        leaf_sha256: String,
        principal_id: String,
    ) -> Result<Self, DelegationUseCommandError> {
        if !valid_workload_uri(&workload_uri)
            || leaf_sha256.len() != 71
            || !leaf_sha256.starts_with("sha256:")
            || !leaf_sha256[7..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !crate::domain::valid_uri(Some(&principal_id))
        {
            return Err(DelegationUseCommandError::InvalidCommand);
        }
        Ok(Self {
            workload_uri,
            leaf_sha256,
            principal_id,
        })
    }
}

/// A bounded, unambiguous deployment mapping. Each URI and leaf pin occurs once;
/// one certificate cannot choose between multiple machine principals.
#[derive(Clone, Debug)]
pub struct DelegatedUseWorkloadBindings {
    by_uri: BTreeMap<String, DelegatedUseWorkloadBinding>,
}

impl DelegatedUseWorkloadBindings {
    pub fn new(
        bindings: Vec<DelegatedUseWorkloadBinding>,
    ) -> Result<Self, DelegationUseCommandError> {
        if bindings.is_empty() || bindings.len() > 128 {
            return Err(DelegationUseCommandError::InvalidCommand);
        }
        let mut by_uri = BTreeMap::new();
        let mut pins = BTreeSet::new();
        for binding in bindings {
            if !pins.insert(binding.leaf_sha256.clone())
                || by_uri
                    .insert(binding.workload_uri.clone(), binding)
                    .is_some()
            {
                return Err(DelegationUseCommandError::InvalidCommand);
            }
        }
        Ok(Self { by_uri })
    }

    pub(crate) fn authenticate(
        &self,
        organization_id: Uuid,
        peer: &AuthenticatedUseTlsPeer,
        now: DateTime<Utc>,
    ) -> Result<(DelegationCommandCaller, DateTime<Utc>), UseHttpError> {
        let denied = || UseHttpError::new(StatusCode::FORBIDDEN, "delegation_use_workload_denied");
        if peer.authenticated_at > now || peer.not_before > now || peer.not_after <= now {
            return Err(denied());
        }
        let binding = self.by_uri.get(&peer.workload_uri).ok_or_else(denied)?;
        if binding.leaf_sha256 != peer.leaf_sha256 {
            return Err(denied());
        }
        let caller = DelegationCommandCaller::from_authenticated_context(
            organization_id,
            Principal {
                principal_type: PrincipalType::MachineIdentity,
                id: binding.principal_id.clone(),
            },
        )
        .map_err(|_| denied())?;
        let valid_until = now
            .checked_add_signed(chrono::Duration::seconds(30))
            .ok_or_else(denied)?
            .min(peer.not_after);
        Ok((caller, valid_until))
    }
}

fn valid_workload_uri(value: &str) -> bool {
    if value.len() > 512 || value.contains('%') || !value.bytes().all(|b| b.is_ascii_graphic()) {
        return false;
    }
    let Ok(uri) = url::Url::parse(value) else {
        return false;
    };
    uri.scheme() == "spiffe"
        && uri.as_str() == value
        && uri.username().is_empty()
        && uri.password().is_none()
        && uri.port().is_none()
        && uri.query().is_none()
        && uri.fragment().is_none()
        && uri.host_str().is_some_and(|host| {
            !host.is_empty()
                && host.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_')
                })
        })
        && uri.path().starts_with('/')
        && uri.path().len() > 1
        && uri.path()[1..]
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

/// Private transport evidence. Public certificate bytes alone cannot create it
/// outside this module: the production construction path follows TLS validation.
#[derive(Clone)]
pub(crate) struct AuthenticatedUseTlsPeer {
    workload_uri: String,
    leaf_sha256: String,
    authenticated_at: DateTime<Utc>,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
}

impl AuthenticatedUseTlsPeer {
    pub(crate) fn identity_ref(&self) -> String {
        format!("urn:marty:delegated-use:mtls:{}", self.leaf_sha256)
    }
    fn from_verified_leaf(leaf: &[u8]) -> io::Result<Self> {
        let invalid = || {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "invalid delegated-use TLS identity",
            )
        };
        if leaf.len() > 65_536 {
            return Err(invalid());
        }
        let info = get_certificate_info(leaf).map_err(|_| invalid())?;
        let uris: Vec<_> = info
            .subject_alt_names
            .iter()
            .filter_map(|name| name.strip_prefix("URI:"))
            .collect();
        if info.is_ca || uris.len() != 1 || !valid_workload_uri(uris[0]) {
            return Err(invalid());
        }
        let not_before = DateTime::parse_from_rfc3339(&info.not_before)
            .map_err(|_| invalid())?
            .with_timezone(&Utc);
        let not_after = DateTime::parse_from_rfc3339(&info.not_after)
            .map_err(|_| invalid())?
            .with_timezone(&Utc);
        let now = Utc::now();
        if not_before > now || not_after <= now {
            return Err(invalid());
        }
        Ok(Self {
            workload_uri: uris[0].to_owned(),
            leaf_sha256: format!("sha256:{}", info.fingerprint_sha256),
            authenticated_at: now,
            not_before,
            not_after,
        })
    }
}

#[derive(Clone)]
struct WorkloadTlsAcceptor {
    inner: RustlsAcceptor,
}

impl<I, S> Accept<I, S> for WorkloadTlsAcceptor
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = TlsStream<I>;
    type Service = AddExtension<S, AuthenticatedUseTlsPeer>;
    type Future = Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let acceptor = self.inner.clone();
        Box::pin(async move {
            let (stream, service) = acceptor.accept(stream, service).await?;
            let leaf = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|chain| chain.first())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "client certificate required",
                    )
                })?;
            // Never inspect a CA/intermediate SAN as the workload identity.
            let peer = AuthenticatedUseTlsPeer::from_verified_leaf(leaf.as_ref())?;
            Ok((stream, Extension(peer).layer(service)))
        })
    }
}

/// Explicit, keyless server assembly; no executable or default listener selects
/// this transport. There is no plaintext or local private-key production mode.
pub struct BoundDelegatedUseMtlsServer {
    listener: std::net::TcpListener,
    tls: RustlsConfig,
    router: Router,
}

impl BoundDelegatedUseMtlsServer {
    pub async fn bind(
        address: SocketAddr,
        identity: &RemoteTlsIdentityFiles,
        client_ca_der: Vec<Vec<u8>>,
        router: Router,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        if client_ca_der.is_empty()
            || client_ca_der.len() > 16
            || client_ca_der
                .iter()
                .any(|ca| ca.is_empty() || ca.len() > 65_536)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "bounded client CA set required",
            )
            .into());
        }
        let identity = identity.connect().await?;
        let mut config =
            (*mmf_platform::keyless_grpc_server_config(&identity, client_ca_der)?).clone();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        // Fresh handshakes validate the client chain. Every request additionally
        // checks the original leaf validity and the exact configured pin.
        config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        config.send_tls13_tickets = 0;
        Self::bind_config(address, Arc::new(config), router).map_err(Into::into)
    }

    fn bind_config(
        address: SocketAddr,
        config: Arc<rustls::ServerConfig>,
        router: Router,
    ) -> io::Result<Self> {
        let listener = std::net::TcpListener::bind(address)?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            tls: RustlsConfig::from_config(config),
            router,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub async fn serve(self, mut shutdown: watch::Receiver<bool>) -> io::Result<()> {
        let handle = Handle::new();
        let acceptor = WorkloadTlsAcceptor {
            inner: RustlsAcceptor::new(self.tls).handshake_timeout(Duration::from_secs(5)),
        };
        let server = axum_server::from_tcp(self.listener)?
            .acceptor(acceptor)
            .handle(handle.clone())
            .serve(self.router.into_make_service());
        tokio::pin!(server);
        tokio::select! {
            result = &mut server => result,
            () = marty_service_runtime::wait_for_shutdown(&mut shutdown) => {
                handle.graceful_shutdown(Some(Duration::from_secs(15)));
                server.await
            }
        }
    }
}

#[cfg(test)]
mod tests;
