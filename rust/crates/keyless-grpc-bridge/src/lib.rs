//! Local plaintext gRPC from Envoy is confined to its loopback network
//! namespace. The upstream connection uses mTLS with a non-exportable remote
//! identity and a pinned public CA; no private key enters this process.

use std::{
    collections::BTreeMap, env, error::Error, net::SocketAddr, path::PathBuf, sync::Arc,
    time::Duration,
};

use marty_service_runtime::{RemoteTlsIdentityFiles, TlsIdentityNames};
use mmf_platform::{keyless_grpc_client_config, read_public_certificates};
use rustls::pki_types::ServerName;
use tokio::{
    io::copy_bidirectional,
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    time::timeout,
};
use tokio_rustls::TlsConnector;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CONNECTIONS: usize = 128;

fn required(name: &str) -> Result<String, Box<dyn Error + Send + Sync>> {
    let value = env::var(name)?;
    if value.trim().is_empty() || value.contains(['\r', '\n']) {
        return Err(format!("{name} must be a nonempty single-line value").into());
    }
    Ok(value)
}

fn loopback_listener(value: &str) -> Result<SocketAddr, Box<dyn Error + Send + Sync>> {
    let address: SocketAddr = value.parse()?;
    if !address.ip().is_loopback() || address.port() == 0 {
        return Err("bridge listener must be a nonzero loopback socket".into());
    }
    Ok(address)
}

fn upstream_name(value: &str) -> Result<ServerName<'static>, Box<dyn Error + Send + Sync>> {
    let name = ServerName::try_from(value.to_owned())?;
    if name.to_str() == "localhost" || name.to_str().is_empty() {
        return Err("bridge upstream must be an explicit remote service name".into());
    }
    Ok(name)
}

pub async fn run_from_environment() -> Result<(), Box<dyn Error + Send + Sync>> {
    let listen = loopback_listener(&required("KEYLESS_BRIDGE_LISTEN")?)?;
    let host = required("KEYLESS_BRIDGE_UPSTREAM_HOST")?;
    let port: u16 = required("KEYLESS_BRIDGE_UPSTREAM_PORT")?.parse()?;
    if port == 0 {
        return Err("bridge upstream port must be nonzero".into());
    }
    upstream_name(&host)?;
    let values = env::vars().collect::<BTreeMap<_, _>>();
    let mut names = TlsIdentityNames::files("KEYLESS_BRIDGE");
    names.certificate = "KEYLESS_BRIDGE_CLIENT_CERT_FILE".into();
    names.private_key = "KEYLESS_BRIDGE_CLIENT_KEY_FILE".into();
    let identity = RemoteTlsIdentityFiles::from_values(
        |name| values.get(name).map(String::as_str),
        names,
        CONNECT_TIMEOUT,
        64,
    )?
    .ok_or("keyless gRPC bridge requires a remote TLS identity")?;
    let bridge = Bridge::connect(
        identity,
        PathBuf::from(required("KEYLESS_BRIDGE_SERVER_CA_FILE")?),
        host,
        port,
    )
    .await?;
    let listener = TcpListener::bind(listen).await?;
    bridge.serve(listener).await?;
    Ok(())
}

/// One in-process Envoy client identity and bounded mTLS forwarder.
/// Callers must bind the listener to loopback in Envoy's network namespace.
pub struct Bridge {
    tls: TlsConnector,
    name: ServerName<'static>,
    host: String,
    port: u16,
    permits: Arc<Semaphore>,
}

impl Bridge {
    pub async fn connect(
        identity: impl Into<RemoteTlsIdentityFiles>,
        server_ca_file: PathBuf,
        host: String,
        port: u16,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        if port == 0 {
            return Err("bridge upstream port must be nonzero".into());
        }
        let name = upstream_name(&host).map_err(|_| "bridge upstream name is invalid")?;
        let identity = identity.into().connect().await?;
        let server_ca = read_public_certificates(&server_ca_file)?;
        Ok(Self {
            tls: TlsConnector::from(keyless_grpc_client_config(&identity, server_ca)?),
            name,
            host,
            port,
            permits: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
        })
    }

    pub async fn serve(self, listener: TcpListener) -> Result<(), Box<dyn Error + Send + Sync>> {
        if !listener.local_addr()?.ip().is_loopback() {
            return Err("bridge listener must bind loopback".into());
        }
        loop {
            let (downstream, peer) = listener.accept().await?;
            if !peer.ip().is_loopback() {
                continue;
            }
            let permit = self.permits.clone().acquire_owned().await?;
            let tls = self.tls.clone();
            let name = self.name.clone();
            let host = self.host.clone();
            let port = self.port;
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(error) = forward(downstream, &host, port, name, tls).await {
                    eprintln!("keyless gRPC bridge connection failed: {error}");
                }
            });
        }
    }
}

async fn forward(
    mut downstream: TcpStream,
    host: &str,
    port: u16,
    name: ServerName<'static>,
    tls: TlsConnector,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let upstream = timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port))).await??;
    let mut upstream = timeout(CONNECT_TIMEOUT, tls.connect(name, upstream)).await??;
    copy_bidirectional(&mut downstream, &mut upstream).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_refuses_nonlocal_listener_and_implicit_upstream() {
        assert!(loopback_listener("0.0.0.0:19006").is_err());
        assert!(loopback_listener("127.0.0.1:0").is_err());
        assert!(loopback_listener("127.0.0.1:19006").is_ok());
        assert!(upstream_name("localhost").is_err());
        assert!(upstream_name("issuance-native").is_ok());
    }
}
