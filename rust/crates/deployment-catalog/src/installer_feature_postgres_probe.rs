//! Fixed, read-only PostgreSQL TLS probe. It sends only SSLRequest and a TLS
//! handshake, never a password, SQL statement, connection startup or retry.
#![cfg(target_os = "linux")]

use rustls::{
    pki_types::{CertificateDer, ServerName},
    ClientConfig, ClientConnection, RootCertStore,
};
use std::{
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
    sync::Arc,
    time::Duration,
};
use x509_cert::{
    der::{DecodePem, Encode},
    Certificate,
};

const REFUSED: &str = "owned PostgreSQL fresh TLS fingerprint verification failed";
const CA: &str = "/run/feature-profile/feature_postgres_ca";
const SSL_REQUEST: [u8; 8] = [0, 0, 0, 8, 4, 210, 22, 47];

pub fn run(expected_sha256: &str) -> Result<(), String> {
    if expected_sha256.len() != 64
        || !expected_sha256
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
    {
        return Err(REFUSED.into());
    }
    let mut raw = Vec::new();
    std::fs::File::open(CA)
        .map_err(|_| REFUSED)?
        .take(16_385)
        .read_to_end(&mut raw)
        .map_err(|_| REFUSED)?;
    if raw.is_empty()
        || raw.len() > 16_384
        || raw.windows(11).any(|v| v == b"PRIVATE KEY")
        || raw
            .windows(b"-----BEGIN CERTIFICATE-----".len())
            .filter(|v| *v == b"-----BEGIN CERTIFICATE-----")
            .count()
            != 1
        || raw
            .windows(b"-----END CERTIFICATE-----".len())
            .filter(|v| *v == b"-----END CERTIFICATE-----")
            .count()
            != 1
    {
        return Err(REFUSED.into());
    }
    let certificate = Certificate::from_pem(&raw).map_err(|_| REFUSED)?;
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(
            certificate.to_der().map_err(|_| REFUSED)?,
        ))
        .map_err(|_| REFUSED)?;
    let config = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| REFUSED)?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let addresses: Vec<_> = ("postgres", 5432)
        .to_socket_addrs()
        .map_err(|_| REFUSED)?
        .collect();
    if addresses.is_empty() || addresses.len() > 8 {
        return Err(REFUSED.into());
    }
    // The native caller bounds the whole exec. A single address/handshake is
    // deliberate: a failed observation is not permission to try another owner.
    let mut socket =
        TcpStream::connect_timeout(&addresses[0], Duration::from_secs(5)).map_err(|_| REFUSED)?;
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| REFUSED)?;
    socket
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| REFUSED)?;
    negotiate(&mut socket)?;
    let mut client = ClientConnection::new(
        Arc::new(config),
        ServerName::try_from("postgres").map_err(|_| REFUSED)?,
    )
    .map_err(|_| REFUSED)?;
    while client.is_handshaking() {
        client.complete_io(&mut socket).map_err(|_| REFUSED)?;
    }
    let peer = client
        .peer_certificates()
        .and_then(|chain| chain.first())
        .ok_or(REFUSED)?;
    if crate::installer_release::sha256(peer.as_ref()) != expected_sha256 {
        return Err(REFUSED.into());
    }
    Ok(())
}

fn negotiate(stream: &mut (impl Read + Write)) -> Result<(), String> {
    stream.write_all(&SSL_REQUEST).map_err(|_| REFUSED)?;
    let mut response = [0u8];
    stream.read_exact(&mut response).map_err(|_| REFUSED)?;
    if response != [b'S'] {
        return Err(REFUSED.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Wire {
        request: Vec<u8>,
        response: std::io::Cursor<Vec<u8>>,
    }
    impl Write for Wire {
        fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
            self.request.extend_from_slice(input);
            Ok(input.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl Read for Wire {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            self.response.read(bytes)
        }
    }
    #[test]
    fn postgres_tls_negotiation_never_sends_login_or_accepts_plaintext() {
        for (response, accepted) in [
            (b"S".as_slice(), true),
            (b"N".as_slice(), false),
            (b"E".as_slice(), false),
            (b"".as_slice(), false),
        ] {
            let mut wire = Wire {
                request: Vec::new(),
                response: std::io::Cursor::new(response.to_vec()),
            };
            assert_eq!(negotiate(&mut wire).is_ok(), accepted);
            assert_eq!(wire.request, SSL_REQUEST);
        }
    }
}
