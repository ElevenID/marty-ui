//! HTTPS transport pinned to the installer-owned ingress certificate.
//! Shared by read-only probes and authenticated operator requests.
#![cfg(target_os = "linux")]

use crate::installer_trust::TrustInfo;
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{pem::PemObject, CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, Error, SignatureScheme,
};
use sha2::{Digest, Sha256};
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

#[derive(Debug)]
struct BoundCertificate {
    verifier: Arc<dyn ServerCertVerifier>,
    fingerprint: String,
}

impl ServerCertVerifier for BoundCertificate {
    fn verify_server_cert(
        &self,
        certificate: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, Error> {
        self.verifier.verify_server_cert(
            certificate,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        if format!("{:x}", Sha256::digest(certificate)) != self.fingerprint {
            return Err(Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        self.verifier
            .verify_tls12_signature(message, certificate, signature)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        self.verifier
            .verify_tls13_signature(message, certificate, signature)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.verifier.supported_verify_schemes()
    }
}

pub(crate) fn valid_origin(origin: &str) -> Option<u16> {
    let raw_port = origin.strip_prefix("https://localhost:")?;
    let port = raw_port.parse::<u16>().ok()?;
    (port >= 1024 && raw_port == port.to_string()).then_some(port)
}

pub(crate) fn client(trust: &TrustInfo, timeout: Duration) -> Result<reqwest::Client, String> {
    let port = valid_origin(&trust.origin).ok_or("invalid bound HTTPS origin")?;
    if trust.certificate_der_sha256.len() != 64
        || !trust
            .certificate_der_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid bound HTTPS origin or certificate".into());
    }
    let mut roots = rustls::RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(trust.ca_certificate_pem.as_bytes()) {
        roots
            .add(certificate.map_err(|_| "invalid bound HTTPS CA")?)
            .map_err(|_| "invalid bound HTTPS CA")?;
    }
    if roots.is_empty() {
        return Err("invalid bound HTTPS CA".into());
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        provider.clone(),
    )
    .build()
    .map_err(|_| "bound HTTPS verifier unavailable")?;
    let tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| "bound HTTPS verifier unavailable")?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(BoundCertificate {
            verifier,
            fingerprint: trust.certificate_der_sha256.clone(),
        }))
        .with_no_client_auth();
    reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .use_preconfigured_tls(tls)
        .tls_info(true)
        .resolve("localhost", SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
        .connect_timeout(Duration::from_secs(2))
        .timeout(timeout)
        .build()
        .map_err(|_| "bound HTTPS transport unavailable".into())
}
