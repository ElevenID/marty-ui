//! HTTPS transport pinned to the installer-owned ingress certificate.
//! Shared by read-only probes and authenticated operator requests.
#![cfg(target_os = "linux")]

use crate::installer_trust::{TrustInfo, TrustSource};
use marty_selfhost_identity::origin::PublicOrigin;
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{pem::PemObject, CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, Error, SignatureScheme,
};
use sha2::{Digest, Sha256};
use std::{net::SocketAddr, sync::Arc, time::Duration};

#[derive(Debug)]
struct BoundCertificate {
    verifier: Arc<dyn ServerCertVerifier>,
    fingerprint: String,
    name: ServerName<'static>,
}

impl ServerCertVerifier for BoundCertificate {
    fn verify_server_cert(
        &self,
        certificate: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, Error> {
        self.verifier.verify_server_cert(
            certificate,
            intermediates,
            &self.name,
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

#[cfg(test)]
pub(crate) fn valid_origin(origin: &str) -> Option<u16> {
    PublicOrigin::parse(origin).ok().map(|origin| origin.port())
}

/// Probe the installation's bound local listener, while preserving the public
/// authority in HTTP and the configured public certificate identity in TLS.
/// DNS overrides alone are insufficient: IP URLs bypass DNS and an explicit
/// URL port takes precedence over a resolver-provided port.
pub(crate) fn endpoint(trust: &TrustInfo) -> Result<String, String> {
    let origin = PublicOrigin::parse(&trust.origin)?;
    let address = trust.local_probe_address;
    if address.port() < 1024 || address.ip().is_unspecified() || address.ip().is_multicast() {
        return Err("invalid bound HTTPS listener".into());
    }
    Ok(match origin.dns_name() {
        Some(name) => format!("https://{name}:{}", address.port()),
        None => format!("https://{address}"),
    })
}

pub(crate) fn client(trust: &TrustInfo, timeout: Duration) -> Result<reqwest::Client, String> {
    let origin = PublicOrigin::parse(&trust.origin)?;
    endpoint(trust)?;
    if trust.certificate_der_sha256.len() != 64
        || !trust
            .certificate_der_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid bound HTTPS origin or certificate".into());
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = match trust.trust_source {
        TrustSource::ConfiguredCa => verifier(
            trust
                .ca_certificate_pem
                .as_deref()
                .ok_or("configured HTTPS CA absent")?
                .as_bytes(),
            provider.clone(),
        )?,
        TrustSource::MozillaPublicRoots => {
            if trust.ca_certificate_pem.is_some()
                || trust.ca_der_sha256.is_some()
                || trust.ca_der_sha256s.is_some()
                || trust.ca_expires_at.is_some()
            {
                return Err("public HTTPS trust cannot substitute a configured CA".into());
            }
            verifier_from_roots(
                rustls::RootCertStore {
                    roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
                },
                provider.clone(),
            )?
        }
    };
    let tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| "bound HTTPS verifier unavailable")?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(BoundCertificate {
            verifier,
            fingerprint: trust.certificate_der_sha256.clone(),
            name: ServerName::try_from(origin.host().to_owned())
                .map_err(|_| "invalid bound HTTPS name")?,
        }))
        .with_no_client_auth();
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::HOST,
        origin
            .authority()
            .parse()
            .map_err(|_| "invalid bound HTTPS authority")?,
    );
    let mut builder = reqwest::Client::builder()
        .https_only(true)
        .http1_only()
        .default_headers(headers)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .use_preconfigured_tls(tls)
        .tls_info(true);
    if let Some(name) = origin.dns_name() {
        builder = builder.resolve(
            name,
            SocketAddr::new(
                trust.local_probe_address.ip(),
                trust.local_probe_address.port(),
            ),
        );
    }
    builder
        .connect_timeout(Duration::from_secs(2))
        .timeout(timeout)
        .build()
        .map_err(|_| "bound HTTPS transport unavailable".into())
}

fn verifier(
    ca: &[u8],
    provider: Arc<rustls::crypto::CryptoProvider>,
) -> Result<Arc<rustls::client::WebPkiServerVerifier>, String> {
    let mut roots = rustls::RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(ca) {
        roots
            .add(certificate.map_err(|_| "invalid bound HTTPS CA")?)
            .map_err(|_| "invalid bound HTTPS CA")?;
    }
    if roots.is_empty() {
        return Err("invalid bound HTTPS CA".into());
    }
    verifier_from_roots(roots, provider)
}

fn verifier_from_roots(
    roots: rustls::RootCertStore,
    provider: Arc<rustls::crypto::CryptoProvider>,
) -> Result<Arc<rustls::client::WebPkiServerVerifier>, String> {
    rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
        .build()
        .map_err(|_| "bound HTTPS verifier unavailable".into())
}

/// Admission uses exactly the public chain, name and usage checks that the
/// authenticated HTTP transport will repeat before sending any credential.
pub(crate) fn validate_server_chain_for_origin(
    ca: &[u8],
    chain: &[CertificateDer<'_>],
    now: UnixTime,
    origin: &PublicOrigin,
) -> Result<(), String> {
    let (leaf, intermediates) = chain
        .split_first()
        .ok_or("bound HTTPS certificate absent")?;
    verifier(ca, Arc::new(rustls::crypto::aws_lc_rs::default_provider()))?
        .verify_server_cert(
            leaf,
            intermediates,
            &ServerName::try_from(origin.host().to_owned())
                .map_err(|_| "invalid bound HTTPS name")?,
            &[],
            now,
        )
        .map_err(|_| "bound HTTPS certificate chain, name or usage is invalid")?;
    Ok(())
}
