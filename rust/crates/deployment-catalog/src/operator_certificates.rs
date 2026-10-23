//! Offline validation of public renewal certificates; never reads a signing key.
use crate::operator::{Result, REFUSAL};
use spki::der::{Decode, DecodePem, Encode};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use x509_cert::{
    ext::pkix::{
        AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectKeyIdentifier,
    },
    Certificate,
};

fn first_certificate(pem: &[u8]) -> Result<Certificate> {
    if pem.is_empty() || pem.len() > 64 * 1024 || !pem.is_ascii() {
        return Err(REFUSAL);
    }
    let end = b"-----END CERTIFICATE-----";
    let length = pem
        .windows(end.len())
        .position(|s| s == end)
        .ok_or(REFUSAL)?
        + end.len();
    Certificate::from_pem(&pem[..length]).map_err(|_| REFUSAL)
}

fn lifetime(cert: &Certificate, now: Duration, minimum_ttl: Duration) -> Result<()> {
    let validity = &cert.tbs_certificate.validity;
    if validity.not_before.to_unix_duration() > now
        || validity.not_after.to_unix_duration() < now.checked_add(minimum_ttl).ok_or(REFUSAL)?
    {
        return Err(REFUSAL);
    }
    Ok(())
}

pub fn check_lifetime(pem: &[u8], minimum_ttl: u64) -> Result<bool> {
    Ok(lifetime(
        &first_certificate(pem)?,
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| REFUSAL)?,
        Duration::from_secs(minimum_ttl),
    )
    .is_ok())
}

// The old `openssl verify` invocation had no purpose or hostname option. Parse
// every EKU OID, including trailing values, without imposing TLS server/client use.
struct AnyPurpose;
impl webpki::ExtendedKeyUsageValidator for AnyPurpose {
    fn validate(
        &self,
        iter: webpki::KeyPurposeIdIter<'_, '_>,
    ) -> std::result::Result<(), webpki::Error> {
        for oid in iter {
            let _ = oid?;
        }
        Ok(())
    }
}

fn issuer_constraints(cert: &Certificate, now: Duration, subordinate_cas: usize) -> Result<()> {
    lifetime(cert, now, Duration::ZERO)?;
    let tbs = &cert.tbs_certificate;
    let (_, constraints) = tbs
        .get::<BasicConstraints>()
        .map_err(|_| REFUSAL)?
        .ok_or(REFUSAL)?;
    if !constraints.ca
        || constraints
            .path_len_constraint
            .is_some_and(|limit| subordinate_cas > usize::from(limit))
    {
        return Err(REFUSAL);
    }
    if tbs
        .get::<KeyUsage>()
        .map_err(|_| REFUSAL)?
        .is_some_and(|(_, usage)| !usage.key_cert_sign())
    {
        return Err(REFUSAL);
    }
    // Trust anchors bypass webpki's extension checks. Re-parse through its
    // certificate parser so unknown critical extensions are not silently ignored.
    let der = rustls::pki_types::CertificateDer::from(cert.to_der().map_err(|_| REFUSAL)?);
    webpki::EndEntityCert::try_from(&der).map_err(|_| REFUSAL)?;
    tbs.get::<ExtendedKeyUsage>().map_err(|_| REFUSAL)?;
    Ok(())
}

fn issuer_matches(child: &Certificate, parent: &Certificate) -> Result<()> {
    let child = &child.tbs_certificate;
    let parent = &parent.tbs_certificate;
    if child.issuer != parent.subject {
        return Err(REFUSAL);
    }
    if let Some((_, aki)) = child.get::<AuthorityKeyIdentifier>().map_err(|_| REFUSAL)? {
        if let (Some(key), Some((_, ski))) = (
            aki.key_identifier,
            parent.get::<SubjectKeyIdentifier>().map_err(|_| REFUSAL)?,
        ) {
            if key != ski.0 {
                return Err(REFUSAL);
            }
        }
        if aki
            .authority_cert_serial_number
            .is_some_and(|serial| serial != parent.serial_number)
        {
            return Err(REFUSAL);
        }
        if aki.authority_cert_issuer.is_some_and(|names| !names.iter().any(|name| matches!(name, x509_cert::ext::pkix::name::GeneralName::DirectoryName(dn) if *dn == parent.issuer))) {
            return Err(REFUSAL);
        }
    }
    Ok(())
}

pub fn check_chain(pem: &[u8], issuers: &[u8]) -> Result<()> {
    use rustls::pki_types::{CertificateDer, UnixTime};
    if !issuers.iter().any(|byte| !byte.is_ascii_whitespace())
        || issuers.len() > 64 * 1024
        || !issuers.is_ascii()
    {
        return Err(REFUSAL);
    }
    let leaf = first_certificate(pem)?;
    let leaf_der = CertificateDer::from(leaf.to_der().map_err(|_| REFUSAL)?);
    let leaf_verifier = webpki::EndEntityCert::try_from(&leaf_der).map_err(|_| REFUSAL)?;
    leaf.tbs_certificate
        .get::<ExtendedKeyUsage>()
        .map_err(|_| REFUSAL)?;
    let certificates = Certificate::load_pem_chain(issuers).map_err(|_| REFUSAL)?;
    if certificates.is_empty() || certificates.len() > 16 {
        return Err(REFUSAL);
    }
    let ders = certificates
        .iter()
        .map(|cert| cert.to_der().map(CertificateDer::from).map_err(|_| REFUSAL))
        .collect::<Result<Vec<_>>>()?;
    let mut anchors = Vec::new();
    let mut roots = Vec::new();
    let mut intermediates = Vec::new();
    for (cert, der) in certificates.iter().zip(&ders) {
        if cert.tbs_certificate.subject == cert.tbs_certificate.issuer {
            anchors.push(webpki::anchor_from_trusted_cert(der).map_err(|_| REFUSAL)?);
            roots.push(cert);
        } else {
            intermediates.push(der.clone());
        }
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| REFUSAL)?;
    let verify_path = |path: &webpki::VerifiedPath<'_>| {
        let check = || -> Result<()> {
            let index = anchors
                .iter()
                .position(|a| std::ptr::eq(a, path.anchor()))
                .ok_or(REFUSAL)?;
            let root = roots[index];
            let mut child = leaf.clone();
            let mut subordinate_cas = 0;
            for issuer in path.intermediate_certificates() {
                let issuer = Certificate::from_der(issuer.der().as_ref()).map_err(|_| REFUSAL)?;
                issuer_matches(&child, &issuer)?;
                issuer_constraints(&issuer, now, subordinate_cas)?;
                if issuer.tbs_certificate.subject != issuer.tbs_certificate.issuer {
                    subordinate_cas += 1;
                }
                child = issuer;
            }
            issuer_matches(&child, root)?;
            issuer_constraints(root, now, subordinate_cas)
        };
        check().map_err(|_| webpki::Error::UnknownIssuer)
    };
    leaf_verifier
        .verify_for_usage(
            rustls::crypto::aws_lc_rs::default_provider()
                .signature_verification_algorithms
                .all,
            &anchors,
            &intermediates,
            UnixTime::since_unix_epoch(now),
            AnyPurpose,
            None,
            Some(&verify_path),
        )
        .map_err(|_| REFUSAL)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifetime_preserves_exact_overlap_and_fractional_clock_boundaries() {
        let mut cert = Certificate::from_pem(include_bytes!(
            "../../../../tests/fixtures/selfhost_ca_issuer_public.pem"
        ))
        .unwrap();
        let now = Duration::from_secs(1_800_000_000);
        cert.tbs_certificate.validity.not_before = (UNIX_EPOCH + now).try_into().unwrap();
        cert.tbs_certificate.validity.not_after = (UNIX_EPOCH + now + Duration::from_secs(3600))
            .try_into()
            .unwrap();
        assert!(lifetime(&cert, now, Duration::from_secs(3600)).is_ok());
        assert!(lifetime(&cert, now - Duration::from_nanos(1), Duration::ZERO).is_err());
        assert!(lifetime(
            &cert,
            now + Duration::from_nanos(1),
            Duration::from_secs(3600)
        )
        .is_err());
        assert!(lifetime(&cert, now, Duration::MAX).is_err());
    }
}
