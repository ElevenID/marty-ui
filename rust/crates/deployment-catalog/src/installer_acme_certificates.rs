//! Public-only CSR preparation and external TLS certificate admission.
//! This module never creates, imports, exports or activates a private key.
//! Issuance transport, order persistence and generation activation are separate.
#![cfg(target_os = "linux")]

use crate::{installer_ingress_provision::IngressIdentity, installer_release, operator};
use marty_selfhost_identity::origin::PublicOrigin;
use rustls::pki_types::{CertificateDer, ServerName, TrustAnchor, UnixTime};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use spki::{
    der::{
        asn1::{AnyRef, BitString, Ia5String, OctetString, SetOfVec},
        pem::LineEnding,
        Decode, DecodePem, Encode, EncodePem,
    },
    AlgorithmIdentifierOwned, ObjectIdentifier, SubjectPublicKeyInfoOwned,
};
use std::{
    collections::BTreeSet,
    net::IpAddr,
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use x509_cert::{
    attr::Attributes,
    ext::{
        pkix::{
            name::GeneralName, BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages,
            SubjectAltName,
        },
        AsExtension,
    },
    name::Name,
    request::{CertReq, CertReqInfo, ExtensionReq, Version},
    Certificate,
};

type Result<T> = std::result::Result<T, String>;
const REFUSED: &str = "External ingress certificate refused; preserve the retained Transit key, exact CSR and order evidence. No certificate activation was attempted";
const ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const EXTENSION_REQUEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.14");
const SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");
const SERVER_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");
const MAX_CHAIN: usize = 8;
const MAX_PEM_BYTES: usize = 128 * 1024;
// Release policy, independent of any CA's current default profile. Short-lived
// DNS/IP certificates fit this window; nearly expired results are not activated.
pub(crate) const MINIMUM_REMAINING: Duration = Duration::from_secs(3600);
const MAXIMUM_VALIDITY: Duration = Duration::from_secs(100 * 86400);

fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}

/// A canonical DNS identity with at most one explicitly selected IP SAN.
/// Ports belong to origins and do not appear in certificate identities.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateIdentity {
    dns: String,
    ip: Option<IpAddr>,
}
impl CertificateIdentity {
    pub fn from_ingress(identity: &IngressIdentity) -> Result<Self> {
        let dns = identity.dns_names();
        let ips = identity.ip_addresses();
        require(dns.len() == 1 && ips.len() <= 1)?;
        let origin = PublicOrigin::parse(&format!("https://{}", dns[0])).map_err(|_| REFUSED)?;
        require(origin.dns_name() == Some(dns[0].as_str()) && dns[0] != "localhost")?;
        origin.did_web_authority().map_err(|_| REFUSED)?;
        let ip = ips
            .first()
            .map(|ip| ip.parse::<IpAddr>().map_err(|_| REFUSED))
            .transpose()?;
        require(ip.is_none_or(|ip| !ip.is_loopback()))?;
        Ok(Self {
            dns: dns[0].clone(),
            ip,
        })
    }
    pub fn dns_name(&self) -> &str {
        &self.dns
    }
    pub fn ip_address(&self) -> Option<IpAddr> {
        self.ip
    }
    fn subject(&self) -> Result<Name> {
        Name::from_str(&format!("CN={}", self.dns)).map_err(|_| REFUSED.into())
    }
    fn sans(&self) -> Result<SubjectAltName> {
        let mut names = vec![GeneralName::DnsName(
            Ia5String::new(&self.dns).map_err(|_| REFUSED)?,
        )];
        if let Some(ip) = self.ip {
            names.push(GeneralName::IpAddress(
                OctetString::new(ip_bytes(ip)).map_err(|_| REFUSED)?,
            ));
        }
        Ok(SubjectAltName(names))
    }
}
fn ip_bytes(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    }
}

/// Public evidence for the already-retained ingress key. The caller supplies
/// its independently recorded SPKI; a CA response can never choose this key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedIngressKey {
    installation_id: uuid::Uuid,
    name: String,
    version: u64,
    spki: Vec<u8>,
}
impl RetainedIngressKey {
    pub fn bind(
        installation_id: &str,
        version: u64,
        retained_spki: &[u8],
        metadata: &Value,
    ) -> Result<Self> {
        let name = crate::installer_ingress_provision::resource_name(installation_id)?;
        require(
            version == 1
                && metadata["name"] == name
                && metadata["derived"] == false
                && metadata["imported_key"] == false
                && metadata["supports_signing"] == true,
        )?;
        operator::version_one_custody(metadata, "ecdsa-p256").map_err(|_| REFUSED)?;
        let keys = metadata["keys"].as_object().ok_or(REFUSED)?;
        require(keys.len() == 1 && keys.contains_key("1"))?;
        let public = metadata["keys"]["1"]["public_key"]
            .as_str()
            .ok_or(REFUSED)?;
        let spki = operator::public_spki(public.as_bytes(), false).map_err(|_| REFUSED)?;
        require(spki == retained_spki)?;
        Self::from_recorded_public_key(installation_id, version, &spki)
    }
    /// Reconstruct only a previously authenticated public-key binding. This
    /// validates its identity and encoding, not current OpenBao key custody.
    /// A caller performing a signing operation must also require_metadata on
    /// an authenticated live response before using this retained binding.
    pub(crate) fn from_recorded_public_key(
        installation_id: &str,
        version: u64,
        spki: &[u8],
    ) -> Result<Self> {
        let name = crate::installer_ingress_provision::resource_name(installation_id)?;
        require(version == 1)?;
        p256_spki(spki)?;
        Ok(Self {
            installation_id: uuid::Uuid::parse_str(installation_id).map_err(|_| REFUSED)?,
            name,
            version,
            spki: spki.to_vec(),
        })
    }
    pub fn transit_key_name(&self) -> &str {
        &self.name
    }
    pub fn key_version(&self) -> u64 {
        self.version
    }
    pub fn public_spki_der(&self) -> &[u8] {
        &self.spki
    }
    pub fn require_metadata(&self, metadata: &Value) -> Result<()> {
        require(
            Self::bind(
                &self.installation_id.to_string(),
                self.version,
                &self.spki,
                metadata,
            )? == *self,
        )
    }
    /// Exact version selection, never OpenBao's implicit latest-version default.
    pub fn csr_request(&self, identity: &CertificateIdentity) -> Result<Value> {
        // OpenBao 2.5.x ACLs distinguish JSON numbers from HCL integers. Use
        // one exact string on the wire and in the narrow CSR policy.
        Ok(json!({"version":self.version.to_string(), "csr":csr_template(identity, self)?}))
    }
}
fn p256_spki(bytes: &[u8]) -> Result<()> {
    require(!bytes.is_empty() && bytes.len() <= 1024)?;
    let key = marty_crypto::jwk::public_key_der_to_jwk(bytes).map_err(|_| REFUSED)?;
    require(key.kty == "EC" && key.crv.as_deref() == Some("P-256"))
}

/// An unsigned PKCS#10 template containing only public material. OpenBao 2.5.5
/// parses this without signature verification, replaces its key/signature, and
/// preserves CN/SAN. Only validate_signed_csr's result may be sent to an ACME CA.
pub fn csr_template(identity: &CertificateIdentity, key: &RetainedIngressKey) -> Result<String> {
    let subject = identity.subject()?;
    let extensions = ExtensionReq(vec![identity
        .sans()?
        .to_extension(&subject, &[])
        .map_err(|_| REFUSED)?]);
    let attributes: Attributes =
        SetOfVec::try_from(vec![extensions.try_into().map_err(|_| REFUSED)?])
            .map_err(|_| REFUSED)?;
    let request = CertReq {
        info: CertReqInfo {
            version: Version::V1,
            subject,
            public_key: SubjectPublicKeyInfoOwned::from_der(&key.spki).map_err(|_| REFUSED)?,
            attributes,
        },
        algorithm: AlgorithmIdentifierOwned {
            oid: ECDSA_SHA256,
            parameters: None,
        },
        signature: BitString::from_bytes(&[]).map_err(|_| REFUSED)?,
    };
    request.to_pem(LineEnding::LF).map_err(|_| REFUSED.into())
}

#[derive(Clone, Debug)]
pub struct ValidatedCsr {
    der: Vec<u8>,
    pem: String,
    metadata: Value,
}
impl ValidatedCsr {
    pub fn der(&self) -> &[u8] {
        &self.der
    }
    pub fn pem(&self) -> &str {
        &self.pem
    }
    pub fn metadata(&self) -> &Value {
        &self.metadata
    }
}

fn check_sans(san: &SubjectAltName, identity: &CertificateIdentity) -> Result<()> {
    require(san.0.len() == 1 + usize::from(identity.ip.is_some()))?;
    let mut dns = BTreeSet::new();
    let mut ips = BTreeSet::new();
    for name in &san.0 {
        match name {
            GeneralName::DnsName(name) if dns.insert(name.as_str().to_owned()) => {}
            GeneralName::IpAddress(ip) if ips.insert(ip.as_bytes().to_vec()) => {}
            _ => return Err(REFUSED.into()),
        }
    }
    require(
        dns == BTreeSet::from([identity.dns.clone()])
            && ips == identity.ip.map(ip_bytes).into_iter().collect(),
    )
}

fn check_request_info(
    request: &CertReq,
    identity: &CertificateIdentity,
    key: &RetainedIngressKey,
) -> Result<()> {
    require(
        request.info.version == Version::V1
            && request.info.subject.to_string() == format!("CN={}", identity.dns)
            && request.info.public_key.to_der().map_err(|_| REFUSED)? == key.spki
            && request.info.attributes.len() == 1
            && request.algorithm.oid == ECDSA_SHA256
            && request.algorithm.parameters.is_none(),
    )?;
    let attribute = request.info.attributes.iter().next().ok_or(REFUSED)?;
    require(attribute.oid == EXTENSION_REQUEST && attribute.values.len() == 1)?;
    let extensions = ExtensionReq::from_der(
        &attribute
            .values
            .iter()
            .next()
            .ok_or(REFUSED)?
            .to_der()
            .map_err(|_| REFUSED)?,
    )
    .map_err(|_| REFUSED)?;
    require(
        extensions.0.len() == 1
            && extensions.0[0].extn_id == SUBJECT_ALT_NAME
            && !extensions.0[0].critical,
    )?;
    let san =
        SubjectAltName::from_der(extensions.0[0].extn_value.as_bytes()).map_err(|_| REFUSED)?;
    check_sans(&san, identity)
}

fn verify_signature(
    public: &SubjectPublicKeyInfoOwned,
    algorithm: &AlgorithmIdentifierOwned,
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    let public_algorithm = public.algorithm.to_der().map_err(|_| REFUSED)?;
    let signature_algorithm = algorithm.to_der().map_err(|_| REFUSED)?;
    let public_algorithm = AnyRef::from_der(&public_algorithm).map_err(|_| REFUSED)?;
    let signature_algorithm = AnyRef::from_der(&signature_algorithm).map_err(|_| REFUSED)?;
    let public = public.subject_public_key.as_bytes().ok_or(REFUSED)?;
    require(
        !signature.is_empty()
            && webpki::ALL_VERIFICATION_ALGS.iter().any(|candidate| {
                candidate.public_key_alg_id().as_ref() == public_algorithm.value()
                    && candidate.signature_alg_id().as_ref() == signature_algorithm.value()
                    && candidate
                        .verify_signature(public, message, signature)
                        .is_ok()
            }),
    )
}

pub fn validate_signed_csr(
    pem: &[u8],
    identity: &CertificateIdentity,
    key: &RetainedIngressKey,
) -> Result<ValidatedCsr> {
    let text = public_pem(pem, 16 * 1024)?;
    require(
        text.trim()
            .starts_with("-----BEGIN CERTIFICATE REQUEST-----")
            && text.trim().ends_with("-----END CERTIFICATE REQUEST-----")
            && text.matches("-----BEGIN ").count() == 1,
    )?;
    let request = CertReq::from_pem(pem).map_err(|_| REFUSED)?;
    check_request_info(&request, identity, key)?;
    verify_signature(
        &request.info.public_key,
        &request.algorithm,
        &request.info.to_der().map_err(|_| REFUSED)?,
        request.signature.as_bytes().ok_or(REFUSED)?,
    )?;
    let der = request.to_der().map_err(|_| REFUSED)?;
    let pem = request.to_pem(LineEnding::LF).map_err(|_| REFUSED)?;
    let mut metadata = binding_metadata(identity, key);
    metadata["schema"] = json!("elevenid.installer-external-csr/v1");
    metadata["csr_der_sha256"] = json!(installer_release::sha256(&der));
    metadata["csr_signature_verified"] = json!(true);
    Ok(ValidatedCsr { der, pem, metadata })
}

fn binding_metadata(identity: &CertificateIdentity, key: &RetainedIngressKey) -> Value {
    json!({"installation_id":key.installation_id, "transit_key_name":key.name, "transit_key_version":key.version,
        "public_spki_sha256":installer_release::sha256(&key.spki), "dns_names":[identity.dns],
        "ip_addresses":identity.ip.map(|ip|ip.to_string()).into_iter().collect::<Vec<_>>(),
        "private_key_exported":false, "activation_performed":false, "installation_ready":false})
}

fn public_pem(bytes: &[u8], maximum: usize) -> Result<&str> {
    require(
        !bytes.is_empty()
            && bytes.len() <= maximum
            && bytes.is_ascii()
            && !bytes.windows(11).any(|part| part == b"PRIVATE KEY"),
    )?;
    std::str::from_utf8(bytes).map_err(|_| REFUSED.into())
}

fn parse_chain(pem: &[u8]) -> Result<Vec<Certificate>> {
    let mut rest = public_pem(pem, MAX_PEM_BYTES)?;
    let mut certificates = Vec::new();
    let mut seen = BTreeSet::new();
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    loop {
        rest = rest.trim_start_matches(|c: char| c.is_ascii_whitespace());
        if rest.is_empty() {
            break;
        }
        require(certificates.len() < MAX_CHAIN && rest.starts_with(BEGIN))?;
        let end = rest.find(END).ok_or(REFUSED)? + END.len();
        let certificate = Certificate::from_pem(&rest.as_bytes()[..end]).map_err(|_| REFUSED)?;
        require(seen.insert(certificate.to_der().map_err(|_| REFUSED)?))?;
        certificates.push(certificate);
        rest = &rest[end..];
    }
    require(!certificates.is_empty())?;
    Ok(certificates)
}

fn check_extensions(cert: &Certificate) -> Result<()> {
    let mut seen = BTreeSet::new();
    require(
        cert.tbs_certificate
            .extensions
            .iter()
            .flatten()
            .all(|extension| seen.insert(extension.extn_id)),
    )?;
    require(cert.signature_algorithm == cert.tbs_certificate.signature)?;
    let der = CertificateDer::from(cert.to_der().map_err(|_| REFUSED)?);
    webpki::EndEntityCert::try_from(&der).map_err(|_| REFUSED)?;
    Ok(())
}
fn check_lifetime(cert: &Certificate, now: Duration, minimum_remaining: Duration) -> Result<()> {
    let validity = &cert.tbs_certificate.validity;
    let before = validity.not_before.to_unix_duration();
    let after = validity.not_after.to_unix_duration();
    require(
        before <= now
            && after > now
            && after >= now.checked_add(minimum_remaining).ok_or(REFUSED)?
            && after > before,
    )
}
#[cfg(test)]
fn check_leaf(
    cert: &Certificate,
    identity: &CertificateIdentity,
    key: &RetainedIngressKey,
    now: Duration,
) -> Result<()> {
    check_leaf_with_minimum(cert, identity, key, now, MINIMUM_REMAINING)
}
fn check_leaf_with_minimum(
    cert: &Certificate,
    identity: &CertificateIdentity,
    key: &RetainedIngressKey,
    now: Duration,
    minimum_remaining: Duration,
) -> Result<()> {
    check_extensions(cert)?;
    check_lifetime(cert, now, minimum_remaining)?;
    let tbs = &cert.tbs_certificate;
    require(
        tbs.validity
            .not_after
            .to_unix_duration()
            .checked_sub(tbs.validity.not_before.to_unix_duration())
            .ok_or(REFUSED)?
            <= MAXIMUM_VALIDITY
            && tbs.subject_public_key_info.to_der().map_err(|_| REFUSED)? == key.spki
            && (tbs.subject.0.is_empty()
                || tbs.subject.to_string() == format!("CN={}", identity.dns)),
    )?;
    let constraints = tbs
        .get::<BasicConstraints>()
        .map_err(|_| REFUSED)?
        .ok_or(REFUSED)?
        .1;
    require(!constraints.ca && constraints.path_len_constraint.is_none())?;
    let usage = tbs
        .get::<KeyUsage>()
        .map_err(|_| REFUSED)?
        .ok_or(REFUSED)?
        .1;
    require(usage == KeyUsage(KeyUsages::DigitalSignature.into()))?;
    let eku = tbs
        .get::<ExtendedKeyUsage>()
        .map_err(|_| REFUSED)?
        .ok_or(REFUSED)?
        .1;
    require(eku.0 == vec![SERVER_AUTH])?;
    let (critical, san) = tbs
        .get::<SubjectAltName>()
        .map_err(|_| REFUSED)?
        .ok_or(REFUSED)?;
    require(!tbs.subject.0.is_empty() || critical)?;
    check_sans(&san, identity)
}
fn check_ca(cert: &Certificate, now: Duration, self_signed: bool) -> Result<()> {
    check_extensions(cert)?;
    check_lifetime(cert, now, Duration::ZERO)?;
    require(
        cert.tbs_certificate
            .get::<BasicConstraints>()
            .map_err(|_| REFUSED)?
            .ok_or(REFUSED)?
            .1
            .ca,
    )?;
    require(
        cert.tbs_certificate
            .get::<KeyUsage>()
            .map_err(|_| REFUSED)?
            .is_none_or(|(_, usage)| usage.key_cert_sign()),
    )?;
    if self_signed {
        require(cert.tbs_certificate.issuer == cert.tbs_certificate.subject)?;
        verify_signature(
            &cert.tbs_certificate.subject_public_key_info,
            &cert.signature_algorithm,
            &cert.tbs_certificate.to_der().map_err(|_| REFUSED)?,
            cert.signature.as_bytes().ok_or(REFUSED)?,
        )?;
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct ValidatedCertificate {
    leaf_pem: String,
    fullchain_pem: String,
    metadata: Value,
}
impl ValidatedCertificate {
    pub fn leaf_pem(&self) -> &str {
        &self.leaf_pem
    }
    /// Canonical leaf-first PEM, with verified intermediates and no root.
    pub fn fullchain_pem(&self) -> &str {
        &self.fullchain_pem
    }
    pub fn metadata(&self) -> &Value {
        &self.metadata
    }
}

#[derive(Clone, Copy)]
enum TrustSelection<'a> {
    Production,
    StagingTest(&'a [u8]),
}

/// Production roots come exclusively from the maintained compiled Mozilla set.
/// Host/OS roots and caller-provided anchors cannot widen production trust.
pub fn admit_production(
    pem: &[u8],
    identity: &CertificateIdentity,
    key: &RetainedIngressKey,
) -> Result<ValidatedCertificate> {
    admit_production_at(pem, identity, key, now()?)
}
/// Recheck an immutable generation receipt at its recorded observation time.
/// This is historical new-candidate validation; activation must still use the
/// actual current clock through admit_production.
pub(crate) fn admit_production_at(
    pem: &[u8],
    identity: &CertificateIdentity,
    key: &RetainedIngressKey,
    observed: Duration,
) -> Result<ValidatedCertificate> {
    admit_at(pem, identity, key, TrustSelection::Production, observed)
}
/// Validate a serving chain through its actual expiry, independently of the
/// advance margin required when admitting a new candidate. Callers supply the
/// current clock for runtime checks or the recorded clock for receipt checks.
pub(crate) fn validate_selected_production_at(
    pem: &[u8],
    identity: &CertificateIdentity,
    key: &RetainedIngressKey,
    observed: Duration,
) -> Result<ValidatedCertificate> {
    admit_with_minimum_at(
        pem,
        identity,
        key,
        TrustSelection::Production,
        observed,
        Duration::ZERO,
    )
}
/// Explicit test-only trust remains staging even if its chain also happens to
/// validate publicly. This result never claims activation or browser readiness.
pub fn admit_staging_test(
    pem: &[u8],
    staging_roots_pem: &[u8],
    identity: &CertificateIdentity,
    key: &RetainedIngressKey,
) -> Result<ValidatedCertificate> {
    admit_staging_test_at(pem, staging_roots_pem, identity, key, now()?)
}
/// Historical staging admission is only for retained candidate receipts. It
/// never substitutes caller anchors for the compiled production trust store.
pub(crate) fn admit_staging_test_at(
    pem: &[u8],
    staging_roots_pem: &[u8],
    identity: &CertificateIdentity,
    key: &RetainedIngressKey,
    observed: Duration,
) -> Result<ValidatedCertificate> {
    admit_at(
        pem,
        identity,
        key,
        TrustSelection::StagingTest(staging_roots_pem),
        observed,
    )
}
/// Reject malformed or unusable explicit staging anchors before setup starts.
/// This validates only the staging input and grants no production trust.
pub(crate) fn validate_staging_roots(pem: &[u8]) -> Result<()> {
    staging_root_certificates(pem, now()?).map(|_| ())
}
fn staging_root_certificates(pem: &[u8], observed: Duration) -> Result<Vec<Certificate>> {
    let roots = parse_chain(pem)?;
    require(roots.len() <= 4)?;
    for root in &roots {
        check_ca(root, observed, true)?;
    }
    Ok(roots)
}
fn now() -> Result<Duration> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| REFUSED.into())
}

fn roots_digest(roots: &[TrustAnchor<'_>]) -> String {
    let mut digest = Sha256::new();
    for root in roots {
        for field in [
            root.subject.as_ref(),
            root.subject_public_key_info.as_ref(),
            root.name_constraints
                .as_ref()
                .map_or(&[][..], |value| value.as_ref()),
        ] {
            digest.update((field.len() as u64).to_be_bytes());
            digest.update(field);
        }
    }
    format!("{:x}", digest.finalize())
}

fn admit_at(
    pem: &[u8],
    identity: &CertificateIdentity,
    key: &RetainedIngressKey,
    trust: TrustSelection<'_>,
    now: Duration,
) -> Result<ValidatedCertificate> {
    admit_with_minimum_at(pem, identity, key, trust, now, MINIMUM_REMAINING)
}
fn admit_with_minimum_at(
    pem: &[u8],
    identity: &CertificateIdentity,
    key: &RetainedIngressKey,
    trust: TrustSelection<'_>,
    now: Duration,
    minimum_remaining: Duration,
) -> Result<ValidatedCertificate> {
    let certificates = parse_chain(pem)?;
    check_leaf_with_minimum(&certificates[0], identity, key, now, minimum_remaining)?;
    let ders = certificates
        .iter()
        .map(|cert| cert.to_der().map(CertificateDer::from).map_err(|_| REFUSED))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let provided_root = certificates.len() > 1
        && certificates
            .last()
            .is_some_and(|cert| cert.tbs_certificate.subject == cert.tbs_certificate.issuer);
    let chain_end = certificates.len() - usize::from(provided_root);
    for (index, cert) in certificates.iter().enumerate().skip(1) {
        check_ca(cert, now, provided_root && index == chain_end)?;
        require(certificates[index - 1].tbs_certificate.issuer == cert.tbs_certificate.subject)?;
    }
    let presented_root = if provided_root {
        Some(webpki::anchor_from_trusted_cert(&ders[chain_end]).map_err(|_| REFUSED)?)
    } else {
        None
    };
    let staging_roots = if let TrustSelection::StagingTest(roots) = &trust {
        let roots = staging_root_certificates(roots, now)?;
        roots
            .iter()
            .map(|root| root.to_der().map(CertificateDer::from).map_err(|_| REFUSED))
            .collect::<std::result::Result<Vec<_>, _>>()?
    } else {
        Vec::new()
    };
    let staging_anchors = staging_roots
        .iter()
        .map(webpki::anchor_from_trusted_cert)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| REFUSED)?;
    let anchors = match trust {
        TrustSelection::Production => webpki_roots::TLS_SERVER_ROOTS,
        TrustSelection::StagingTest(_) => &staging_anchors,
    };
    let intermediates = &ders[1..chain_end];
    // Reject unused, unrelated, out-of-order or missing chain members rather
    // than allowing the path builder to silently ignore surplus certificates.
    let exact_path = |path: &webpki::VerifiedPath<'_>| {
        let complete = path
            .intermediate_certificates()
            .map(|cert| cert.der())
            .eq(intermediates.iter().cloned())
            && presented_root.as_ref().is_none_or(|root| {
                root.subject == path.anchor().subject
                    && root.subject_public_key_info == path.anchor().subject_public_key_info
            });
        if complete {
            Ok(())
        } else {
            Err(webpki::Error::UnknownIssuer)
        }
    };
    let verifier = webpki::EndEntityCert::try_from(&ders[0]).map_err(|_| REFUSED)?;
    let path = verifier
        .verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            anchors,
            intermediates,
            UnixTime::since_unix_epoch(now),
            webpki::KeyUsage::server_auth(),
            None,
            Some(&exact_path),
        )
        .map_err(|_| REFUSED)?;
    verifier
        .verify_is_valid_for_subject_name(
            &ServerName::try_from(identity.dns.as_str()).map_err(|_| REFUSED)?,
        )
        .map_err(|_| REFUSED)?;
    if let Some(ip) = identity.ip {
        verifier
            .verify_is_valid_for_subject_name(&ServerName::from(ip))
            .map_err(|_| REFUSED)?;
    }
    let leaf_pem = certificates[0]
        .to_pem(LineEnding::LF)
        .map_err(|_| REFUSED)?;
    let fullchain_pem = certificates[..chain_end]
        .iter()
        .map(|cert| cert.to_pem(LineEnding::LF).map_err(|_| REFUSED))
        .collect::<std::result::Result<Vec<_>, _>>()?
        .join("");
    let production = matches!(trust, TrustSelection::Production);
    let mut metadata = binding_metadata(identity, key);
    metadata["schema"] = json!("elevenid.installer-external-certificate/v1");
    metadata["trust_class"] = json!(if production {
        "production_public"
    } else {
        "staging_test"
    });
    metadata["trust_store"] = json!(if production {
        "mozilla_webpki_roots"
    } else {
        "explicit_staging_roots"
    });
    metadata["trust_store_sha256"] = json!(roots_digest(anchors));
    metadata["trust_anchor_spki_value_sha256"] = json!(installer_release::sha256(
        path.anchor().subject_public_key_info.as_ref()
    ));
    metadata["public_chain_validated"] = json!(production);
    metadata["observed_at"] = json!(now.as_secs());
    metadata["not_before"] = json!(certificates[0]
        .tbs_certificate
        .validity
        .not_before
        .to_unix_duration()
        .as_secs());
    metadata["not_after"] = json!(certificates[0]
        .tbs_certificate
        .validity
        .not_after
        .to_unix_duration()
        .as_secs());
    metadata["minimum_remaining_seconds"] = json!(minimum_remaining.as_secs());
    metadata["maximum_validity_seconds"] = json!(MAXIMUM_VALIDITY.as_secs());
    metadata["leaf_der_sha256"] = json!(installer_release::sha256(ders[0].as_ref()));
    metadata["fullchain_pem_sha256"] = json!(installer_release::sha256(fullchain_pem.as_bytes()));
    metadata["intermediate_count"] = json!(intermediates.len());
    metadata["revocation_status"] = json!("not_checked");
    metadata["browser_acceptance"] = json!("not_assessed");
    Ok(ValidatedCertificate {
        leaf_pem,
        fullchain_pem,
        metadata,
    })
}

#[cfg(test)]
#[path = "installer_acme_certificates_tests.rs"]
mod tests;
