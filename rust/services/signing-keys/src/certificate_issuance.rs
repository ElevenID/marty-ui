//! Pure X.509 DSC assembly for an already authorized managed issuer ceremony.
//!
//! The caller owns tenant authorization, active-profile resolution, serial
//! reservation, KMS signing, and the fenced lifecycle/attachment commit. This
//! module only handles public material and verifies both signatures.

use std::time::{Duration, SystemTime};

use const_oid::{db::rfc4519::COUNTRY_NAME, ObjectIdentifier};
use der::{
    asn1::{BitString, PrintableStringRef, Utf8StringRef},
    Decode, DecodePem, Encode, EncodePem, Tag, Tagged,
};
use marty_crypto::{certificate::verify_certificate_signature, jwk::public_key_der_to_jwk};
use serde_json::Value;
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use thiserror::Error;
use x509_cert::{
    certificate::{Certificate, TbsCertificate, Version},
    ext::{
        pkix::{BasicConstraints, KeyUsage, KeyUsages},
        AsExtension,
    },
    name::Name,
    request::CertReq,
    serial_number::SerialNumber,
    time::{Time, Validity},
};

const ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DscCertificateError {
    #[error("DSC CSR is invalid or does not match the current managed key")]
    InvalidCsr,
    #[error("CSCA certificate is invalid or does not match the current managed key")]
    InvalidIssuer,
    #[error("DSC serial number is invalid")]
    InvalidSerial,
    #[error("DSC validity is outside the active CSCA or issuance policy")]
    InvalidValidity,
    #[error("DSC certificate encoding failed")]
    Encoding,
    #[error("KMS signature does not verify against the active CSCA")]
    InvalidSignature,
}

/// A DSC CSR whose ES256 proof of possession and current KMS key match passed.
pub struct VerifiedDscSubject {
    subject: Name,
    public_key: SubjectPublicKeyInfoOwned,
}

impl VerifiedDscSubject {
    pub fn from_csr_pem(
        csr_pem: &str,
        current_public_jwk: &Value,
    ) -> Result<Self, DscCertificateError> {
        if !is_es256_jwk(current_public_jwk) {
            return Err(DscCertificateError::InvalidCsr);
        }
        let csr = CertReq::from_pem(csr_pem).map_err(|_| DscCertificateError::InvalidCsr)?;
        if csr.algorithm.oid != ECDSA_SHA256 || csr.algorithm.parameters.is_some() {
            return Err(DscCertificateError::InvalidCsr);
        }
        let spki_der = csr
            .info
            .public_key
            .to_der()
            .map_err(|_| DscCertificateError::InvalidCsr)?;
        if !matches_current_jwk(&spki_der, current_public_jwk) {
            return Err(DscCertificateError::InvalidCsr);
        }
        let info_der = csr
            .info
            .to_der()
            .map_err(|_| DscCertificateError::InvalidCsr)?;
        let signature = csr
            .signature
            .as_bytes()
            .ok_or(DscCertificateError::InvalidCsr)?;
        if !der_ecdsa_signature(signature) {
            return Err(DscCertificateError::InvalidCsr);
        }
        if !marty_crypto::ecdsa::verify_p256_sha256(&spki_der, &info_der, signature)
            .map_err(|_| DscCertificateError::InvalidCsr)?
        {
            return Err(DscCertificateError::InvalidCsr);
        }
        Ok(Self {
            subject: csr.info.subject,
            public_key: csr.info.public_key,
        })
    }

    pub fn country(&self) -> Option<String> {
        country_from_name(&self.subject)
    }
}

/// Read an X.509 subject country without parsing its display representation.
pub fn certificate_country(certificate_pem: &str) -> Option<String> {
    let certificate = Certificate::from_pem(certificate_pem).ok()?;
    country_from_name(&certificate.tbs_certificate.subject)
}

fn country_from_name(name: &Name) -> Option<String> {
    let mut country = None;
    for rdn in &name.0 {
        for attribute in rdn.0.iter() {
            if attribute.oid != COUNTRY_NAME {
                continue;
            }
            let value = attribute
                .value
                .decode_as::<PrintableStringRef>()
                .ok()
                .map(|value| value.as_str().to_owned())
                .or_else(|| {
                    attribute
                        .value
                        .decode_as::<Utf8StringRef>()
                        .ok()
                        .map(|value| value.as_str().to_owned())
                })?;
            if value.len() != 2
                || !value.bytes().all(|byte| byte.is_ascii_uppercase())
                || country.replace(value).is_some()
            {
                return None;
            }
        }
    }
    country
}

fn matches_current_jwk(spki_der: &[u8], expected: &Value) -> bool {
    public_key_der_to_jwk(spki_der)
        .ok()
        .and_then(|jwk| serde_json::to_value(jwk).ok())
        .is_some_and(|actual| crate::documents::same_public_jwk(&actual, expected))
}

fn is_es256_jwk(jwk: &Value) -> bool {
    jwk.get("kty").and_then(Value::as_str) == Some("EC")
        && jwk.get("crv").and_then(Value::as_str) == Some("P-256")
}

fn der_ecdsa_signature(signature: &[u8]) -> bool {
    der::asn1::Any::from_der(signature).is_ok_and(|value| value.tag() == Tag::Sequence)
}

/// Prepared DER TBS certificate. No signing credential or key locator is held.
pub struct PreparedDscCertificate {
    tbs: TbsCertificate,
    tbs_der: Vec<u8>,
    issuer_der: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DscCertificateMetadata {
    pub serial_hex: String,
    pub not_before: String,
    pub not_after: String,
}

impl PreparedDscCertificate {
    pub fn signing_bytes(&self) -> &[u8] {
        &self.tbs_der
    }

    pub fn metadata(&self) -> Result<DscCertificateMetadata, DscCertificateError> {
        let timestamp = |time: Time| {
            i64::try_from(time.to_unix_duration().as_secs())
                .ok()
                .and_then(|seconds| chrono::DateTime::<chrono::Utc>::from_timestamp(seconds, 0))
                .map(|time| time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
                .ok_or(DscCertificateError::Encoding)
        };
        Ok(DscCertificateMetadata {
            serial_hex: self
                .tbs
                .serial_number
                .as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
            not_before: timestamp(self.tbs.validity.not_before)?,
            not_after: timestamp(self.tbs.validity.not_after)?,
        })
    }

    /// Accept only a DER ECDSA signature over exactly `signing_bytes()`.
    pub fn finish(self, signature_der: &[u8]) -> Result<String, DscCertificateError> {
        if !der_ecdsa_signature(signature_der) {
            return Err(DscCertificateError::InvalidSignature);
        }
        let algorithm = AlgorithmIdentifierOwned {
            oid: ECDSA_SHA256,
            parameters: None,
        };
        let certificate = Certificate {
            tbs_certificate: self.tbs,
            signature_algorithm: algorithm,
            signature: BitString::from_bytes(signature_der)
                .map_err(|_| DscCertificateError::Encoding)?,
        };
        let certificate_der = certificate
            .to_der()
            .map_err(|_| DscCertificateError::Encoding)?;
        if !verify_certificate_signature(&certificate_der, &self.issuer_der)
            .map_err(|_| DscCertificateError::InvalidSignature)?
        {
            return Err(DscCertificateError::InvalidSignature);
        }
        certificate
            .to_pem(der::pem::LineEnding::LF)
            .map_err(|_| DscCertificateError::Encoding)
    }
}

/// Validate public DSC/CSCA material and prepare an ES256 leaf certificate.
/// `now` is explicit so the caller can use one clock across policy and commit.
#[allow(clippy::too_many_arguments)]
pub fn prepare_dsc(
    subject: &VerifiedDscSubject,
    issuer_certificate_pem: &str,
    issuer_chain_pem: &str,
    current_issuer_public_jwk: &Value,
    serial_bytes: &[u8],
    validity_days: u8,
    now: SystemTime,
) -> Result<PreparedDscCertificate, DscCertificateError> {
    if !(1..=90).contains(&validity_days) {
        return Err(DscCertificateError::InvalidValidity);
    }
    let not_before = now;
    let not_after = now
        .checked_add(Duration::from_secs(u64::from(validity_days) * 24 * 60 * 60))
        .ok_or(DscCertificateError::InvalidValidity)?;
    let issuer = Certificate::from_pem(issuer_certificate_pem)
        .map_err(|_| DscCertificateError::InvalidIssuer)?;
    let issuer_der = issuer
        .to_der()
        .map_err(|_| DscCertificateError::InvalidIssuer)?;
    let issuer_tbs = &issuer.tbs_certificate;
    if !is_es256_jwk(current_issuer_public_jwk)
        || issuer_tbs.signature.oid != ECDSA_SHA256
        || issuer_tbs.signature.parameters.is_some()
        || issuer.signature_algorithm.oid != ECDSA_SHA256
        || issuer.signature_algorithm.parameters.is_some()
        || !matches_current_jwk(
            &issuer_tbs
                .subject_public_key_info
                .to_der()
                .map_err(|_| DscCertificateError::InvalidIssuer)?,
            current_issuer_public_jwk,
        )
    {
        return Err(DscCertificateError::InvalidIssuer);
    }
    if subject.public_key == issuer_tbs.subject_public_key_info {
        return Err(DscCertificateError::InvalidIssuer);
    }
    verify_issuer_chain(
        &issuer,
        &issuer_der,
        issuer_chain_pem,
        not_before,
        not_after,
    )?;
    let constraints = issuer_tbs
        .get::<BasicConstraints>()
        .map_err(|_| DscCertificateError::InvalidIssuer)?;
    let usage = issuer_tbs
        .get::<KeyUsage>()
        .map_err(|_| DscCertificateError::InvalidIssuer)?;
    if !matches!(constraints, Some((true, BasicConstraints { ca: true, .. })))
        || !usage.is_some_and(|(critical, usage)| critical && usage.key_cert_sign())
    {
        return Err(DscCertificateError::InvalidIssuer);
    }
    let serial = SerialNumber::new(serial_bytes).map_err(|_| DscCertificateError::InvalidSerial)?;
    if !serial_bytes.iter().any(|byte| *byte != 0) {
        return Err(DscCertificateError::InvalidSerial);
    }
    let issuer_validity = issuer_tbs.validity;
    let not_before_unix = not_before
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| DscCertificateError::InvalidValidity)?;
    let not_after_unix = not_after
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| DscCertificateError::InvalidValidity)?;
    let now_unix = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| DscCertificateError::InvalidValidity)?;
    if now_unix < issuer_validity.not_before.to_unix_duration()
        || now_unix >= issuer_validity.not_after.to_unix_duration()
        || not_before_unix < issuer_validity.not_before.to_unix_duration()
        || not_after_unix > issuer_validity.not_after.to_unix_duration()
        || not_after_unix <= now_unix
    {
        return Err(DscCertificateError::InvalidValidity);
    }
    let validity = Validity {
        not_before: Time::try_from(not_before).map_err(|_| DscCertificateError::InvalidValidity)?,
        not_after: Time::try_from(not_after).map_err(|_| DscCertificateError::InvalidValidity)?,
    };
    let constraints = BasicConstraints {
        ca: false,
        path_len_constraint: None,
    }
    .to_extension(&subject.subject, &[])
    .map_err(|_| DscCertificateError::Encoding)?;
    let usage = KeyUsage(KeyUsages::DigitalSignature.into())
        .to_extension(&subject.subject, std::slice::from_ref(&constraints))
        .map_err(|_| DscCertificateError::Encoding)?;
    let extensions = vec![constraints, usage];
    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: serial,
        signature: AlgorithmIdentifierOwned {
            oid: ECDSA_SHA256,
            parameters: None,
        },
        issuer: issuer_tbs.subject.clone(),
        validity,
        subject: subject.subject.clone(),
        subject_public_key_info: subject.public_key.clone(),
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(extensions),
    };
    let tbs_der = tbs.to_der().map_err(|_| DscCertificateError::Encoding)?;
    Ok(PreparedDscCertificate {
        tbs,
        tbs_der,
        issuer_der,
    })
}

fn verify_issuer_chain(
    leaf: &Certificate,
    leaf_der: &[u8],
    chain_pem: &str,
    not_before: SystemTime,
    not_after: SystemTime,
) -> Result<(), DscCertificateError> {
    if chain_pem.contains("PRIVATE KEY-----") {
        return Err(DscCertificateError::InvalidIssuer);
    }
    let pattern = regex::Regex::new(r"(?s)-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----")
        .expect("static PEM pattern");
    let links = pattern.find_iter(chain_pem).collect::<Vec<_>>();
    if !pattern.replace_all(chain_pem, "").trim().is_empty() {
        return Err(DscCertificateError::InvalidIssuer);
    }
    let mut child = leaf.clone();
    let mut child_der = leaf_der.to_vec();
    let mut subordinate_cas =
        usize::from(leaf.tbs_certificate.subject != leaf.tbs_certificate.issuer);
    for link in links {
        let parent =
            Certificate::from_pem(link.as_str()).map_err(|_| DscCertificateError::InvalidIssuer)?;
        let parent_der = parent
            .to_der()
            .map_err(|_| DscCertificateError::InvalidIssuer)?;
        if child.tbs_certificate.issuer != parent.tbs_certificate.subject
            || !valid_chain_parent(&parent, not_before, not_after, subordinate_cas)?
            || !verify_certificate_signature(&child_der, &parent_der)
                .map_err(|_| DscCertificateError::InvalidIssuer)?
        {
            return Err(DscCertificateError::InvalidIssuer);
        }
        child = parent;
        child_der = parent_der;
        if child.tbs_certificate.subject != child.tbs_certificate.issuer {
            subordinate_cas += 1;
        }
    }
    if child.tbs_certificate.subject == child.tbs_certificate.issuer {
        if !verify_certificate_signature(&child_der, &child_der)
            .map_err(|_| DscCertificateError::InvalidIssuer)?
        {
            return Err(DscCertificateError::InvalidIssuer);
        }
    } else if chain_pem.trim().is_empty() {
        return Err(DscCertificateError::InvalidIssuer);
    }
    Ok(())
}

fn valid_chain_parent(
    issuer: &Certificate,
    not_before: SystemTime,
    not_after: SystemTime,
    subordinate_cas: usize,
) -> Result<bool, DscCertificateError> {
    let tbs = &issuer.tbs_certificate;
    let constraints = tbs
        .get::<BasicConstraints>()
        .map_err(|_| DscCertificateError::InvalidIssuer)?;
    let usage = tbs
        .get::<KeyUsage>()
        .map_err(|_| DscCertificateError::InvalidIssuer)?;
    let start = not_before
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| DscCertificateError::InvalidIssuer)?;
    let end = not_after
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| DscCertificateError::InvalidIssuer)?;
    Ok(matches!(
        constraints,
        Some((true, BasicConstraints { ca: true, path_len_constraint, .. }))
            if path_len_constraint.is_none_or(|limit| subordinate_cas <= usize::from(limit))
    ) && usage.is_some_and(|(critical, usage)| critical && usage.key_cert_sign())
        && start >= tbs.validity.not_before.to_unix_duration()
        && end <= tbs.validity.not_after.to_unix_duration())
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::{Decode, EncodePem};
    use marty_crypto::{
        cert_builder::{
            create_csca_certificate, create_csr, CertProfile, CertificateBuilderConfig,
            DistinguishedName,
        },
        keygen::KeyType,
    };
    use std::str::FromStr;

    fn jwk_for_spki(spki: &SubjectPublicKeyInfoOwned) -> Value {
        serde_json::to_value(public_key_der_to_jwk(&spki.to_der().unwrap()).unwrap()).unwrap()
    }

    #[test]
    fn country_reader_uses_x509_attributes_and_rejects_ambiguous_country() {
        let name = Name::from_str("C=US,O=Disposable,CN=DSC").unwrap();
        assert_eq!(country_from_name(&name).as_deref(), Some("US"));
        let duplicate = Name::from_str("C=US,C=GB,O=Disposable,CN=DSC").unwrap();
        assert_eq!(country_from_name(&duplicate), None);
        let missing = Name::from_str("O=Disposable,CN=DSC").unwrap();
        assert_eq!(country_from_name(&missing), None);
    }

    #[test]
    fn csr_proof_and_current_subject_key_are_required() {
        let (csr_der, _) = create_csr("Disposable DSC", KeyType::EcdsaP256).unwrap();
        let mut csr = CertReq::from_der(&csr_der).unwrap();
        let public = jwk_for_spki(&csr.info.public_key);
        let pem = csr.to_pem(der::pem::LineEnding::LF).unwrap();
        let mut wrong = public.clone();
        wrong["x"] = Value::String("wrong".into());
        assert!(matches!(
            VerifiedDscSubject::from_csr_pem(&pem, &wrong),
            Err(DscCertificateError::InvalidCsr)
        ));
        csr.signature = BitString::from_bytes(&[0u8; 64]).unwrap();
        let forged = csr.to_pem(der::pem::LineEnding::LF).unwrap();
        assert!(matches!(
            VerifiedDscSubject::from_csr_pem(&forged, &public),
            Err(DscCertificateError::InvalidCsr)
        ));
    }

    fn fixture() -> (VerifiedDscSubject, Value, String) {
        let (csr_der, _) = create_csr("Disposable DSC", KeyType::EcdsaP256).unwrap();
        let csr = CertReq::from_der(&csr_der).unwrap();
        let subject_jwk = jwk_for_spki(&csr.info.public_key);
        let csr_pem = csr.to_pem(der::pem::LineEnding::LF).unwrap();
        let subject = VerifiedDscSubject::from_csr_pem(&csr_pem, &subject_jwk).unwrap();
        let (csca_der, _) =
            create_csca_certificate("US", "Disposable CA", 365, KeyType::EcdsaP256).unwrap();
        let csca = Certificate::from_der(&csca_der).unwrap();
        let csca_jwk = jwk_for_spki(&csca.tbs_certificate.subject_public_key_info);
        (
            subject,
            csca_jwk,
            csca.to_pem(der::pem::LineEnding::LF).unwrap(),
        )
    }

    #[test]
    fn prepares_bounded_dsc_with_public_material_and_rejects_bad_signature() {
        let (subject, csca_jwk, csca_pem) = fixture();
        assert_eq!(certificate_country(&csca_pem).as_deref(), Some("US"));
        let now = SystemTime::now();
        let prepared = prepare_dsc(&subject, &csca_pem, "", &csca_jwk, &[1], 29, now).unwrap();
        assert!(!prepared.signing_bytes().is_empty());
        let metadata = prepared.metadata().unwrap();
        assert_eq!(metadata.serial_hex, "01");
        let start = chrono::DateTime::parse_from_rfc3339(&metadata.not_before).unwrap();
        let end = chrono::DateTime::parse_from_rfc3339(&metadata.not_after).unwrap();
        assert_eq!(end - start, chrono::Duration::days(29));
        assert!(matches!(
            prepared.finish(&[0u8; 64]),
            Err(DscCertificateError::InvalidSignature)
        ));
        assert!(matches!(
            prepare_dsc(&subject, &csca_pem, "", &csca_jwk, &[0], 29, now),
            Err(DscCertificateError::InvalidSerial)
        ));
        assert!(matches!(
            prepare_dsc(&subject, &csca_pem, "", &csca_jwk, &[1], 0, now),
            Err(DscCertificateError::InvalidValidity)
        ));
        assert!(matches!(
            prepare_dsc(&subject, &csca_pem, "", &csca_jwk, &[1], 91, now),
            Err(DscCertificateError::InvalidValidity)
        ));
        assert!(prepare_dsc(&subject, &csca_pem, "", &csca_jwk, &[1], 90, now).is_ok());
        assert!(matches!(
            prepare_dsc(&subject, &csca_pem, "", &csca_jwk, &[0xff; 20], 29, now),
            Err(DscCertificateError::InvalidSerial)
        ));
        let (short_der, _) =
            create_csca_certificate("US", "Short CA", 1, KeyType::EcdsaP256).unwrap();
        let short = Certificate::from_der(&short_der).unwrap();
        let short_pem = short.to_pem(der::pem::LineEnding::LF).unwrap();
        let short_jwk = jwk_for_spki(&short.tbs_certificate.subject_public_key_info);
        let short_now = SystemTime::now();
        assert!(matches!(
            prepare_dsc(&subject, &short_pem, "", &short_jwk, &[1], 2, short_now),
            Err(DscCertificateError::InvalidValidity)
        ));
    }

    #[test]
    fn rejects_wrong_csca_key_and_untrusted_or_malformed_chain() {
        let (subject, csca_jwk, csca_pem) = fixture();
        let now = SystemTime::now();
        let mut wrong = csca_jwk.clone();
        wrong["x"] = Value::String("wrong".into());
        assert!(matches!(
            prepare_dsc(&subject, &csca_pem, "", &wrong, &[1], 29, now),
            Err(DscCertificateError::InvalidIssuer)
        ));
        assert!(matches!(
            prepare_dsc(
                &subject,
                &csca_pem,
                "-----BEGIN PRIVATE KEY-----",
                &csca_jwk,
                &[1],
                29,
                now
            ),
            Err(DscCertificateError::InvalidIssuer)
        ));
        assert!(matches!(
            prepare_dsc(&subject, &csca_pem, "invalid", &csca_jwk, &[1], 29, now),
            Err(DscCertificateError::InvalidIssuer)
        ));
    }

    #[test]
    fn accepts_enrolled_non_self_issued_csca_chain() {
        let (subject, _, _) = fixture();
        let (root_der, root_key) =
            create_csca_certificate("US", "Root", 365, KeyType::EcdsaP256).unwrap();
        let (child_der, _) = CertificateBuilderConfig::new()
            .subject(
                DistinguishedName::new()
                    .cn("Enrolled CSCA")
                    .country("US")
                    .organization("Disposable"),
            )
            .validity_days(365)
            .profile(CertProfile::SubCa { path_length: 0 })
            .key_type(KeyType::EcdsaP256)
            .build_signed_by(&root_der, &root_key)
            .unwrap();
        let child = Certificate::from_der(&child_der).unwrap();
        let child_jwk = jwk_for_spki(&child.tbs_certificate.subject_public_key_info);
        let child_pem = child.to_pem(der::pem::LineEnding::LF).unwrap();
        let root_pem = Certificate::from_der(&root_der)
            .unwrap()
            .to_pem(der::pem::LineEnding::LF)
            .unwrap();
        let now = SystemTime::now();
        let prepared = prepare_dsc(&subject, &child_pem, &root_pem, &child_jwk, &[2], 29, now);
        assert!(prepared.is_ok(), "{:?}", prepared.err());
        assert!(matches!(
            prepare_dsc(&subject, &child_pem, "", &child_jwk, &[2], 29, now),
            Err(DscCertificateError::InvalidIssuer)
        ));
    }

    #[test]
    fn rejects_expired_intermediate_even_when_enrolled_csca_is_still_valid() {
        let (subject, _, _) = fixture();
        let (root_der, root_key) =
            create_csca_certificate("US", "Root", 365, KeyType::EcdsaP256).unwrap();
        let (intermediate_der, intermediate_key) = CertificateBuilderConfig::new()
            .subject(
                DistinguishedName::new()
                    .cn("Short Intermediate")
                    .country("US")
                    .organization("Disposable"),
            )
            .validity_days(1)
            .profile(CertProfile::SubCa { path_length: 1 })
            .key_type(KeyType::EcdsaP256)
            .build_signed_by(&root_der, &root_key)
            .unwrap();
        let (child_der, _) = CertificateBuilderConfig::new()
            .subject(
                DistinguishedName::new()
                    .cn("Long-Lived CSCA")
                    .country("US")
                    .organization("Disposable"),
            )
            .validity_days(365)
            .profile(CertProfile::SubCa { path_length: 0 })
            .key_type(KeyType::EcdsaP256)
            .build_signed_by(&intermediate_der, &intermediate_key)
            .unwrap();
        let child = Certificate::from_der(&child_der).unwrap();
        let child_jwk = jwk_for_spki(&child.tbs_certificate.subject_public_key_info);
        let child_pem = child.to_pem(der::pem::LineEnding::LF).unwrap();
        let intermediate_pem = Certificate::from_der(&intermediate_der)
            .unwrap()
            .to_pem(der::pem::LineEnding::LF)
            .unwrap();
        let root_pem = Certificate::from_der(&root_der)
            .unwrap()
            .to_pem(der::pem::LineEnding::LF)
            .unwrap();
        let chain = format!("{intermediate_pem}\n{root_pem}");
        let after_intermediate_expiry = SystemTime::now() + Duration::from_secs(2 * 24 * 60 * 60);
        assert!(matches!(
            prepare_dsc(
                &subject,
                &child_pem,
                &chain,
                &child_jwk,
                &[3],
                1,
                after_intermediate_expiry,
            ),
            Err(DscCertificateError::InvalidIssuer)
        ));
    }

    #[test]
    fn rejects_intermediate_without_critical_ca_signing_usage() {
        let (root_der, root_key) =
            create_csca_certificate("US", "Root", 365, KeyType::EcdsaP256).unwrap();
        let (intermediate_der, _) = CertificateBuilderConfig::new()
            .subject(
                DistinguishedName::new()
                    .cn("Intermediate")
                    .country("US")
                    .organization("Disposable"),
            )
            .validity_days(365)
            .profile(CertProfile::SubCa { path_length: 1 })
            .key_type(KeyType::EcdsaP256)
            .build_signed_by(&root_der, &root_key)
            .unwrap();
        let mut intermediate = Certificate::from_der(&intermediate_der).unwrap();
        let now = SystemTime::now();
        let end = now + Duration::from_secs(24 * 60 * 60);
        assert!(valid_chain_parent(&intermediate, now, end, 1).unwrap());
        let constraints = BasicConstraints {
            ca: true,
            path_len_constraint: Some(0),
        }
        .to_extension(&intermediate.tbs_certificate.subject, &[])
        .unwrap();
        let wrong_usage = KeyUsage(KeyUsages::DigitalSignature.into())
            .to_extension(
                &intermediate.tbs_certificate.subject,
                std::slice::from_ref(&constraints),
            )
            .unwrap();
        intermediate.tbs_certificate.extensions = Some(vec![constraints, wrong_usage]);
        assert!(!valid_chain_parent(&intermediate, now, end, 1).unwrap());
    }

    #[test]
    fn rejects_path_length_zero_ca_with_subordinate_ca() {
        let (subject, _, _) = fixture();
        let (root_der, root_key) =
            create_csca_certificate("US", "Root", 365, KeyType::EcdsaP256).unwrap();
        let (intermediate_der, intermediate_key) = CertificateBuilderConfig::new()
            .subject(
                DistinguishedName::new()
                    .cn("Path-Length-Zero Intermediate")
                    .country("US")
                    .organization("Disposable"),
            )
            .validity_days(365)
            .profile(CertProfile::SubCa { path_length: 0 })
            .key_type(KeyType::EcdsaP256)
            .build_signed_by(&root_der, &root_key)
            .unwrap();
        let (child_der, _) = CertificateBuilderConfig::new()
            .subject(
                DistinguishedName::new()
                    .cn("Enrolled CSCA")
                    .country("US")
                    .organization("Disposable"),
            )
            .validity_days(365)
            .profile(CertProfile::SubCa { path_length: 0 })
            .key_type(KeyType::EcdsaP256)
            .build_signed_by(&intermediate_der, &intermediate_key)
            .unwrap();
        let child = Certificate::from_der(&child_der).unwrap();
        let child_jwk = jwk_for_spki(&child.tbs_certificate.subject_public_key_info);
        let child_pem = child.to_pem(der::pem::LineEnding::LF).unwrap();
        let intermediate_pem = Certificate::from_der(&intermediate_der)
            .unwrap()
            .to_pem(der::pem::LineEnding::LF)
            .unwrap();
        let root_pem = Certificate::from_der(&root_der)
            .unwrap()
            .to_pem(der::pem::LineEnding::LF)
            .unwrap();
        let chain = format!("{intermediate_pem}\n{root_pem}");
        assert!(matches!(
            prepare_dsc(
                &subject,
                &child_pem,
                &chain,
                &child_jwk,
                &[4],
                1,
                SystemTime::now()
            ),
            Err(DscCertificateError::InvalidIssuer)
        ));

        // The same restriction applies when the enrolled CSCA is directly
        // below a root with a zero path-length constraint.
        let mut root = Certificate::from_der(&root_der).unwrap();
        let constraints = BasicConstraints {
            ca: true,
            path_len_constraint: Some(0),
        }
        .to_extension(&root.tbs_certificate.subject, &[])
        .unwrap();
        let usage = KeyUsage(KeyUsages::KeyCertSign.into())
            .to_extension(
                &root.tbs_certificate.subject,
                std::slice::from_ref(&constraints),
            )
            .unwrap();
        root.tbs_certificate.extensions = Some(vec![constraints, usage]);
        let now = SystemTime::now();
        let end = now + Duration::from_secs(24 * 60 * 60);
        assert!(valid_chain_parent(&root, now, end, 0).unwrap());
        assert!(!valid_chain_parent(&root, now, end, 1).unwrap());
    }
}
