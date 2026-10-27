//! Public certificate-profile construction/validation shared by managed MDOC
//! issuance and certificate attachment. No private key, network or signer lives
//! here. This is Marty's governed profile, not a claim of complete ISO conformance.
use base64::{engine::general_purpose::STANDARD, Engine};
use const_oid::{AssociatedOid, ObjectIdentifier};
use der::asn1::Ia5String;
use der::{Decode, DecodePem, Encode};
use marty_signing_grant::certificate_profile::{
    ManagedCertificateProfile, MdocCertificateMetadata,
};
use serde::{Deserialize, Serialize};
use x509_cert::{
    certificate::TbsCertificate,
    ext::{
        pkix::{
            crl::dp::DistributionPoint,
            name::{DistributionPointName, GeneralName},
            AuthorityKeyIdentifier, BasicConstraints, CrlDistributionPoints, ExtendedKeyUsage,
            IssuerAltName, KeyUsage, KeyUsages, SubjectKeyIdentifier,
        },
        AsExtension,
    },
};

// Document-signer purpose recorded in the primary Apple Issuing Authority Root
// CPS (2025), pp31-32. Other ecosystem purposes are not silently added here.
pub const MDL_DOCUMENT_SIGNER: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.0.18013.5.1.2");

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MdocAuthorityConfiguration {
    pub organization_id: String,
    pub issuer_did: String,
    pub certificate: MdocCertificateMetadata,
}

/// Optional, separately scoped producer authority. No development credential or
/// publication URL is synthesized when it is absent.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct MdocCertificateOptions {
    pub iaca_gateway_key: Option<String>,
    pub dsc_gateway_key: Option<String>,
    pub authorities: Vec<MdocAuthorityConfiguration>,
}

impl MdocCertificateOptions {
    pub fn metadata_for(
        &self,
        organization_id: &str,
        issuer_did: &str,
    ) -> Result<MdocCertificateMetadata, &'static str> {
        let matches = self
            .authorities
            .iter()
            .filter(|entry| {
                entry.organization_id == organization_id && entry.issuer_did == issuer_did
            })
            .collect::<Vec<_>>();
        let [entry] = matches.as_slice() else {
            return Err("MDOC_ISSUER_CONFIGURATION_REQUIRED");
        };
        entry
            .certificate
            .validate()
            .map_err(|_| "MDOC_ISSUER_CONFIGURATION_INVALID")?;
        Ok(entry.certificate.clone())
    }

    pub fn parse_authorities(
        input: Option<&str>,
    ) -> Result<Vec<MdocAuthorityConfiguration>, String> {
        let Some(input) = input else {
            return Ok(Vec::new());
        };
        if input.len() > 262_144 {
            return Err("MDOC authority configuration exceeds its bound".into());
        }
        let entries: Vec<MdocAuthorityConfiguration> = serde_json::from_str(input)
            .map_err(|_| "MDOC authority configuration must be a typed public JSON array")?;
        if entries.len() > 128 {
            return Err("MDOC authority configuration exceeds its bound".into());
        }
        let mut unique = std::collections::BTreeSet::new();
        for entry in &entries {
            if uuid::Uuid::parse_str(&entry.organization_id).is_err()
                || !entry.issuer_did.starts_with("did:")
                || entry.issuer_did.len() > 2048
                || entry.issuer_did.chars().any(char::is_control)
                || !unique.insert((&entry.organization_id, &entry.issuer_did))
            {
                return Err("MDOC authority configuration ownership is invalid".into());
            }
            entry.certificate.validate().map_err(str::to_owned)?;
        }
        Ok(entries)
    }
}

pub(crate) fn apply_profile(
    tbs: &mut TbsCertificate,
    profile: ManagedCertificateProfile,
    metadata: &MdocCertificateMetadata,
) -> Result<(), &'static str> {
    metadata.validate()?;
    let subject = &tbs.subject;
    let extensions = tbs.extensions.get_or_insert_with(Vec::new);
    extensions.retain(|e| e.extn_id != KeyUsage::OID);
    let usage = match profile {
        ManagedCertificateProfile::MdocIaca => {
            KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign)
        }
        ManagedCertificateProfile::MdocDocumentSigner => {
            KeyUsage(KeyUsages::DigitalSignature.into())
        }
        _ => return Err("MDOC certificate profile is required"),
    };
    let mut usage = usage
        .to_extension(subject, extensions)
        .map_err(|_| "MDOC KeyUsage encoding failed")?;
    usage.critical = true;
    extensions.push(usage);
    if profile == ManagedCertificateProfile::MdocDocumentSigner {
        let mut eku = ExtendedKeyUsage(vec![MDL_DOCUMENT_SIGNER])
            .to_extension(subject, extensions)
            .map_err(|_| "MDOC ExtendedKeyUsage encoding failed")?;
        eku.critical = true;
        extensions.push(eku);
    }
    let contact = GeneralName::UniformResourceIdentifier(
        Ia5String::new(&metadata.issuer_contact_uri)
            .map_err(|_| "MDOC issuer contact is invalid")?,
    );
    extensions.push(
        IssuerAltName(vec![contact])
            .to_extension(subject, extensions)
            .map_err(|_| "MDOC issuer contact encoding failed")?,
    );
    let distribution = GeneralName::UniformResourceIdentifier(
        Ia5String::new(&metadata.crl_distribution_uri).map_err(|_| "MDOC CRL URI is invalid")?,
    );
    extensions.push(
        CrlDistributionPoints(vec![DistributionPoint {
            distribution_point: Some(DistributionPointName::FullName(vec![distribution])),
            reasons: None,
            crl_issuer: None,
        }])
        .to_extension(subject, extensions)
        .map_err(|_| "MDOC CRL distribution encoding failed")?,
    );
    validate_profile(tbs, profile, Some(metadata))
}

pub(crate) fn validate_profile(
    tbs: &TbsCertificate,
    profile: ManagedCertificateProfile,
    expected: Option<&MdocCertificateMetadata>,
) -> Result<(), &'static str> {
    let spki = tbs
        .subject_public_key_info
        .to_der()
        .map_err(|_| "MDOC SPKI is invalid")?;
    let jwk = marty_crypto::jwk::public_key_der_to_jwk(&spki)
        .ok()
        .and_then(|key| serde_json::to_value(key).ok())
        .ok_or("MDOC SPKI is invalid")?;
    if tbs.signature.oid != ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2")
        || tbs.signature.parameters.is_some()
        || jwk.get("kty").and_then(serde_json::Value::as_str) != Some("EC")
        || jwk.get("crv").and_then(serde_json::Value::as_str) != Some("P-256")
    {
        return Err("Governed MDOC certificate requires ES256");
    }
    let expected_ski = SubjectKeyIdentifier::try_from(
        spki::SubjectPublicKeyInfoRef::from_der(&spki).map_err(|_| "MDOC SPKI is invalid")?,
    )
    .map_err(|_| "MDOC subject key identifier is invalid")?;
    let (ski_critical, ski) = tbs
        .get::<SubjectKeyIdentifier>()
        .map_err(|_| "MDOC subject key identifier is invalid")?
        .ok_or("MDOC subject key identifier is required")?;
    let (aki_critical, aki) = tbs
        .get::<AuthorityKeyIdentifier>()
        .map_err(|_| "MDOC authority key identifier is invalid")?
        .ok_or("MDOC authority key identifier is required")?;
    if ski_critical
        || aki_critical
        || ski != expected_ski
        || aki.key_identifier.is_none()
        || aki.authority_cert_issuer.is_some()
        || aki.authority_cert_serial_number.is_some()
        || (profile == ManagedCertificateProfile::MdocIaca && aki.key_identifier != Some(ski.0))
    {
        return Err("MDOC certificate key identifiers are invalid");
    }
    if crate::certificate_issuance::country_from_name(&tbs.subject).is_none()
        || !tbs.serial_number.as_bytes().iter().any(|value| *value != 0)
    {
        return Err("MDOC certificate requires an unambiguous country and positive serial");
    }
    let extensions = tbs.extensions.as_deref().unwrap_or_default();
    for oid in [
        SubjectKeyIdentifier::OID,
        AuthorityKeyIdentifier::OID,
        BasicConstraints::OID,
        KeyUsage::OID,
        ExtendedKeyUsage::OID,
        IssuerAltName::OID,
        CrlDistributionPoints::OID,
    ] {
        if extensions.iter().filter(|e| e.extn_id == oid).count() > 1 {
            return Err("MDOC certificate has duplicate profile extensions");
        }
    }
    let constraints = tbs
        .get::<BasicConstraints>()
        .map_err(|_| "MDOC BasicConstraints is invalid")?;
    let (critical, usage) = tbs
        .get::<KeyUsage>()
        .map_err(|_| "MDOC KeyUsage is invalid")?
        .ok_or("MDOC KeyUsage is required")?;
    if !critical {
        return Err("MDOC KeyUsage must be critical");
    }
    let eku = tbs
        .get::<ExtendedKeyUsage>()
        .map_err(|_| "MDOC ExtendedKeyUsage is invalid")?;
    match profile {
        ManagedCertificateProfile::MdocIaca => {
            if tbs.subject != tbs.issuer
                || !matches!(
                    constraints,
                    Some((
                        true,
                        BasicConstraints {
                            ca: true,
                            path_len_constraint: Some(0)
                        }
                    ))
                )
                || usage.0 != (KeyUsages::KeyCertSign | KeyUsages::CRLSign)
                || eku.is_some()
            {
                return Err("Certificate is not the governed MDOC IACA profile");
            }
        }
        ManagedCertificateProfile::MdocDocumentSigner => {
            if constraints.is_some_and(|(_, c)| c.ca || c.path_len_constraint.is_some())
                || usage != KeyUsage(KeyUsages::DigitalSignature.into())
                || !matches!(eku, Some((true, ExtendedKeyUsage(ref purposes))) if purposes == &[MDL_DOCUMENT_SIGNER])
            {
                return Err("Certificate is not the governed MDOC document-signer profile");
            }
        }
        _ => return Err("MDOC certificate profile is required"),
    }
    let (contact_critical, contact) = tbs
        .get::<IssuerAltName>()
        .map_err(|_| "MDOC issuer contact is invalid")?
        .ok_or("MDOC issuer contact is required")?;
    let (crl_critical, points) = tbs
        .get::<CrlDistributionPoints>()
        .map_err(|_| "MDOC CRL distribution is invalid")?
        .ok_or("MDOC CRL distribution is required")?;
    if contact_critical || crl_critical || points.0.len() != 1 {
        return Err("MDOC publication extensions are invalid");
    }
    let [GeneralName::UniformResourceIdentifier(contact)] = contact.0.as_slice() else {
        return Err("MDOC issuer contact URI is required");
    };
    let point = &points.0[0];
    if point.reasons.is_some() || point.crl_issuer.is_some() {
        return Err("MDOC CRL distribution scope is invalid");
    }
    let Some(DistributionPointName::FullName(names)) = &point.distribution_point else {
        return Err("MDOC CRL distribution URI is required");
    };
    let [GeneralName::UniformResourceIdentifier(crl)] = names.as_slice() else {
        return Err("MDOC CRL distribution URI is required");
    };
    let actual = MdocCertificateMetadata {
        issuer_contact_uri: contact.as_str().into(),
        crl_distribution_uri: crl.as_str().into(),
    };
    actual.validate()?;
    if expected.is_some_and(|expected| expected != &actual) {
        return Err("MDOC certificate publication configuration changed");
    }
    Ok(())
}

/// Server-selected import policy. Wire callers cannot opt out of an existing
/// governed receipt, or turn a legacy import into a governed profile assertion.
#[derive(Clone, Copy)]
pub enum MdocAttachmentPolicy {
    SignedPublicImport,
    GovernedV1(ManagedCertificateProfile),
}

fn public_certificates(pem: &str) -> Result<Vec<x509_cert::Certificate>, &'static str> {
    if pem.len() > 524_288 || pem.contains("PRIVATE KEY") {
        return Err("MDOC certificate material must be bounded and public");
    }
    let pattern = regex::Regex::new(r"(?s)-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----")
        .expect("fixed certificate pattern");
    let matches = pattern.find_iter(pem).collect::<Vec<_>>();
    if matches.len() > 8 || !pattern.replace_all(pem, "").trim().is_empty() {
        return Err("MDOC chain must contain at most eight public certificates");
    }
    matches
        .into_iter()
        .map(|item| {
            x509_cert::Certificate::from_pem(item.as_str())
                .map_err(|_| "MDOC certificate PEM is invalid")
        })
        .collect()
}

fn single_certificate(pem: &str) -> Result<x509_cert::Certificate, &'static str> {
    let mut certificates = public_certificates(pem)?;
    if certificates.len() != 1 {
        return Err("Exactly one public MDOC certificate is required");
    }
    Ok(certificates.remove(0))
}

/// Common cryptographic chain boundary, independent of the ES256 producer.
/// Legacy imports retain their supported algorithms through Core's parameter-
/// aware verifier. This is not full ISO/profile or revocation validation.
fn validated_chain(
    certificate_pem: &str,
    chain_pem: &str,
    authority: bool,
) -> Result<Vec<x509_cert::Certificate>, &'static str> {
    use marty_crypto::certificate::verify_parsed_certificate_signature;
    let mut chain = vec![single_certificate(certificate_pem)?];
    chain.extend(public_certificates(chain_pem)?);
    if (!authority && chain.len() < 2) || chain.len() > 8 {
        return Err("A complete bounded MDOC issuer chain is required");
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "MDOC clock is invalid")?;
    for (index, certificate) in chain.iter().enumerate() {
        let tbs = &certificate.tbs_certificate;
        if tbs.validity.not_before.to_unix_duration() > now
            || now >= tbs.validity.not_after.to_unix_duration()
        {
            return Err("MDOC certificate chain is not currently valid");
        }
        for oid in [
            BasicConstraints::OID,
            KeyUsage::OID,
            ExtendedKeyUsage::OID,
            SubjectKeyIdentifier::OID,
            AuthorityKeyIdentifier::OID,
        ] {
            if tbs
                .extensions
                .as_deref()
                .unwrap_or_default()
                .iter()
                .filter(|extension| extension.extn_id == oid)
                .count()
                > 1
            {
                return Err("MDOC chain has duplicate security extensions");
            }
        }
        if tbs
            .extensions
            .as_deref()
            .unwrap_or_default()
            .iter()
            .any(|extension| {
                extension.critical
                    && ![BasicConstraints::OID, KeyUsage::OID, ExtendedKeyUsage::OID]
                        .contains(&extension.extn_id)
            })
        {
            return Err("MDOC chain has an unsupported critical extension");
        }
        if !tbs.serial_number.as_bytes().iter().any(|value| *value != 0) {
            return Err("MDOC certificate serial must be positive");
        }
        let constraints = tbs
            .get::<BasicConstraints>()
            .map_err(|_| "MDOC BasicConstraints is invalid")?;
        let usage = tbs
            .get::<KeyUsage>()
            .map_err(|_| "MDOC KeyUsage is invalid")?
            .ok_or("MDOC KeyUsage is required")?
            .1;
        if index == 0 && !authority {
            if constraints.is_some_and(|(_, value)| value.ca || value.path_len_constraint.is_some())
                || !usage.digital_signature()
                || usage.key_cert_sign()
                || usage.crl_sign()
            {
                return Err("MDOC document signer may not act as a CA");
            }
            if tbs
                .get::<ExtendedKeyUsage>()
                .map_err(|_| "MDOC ExtendedKeyUsage is invalid")?
                .is_some_and(|(_, purposes)| !purposes.0.contains(&MDL_DOCUMENT_SIGNER))
            {
                return Err("MDOC ExtendedKeyUsage does not permit document signing");
            }
        } else {
            if tbs
                .get::<ExtendedKeyUsage>()
                .map_err(|_| "MDOC issuer ExtendedKeyUsage is invalid")?
                .is_some_and(|(_, purposes)| !purposes.0.contains(&MDL_DOCUMENT_SIGNER))
            {
                return Err("MDOC issuer ExtendedKeyUsage excludes document signing");
            }
            let subordinate_cas = if authority { index } else { index - 1 };
            if !matches!(constraints, Some((true, BasicConstraints { ca: true, path_len_constraint })) if path_len_constraint.is_none_or(|limit| subordinate_cas <= usize::from(limit)))
                || !usage.key_cert_sign()
            {
                return Err("MDOC issuer is not authorized to sign this chain");
            }
        }
        let parent = chain.get(index + 1).unwrap_or(certificate);
        if tbs.issuer != parent.tbs_certificate.subject
            || !verify_parsed_certificate_signature(certificate, parent).unwrap_or(false)
        {
            return Err("MDOC certificate issuer/signature binding failed");
        }
        if let Some((_, aki)) = tbs
            .get::<AuthorityKeyIdentifier>()
            .map_err(|_| "MDOC authority identifier is invalid")?
        {
            if let (Some(key), Some((_, ski))) = (
                aki.key_identifier,
                parent
                    .tbs_certificate
                    .get::<SubjectKeyIdentifier>()
                    .map_err(|_| "MDOC issuer key identifier is invalid")?,
            ) {
                if key != ski.0 {
                    return Err("MDOC authority key identifier does not match issuer");
                }
            }
        }
    }
    if !authority {
        let country =
            crate::certificate_issuance::country_from_name(&chain[0].tbs_certificate.subject);
        if country.is_none()
            || country
                != crate::certificate_issuance::country_from_name(&chain[1].tbs_certificate.subject)
        {
            return Err("MDOC document signer country does not match its issuer");
        }
    }
    Ok(chain)
}

pub(crate) fn validate_public_import(
    certificate_pem: &str,
    chain_pem: &str,
) -> Result<Vec<String>, &'static str> {
    let chain = validated_chain(certificate_pem, chain_pem, false)?;
    // Retain intermediate certificates when present, excluding the verified
    // self-signed root. This preserves supported public-import chain shapes.
    chain[..chain.len() - 1]
        .iter()
        .map(|certificate| {
            certificate
                .to_der()
                .map(|der| STANDARD.encode(der))
                .map_err(|_| "MDOC certificate DER is invalid")
        })
        .collect()
}

/// Validate the closed direct IACA -> DS Marty-v1 profile. Original PEM custody
/// stays stored separately, and no issuer root is emitted as an IssuerAuth member.
pub(crate) fn validate_attachment(
    certificate_pem: &str,
    chain_pem: &str,
    profile: ManagedCertificateProfile,
) -> Result<Vec<String>, &'static str> {
    let authority = profile == ManagedCertificateProfile::MdocIaca;
    let chain = validated_chain(certificate_pem, chain_pem, authority)?;
    if chain.len() != if authority { 1 } else { 2 } {
        return Err("Governed MDOC requires one direct IACA");
    }
    validate_profile(&chain[0].tbs_certificate, profile, None)?;
    if !authority {
        let issuer = &chain[1].tbs_certificate;
        validate_profile(issuer, ManagedCertificateProfile::MdocIaca, None)?;
        if chain[0]
            .tbs_certificate
            .validity
            .not_before
            .to_unix_duration()
            < issuer.validity.not_before.to_unix_duration()
            || chain[0]
                .tbs_certificate
                .validity
                .not_after
                .to_unix_duration()
                > issuer.validity.not_after.to_unix_duration()
        {
            return Err("Governed MDOC signer validity exceeds IACA");
        }
    }
    Ok(vec![STANDARD.encode(
        chain[0]
            .to_der()
            .map_err(|_| "MDOC certificate DER is invalid")?,
    )])
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn governed_metadata_requires_exact_tenant_authority_and_real_public_configuration() {
        let org = uuid::Uuid::new_v4().to_string();
        let entry = MdocAuthorityConfiguration {
            organization_id: org.clone(),
            issuer_did: "did:web:authority.example".into(),
            certificate: MdocCertificateMetadata {
                issuer_contact_uri: "https://authority.example/contact".into(),
                crl_distribution_uri: "https://authority.example/mdoc.crl".into(),
            },
        };
        let mut options = MdocCertificateOptions {
            authorities: vec![entry.clone()],
            ..Default::default()
        };
        assert_eq!(
            options.metadata_for(&org, &entry.issuer_did),
            Ok(entry.certificate.clone())
        );
        assert!(options
            .metadata_for(&uuid::Uuid::new_v4().to_string(), &entry.issuer_did)
            .is_err());
        assert!(options.metadata_for(&org, "did:web:other.example").is_err());
        options.authorities.push(entry.clone());
        assert!(options.metadata_for(&org, &entry.issuer_did).is_err());
        assert!(MdocCertificateOptions::parse_authorities(Some(
            &serde_json::to_string(&options.authorities).unwrap()
        ))
        .is_err());
        for uri in [
            "",
            "file:///tmp/crl",
            "https://user:secret@authority.example/crl",
            "https://authority.example/crl?token=secret",
            "https://authority.example/crl#fragment",
        ] {
            let mut wrong = entry.certificate.clone();
            wrong.crl_distribution_uri = uri.into();
            assert!(wrong.validate().is_err());
        }
        assert!(MdocCertificateOptions::default()
            .metadata_for(&org, &entry.issuer_did)
            .is_err());
        assert!(single_certificate("").is_err());
        let public_ca = include_str!("../tests/fixtures/public_certificates/root-ca.pem");
        assert!(single_certificate(public_ca).is_ok());
        assert!(single_certificate(&format!("{public_ca}\n{public_ca}")).is_err());
        assert!(single_certificate(&format!("unexpected{public_ca}")).is_err());
    }
}
