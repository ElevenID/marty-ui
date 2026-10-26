//! Local mdoc lifecycle references, shared by issuance and verification.
//!
//! A reference identifies the signed MSO and its DSC, independently of which
//! namespace elements a holder discloses. It is not status evidence or proof of
//! authenticity. Presentation callers must authenticate issuer and device
//! signatures first; issuance callers use only their trusted builder output.
use std::fmt;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use coset::Label;
use isomdl::definitions::{
    device_response::{DeviceResponse, Status},
    x509::x5chain::{X5Chain, X5CHAIN_COSE_HEADER_LABEL},
    IssuerSigned,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

const PREFIX: &str = "urn:mdoc-status:v1:";
const DOMAIN: &[u8] = b"ElevenID authenticated mdoc status binding v1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MdocStatusReference {
    certificate_sha256: String,
    signed_mso_sha256: String,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("Invalid mdoc lifecycle binding")]
pub struct InvalidBinding;

impl MdocStatusReference {
    pub fn is_reference(value: &str) -> bool {
        value.starts_with("urn:mdoc-status:")
    }

    pub fn parse(value: &str) -> Result<Self, InvalidBinding> {
        let (certificate, mso) = value
            .strip_prefix(PREFIX)
            .and_then(|value| value.split_once(':'))
            .ok_or(InvalidBinding)?;
        if !sha256_hex(certificate) || !sha256_hex(mso) {
            return Err(InvalidBinding);
        }
        Ok(Self {
            certificate_sha256: certificate.into(),
            signed_mso_sha256: mso.into(),
        })
    }

    pub fn issuer_id(&self) -> String {
        format!("x509-sha256:{}", self.certificate_sha256)
    }

    /// Parse output from the trusted credential builder, never a holder's
    /// assertion about an arbitrary stored UUID or status URI.
    pub fn from_issuer_signed_base64(value: &str) -> Result<Self, InvalidBinding> {
        let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|_| InvalidBinding)?;
        let signed: IssuerSigned = isomdl::cbor::from_slice(&bytes).map_err(|_| InvalidBinding)?;
        from_issuer_signed(&signed)
    }

    /// Call only after complete Core issuer/holder authentication of these
    /// exact response bytes. Cross-check the authenticated document and DSC.
    pub fn from_authenticated_presentation(
        bytes: &[u8],
        document_type: &str,
        certificate_sha256: &str,
    ) -> Result<Self, InvalidBinding> {
        let response: DeviceResponse =
            isomdl::cbor::from_slice(bytes).map_err(|_| InvalidBinding)?;
        if response.version != DeviceResponse::VERSION || !matches!(response.status, Status::OK) {
            return Err(InvalidBinding);
        }
        let documents = response.documents.as_ref().ok_or(InvalidBinding)?;
        if documents.len() != 1 || documents[0].doc_type != document_type {
            return Err(InvalidBinding);
        }
        let binding = from_issuer_signed(&documents[0].issuer_signed)?;
        if binding.certificate_sha256 != certificate_sha256 {
            return Err(InvalidBinding);
        }
        Ok(binding)
    }
}

impl fmt::Display for MdocStatusReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{PREFIX}{}:{}",
            self.certificate_sha256, self.signed_mso_sha256
        )
    }
}

fn sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn from_issuer_signed(signed: &IssuerSigned) -> Result<MdocStatusReference, InvalidBinding> {
    let auth = &signed.issuer_auth;
    let protected = auth
        .protected
        .original_data
        .as_deref()
        .ok_or(InvalidBinding)?;
    let payload = auth
        .payload
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or(InvalidBinding)?;
    if protected.is_empty() || auth.signature.is_empty() || auth.protected.header.alg.is_none() {
        return Err(InvalidBinding);
    }
    let chains = auth
        .protected
        .header
        .rest
        .iter()
        .chain(auth.unprotected.rest.iter())
        .filter(|(label, _)| label == &Label::Int(X5CHAIN_COSE_HEADER_LABEL))
        .map(|(_, value)| value)
        .collect::<Vec<_>>();
    if chains.len() != 1 {
        return Err(InvalidBinding);
    }
    let chain = X5Chain::from_cbor((*chains[0]).clone()).map_err(|_| InvalidBinding)?;
    let first = match chain.into_cbor() {
        coset::cbor::value::Value::Bytes(value) => value,
        coset::cbor::value::Value::Array(values) => match values.into_iter().next() {
            Some(coset::cbor::value::Value::Bytes(value)) => value,
            _ => return Err(InvalidBinding),
        },
        _ => return Err(InvalidBinding),
    };
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    for bytes in [protected, payload] {
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    // The MSO and protected header are signature-authenticated. Do not include
    // the ECDSA signature bytes: alternate valid signature encodings must not
    // create a new credential identity. Disclosure maps are deliberately absent.
    Ok(MdocStatusReference {
        certificate_sha256: hex::encode(Sha256::digest(first)),
        signed_mso_sha256: hex::encode(hash.finalize()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use coset::{cbor::value::Value, iana, CoseSign1Builder, HeaderBuilder};
    use isomdl::{
        cose::MaybeTagged,
        definitions::{
            device_response::{Document, Documents},
            device_signed::{DeviceAuth, DeviceSigned},
            helpers::{NonEmptyMap, NonEmptyVec, Tag24},
            issuer_signed::IssuerSignedItem,
        },
    };
    use std::collections::BTreeMap;

    // Identification controls only: signatures are deliberately not valid.
    // The service must establish complete Core authentication before lookup.
    fn signed() -> IssuerSigned {
        let pem = include_str!(
            "../../../services/signing-keys/tests/fixtures/public_certificates/root-ca.pem"
        );
        let der = certificate_der(pem);
        let auth = CoseSign1Builder::new()
            .protected(
                HeaderBuilder::new()
                    .algorithm(iana::Algorithm::ES256)
                    .build(),
            )
            .unprotected(
                HeaderBuilder::new()
                    .value(X5CHAIN_COSE_HEADER_LABEL, Value::Bytes(der))
                    .build(),
            )
            .payload(vec![0xd8, 0x18, 0x41, 0xa0])
            .signature(vec![1; 64])
            .build();
        let raw = IssuerSigned {
            namespaces: None,
            issuer_auth: MaybeTagged::new(false, auth),
        };
        // Deserialization preserves the exact signature-authenticated header bytes.
        isomdl::cbor::from_slice(&isomdl::cbor::to_vec(&raw).unwrap()).unwrap()
    }
    fn certificate_der(pem: &str) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(
                pem.lines()
                    .filter(|line| !line.starts_with("---"))
                    .collect::<String>(),
            )
            .unwrap()
    }
    fn reference(signed: &IssuerSigned) -> MdocStatusReference {
        MdocStatusReference::from_issuer_signed_base64(
            &URL_SAFE_NO_PAD.encode(isomdl::cbor::to_vec(signed).unwrap()),
        )
        .unwrap()
    }
    fn response(signed: IssuerSigned) -> DeviceResponse {
        DeviceResponse {
            version: DeviceResponse::VERSION.into(),
            status: Status::OK,
            document_errors: None,
            documents: Some(Documents::new(Document {
                doc_type: "org.iso.18013.5.1.mDL".into(),
                issuer_signed: signed,
                device_signed: DeviceSigned {
                    namespaces: Tag24::new(BTreeMap::new()).unwrap(),
                    device_auth: DeviceAuth::DeviceSignature(MaybeTagged::new(
                        false,
                        CoseSign1Builder::new().signature(vec![2; 64]).build(),
                    )),
                },
                errors: None,
            })),
        }
    }

    #[test]
    fn issuer_and_presentation_references_survive_selective_disclosure_and_cose_tagging() {
        let mut full = signed();
        full.namespaces = Some(NonEmptyMap::new(
            "org.iso.18013.5.1".into(),
            NonEmptyVec::new(
                Tag24::new(IssuerSignedItem {
                    digest_id: isomdl::definitions::mso::DigestId::new(0),
                    random: vec![7; 32].into(),
                    element_identifier: "age_over_21".into(),
                    element_value: Value::Bool(true),
                })
                .unwrap(),
            ),
        ));
        let expected = reference(&full);
        let mut selective = full.clone();
        selective.namespaces = None;
        selective.issuer_auth.tagged = true;
        assert_eq!(reference(&selective), expected);
        let bytes = isomdl::cbor::to_vec(&response(selective)).unwrap();
        assert_eq!(
            MdocStatusReference::from_authenticated_presentation(
                &bytes,
                "org.iso.18013.5.1.mDL",
                &expected.certificate_sha256
            )
            .unwrap(),
            expected
        );
    }
    #[test]
    fn authenticated_payload_header_and_certificate_bind_the_reference_but_signature_encoding_does_not(
    ) {
        let original = signed();
        let expected = reference(&original);
        let mut changed = original.clone();
        changed.issuer_auth.payload = Some(vec![9]);
        assert_ne!(reference(&changed), expected);
        let mut changed = original.clone();
        changed.issuer_auth.protected.original_data = Some(vec![0xa1, 1, 0x27]);
        assert_ne!(reference(&changed), expected);
        let mut changed = original;
        changed.issuer_auth.signature = vec![3; 64];
        assert_eq!(reference(&changed), expected);
        let mut alternate_certificate = changed;
        alternate_certificate.issuer_auth.unprotected.rest[0].1 = Value::Bytes(certificate_der(
            include_str!("../../../services/signing-keys/tests/fixtures/public_certificates/intermediate-ca.pem")
        ));
        let other = reference(&alternate_certificate);
        assert_eq!(other.signed_mso_sha256, expected.signed_mso_sha256);
        assert_ne!(other.issuer_id(), expected.issuer_id());
        assert_ne!(other, expected);
    }
    #[test]
    fn unbound_malformed_and_multiple_document_inputs_are_rejected() {
        let original = signed();
        let expected = reference(&original);
        for modify in [0, 1, 2] {
            let mut changed = original.clone();
            match modify {
                0 => changed.issuer_auth.payload = None,
                1 => changed.issuer_auth.signature.clear(),
                _ => {
                    let duplicate = changed.issuer_auth.unprotected.rest[0].clone();
                    changed.issuer_auth.unprotected.rest.push(duplicate);
                }
            }
            assert!(from_issuer_signed(&changed).is_err());
        }
        let mut multi = response(original);
        let second = multi.documents.as_ref().unwrap()[0].clone();
        multi.documents.as_mut().unwrap().push(second);
        let bytes = isomdl::cbor::to_vec(&multi).unwrap();
        assert!(MdocStatusReference::from_authenticated_presentation(
            &bytes,
            "org.iso.18013.5.1.mDL",
            &expected.certificate_sha256
        )
        .is_err());
        let bytes = isomdl::cbor::to_vec(&response(signed())).unwrap();
        assert!(MdocStatusReference::from_authenticated_presentation(
            &bytes,
            "other",
            &expected.certificate_sha256
        )
        .is_err());
        assert!(MdocStatusReference::from_authenticated_presentation(
            &bytes,
            "org.iso.18013.5.1.mDL",
            &"a".repeat(64)
        )
        .is_err());
        for value in ["", "e30", "invalid/credential"] {
            assert!(MdocStatusReference::from_issuer_signed_base64(value).is_err());
        }
    }
    #[test]
    fn references_are_canonical_versioned_values_not_urls_or_arbitrary_ids() {
        let value = reference(&signed()).to_string();
        assert_eq!(
            MdocStatusReference::parse(&value).unwrap().to_string(),
            value
        );
        for malformed in [
            "urn:uuid:owned".into(),
            value.to_uppercase(),
            value.replace(":v1:", ":v2:"),
            format!("{value}:extra"),
            format!("{PREFIX}{}:{}", "a".repeat(63), "b".repeat(64)),
            format!("https://status.invalid/{value}"),
        ] {
            assert!(MdocStatusReference::parse(&malformed).is_err());
        }
    }
}
