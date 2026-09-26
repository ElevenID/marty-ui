//! Public PKCS#10 construction for issuer identities whose private keys remain
//! inside the configured KMS. This module never creates or accepts key material.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use const_oid::ObjectIdentifier;
use der::{
    asn1::{Any, BitString},
    pem::LineEnding,
    Encode, EncodePem,
};
use serde_json::Value;
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use std::str::FromStr;
use thiserror::Error;
use x509_cert::{
    name::Name,
    request::{CertReq, CertReqInfo, Version},
};

const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const P521: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");
const ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const ECDSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");

#[derive(Debug, Error)]
pub enum CsrError {
    #[error("CSR subject must contain a two-letter country and bounded C, O, CN text")]
    InvalidSubject,
    #[error("CSR public key is not a matching managed ECDSA key")]
    InvalidPublicKey,
    #[error("CSR signature does not verify with the current managed public key")]
    InvalidSignature,
    #[error("CSR encoding failed")]
    Encoding,
}

pub struct CsrSubject<'a> {
    pub country: &'a str,
    pub organization: &'a str,
    pub common_name: &'a str,
}

pub struct PreparedCsr {
    info: CertReqInfo,
    info_der: Vec<u8>,
    spki_der: Vec<u8>,
    signature_oid: ObjectIdentifier,
    algorithm: &'static str,
}

impl PreparedCsr {
    pub fn signing_bytes(&self) -> &[u8] {
        &self.info_der
    }

    pub fn finish(self, signature_der: &[u8]) -> Result<String, CsrError> {
        let valid = match self.algorithm {
            "ES256" => marty_crypto::ecdsa::verify_p256_sha256(
                &self.spki_der,
                &self.info_der,
                signature_der,
            ),
            "ES384" => marty_crypto::ecdsa::verify_p384_sha384(
                &self.spki_der,
                &self.info_der,
                signature_der,
            ),
            "ES512" => marty_crypto::ecdsa::verify_p521_sha512(
                &self.spki_der,
                &self.info_der,
                signature_der,
            ),
            _ => return Err(CsrError::InvalidPublicKey),
        }
        .map_err(|_| CsrError::InvalidSignature)?;
        if !valid {
            return Err(CsrError::InvalidSignature);
        }
        CertReq {
            info: self.info,
            algorithm: AlgorithmIdentifierOwned {
                oid: self.signature_oid,
                parameters: None,
            },
            signature: BitString::from_bytes(signature_der).map_err(|_| CsrError::Encoding)?,
        }
        .to_pem(LineEnding::LF)
        .map_err(|_| CsrError::Encoding)
    }
}

pub fn prepare(
    public_jwk: &Value,
    algorithm: &str,
    subject: &CsrSubject<'_>,
) -> Result<PreparedCsr, CsrError> {
    if subject.country.len() != 2
        || !subject
            .country
            .bytes()
            .all(|byte| byte.is_ascii_uppercase())
        || !valid_component(subject.organization)
        || !valid_component(subject.common_name)
    {
        return Err(CsrError::InvalidSubject);
    }
    let (curve, signature_oid, coordinate_len, curve_name) = match algorithm {
        "ES256" => (P256, ECDSA_SHA256, 32, "P-256"),
        "ES384" => (P384, ECDSA_SHA384, 48, "P-384"),
        "ES512" => (P521, ECDSA_SHA512, 66, "P-521"),
        _ => return Err(CsrError::InvalidPublicKey),
    };
    if public_jwk.get("kty").and_then(Value::as_str) != Some("EC")
        || public_jwk.get("crv").and_then(Value::as_str) != Some(curve_name)
    {
        return Err(CsrError::InvalidPublicKey);
    }
    let coordinate = |field| {
        public_jwk
            .get(field)
            .and_then(Value::as_str)
            .and_then(|encoded| URL_SAFE_NO_PAD.decode(encoded).ok())
            .filter(|bytes| bytes.len() == coordinate_len)
            .ok_or(CsrError::InvalidPublicKey)
    };
    let mut point = Vec::with_capacity(1 + 2 * coordinate_len);
    point.push(0x04);
    point.extend(coordinate("x")?);
    point.extend(coordinate("y")?);
    let public_key = SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid: EC_PUBLIC_KEY,
            parameters: Some(Any::encode_from(&curve).map_err(|_| CsrError::Encoding)?),
        },
        subject_public_key: BitString::from_bytes(&point).map_err(|_| CsrError::Encoding)?,
    };
    let spki_der = public_key.to_der().map_err(|_| CsrError::Encoding)?;
    let name = Name::from_str(&format!(
        "C={},O={},CN={}",
        subject.country, subject.organization, subject.common_name
    ))
    .map_err(|_| CsrError::InvalidSubject)?;
    let info = CertReqInfo {
        version: Version::V1,
        subject: name,
        public_key,
        attributes: Default::default(),
    };
    let info_der = info.to_der().map_err(|_| CsrError::Encoding)?;
    Ok(PreparedCsr {
        info,
        info_der,
        spki_der,
        signature_oid,
        algorithm: match algorithm {
            "ES256" => "ES256",
            "ES384" => "ES384",
            _ => "ES512",
        },
    })
}

fn valid_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b" -._".contains(&byte))
        && value.trim() == value
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn subject<'a>() -> CsrSubject<'a> {
        CsrSubject {
            country: "US",
            organization: "ElevenID Beta",
            common_name: "Pilot CSCA",
        }
    }

    #[test]
    fn behavior_contract_requires_kms_custody_and_public_projection() {
        let behavior: Value = serde_json::from_str(include_str!(
            "../../../../contracts/passport-certificate-csr-behavior.json"
        ))
        .unwrap();
        assert_eq!(behavior["schema_version"], 1);
        assert_eq!(behavior["custody"]["private_key_export"], false);
        assert_eq!(
            behavior["custody"]["verify_signature_before_returning_csr"],
            true
        );
        assert_eq!(
            behavior["public_route"]["response_fields"],
            json!(["csr_pem", "issuer_did", "subject"])
        );
    }

    #[test]
    fn rejects_subject_injection_wrong_curve_and_bad_coordinates() {
        let jwk = json!({"kty":"EC", "crv":"P-256", "x": URL_SAFE_NO_PAD.encode([0u8;32]), "y": URL_SAFE_NO_PAD.encode([0u8;32])});
        assert!(prepare(&jwk, "ES256", &subject()).is_ok());
        assert!(prepare(&jwk, "ES384", &subject()).is_err());
        assert!(prepare(
            &json!({"kty":"EC", "crv":"P-256", "x":"bad", "y":"bad"}),
            "ES256",
            &subject()
        )
        .is_err());
        assert!(prepare(
            &jwk,
            "ES256",
            &CsrSubject {
                country: "US",
                organization: "ElevenID,Bad",
                common_name: "Pilot"
            }
        )
        .is_err());
    }

    #[test]
    fn rejects_signature_not_bound_to_managed_public_key() {
        let jwk = json!({"kty":"EC", "crv":"P-256", "x": URL_SAFE_NO_PAD.encode([0u8;32]), "y": URL_SAFE_NO_PAD.encode([0u8;32])});
        let csr = prepare(&jwk, "ES256", &subject()).unwrap();
        assert!(!csr.signing_bytes().is_empty());
        assert!(csr.finish(&[0u8; 64]).is_err());
    }
}
