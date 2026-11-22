//! Typed SHA-256 fingerprints. Representation conversion never re-hashes.

use std::{collections::BTreeMap, fmt};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::{
    model, strict_json, BindingError, ErrorKind, HashBasis, KeyAlgorithm, ThumbprintEncoding,
};

#[derive(Clone, PartialEq, Eq)]
pub struct TypedThumbprint {
    basis: HashBasis,
    encoding: ThumbprintEncoding,
    digest: [u8; 32],
}

impl fmt::Debug for TypedThumbprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TypedThumbprint")
            .field("basis", &self.basis)
            .field("encoding", &self.encoding)
            .finish_non_exhaustive()
    }
}

pub(crate) fn decode_b64(value: &str, field: &'static str) -> Result<[u8; 32], BindingError> {
    let fail = || BindingError::new(ErrorKind::NonCanonicalEncoding, field);
    if value.len() != 43
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(fail());
    }
    let decoded = URL_SAFE_NO_PAD.decode(value).map_err(|_| fail())?;
    if URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(fail());
    }
    decoded.try_into().map_err(|_| fail())
}

fn hex(digest: &[u8; 32]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(71);
    output.push_str("sha256:");
    for byte in digest {
        output.push(ALPHABET[usize::from(byte >> 4)] as char);
        output.push(ALPHABET[usize::from(byte & 15)] as char);
    }
    output
}

impl TypedThumbprint {
    pub(crate) fn from_document(document: &model::Thumbprint) -> Result<Self, BindingError> {
        let fail = || BindingError::new(ErrorKind::NonCanonicalEncoding, "thumbprint.value");
        let digest = match document.encoding {
            ThumbprintEncoding::Base64urlSha256 => decode_b64(&document.value, "thumbprint.value")?,
            ThumbprintEncoding::MipSha256Base64url => {
                let value = document.value.strip_prefix("sha256:").ok_or_else(fail)?;
                decode_b64(value, "thumbprint.value")?
            }
            ThumbprintEncoding::MipSha256Hex => {
                let value = document.value.strip_prefix("sha256:").ok_or_else(fail)?;
                if value.len() != 64
                    || !value
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err(fail());
                }
                let mut digest = [0; 32];
                for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
                    let nibble = |b| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
                    digest[index] = (nibble(pair[0]) << 4) | nibble(pair[1]);
                }
                digest
            }
        };
        Ok(Self {
            basis: document.basis,
            encoding: document.encoding,
            digest,
        })
    }

    pub const fn basis(&self) -> HashBasis {
        self.basis
    }
    pub const fn encoding(&self) -> ThumbprintEncoding {
        self.encoding
    }
    pub fn digest_bytes(&self) -> &[u8; 32] {
        &self.digest
    }
    /// Equality of basis and digest, independent of representation.
    pub fn same_binding(&self, other: &Self) -> bool {
        self.basis == other.basis && self.digest == other.digest
    }
    /// Re-encoding never changes the hash basis.
    pub fn reencode(&self, encoding: ThumbprintEncoding) -> Self {
        Self {
            basis: self.basis,
            encoding,
            digest: self.digest,
        }
    }
    pub fn encoded_value(&self) -> String {
        match self.encoding {
            ThumbprintEncoding::Base64urlSha256 => URL_SAFE_NO_PAD.encode(self.digest),
            ThumbprintEncoding::MipSha256Base64url => {
                format!("sha256:{}", URL_SAFE_NO_PAD.encode(self.digest))
            }
            ThumbprintEncoding::MipSha256Hex => hex(&self.digest),
        }
    }
    /// Existing DelegationGrant KEY binding uses RFC 7638, never full DER hash.
    pub fn delegation_key_thumbprint(&self) -> Result<String, BindingError> {
        if self.basis != HashBasis::JwkRfc7638Sha256 {
            return Err(BindingError::new(
                ErrorKind::WrongHashBasis,
                "thumbprint.basis",
            ));
        }
        Ok(hex(&self.digest))
    }
}

/// Convert a verified RFC 7638 SHA-256 `jkt`, preserving its 32 digest bytes.
/// The caller must independently establish the JWK hash basis. Do not pass a
/// generic MachineIdentity string or full-certificate fingerprint here.
pub fn jwk_thumbprint_to_digest(jkt: &str) -> Result<String, BindingError> {
    Ok(hex(&decode_b64(jkt, "dpop_jkt")?))
}

/// Bounded public P-256/Ed25519 JWK fingerprinting, not proof verification.
/// Metadata is checked but excluded from the RFC 7638 canonical projection.
pub fn jwk_sha256_thumbprint(raw: &[u8]) -> Result<TypedThumbprint, BindingError> {
    let object = strict_json::object(raw)?;
    let (_, thumbprint) = public_jwk(object.as_object().expect("strict object"))?;
    Ok(thumbprint)
}

pub(crate) fn public_jwk(
    jwk: &Map<String, Value>,
) -> Result<(KeyAlgorithm, TypedThumbprint), BindingError> {
    let fail = |kind| BindingError::new(kind, "jwk");
    if ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
        .iter()
        .any(|field| jwk.contains_key(*field))
    {
        return Err(fail(ErrorKind::PrivateKeyMaterial));
    }
    let text = |field: &str| jwk.get(field).and_then(Value::as_str);
    let (algorithm, required): (KeyAlgorithm, &[&str]) = match (text("kty"), text("crv")) {
        (Some("EC"), Some("P-256")) => (KeyAlgorithm::ES256, &["crv", "kty", "x", "y"]),
        (Some("OKP"), Some("Ed25519")) => (KeyAlgorithm::Ed25519, &["crv", "kty", "x"]),
        _ => return Err(fail(ErrorKind::UnsupportedPublicKey)),
    };
    if jwk.keys().any(|field| {
        !required.contains(&field.as_str())
            && !["kid", "alg", "use", "key_ops"].contains(&field.as_str())
    }) || required.iter().any(|field| text(field).is_none())
    {
        return Err(fail(ErrorKind::InvalidPublicKey));
    }
    for (field, valid) in [
        (
            "alg",
            text("alg").is_some_and(|value| algorithm.compatible_with(value)),
        ),
        ("use", text("use") == Some("sig")),
        (
            "kid",
            text("kid").is_some_and(|value| (1..=512).contains(&value.chars().count())),
        ),
        (
            "key_ops",
            jwk.get("key_ops") == Some(&serde_json::json!(["verify"])),
        ),
    ] {
        if jwk.contains_key(field) && !valid {
            return Err(BindingError::new(
                ErrorKind::InvalidPublicKeyMetadata,
                match field {
                    "alg" => "jwk.alg",
                    "use" => "jwk.use",
                    "kid" => "jwk.kid",
                    _ => "jwk.key_ops",
                },
            ));
        }
    }
    let x = decode_b64(text("x").expect("required public coordinate"), "jwk.x")?;
    if algorithm == KeyAlgorithm::ES256 {
        let y = decode_b64(text("y").expect("required public coordinate"), "jwk.y")?;
        let mut sec1 = [0; 65];
        sec1[0] = 4;
        sec1[1..33].copy_from_slice(&x);
        sec1[33..].copy_from_slice(&y);
        p256::PublicKey::from_sec1_bytes(&sec1).map_err(|_| fail(ErrorKind::InvalidPublicKey))?;
    }
    let projection: BTreeMap<&str, &str> = required
        .iter()
        .map(|field| (*field, text(field).expect("checked required member")))
        .collect();
    // Required members are ASCII strings for the two supported key families.
    let canonical =
        serde_json::to_vec(&projection).map_err(|_| fail(ErrorKind::InvalidPublicKey))?;
    Ok((
        algorithm,
        TypedThumbprint {
            basis: HashBasis::JwkRfc7638Sha256,
            encoding: ThumbprintEncoding::Base64urlSha256,
            digest: Sha256::digest(canonical).into(),
        },
    ))
}
