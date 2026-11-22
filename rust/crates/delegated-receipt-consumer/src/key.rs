use p256::ecdsa::{signature::Verifier, Signature};
use uuid::Uuid;

use crate::{strict, Algorithm, Principal, ReceiptVerificationError as Error, Result};

type VerifyingKey = ecdsa_core::VerifyingKey<p256::NistP256>;

/// A dedicated receipt verification key selected outside the receipt. It
/// carries no provider credentials, private material, or resolution mechanism.
#[derive(Clone)]
pub struct PinnedReceiptKey {
    pub(crate) organization_id: Uuid,
    pub(crate) issuer: Principal,
    pub(crate) algorithm: Algorithm,
    pub(crate) key_id: String,
    key: PublicKey,
}
#[derive(Clone)]
enum PublicKey {
    Es256(VerifyingKey),
    Ed25519(ed25519_dalek::VerifyingKey),
}
impl std::fmt::Debug for PinnedReceiptKey {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str("PinnedReceiptKey { <independent public trust> }")
    }
}
impl PinnedReceiptKey {
    pub fn new(
        organization_id: Uuid,
        issuer: Principal,
        algorithm: Algorithm,
        key_id: String,
        public_jwk: &[u8],
    ) -> Result<Self> {
        let value = strict::read(public_jwk, 4096).map_err(|_| Error::InvalidTrust)?;
        let map = value.as_object().ok_or(Error::InvalidTrust)?;
        let fields: &[&str] = match algorithm {
            Algorithm::Es256 => &["kty", "crv", "x", "y"],
            Algorithm::EdDsa => &["kty", "crv", "x"],
        };
        if organization_id.is_nil()
            || !bare_did(&issuer.id)
            || issuer.id.len() > 500
            || !strict::uri(&issuer.id)
            || key_id.len() > 512
            || !strict::uri(&key_id)
            || key_id
                .strip_prefix(&issuer.id)
                .is_none_or(|tail| !tail.starts_with('#') || tail.len() < 2)
            || map.len() != fields.len()
            || fields.iter().any(|name| !map.contains_key(*name))
        {
            return Err(Error::InvalidTrust);
        }
        let coordinate = |name: &str| -> Result<[u8; 32]> {
            strict::segment(value[name].as_str().ok_or(Error::InvalidTrust)?, 32)
                .map_err(|_| Error::InvalidTrust)?
                .try_into()
                .map_err(|_| Error::InvalidTrust)
        };
        let x = coordinate("x")?;
        let key = match algorithm {
            Algorithm::Es256 if value["kty"] == "EC" && value["crv"] == "P-256" => {
                let y = coordinate("y")?;
                let mut point = [0u8; 65];
                point[0] = 4;
                point[1..33].copy_from_slice(&x);
                point[33..].copy_from_slice(&y);
                PublicKey::Es256(
                    VerifyingKey::from_sec1_bytes(&point).map_err(|_| Error::InvalidTrust)?,
                )
            }
            Algorithm::EdDsa if value["kty"] == "OKP" && value["crv"] == "Ed25519" => {
                let key =
                    ed25519_dalek::VerifyingKey::from_bytes(&x).map_err(|_| Error::InvalidTrust)?;
                if key.is_weak() || key.to_edwards().compress().to_bytes() != x {
                    return Err(Error::InvalidTrust);
                }
                PublicKey::Ed25519(key)
            }
            _ => return Err(Error::InvalidTrust),
        };
        Ok(Self {
            organization_id,
            issuer,
            algorithm,
            key_id,
            key,
        })
    }

    pub(crate) fn verify(&self, signing_input: &[u8], signature: &[u8]) -> Result<()> {
        if signature.len() != 64 {
            return Err(Error::InvalidSignature);
        }
        match &self.key {
            PublicKey::Es256(key) => {
                let signature =
                    Signature::from_slice(signature).map_err(|_| Error::InvalidSignature)?;
                // ECDSA's equivalent high/low-S forms do not change the input
                // bytes or retained digest. Only a temporary verification value
                // is normalized; the original compact receipt is never rewritten.
                key.verify(signing_input, &signature.normalize_s())
                    .map_err(|_| Error::InvalidSignature)
            }
            PublicKey::Ed25519(key) => {
                let signature = ed25519_dalek::Signature::from_slice(signature)
                    .map_err(|_| Error::InvalidSignature)?;
                key.verify_strict(signing_input, &signature)
                    .map_err(|_| Error::InvalidSignature)
            }
        }
    }
}

fn bare_did(value: &str) -> bool {
    value
        .strip_prefix("did:")
        .and_then(|rest| rest.split_once(':'))
        .is_some_and(|(method, identifier)| {
            !method.is_empty()
                && method
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
                && !identifier.is_empty()
                && !identifier.ends_with(':')
                && identifier
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-:%".contains(&b))
        })
}
