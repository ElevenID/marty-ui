use std::collections::BTreeMap;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use marty_oid4vci::jose::verify_compact_jwt_with_public_jwk;
use mmf_security::constant_time_secret_eq;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::token_exchange::{DpopProofVerifier, TokenExchangeError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundDpopError {
    Required,
    Invalid,
    Mismatch,
}

pub fn verify_bound_dpop(
    verifier: &dyn DpopProofVerifier,
    expected_jkt: Option<&str>,
    proof: Option<&str>,
    method: &str,
    expected_htu: &str,
) -> Result<(), BoundDpopError> {
    let Some(expected_jkt) = expected_jkt.filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    let proof = proof.ok_or(BoundDpopError::Required)?;
    let actual = verifier
        .verify(proof, method, expected_htu)
        .map_err(|_| BoundDpopError::Invalid)?;
    if !constant_time_secret_eq(expected_jkt.as_bytes(), actual.as_bytes()) {
        return Err(BoundDpopError::Mismatch);
    }
    Ok(())
}

#[derive(Clone, Debug, Default)]
pub struct MartyDpopProofVerifier;

impl DpopProofVerifier for MartyDpopProofVerifier {
    fn verify(
        &self,
        proof: &str,
        method: &str,
        expected_htu: &str,
    ) -> Result<String, TokenExchangeError> {
        verify_dpop(proof, method, expected_htu)
    }
}

fn verify_dpop(
    proof: &str,
    method: &str,
    expected_htu: &str,
) -> Result<String, TokenExchangeError> {
    let encoded_header = proof
        .split('.')
        .next()
        .filter(|_| proof.split('.').count() == 3)
        .ok_or(TokenExchangeError::InvalidDpopProof)?;
    let header: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(encoded_header)
            .map_err(|_| TokenExchangeError::InvalidDpopProof)?,
    )
    .map_err(|_| TokenExchangeError::InvalidDpopProof)?;
    let algorithm = header
        .get("alg")
        .and_then(Value::as_str)
        .filter(|algorithm| matches!(*algorithm, "ES256" | "PS256"))
        .ok_or(TokenExchangeError::InvalidDpopProof)?;
    let jwk = header
        .get("jwk")
        .and_then(Value::as_object)
        .ok_or(TokenExchangeError::InvalidDpopProof)?;
    match algorithm {
        "ES256"
            if jwk.get("kty").and_then(Value::as_str) == Some("EC")
                && jwk.get("crv").and_then(Value::as_str) == Some("P-256") => {}
        "PS256" if jwk.get("kty").and_then(Value::as_str) == Some("RSA") => {}
        _ => return Err(TokenExchangeError::InvalidDpopProof),
    }
    let jwk_json = serde_json::to_string(jwk).map_err(|_| TokenExchangeError::InvalidDpopProof)?;
    let verified = verify_compact_jwt_with_public_jwk(proof, &jwk_json, algorithm)
        .map_err(|_| TokenExchangeError::InvalidDpopProof)?;
    if verified.header.get("jwk") != header.get("jwk")
        || verified.header.get("typ").and_then(Value::as_str) != Some("dpop+jwt")
        || verified.header.get("alg").and_then(Value::as_str) != Some(algorithm)
        || verified
            .claims
            .get("htm")
            .and_then(Value::as_str)
            .is_none_or(|value| !value.eq_ignore_ascii_case(method))
        || verified
            .claims
            .get("htu")
            .and_then(Value::as_str)
            .is_none_or(|value| value.trim_end_matches('/') != expected_htu.trim_end_matches('/'))
    {
        return Err(TokenExchangeError::InvalidDpopProof);
    }
    thumbprint(jwk)
}

fn thumbprint(jwk: &serde_json::Map<String, Value>) -> Result<String, TokenExchangeError> {
    let fields: &[&str] = match jwk.get("kty").and_then(Value::as_str) {
        Some("EC") => &["crv", "kty", "x", "y"],
        Some("OKP") => &["crv", "kty", "x"],
        Some("RSA") => &["e", "kty", "n"],
        _ => return Err(TokenExchangeError::InvalidDpopProof),
    };
    let canonical = fields
        .iter()
        .map(|field| {
            jwk.get(*field)
                .and_then(Value::as_str)
                .map(|value| ((*field).to_owned(), value.to_owned()))
                .ok_or(TokenExchangeError::InvalidDpopProof)
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let canonical =
        serde_json::to_vec(&canonical).map_err(|_| TokenExchangeError::InvalidDpopProof)?;
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(canonical)))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{thumbprint, verify_dpop};
    use crate::token_exchange::TokenExchangeError;

    fn public_proof_vector(algorithm: &str) -> serde_json::Value {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/dpop_public_proofs.json"))
                .expect("public signed DPoP proof vectors");
        vectors[algorithm].clone()
    }

    #[test]
    fn thumbprint_uses_only_rfc_7638_public_members() {
        let value = json!({
            "kty": "EC", "crv": "P-256", "x": "x-value", "y": "y-value",
            "kid": "ignored", "alg": "ES256"
        });
        let thumbprint = thumbprint(value.as_object().unwrap()).expect("thumbprint");
        assert_eq!(thumbprint, "pYVZv_YyMPqcss69GIei65J2mO3sXU8eTZW1zakm5o0");
    }

    #[test]
    fn es256_proof_requires_its_embedded_key_method_and_endpoint() {
        let vector = public_proof_vector("es256");
        let proof = vector["proof"].as_str().expect("signed public DPoP proof");
        let jwk = &vector["jwk"];
        assert_eq!(
            verify_dpop(proof, "POST", "https://issuer.example/v1/issuance/token"),
            thumbprint(jwk.as_object().unwrap())
        );
        assert_eq!(
            verify_dpop(proof, "GET", "https://issuer.example/v1/issuance/token"),
            Err(TokenExchangeError::InvalidDpopProof)
        );
        assert_eq!(
            verify_dpop(
                proof,
                "POST",
                "https://issuer.example/v1/issuance/credential"
            ),
            Err(TokenExchangeError::InvalidDpopProof)
        );
    }

    #[test]
    fn ps256_proof_supports_the_oidf_conformance_key_shape() {
        let vector = public_proof_vector("ps256");
        let proof = vector["proof"]
            .as_str()
            .expect("signed public RSA DPoP proof");
        let jwk = &vector["jwk"];

        assert_eq!(
            verify_dpop(proof, "POST", "https://issuer.example/v1/issuance/token"),
            thumbprint(jwk.as_object().expect("public JWK"))
        );
    }
}
