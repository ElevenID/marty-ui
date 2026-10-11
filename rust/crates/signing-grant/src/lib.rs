//! Canonical, short-lived authorization claims for remote issuer signing.
//!
//! The byte string returned by [`bound_input`] is authenticated with an
//! OpenBao Transit HMAC. This crate neither stores nor computes a secret key.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub mod replay;
pub mod transit;

const DOMAIN: &[u8] = b"marty:issuer-signing-grant:v1\n";
const MAX_LIFETIME_SECONDS: i64 = 60;
const MAX_FUTURE_SKEW_SECONDS: i64 = 5;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningOrigin {
    GatewayService,
    GatewayIssuerDid,
    FlowWalletRequest,
    IssuanceCredential,
    IssuanceCanvas,
    IssuancePassport,
}

impl SigningOrigin {
    pub const fn transit_key_name(self) -> &'static str {
        match self {
            Self::GatewayService => "marty-sign-grant-gateway-service-v1",
            Self::GatewayIssuerDid => "marty-sign-grant-gateway-issuer-did-v1",
            Self::FlowWalletRequest => "marty-sign-grant-flow-wallet-v1",
            Self::IssuanceCredential => "marty-sign-grant-issuance-credential-v1",
            Self::IssuanceCanvas => "marty-sign-grant-issuance-canvas-v1",
            Self::IssuancePassport => "marty-sign-grant-issuance-passport-v1",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GrantClaims {
    pub version: u8,
    pub origin: SigningOrigin,
    pub operation_id: String,
    pub organization_id: String,
    pub route: String,
    pub service_id: Option<String>,
    pub issuer_did: Option<String>,
    pub key_reference: Option<String>,
    pub key_purpose: String,
    pub algorithm: String,
    pub payload_sha256_b64: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub nonce: String,
}

/// Values derived from the authorized operation and exact request received by
/// Signing Keys. A caller's query string is not an authority source.
pub struct GrantBinding<'a> {
    pub origin: SigningOrigin,
    pub operation_id: &'a str,
    pub organization_id: &'a str,
    pub route: &'a str,
    pub service_id: Option<&'a str>,
    pub issuer_did: Option<&'a str>,
    pub key_reference: Option<&'a str>,
    pub key_purpose: &'a str,
    pub algorithm: &'a str,
    pub payload: &'a [u8],
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum GrantError {
    #[error("signing grant is malformed")]
    Malformed,
    #[error("signing grant has expired or exceeds its lifetime")]
    Expired,
    #[error("signing grant does not bind this signing operation")]
    BindingMismatch,
    #[error("signing grant authentication failed")]
    InvalidHmac,
    #[error("signing grant verifier is unavailable")]
    VerifierUnavailable,
}

/// A bound grant authenticated by OpenBao. Only this crate can construct it;
/// callers must atomically consume it before any issuer KMS signing call.
pub struct VerifiedGrant {
    nonce: String,
    expires_at: i64,
}

impl VerifiedGrant {
    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }
}

pub async fn verify_bound(
    client: &transit::TransitGrantClient,
    verify_token: &str,
    claims: &GrantClaims,
    binding: &GrantBinding<'_>,
    hmac: &str,
) -> Result<VerifiedGrant, GrantError> {
    if client.origin() != claims.origin {
        return Err(GrantError::BindingMismatch);
    }
    let input = bound_input(claims, binding, chrono::Utc::now().timestamp())?;
    let valid = client
        .verify(verify_token, &input, hmac)
        .await
        .map_err(|_| GrantError::VerifierUnavailable)?;
    if !valid {
        return Err(GrantError::InvalidHmac);
    }
    Ok(VerifiedGrant {
        nonce: claims.nonce.clone(),
        expires_at: claims.expires_at,
    })
}

/// Return the exact bytes to authenticate or verify through Transit HMAC.
/// This deliberately does not generate or verify a local MAC.
pub fn bound_input(
    claims: &GrantClaims,
    binding: &GrantBinding<'_>,
    now_seconds: i64,
) -> Result<Vec<u8>, GrantError> {
    if claims.version != 1
        || !bounded(&claims.operation_id, 128)
        || !bounded(&claims.organization_id, 128)
        || !bounded(&claims.route, 256)
        || !claims.route.starts_with('/')
        || !bounded(&claims.key_purpose, 64)
        || !bounded(&claims.algorithm, 32)
        || !claims
            .service_id
            .as_deref()
            .is_none_or(|value| bounded(value, 128))
        || !claims
            .issuer_did
            .as_deref()
            .is_none_or(|value| bounded(value, 512))
        || !claims
            .key_reference
            .as_deref()
            .is_none_or(|value| bounded(value, 512))
        || claims.nonce.len() != 32
        || !claims
            .nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(GrantError::Malformed);
    }
    if claims.issued_at <= 0
        || claims.expires_at <= claims.issued_at
        || i128::from(claims.expires_at) - i128::from(claims.issued_at)
            > i128::from(MAX_LIFETIME_SECONDS)
        || now_seconds > claims.expires_at
        || i128::from(claims.issued_at) - i128::from(now_seconds)
            > i128::from(MAX_FUTURE_SKEW_SECONDS)
    {
        return Err(GrantError::Expired);
    }
    if claims.origin != binding.origin
        || claims.operation_id != binding.operation_id
        || claims.organization_id != binding.organization_id
        || claims.route != binding.route
        || claims.service_id.as_deref() != binding.service_id
        || claims.issuer_did.as_deref() != binding.issuer_did
        || claims.key_reference.as_deref() != binding.key_reference
        || claims.key_purpose != binding.key_purpose
        || claims.algorithm != binding.algorithm
        || claims.payload_sha256_b64 != payload_digest(binding.payload)
    {
        return Err(GrantError::BindingMismatch);
    }
    let encoded = serde_json::to_vec(claims).map_err(|_| GrantError::Malformed)?;
    let mut input = Vec::with_capacity(DOMAIN.len() + encoded.len());
    input.extend_from_slice(DOMAIN);
    input.extend_from_slice(&encoded);
    Ok(input)
}

pub fn payload_digest(payload: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(payload))
}

fn bounded(value: &str, max_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= max_bytes && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashSet;

    #[test]
    fn every_signing_origin_has_a_distinct_transit_key() {
        let origins = [
            SigningOrigin::GatewayService,
            SigningOrigin::GatewayIssuerDid,
            SigningOrigin::FlowWalletRequest,
            SigningOrigin::IssuanceCredential,
            SigningOrigin::IssuanceCanvas,
            SigningOrigin::IssuancePassport,
        ];
        let keys: HashSet<_> = origins
            .map(SigningOrigin::transit_key_name)
            .into_iter()
            .collect();
        assert_eq!(keys.len(), origins.len());
        assert!(keys.iter().all(|key| key.starts_with("marty-sign-grant-")));
    }

    fn sample_claims() -> GrantClaims {
        GrantClaims {
            version: 1,
            origin: SigningOrigin::GatewayService,
            operation_id: "gateway-request-1".into(),
            organization_id: "org-1".into(),
            route: "/v1/signing-keys/services/service-1/sign".into(),
            service_id: Some("service-1".into()),
            issuer_did: None,
            key_reference: Some("key-1".into()),
            key_purpose: "vc_jwt_issuer".into(),
            algorithm: "ES256".into(),
            payload_sha256_b64: payload_digest(b"exact.payload"),
            issued_at: 1_700_000_000,
            expires_at: 1_700_000_030,
            nonce: "0123456789abcdef0123456789abcdef".into(),
        }
    }

    fn binding<'a>(payload: &'a [u8]) -> GrantBinding<'a> {
        GrantBinding {
            origin: SigningOrigin::GatewayService,
            operation_id: "gateway-request-1",
            organization_id: "org-1",
            route: "/v1/signing-keys/services/service-1/sign",
            service_id: Some("service-1"),
            issuer_did: None,
            key_reference: Some("key-1"),
            key_purpose: "vc_jwt_issuer",
            algorithm: "ES256",
            payload,
        }
    }

    #[test]
    fn exact_operation_and_payload_produce_domain_separated_bytes() {
        let claims = sample_claims();
        let input = bound_input(&claims, &binding(b"exact.payload"), 1_700_000_001).unwrap();
        assert!(input.starts_with(DOMAIN));
        assert_eq!(
            serde_json::from_slice::<GrantClaims>(&input[DOMAIN.len()..]).unwrap(),
            claims
        );
        assert!(matches!(
            bound_input(&claims, &binding(b"changed.payload"), 1_700_000_001),
            Err(GrantError::BindingMismatch)
        ));
    }

    #[test]
    fn tenant_origin_scope_and_time_mismatches_fail_before_hmac() {
        let mut claims = sample_claims();
        claims.organization_id = "org-2".into();
        assert_eq!(
            bound_input(&claims, &binding(b"exact.payload"), 1_700_000_001),
            Err(GrantError::BindingMismatch)
        );
        claims = sample_claims();
        claims.origin = SigningOrigin::FlowWalletRequest;
        assert_eq!(
            bound_input(&claims, &binding(b"exact.payload"), 1_700_000_001),
            Err(GrantError::BindingMismatch)
        );
        claims = sample_claims();
        claims.key_reference = Some("other-key".into());
        assert_eq!(
            bound_input(&claims, &binding(b"exact.payload"), 1_700_000_001),
            Err(GrantError::BindingMismatch)
        );
        claims = sample_claims();
        claims.key_purpose = "mdoc_dsc".into();
        assert_eq!(
            bound_input(&claims, &binding(b"exact.payload"), 1_700_000_001),
            Err(GrantError::BindingMismatch)
        );
        claims = sample_claims();
        claims.expires_at = claims.issued_at + 61;
        assert_eq!(
            bound_input(&claims, &binding(b"exact.payload"), 1_700_000_001),
            Err(GrantError::Expired)
        );
        claims = sample_claims();
        assert_eq!(
            bound_input(&claims, &binding(b"exact.payload"), 1_700_000_031),
            Err(GrantError::Expired)
        );
        claims.nonce = "bad".into();
        assert_eq!(
            bound_input(&claims, &binding(b"exact.payload"), 1_700_000_001),
            Err(GrantError::Malformed)
        );
        claims = sample_claims();
        assert_eq!(
            bound_input(&claims, &binding(b"exact.payload"), i64::MIN),
            Err(GrantError::Expired)
        );
    }
}
