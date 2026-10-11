//! Canonical, short-lived authorization claims for remote issuer signing.
//!
//! The byte string returned by [`bound_input`] is authenticated with an
//! OpenBao Transit HMAC. This crate neither stores nor computes a secret key.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub mod ceremony;
pub mod minter;
pub mod replay;
mod token_file;
pub mod transit;
pub mod verifier;

const DOMAIN: &[u8] = b"marty:issuer-signing-grant:v1\n";
const MAX_LIFETIME_SECONDS: i64 = 60;
const MAX_FUTURE_SKEW_SECONDS: i64 = 5;
const ISSUED_LIFETIME_SECONDS: i64 = 30;
const MAX_HEADER_BYTES: usize = 8192;
pub const HEADER_NAME: &str = "x-marty-signing-grant";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningOrigin {
    GatewayService,
    GatewayIssuerDid,
    FlowWalletRequest,
    IssuanceCredential,
    IssuanceCanvas,
    IssuanceReadiness,
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
            Self::IssuanceReadiness => "marty-sign-grant-issuance-readiness-v1",
            Self::IssuancePassport => "marty-sign-grant-issuance-passport-v1",
        }
    }

    fn authorizes_route_shape(self, claims: &GrantClaims) -> bool {
        match self {
            Self::GatewayService => claims
                .route
                .strip_prefix("/v1/signing-keys/services/")
                .and_then(|tail| {
                    tail.strip_suffix("/sign")
                        .map(|service_id| (service_id, false))
                        .or_else(|| {
                            tail.strip_suffix("/certificate-csr")
                                .map(|service_id| (service_id, true))
                        })
                })
                .is_some_and(|(service_id, csr)| {
                    !service_id.is_empty()
                        && !service_id.contains('/')
                        && claims.service_id.as_deref() == Some(service_id)
                        && claims.issuer_did.is_none()
                        && (!csr
                            || (claims.key_purpose == "x509_csr" && claims.key_reference.is_some()))
                }),
            Self::FlowWalletRequest => {
                issuer_did_route_shape(claims)
                    && claims.key_purpose == "oid4vp_request_signing"
                    && claims.algorithm == "ES256"
            }
            Self::GatewayIssuerDid => {
                claims.route == "/v1/signing-keys/issuer-identities/certificate-csr"
                    && claims.service_id.is_none()
                    && claims.key_reference.is_none()
                    && claims
                        .issuer_did
                        .as_deref()
                        .is_some_and(|did| did.starts_with("did:"))
                    && matches!(claims.key_purpose.as_str(), "csca" | "x509_doc_signer")
                    && matches!(claims.algorithm.as_str(), "ES256" | "ES384" | "ES512")
            }
            Self::IssuanceCredential => {
                issuer_did_route_shape(claims)
                    && matches!(claims.key_purpose.as_str(), "vc_jwt_issuer" | "mdoc_dsc")
            }
            Self::IssuanceCanvas => {
                issuer_did_route_shape(claims)
                    && claims.key_purpose == "lti_tool_signing"
                    && claims.algorithm == "RS256"
            }
            Self::IssuanceReadiness => {
                issuer_did_route_shape(claims)
                    && claims.key_purpose == "vc_jwt_issuer"
                    && matches!(
                        claims.algorithm.as_str(),
                        "ES256" | "ES384" | "RS256" | "EdDSA"
                    )
            }
            Self::IssuancePassport => {
                issuer_did_route_shape(claims)
                    && claims.key_purpose == "x509_doc_signer"
                    && matches!(
                        claims.algorithm.as_str(),
                        "ES256" | "ES384" | "RS256" | "EdDSA"
                    )
            }
        }
    }
}

fn issuer_did_route_shape(claims: &GrantClaims) -> bool {
    claims.route == "/internal/compat/issuer-dids/sign"
        && claims.service_id.is_none()
        && claims
            .key_reference
            .as_deref()
            .is_some_and(|reference| !reference.is_empty())
        && claims
            .issuer_did
            .as_deref()
            .is_some_and(|did| did.starts_with("did:"))
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GrantEnvelope {
    pub claims: GrantClaims,
    pub hmac: String,
}

impl GrantEnvelope {
    pub fn to_header_value(&self) -> Result<String, GrantError> {
        let bytes = serde_json::to_vec(self).map_err(|_| GrantError::Malformed)?;
        let value = URL_SAFE_NO_PAD.encode(bytes);
        if value.len() > MAX_HEADER_BYTES {
            return Err(GrantError::Malformed);
        }
        Ok(value)
    }

    pub fn from_header_value(value: &str) -> Result<Self, GrantError> {
        if value.is_empty()
            || value.len() > MAX_HEADER_BYTES
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(GrantError::Malformed);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| GrantError::Malformed)?;
        serde_json::from_slice(&bytes).map_err(|_| GrantError::Malformed)
    }
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
    #[error("signing grant minter is unavailable")]
    MinterUnavailable,
}

/// A bound grant authenticated by OpenBao. Only this crate can construct it;
/// callers must atomically consume it before any issuer KMS signing call.
pub struct VerifiedGrant {
    claims: GrantClaims,
}

impl VerifiedGrant {
    pub fn expires_at(&self) -> i64 {
        self.claims.expires_at
    }

    pub fn nonce(&self) -> &str {
        &self.claims.nonce
    }
}

/// Mint a grant only after the calling service has independently authorized
/// `binding` against its own operation record. The HMAC key stays in OpenBao.
pub async fn mint_bound(
    client: &transit::TransitGrantClient,
    mint_token: &str,
    binding: &GrantBinding<'_>,
) -> Result<GrantEnvelope, GrantError> {
    if client.origin() != binding.origin {
        return Err(GrantError::BindingMismatch);
    }
    let now = chrono::Utc::now().timestamp();
    let expires_at = now
        .checked_add(ISSUED_LIFETIME_SECONDS)
        .ok_or(GrantError::Expired)?;
    let claims = GrantClaims {
        version: 1,
        origin: binding.origin,
        operation_id: binding.operation_id.to_owned(),
        organization_id: binding.organization_id.to_owned(),
        route: binding.route.to_owned(),
        service_id: binding.service_id.map(str::to_owned),
        issuer_did: binding.issuer_did.map(str::to_owned),
        key_reference: binding.key_reference.map(str::to_owned),
        key_purpose: binding.key_purpose.to_owned(),
        algorithm: binding.algorithm.to_owned(),
        payload_sha256_b64: payload_digest(binding.payload),
        issued_at: now,
        expires_at,
        nonce: uuid::Uuid::new_v4().simple().to_string(),
    };
    let input = bound_input(&claims, binding, now)?;
    let hmac = client
        .mint(mint_token, &input)
        .await
        .map_err(|_| GrantError::MinterUnavailable)?;
    Ok(GrantEnvelope { claims, hmac })
}

pub async fn verify_envelope(
    client: &transit::TransitGrantClient,
    verify_token: &str,
    envelope: &GrantEnvelope,
    binding: &GrantBinding<'_>,
) -> Result<VerifiedGrant, GrantError> {
    verify_bound(
        client,
        verify_token,
        &envelope.claims,
        binding,
        &envelope.hmac,
    )
    .await
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
        claims: claims.clone(),
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
        || !claims.origin.authorizes_route_shape(claims)
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
            SigningOrigin::IssuanceReadiness,
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
    fn gateway_service_csr_grant_requires_the_csr_purpose_and_explicit_key() {
        let mut claims = sample_claims();
        claims.route = "/v1/signing-keys/services/service-1/certificate-csr".into();
        claims.key_purpose = "x509_csr".into();
        let binding = GrantBinding {
            route: &claims.route,
            key_purpose: "x509_csr",
            ..binding(b"exact.payload")
        };
        assert!(bound_input(&claims, &binding, 1_700_000_001).is_ok());
        claims.key_purpose = "vc_jwt_issuer".into();
        assert_eq!(
            bound_input(&claims, &binding, 1_700_000_001),
            Err(GrantError::Malformed)
        );
        claims.key_purpose = "x509_csr".into();
        claims.key_reference = None;
        assert_eq!(
            bound_input(&claims, &binding, 1_700_000_001),
            Err(GrantError::Malformed)
        );
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
            Err(GrantError::Malformed)
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

    #[test]
    fn origin_keys_cannot_authorize_a_different_signing_route() {
        for origin in [
            SigningOrigin::FlowWalletRequest,
            SigningOrigin::IssuanceCredential,
            SigningOrigin::IssuanceCanvas,
            SigningOrigin::IssuanceReadiness,
            SigningOrigin::IssuancePassport,
        ] {
            let mut claims = sample_claims();
            claims.origin = origin;
            claims.route = "/internal/compat/issuer-dids/sign".into();
            claims.service_id = None;
            claims.issuer_did = Some("did:web:issuer.example".into());
            match origin {
                SigningOrigin::FlowWalletRequest => {
                    claims.key_purpose = "oid4vp_request_signing".into();
                }
                SigningOrigin::IssuanceCanvas => {
                    claims.key_purpose = "lti_tool_signing".into();
                    claims.algorithm = "RS256".into();
                }
                SigningOrigin::IssuanceReadiness => {
                    claims.key_purpose = "vc_jwt_issuer".into();
                }
                SigningOrigin::IssuancePassport => {
                    claims.key_purpose = "x509_doc_signer".into();
                }
                SigningOrigin::IssuanceCredential => {}
                SigningOrigin::GatewayService => unreachable!("not an issuer-DID origin"),
                SigningOrigin::GatewayIssuerDid => unreachable!("CSR-only origin"),
            }
            let binding = GrantBinding {
                origin,
                operation_id: &claims.operation_id,
                organization_id: &claims.organization_id,
                route: "/internal/compat/issuer-dids/sign",
                service_id: None,
                issuer_did: Some("did:web:issuer.example"),
                key_reference: claims.key_reference.as_deref(),
                key_purpose: &claims.key_purpose,
                algorithm: &claims.algorithm,
                payload: b"exact.payload",
            };
            assert!(bound_input(&claims, &binding, 1_700_000_001).is_ok());
            let mut missing_key = claims.clone();
            missing_key.key_reference = None;
            assert_eq!(
                bound_input(&missing_key, &binding, 1_700_000_001),
                Err(GrantError::Malformed)
            );
            claims.route = "/v1/signing-keys/services/service-1/sign".into();
            assert_eq!(
                bound_input(&claims, &binding, 1_700_000_001),
                Err(GrantError::Malformed)
            );
            if origin == SigningOrigin::FlowWalletRequest {
                let mut elevated = claims.clone();
                elevated.route = "/internal/compat/issuer-dids/sign".into();
                elevated.key_purpose = "mdoc_dsc".into();
                assert_eq!(
                    bound_input(&elevated, &binding, 1_700_000_001),
                    Err(GrantError::Malformed)
                );
            }
        }
        let mut claims = sample_claims();
        claims.service_id = Some("different-service".into());
        assert_eq!(
            bound_input(&claims, &binding(b"exact.payload"), 1_700_000_001),
            Err(GrantError::Malformed)
        );
    }

    #[test]
    fn gateway_issuer_csr_token_cannot_authorize_ordinary_issuer_signing() {
        let mut claims = sample_claims();
        claims.origin = SigningOrigin::GatewayIssuerDid;
        claims.route = "/internal/compat/issuer-dids/sign".into();
        claims.service_id = None;
        claims.issuer_did = Some("did:web:issuer.example".into());
        claims.key_purpose = "x509_doc_signer".into();
        let binding = GrantBinding {
            origin: SigningOrigin::GatewayIssuerDid,
            operation_id: &claims.operation_id,
            organization_id: &claims.organization_id,
            route: &claims.route,
            service_id: None,
            issuer_did: claims.issuer_did.as_deref(),
            key_reference: claims.key_reference.as_deref(),
            key_purpose: &claims.key_purpose,
            algorithm: &claims.algorithm,
            payload: b"exact.payload",
        };
        assert_eq!(
            bound_input(&claims, &binding, 1_700_000_001),
            Err(GrantError::Malformed)
        );

        claims.route = "/v1/signing-keys/issuer-identities/certificate-csr".into();
        claims.key_reference = None;
        claims.key_purpose = "csca".into();
        let csr_binding = GrantBinding {
            origin: SigningOrigin::GatewayIssuerDid,
            operation_id: &claims.operation_id,
            organization_id: &claims.organization_id,
            route: &claims.route,
            service_id: None,
            issuer_did: claims.issuer_did.as_deref(),
            key_reference: None,
            key_purpose: &claims.key_purpose,
            algorithm: &claims.algorithm,
            payload: b"exact.payload",
        };
        assert!(bound_input(&claims, &csr_binding, 1_700_000_001).is_ok());
    }

    #[test]
    fn issuance_tokens_cannot_cross_credential_canvas_readiness_or_passport_purposes() {
        for (origin, allowed_purpose, algorithm) in [
            (SigningOrigin::IssuanceCredential, "vc_jwt_issuer", "ES256"),
            (SigningOrigin::IssuanceCredential, "mdoc_dsc", "ES256"),
            (SigningOrigin::IssuanceCanvas, "lti_tool_signing", "RS256"),
            (SigningOrigin::IssuanceReadiness, "vc_jwt_issuer", "ES256"),
            (SigningOrigin::IssuancePassport, "x509_doc_signer", "ES256"),
        ] {
            let mut claims = sample_claims();
            claims.origin = origin;
            claims.route = "/internal/compat/issuer-dids/sign".into();
            claims.service_id = None;
            claims.issuer_did = Some("did:web:issuer.example".into());
            claims.key_purpose = allowed_purpose.into();
            claims.algorithm = algorithm.into();
            let binding = GrantBinding {
                origin,
                operation_id: &claims.operation_id,
                organization_id: &claims.organization_id,
                route: &claims.route,
                service_id: None,
                issuer_did: claims.issuer_did.as_deref(),
                key_reference: claims.key_reference.as_deref(),
                key_purpose: &claims.key_purpose,
                algorithm: &claims.algorithm,
                payload: b"exact.payload",
            };
            assert!(bound_input(&claims, &binding, 1_700_000_001).is_ok());
            for forbidden in [
                "vc_jwt_issuer",
                "mdoc_dsc",
                "lti_tool_signing",
                "x509_doc_signer",
            ] {
                if forbidden == allowed_purpose {
                    continue;
                }
                let mut elevated = claims.clone();
                elevated.key_purpose = forbidden.into();
                let result = bound_input(&elevated, &binding, 1_700_000_001);
                if origin == SigningOrigin::IssuanceCredential
                    && matches!(forbidden, "vc_jwt_issuer" | "mdoc_dsc")
                {
                    assert_eq!(result, Err(GrantError::BindingMismatch));
                } else {
                    assert_eq!(result, Err(GrantError::Malformed));
                }
            }
            if origin == SigningOrigin::IssuanceCanvas {
                let mut elevated = claims.clone();
                elevated.algorithm = "ES256".into();
                assert_eq!(
                    bound_input(&elevated, &binding, 1_700_000_001),
                    Err(GrantError::Malformed)
                );
            }
            if matches!(
                origin,
                SigningOrigin::IssuancePassport | SigningOrigin::IssuanceReadiness
            ) {
                for supported in ["ES256", "ES384", "RS256", "EdDSA"] {
                    let mut supported_claims = claims.clone();
                    supported_claims.algorithm = supported.into();
                    let supported_binding = GrantBinding {
                        origin,
                        operation_id: &claims.operation_id,
                        organization_id: &claims.organization_id,
                        route: &claims.route,
                        service_id: None,
                        issuer_did: claims.issuer_did.as_deref(),
                        key_reference: claims.key_reference.as_deref(),
                        key_purpose: &claims.key_purpose,
                        algorithm: supported,
                        payload: b"exact.payload",
                    };
                    assert!(
                        bound_input(&supported_claims, &supported_binding, 1_700_000_001).is_ok()
                    );
                }
                let mut elevated = claims.clone();
                elevated.algorithm = "ES512".into();
                assert_eq!(
                    bound_input(&elevated, &binding, 1_700_000_001),
                    Err(GrantError::Malformed)
                );
            }
        }
    }
}
