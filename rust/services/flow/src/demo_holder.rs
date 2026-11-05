//! Synthetic-example holder using Core protocol construction and opaque KMS
//! signing. This module never generates, imports or retains a private key.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use marty_oid4vci::{wallet::WalletEngine, ResolvedSdJwtIssuerKey, TrustedSdJwtIssuerKeys};
use marty_verification::flow::FlowInstanceStatus;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    FlowInstanceRecord, FlowProviderError, FlowProviderRegistry, SigningIdentity,
    SigningIdentityProvider, SigningRequest,
};

pub const DEMO_HOLDER_PURPOSE: &str = "demo_holder_binding";
const DEMO_HOLDER_FORMAT: &str = "dc+sd-jwt";

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DemoCredentialProfile {
    pub credential_template_id: String,
    pub issuer_did: String,
    pub vct: String,
}

/// The holder represents Marty's synthetic demonstration, never the visitor.
/// The KMS key may persist; each presentation is bound to one session.
pub struct DemoHolder {
    identity: SigningIdentity,
}

impl std::fmt::Debug for DemoHolder {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DemoHolder([opaque signing identity])")
    }
}

/// Server-side presentation material, deliberately not serializable/debuggable
/// as an ordinary public session response.
pub struct DemoHolderPresentation(String);

impl std::fmt::Debug for DemoHolderPresentation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DemoHolderPresentation([redacted])")
    }
}

impl DemoHolderPresentation {
    #[must_use]
    pub fn into_compact(self) -> String {
        self.0
    }
}

#[derive(Debug, Error)]
pub enum DemoHolderError {
    #[error(transparent)]
    Provider(#[from] FlowProviderError),
    #[error(transparent)]
    Definition(#[from] crate::DefinedVerificationError),
    #[error(transparent)]
    Presentation(#[from] crate::FlowPresentationRequestError),
    #[error("FLOW.DEMO_HOLDER_IDENTITY_INVALID")]
    IdentityInvalid,
    #[error("FLOW.DEMO_HOLDER_SESSION_INVALID")]
    SessionInvalid,
    #[error("FLOW.DEMO_CREDENTIAL_PROFILE_INVALID")]
    ProfileInvalid,
    #[error("FLOW.DEMO_CREDENTIAL_INVALID")]
    CredentialInvalid,
    #[error("FLOW.DEMO_HOLDER_SIGNATURE_INVALID")]
    SignatureInvalid,
}

impl DemoHolder {
    pub async fn resolve(
        signer: &dyn SigningIdentityProvider,
        organization_id: &str,
        holder_did: &str,
    ) -> Result<Self, DemoHolderError> {
        let identity = signer
            .resolve(
                organization_id,
                holder_did,
                DEMO_HOLDER_PURPOSE,
                DEMO_HOLDER_FORMAT,
                Some("ES256"),
            )
            .await?;
        identity.validate_binding(
            organization_id,
            holder_did,
            DEMO_HOLDER_PURPOSE,
            DEMO_HOLDER_FORMAT,
            Some("ES256"),
        )?;
        Ok(Self { identity })
    }

    #[must_use]
    pub fn holder_did(&self) -> &str {
        &self.identity.issuer_did
    }

    /// The nonce and issuer URL come from the governed issuance owner. Only
    /// Core's exact proof input is sent to the dedicated demo-holder signer.
    pub async fn issuance_proof(
        &self,
        providers: &FlowProviderRegistry,
        instance: &FlowInstanceRecord,
        issuer_nonce: &str,
        issuer_url: &str,
    ) -> Result<String, DemoHolderError> {
        self.admit(providers, instance).await?;
        let jwk = serde_json::to_string(&self.identity.public_jwk)
            .map_err(|_| DemoHolderError::IdentityInvalid)?;
        let prepared = WalletEngine::new()
            .prepare_proof_jwt(
                &self.identity.verification_method_id,
                issuer_nonce,
                issuer_url,
                &jwk,
            )
            .map_err(|_| DemoHolderError::CredentialInvalid)?;
        let signature = self
            .sign(
                providers,
                &self.identity,
                instance,
                prepared.signing_input(),
            )
            .await?;
        prepared
            .complete(&signature)
            .map_err(|_| DemoHolderError::SignatureInvalid)
    }

    /// Validate the actual policy/template graph and disclose only its literal
    /// requested claim names. This creates protocol material, never a verdict;
    /// the ordinary Flow evaluator and atomic nonce finalizer must consume it.
    pub async fn presentation(
        &self,
        providers: &FlowProviderRegistry,
        instance: &FlowInstanceRecord,
        profile: &DemoCredentialProfile,
        issued_credential: &str,
    ) -> Result<DemoHolderPresentation, DemoHolderError> {
        self.admit(providers, instance).await?;
        let policy_id = instance
            .context
            .get("presentation_policy_id")
            .and_then(serde_json::Value::as_str)
            .ok_or(DemoHolderError::SessionInvalid)?;
        let policy = crate::resolve_flow_presentation_policy(
            providers,
            policy_id,
            &instance.organization_id,
        )
        .await?;
        // Bind disclosure selection to the very same immutable resolved graph;
        // a second policy read must not substitute newly requested claims.
        let artifacts = crate::presentation_request::build_resolved_flow_presentation_request(
            providers, &policy,
        )
        .await?;
        crate::defined_verification::validate_defined_request(instance, &artifacts)?;
        let [(requirement, template)] = policy.requirements.as_slice() else {
            return Err(DemoHolderError::ProfileInvalid);
        };
        if profile.credential_template_id != template.id
            || profile.issuer_did != template.issuer_did
            || profile.vct.is_empty()
            || profile.vct != template.vct
            || profile.issuer_did == self.holder_did()
            || !template
                .supported_formats
                .iter()
                .any(|format| matches!(format.as_str(), "dc+sd-jwt" | "vc+sd-jwt"))
        {
            return Err(DemoHolderError::ProfileInvalid);
        }
        let claims =
            crate::presentation_request::requested_claims(requirement.get("requested_claims"), 0)?
                .into_iter()
                .map(|claim| claim.claim_name)
                .collect::<Vec<_>>();
        if claims.len() > 16 || claims.iter().any(|name| name.len() > 128) {
            return Err(DemoHolderError::ProfileInvalid);
        }
        let signer =
            providers
                .signing_identity
                .as_deref()
                .ok_or(FlowProviderError::Unavailable {
                    provider: "signing_identity",
                })?;
        let issuer = signer
            .resolve(
                &instance.organization_id,
                &profile.issuer_did,
                "vc_jwt_issuer",
                "dc+sd-jwt",
                Some("ES256"),
            )
            .await?;
        issuer.validate_binding(
            &instance.organization_id,
            &profile.issuer_did,
            "vc_jwt_issuer",
            "dc+sd-jwt",
            Some("ES256"),
        )?;
        if issuer.signing_key_reference == self.identity.signing_key_reference
            || issuer.public_jwk == self.identity.public_jwk
        {
            return Err(DemoHolderError::IdentityInvalid);
        }
        let keys = TrustedSdJwtIssuerKeys::new(vec![ResolvedSdJwtIssuerKey::new(
            &profile.issuer_did,
            Some(issuer.verification_method_id.clone()),
            marty_oid4vci::types::SigningAlgorithm::ES256,
            serde_json::to_string(&issuer.public_jwk)
                .map_err(|_| DemoHolderError::IdentityInvalid)?,
        )])
        .map_err(|_| DemoHolderError::IdentityInvalid)?;
        let wallet = WalletEngine::new();
        let holder_jwk = serde_json::to_string(&self.identity.public_jwk)
            .map_err(|_| DemoHolderError::IdentityInvalid)?;
        let received = wallet
            .verify_received_sd_jwt_credential(issued_credential, &holder_jwk, &keys)
            .map_err(|_| DemoHolderError::CredentialInvalid)?;
        if received.issuer != profile.issuer_did || received.credential_type != profile.vct {
            return Err(DemoHolderError::CredentialInvalid);
        }
        let nonce = instance
            .context
            .get("nonce")
            .and_then(serde_json::Value::as_str)
            .ok_or(DemoHolderError::SessionInvalid)?;
        let audience = instance
            .context
            .get("oid4vp_client_id")
            .and_then(serde_json::Value::as_str)
            .ok_or(DemoHolderError::SessionInvalid)?;
        let prepared = wallet
            .prepare_verified_sd_jwt_presentation(
                issued_credential,
                &claims,
                nonce,
                audience,
                &holder_jwk,
                &keys,
            )
            .map_err(|_| DemoHolderError::CredentialInvalid)?;
        let signature = self
            .sign(
                providers,
                &self.identity,
                instance,
                prepared.signing_input(),
            )
            .await?;
        let compact = prepared
            .complete(&signature)
            .map_err(|_| DemoHolderError::SignatureInvalid)?;
        Ok(DemoHolderPresentation(compact))
    }

    async fn admit(
        &self,
        providers: &FlowProviderRegistry,
        instance: &FlowInstanceRecord,
    ) -> Result<(), DemoHolderError> {
        if instance.organization_id != self.identity.organization_id
            || !matches!(
                instance.status,
                FlowInstanceStatus::AwaitingWallet | FlowInstanceStatus::InProgress
            )
            || instance
                .expires_at
                .is_none_or(|expiry| expiry <= Utc::now())
            || instance
                .context
                .get(crate::public_verification_session::PUBLIC_SESSION)
                .and_then(serde_json::Value::as_object)
                .is_none()
            || crate::defined_verification::validate_defined_submission(providers, instance)
                .await?
                .is_none()
        {
            return Err(DemoHolderError::SessionInvalid);
        }
        Ok(())
    }

    async fn sign(
        &self,
        providers: &FlowProviderRegistry,
        identity: &SigningIdentity,
        instance: &FlowInstanceRecord,
        payload: &[u8],
    ) -> Result<Vec<u8>, DemoHolderError> {
        let request = SigningRequest {
            operation_id: instance.id.clone(),
            organization_id: instance.organization_id.clone(),
            issuer_did: identity.issuer_did.clone(),
            verification_method_id: identity.verification_method_id.clone(),
            signing_key_reference: identity.signing_key_reference.clone(),
            key_purpose: DEMO_HOLDER_PURPOSE.into(),
            credential_format: identity.credential_format.clone(),
            algorithm: "ES256".into(),
            payload_b64url: URL_SAFE_NO_PAD.encode(payload),
        };
        let result = providers
            .signing_identity
            .as_deref()
            .ok_or(FlowProviderError::Unavailable {
                provider: "signing_identity",
            })?
            .sign(&request)
            .await?;
        result.validate_binding(&request)?;
        URL_SAFE_NO_PAD
            .decode(&result.signature_raw_b64url)
            .map_err(|_| DemoHolderError::SignatureInvalid)
    }
}

#[cfg(test)]
#[path = "demo_holder_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "demo_policy_tests.rs"]
mod policy_tests;
