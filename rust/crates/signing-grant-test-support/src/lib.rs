//! Deliberately unsigned grants for consumer request-binding contract tests.
//! Consumers must depend on this package only through dev-dependencies.
use marty_signing_grant::{
    minter::GrantMinting, GrantBinding, GrantClaims, GrantEnvelope, GrantError, SigningOrigin,
};

/// A fixed-origin minter; use `AnyOriginGrantMinter` only for origin-agnostic tests.
pub struct ContractGrantMinter(pub SigningOrigin);
pub struct AnyOriginGrantMinter;

#[async_trait::async_trait]
impl GrantMinting for ContractGrantMinter {
    async fn mint(&self, binding: &GrantBinding<'_>) -> Result<GrantEnvelope, GrantError> {
        if binding.origin != self.0 {
            return Err(GrantError::BindingMismatch);
        }
        envelope(binding)
    }
}

#[async_trait::async_trait]
impl GrantMinting for AnyOriginGrantMinter {
    async fn mint(&self, binding: &GrantBinding<'_>) -> Result<GrantEnvelope, GrantError> {
        envelope(binding)
    }
}

fn envelope(binding: &GrantBinding<'_>) -> Result<GrantEnvelope, GrantError> {
    let now = chrono::Utc::now().timestamp();
    Ok(GrantEnvelope {
        claims: GrantClaims {
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
            payload_sha256_b64: marty_signing_grant::payload_digest(binding.payload),
            issued_at: now,
            expires_at: now + 30,
            nonce: "contract-only-nonce".into(),
        },
        hmac: "not-a-production-hmac".into(),
    })
}
