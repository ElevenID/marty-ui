//! Bound grant header for HTTP contract tests that do not verify HMACs.
//! Real mint and verify acceptance runs against HTTPS OpenBao separately.

use async_trait::async_trait;
use marty_signing_grant::{
    minter::GrantMinting, GrantBinding, GrantClaims, GrantEnvelope, GrantError, SigningOrigin,
};

pub struct ContractGrantMinter(pub SigningOrigin);

#[async_trait]
impl GrantMinting for ContractGrantMinter {
    async fn mint(&self, binding: &GrantBinding<'_>) -> Result<GrantEnvelope, GrantError> {
        if binding.origin != self.0 {
            return Err(GrantError::BindingMismatch);
        }
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
}
