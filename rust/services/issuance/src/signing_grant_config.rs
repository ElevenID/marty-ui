//! Fixed-origin remote mint authority for Issuance producers.

use std::{env, path::PathBuf};

use marty_signing_grant::{
    configuration::GrantAuthority, minter::GrantMinter, transit::TransitGrantError, SigningOrigin,
};
use thiserror::Error;

#[cfg(test)]
pub(crate) static BAO_ADDR_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
pub(crate) struct ContractGrantMinter(pub(crate) SigningOrigin);

#[cfg(test)]
#[async_trait::async_trait]
impl marty_signing_grant::minter::GrantMinting for ContractGrantMinter {
    async fn mint(
        &self,
        binding: &marty_signing_grant::GrantBinding<'_>,
    ) -> Result<marty_signing_grant::GrantEnvelope, marty_signing_grant::GrantError> {
        use marty_signing_grant::{GrantClaims, GrantEnvelope, GrantError};
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

#[derive(Debug, Error)]
pub enum IssuanceGrantConfigError {
    #[error("BAO_ADDR is required for Issuance signing grants")]
    MissingEndpoint,
    #[error("{0} is required for Issuance signing grants")]
    MissingTokenFile(&'static str),
    #[error("Issuance signing grant configuration is invalid")]
    Invalid(#[from] TransitGrantError),
    #[error("only fixed Issuance signing origins may be configured")]
    InvalidOrigin,
}

pub fn managed_grant_minter(
    origin: SigningOrigin,
) -> Result<GrantMinter, IssuanceGrantConfigError> {
    let token_file_env = match origin {
        SigningOrigin::IssuanceCredential => "ISSUANCE_CREDENTIAL_SIGN_GRANT_MINT_TOKEN_FILE",
        SigningOrigin::IssuanceCanvas => "ISSUANCE_CANVAS_SIGN_GRANT_MINT_TOKEN_FILE",
        SigningOrigin::IssuanceReadiness => "ISSUANCE_READINESS_SIGN_GRANT_MINT_TOKEN_FILE",
        SigningOrigin::IssuancePassport => "ISSUANCE_PASSPORT_SIGN_GRANT_MINT_TOKEN_FILE",
        _ => return Err(IssuanceGrantConfigError::InvalidOrigin),
    };
    let authority = GrantAuthority::from_environment()?;
    let endpoint = env::var("BAO_ADDR")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let token_file = env::var_os(token_file_env).filter(|value| !value.is_empty());
    if authority.is_openbao() {
        if endpoint.is_none() {
            return Err(IssuanceGrantConfigError::MissingEndpoint);
        }
        if token_file.is_none() {
            return Err(IssuanceGrantConfigError::MissingTokenFile(token_file_env));
        }
    }
    authority
        .minter(origin, endpoint.as_deref(), token_file.map(PathBuf::from))
        .map_err(Into::into)
}
