//! Fixed-origin remote mint authority for Issuance producers.

use std::{env, path::PathBuf};

use marty_signing_grant::{
    configuration::GrantAuthority, minter::GrantMinter, transit::TransitGrantError, SigningOrigin,
};
use thiserror::Error;

#[cfg(test)]
pub(crate) static BAO_ADDR_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
pub(crate) use marty_signing_grant_test_support::ContractGrantMinter;

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
