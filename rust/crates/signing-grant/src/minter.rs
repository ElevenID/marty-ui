//! Scoped OpenBao Transit HMAC minting for an authorized signing operation.

use async_trait::async_trait;
use std::path::PathBuf;

use crate::{
    mint_bound,
    token_file::read_token_file,
    transit::{TransitGrantClient, TransitGrantError},
    GrantBinding, GrantEnvelope, GrantError, SigningOrigin,
};

#[derive(Clone)]
pub struct GrantMinter {
    client: TransitGrantClient,
    mint_token_file: PathBuf,
}

impl GrantMinter {
    /// Construct one fixed-origin minter. The token file is read for every
    /// operation so rotation does not leave a stale token in process memory.
    pub fn for_managed_openbao(
        endpoint: &str,
        origin: SigningOrigin,
        mint_token_file: PathBuf,
    ) -> Result<Self, TransitGrantError> {
        if !mint_token_file.is_absolute() {
            return Err(TransitGrantError::InvalidConfig);
        }
        Ok(Self {
            client: TransitGrantClient::for_origin(endpoint, origin)?,
            mint_token_file,
        })
    }

    pub async fn mint(&self, binding: &GrantBinding<'_>) -> Result<GrantEnvelope, GrantError> {
        if self.client.origin() != binding.origin {
            return Err(GrantError::BindingMismatch);
        }
        let token = read_token_file(&self.mint_token_file)
            .await
            .map_err(|_| GrantError::MinterUnavailable)?;
        mint_bound(&self.client, &token, binding).await
    }
}

/// Mint a grant for an operation authorized by the calling service.
/// Production uses OpenBao; callers can supply a contract-test implementation
/// without enabling plaintext KMS transport in the production client.
#[async_trait]
pub trait GrantMinting: Send + Sync {
    async fn mint(&self, binding: &GrantBinding<'_>) -> Result<GrantEnvelope, GrantError>;
}

#[async_trait]
impl GrantMinting for GrantMinter {
    async fn mint(&self, binding: &GrantBinding<'_>) -> Result<GrantEnvelope, GrantError> {
        GrantMinter::mint(self, binding).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_relative_token_path_before_contacting_openbao() {
        assert!(matches!(
            GrantMinter::for_managed_openbao(
                "http://127.0.0.1:8200",
                SigningOrigin::FlowWalletRequest,
                PathBuf::from("mint.token"),
            ),
            Err(TransitGrantError::InvalidConfig)
        ));
    }
}
