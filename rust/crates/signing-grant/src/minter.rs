//! Scoped OpenBao Transit HMAC minting for an authorized signing operation.

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
