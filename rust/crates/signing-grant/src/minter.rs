//! Scoped remote HMAC minting for an authorized signing operation.

use async_trait::async_trait;
use std::{path::PathBuf, sync::Arc};

use crate::{
    mint_bound,
    provider::GrantMac,
    token_file::read_token_file,
    transit::{TransitGrantClient, TransitGrantError},
    GrantBinding, GrantEnvelope, GrantError, SigningOrigin,
};

#[derive(Clone)]
pub struct GrantMinter {
    client: Arc<dyn GrantMac>,
    mint_token_file: Option<PathBuf>,
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
            client: Arc::new(TransitGrantClient::for_origin(endpoint, origin)?),
            mint_token_file: Some(mint_token_file),
        })
    }

    pub(crate) fn for_aws(client: crate::aws::AwsGrantClient) -> Self {
        Self {
            client: Arc::new(client),
            mint_token_file: None,
        }
    }

    pub async fn mint(&self, binding: &GrantBinding<'_>) -> Result<GrantEnvelope, GrantError> {
        if self.client.origin() != binding.origin {
            return Err(GrantError::BindingMismatch);
        }
        let token = match &self.mint_token_file {
            Some(path) => read_token_file(path)
                .await
                .map_err(|_| GrantError::MinterUnavailable)?,
            None => String::new(),
        };
        mint_bound(self.client.as_ref(), &token, binding).await
    }
}

/// Mint a grant for an operation authorized by the calling service.
/// Production uses the configured remote KMS; callers can supply a contract-test implementation
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
