//! Remote MAC transport for the existing signing-grant protocol.
//!
//! Provider selection belongs to trusted deployment configuration. The grant
//! header cannot select a provider, key, credential, or signing origin.

use async_trait::async_trait;
use thiserror::Error;

use crate::SigningOrigin;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum GrantProviderError {
    #[error("signing grant provider configuration is invalid")]
    InvalidConfig,
    #[error("signing grant provider request failed")]
    Unavailable,
    #[error("signing grant provider response is invalid")]
    InvalidResponse,
}

/// Transport only: claims, authorization, expiry and replay remain in this
/// crate's existing protocol. A provider never computes a local secret MAC.
#[async_trait]
pub trait GrantMac: Send + Sync {
    fn origin(&self) -> SigningOrigin;

    async fn mint(&self, credential: &str, input: &[u8]) -> Result<String, GrantProviderError>;

    async fn verify(
        &self,
        credential: &str,
        input: &[u8],
        mac: &str,
    ) -> Result<bool, GrantProviderError>;
}
