//! AWS HMAC transport for the canonical signing-grant bytes.

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use mmf_aws_kms::{AwsAuth, AwsKmsConfig, AwsKmsKey};
use tokio::sync::OnceCell;

use crate::{
    provider::{GrantMac, GrantProviderError},
    SigningOrigin,
};

const MAC_PREFIX: &str = "aws-kms:v1:";
const MAX_INPUT_BYTES: usize = 4096;
const TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub(crate) struct AwsGrantClient {
    origin: SigningOrigin,
    region: String,
    key_arn: String,
    key: Arc<OnceCell<AwsKmsKey>>,
}

impl AwsGrantClient {
    pub(crate) fn new(
        origin: SigningOrigin,
        region: String,
        key_arn: String,
    ) -> Result<Self, GrantProviderError> {
        mmf_aws_kms::validate_key_arn(&key_arn, &region)
            .map_err(|_| GrantProviderError::InvalidConfig)?;
        Ok(Self {
            origin,
            region,
            key_arn,
            key: Arc::new(OnceCell::new()),
        })
    }

    async fn key(&self) -> Result<&AwsKmsKey, GrantProviderError> {
        self.key
            .get_or_try_init(|| async {
                let key = AwsKmsKey::connect(
                    AwsKmsConfig {
                        region: self.region.clone(),
                        authentication: AwsAuth::IamRole,
                        endpoint: None,
                        request_timeout: TIMEOUT,
                    },
                    self.key_arn.clone(),
                )
                .await
                .map_err(|_| GrantProviderError::Unavailable)?;
                // The shared MAC operations validate provider-generated HMAC
                // custody, capability and exact response binding on every call.
                Ok(key)
            })
            .await
    }
}

fn validate_input(credential: &str, input: &[u8]) -> Result<(), GrantProviderError> {
    // AWS uses only the configured workload identity. A Transit credential
    // cannot accidentally be forwarded into this transport.
    if !credential.is_empty() || input.is_empty() || input.len() > MAX_INPUT_BYTES {
        return Err(GrantProviderError::InvalidConfig);
    }
    Ok(())
}

fn decode_mac(value: &str) -> Result<[u8; 32], GrantProviderError> {
    let encoded = value
        .strip_prefix(MAC_PREFIX)
        .filter(|value| value.len() == 44)
        .ok_or(GrantProviderError::InvalidResponse)?;
    let decoded: [u8; 32] = STANDARD
        .decode(encoded)
        .map_err(|_| GrantProviderError::InvalidResponse)?
        .try_into()
        .map_err(|_| GrantProviderError::InvalidResponse)?;
    if STANDARD.encode(decoded) != encoded {
        return Err(GrantProviderError::InvalidResponse);
    }
    Ok(decoded)
}

#[async_trait]
impl GrantMac for AwsGrantClient {
    fn origin(&self) -> SigningOrigin {
        self.origin
    }

    async fn mint(&self, credential: &str, input: &[u8]) -> Result<String, GrantProviderError> {
        validate_input(credential, input)?;
        let mac = tokio::time::timeout(TIMEOUT, async {
            self.key()
                .await?
                .generate_mac(input)
                .await
                .map_err(|_| GrantProviderError::Unavailable)
        })
        .await
        .map_err(|_| GrantProviderError::Unavailable)??;
        Ok(format!("{MAC_PREFIX}{}", STANDARD.encode(mac)))
    }

    async fn verify(
        &self,
        credential: &str,
        input: &[u8],
        mac: &str,
    ) -> Result<bool, GrantProviderError> {
        validate_input(credential, input)?;
        let mac = decode_mac(mac)?;
        tokio::time::timeout(TIMEOUT, async {
            self.key()
                .await?
                .verify_mac(input, &mac)
                .await
                .map_err(|_| GrantProviderError::Unavailable)
        })
        .await
        .map_err(|_| GrantProviderError::Unavailable)?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aws_tag_cannot_select_another_provider_or_key() {
        let tag = format!("{MAC_PREFIX}{}", STANDARD.encode([7_u8; 32]));
        assert_eq!(decode_mac(&tag), Ok([7_u8; 32]));
        for malformed in [
            tag.replace(MAC_PREFIX, "vault:v1:"),
            tag.replace("v1:", "v2:"),
            format!("{MAC_PREFIX}{}", STANDARD.encode([7_u8; 31])),
            format!("{MAC_PREFIX}{}", STANDARD.encode([7_u8; 33])),
            format!("{tag}:other-key"),
            format!("{tag}\n"),
        ] {
            assert!(decode_mac(&malformed).is_err());
        }
    }

    #[test]
    fn oversized_or_cross_provider_input_fails_before_aws() {
        assert!(validate_input("", b"bound claim").is_ok());
        assert!(validate_input("", &vec![0; MAX_INPUT_BYTES]).is_ok());
        assert!(validate_input("", &vec![0; MAX_INPUT_BYTES + 1]).is_err());
        assert!(validate_input("openbao-token", b"bound claim").is_err());
        assert!(validate_input("", b"").is_err());
    }
}
