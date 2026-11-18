use std::sync::Arc;

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use serde::Serialize;
use thiserror::Error;

pub const PROOF_NONCE_TTL_SECONDS: u64 = 300;
const PROOF_NONCE_BYTES: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProofNonceResponse {
    pub c_nonce: String,
}

#[async_trait]
pub trait ProofNonceRepository: Send + Sync {
    async fn save_proof_nonce(
        &self,
        nonce: &str,
        ttl_seconds: u64,
    ) -> Result<bool, ProofNonceError>;

    async fn consume_proof_nonce(&self, nonce: &str) -> Result<bool, ProofNonceError>;
}

pub trait ProofNonceGenerator: Send + Sync {
    fn generate(&self) -> Result<String, ProofNonceError>;
}

#[derive(Clone, Debug, Default)]
pub struct SecureProofNonceGenerator;

impl ProofNonceGenerator for SecureProofNonceGenerator {
    fn generate(&self) -> Result<String, ProofNonceError> {
        let mut bytes = [0_u8; PROOF_NONCE_BYTES];
        rand::rng().fill_bytes(&mut bytes);
        Ok(URL_SAFE_NO_PAD.encode(bytes))
    }
}

#[derive(Clone)]
pub struct ProofNonceService {
    repository: Arc<dyn ProofNonceRepository>,
    generator: Arc<dyn ProofNonceGenerator>,
}

impl std::fmt::Debug for ProofNonceService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProofNonceService")
            .finish_non_exhaustive()
    }
}

impl ProofNonceService {
    #[must_use]
    pub fn new(
        repository: Arc<dyn ProofNonceRepository>,
        generator: Arc<dyn ProofNonceGenerator>,
    ) -> Self {
        Self {
            repository,
            generator,
        }
    }

    pub async fn issue(&self) -> Result<ProofNonceResponse, ProofNonceError> {
        let nonce = self.generator.generate()?;
        if !self
            .repository
            .save_proof_nonce(&nonce, PROOF_NONCE_TTL_SECONDS)
            .await?
        {
            return Err(ProofNonceError::RepositoryUnavailable);
        }
        Ok(ProofNonceResponse { c_nonce: nonce })
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ProofNonceError {
    #[error("proof nonce repository is unavailable")]
    RepositoryUnavailable,
}

#[cfg(test)]
mod tests {
    use super::{ProofNonceGenerator, SecureProofNonceGenerator};

    #[test]
    fn secure_generator_preserves_the_token_urlsafe_32_shape() {
        let nonce = SecureProofNonceGenerator.generate().expect("proof nonce");
        assert_eq!(nonce.len(), 43);
        assert!(nonce
            .bytes()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, b'-' | b'_')));
    }
}
