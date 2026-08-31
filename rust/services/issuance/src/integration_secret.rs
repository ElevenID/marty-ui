use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use std::fmt;
use thiserror::Error;

const NONCE_LENGTH: usize = 12;
const TAG_LENGTH: usize = 16;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntegrationSecretMetadata {
    pub id: String,
    pub organization_id: String,
    pub provider: String,
    pub purpose: String,
    pub enabled: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ManagedIntegrationSecret {
    pub id: String,
    pub organization_id: String,
    pub name: String,
    pub provider: String,
    pub purpose: String,
    pub secret_hint: Option<String>,
    pub metadata: Map<String, Value>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

impl ManagedIntegrationSecret {
    #[must_use]
    pub fn secret_ref(&self) -> String {
        integration_secret_ref(&self.organization_id, &self.id)
    }
}

#[derive(Clone, PartialEq)]
pub struct NewIntegrationSecret {
    pub id: String,
    pub organization_id: String,
    pub name: String,
    pub provider: String,
    pub purpose: String,
    pub value: String,
    pub metadata: Value,
}

impl fmt::Debug for NewIntegrationSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NewIntegrationSecret")
            .field("id", &self.id)
            .field("organization_id", &self.organization_id)
            .field("name", &self.name)
            .field("provider", &self.provider)
            .field("purpose", &self.purpose)
            .field("value", &"[REDACTED]")
            .field("metadata", &"[REDACTED]")
            .finish()
    }
}

impl NewIntegrationSecret {
    #[must_use]
    pub fn secret_ref(&self) -> String {
        integration_secret_ref(&self.organization_id, &self.id)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum IntegrationSecretError {
    #[error("integration secret master key must be standard base64 encoding of exactly 32 bytes")]
    InvalidMasterKey,
    #[error("encrypted integration secret is invalid")]
    InvalidCiphertext,
    #[error("integration secret persistence is unavailable")]
    RepositoryUnavailable,
}

#[derive(Clone)]
pub struct IntegrationSecretCipher {
    key: [u8; 32],
}

impl std::fmt::Debug for IntegrationSecretCipher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IntegrationSecretCipher")
            .field("key_configured", &true)
            .finish()
    }
}

impl IntegrationSecretCipher {
    pub fn from_base64(value: &str) -> Result<Self, IntegrationSecretError> {
        let decoded = STANDARD
            .decode(value)
            .map_err(|_| IntegrationSecretError::InvalidMasterKey)?;
        let key = decoded
            .try_into()
            .map_err(|_| IntegrationSecretError::InvalidMasterKey)?;
        Ok(Self { key })
    }

    pub fn encrypt(&self, plaintext: &str) -> Result<String, IntegrationSecretError> {
        let nonce: [u8; NONCE_LENGTH] = rand::random();
        self.encrypt_with_nonce(plaintext, nonce)
    }

    fn encrypt_with_nonce(
        &self,
        plaintext: &str,
        nonce: [u8; NONCE_LENGTH],
    ) -> Result<String, IntegrationSecretError> {
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|_| IntegrationSecretError::InvalidMasterKey)?;
        let encrypted = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_bytes())
            .map_err(|_| IntegrationSecretError::InvalidCiphertext)?;
        let mut stored = Vec::with_capacity(NONCE_LENGTH + encrypted.len());
        stored.extend_from_slice(&nonce);
        stored.extend_from_slice(&encrypted);
        Ok(STANDARD.encode(stored))
    }

    pub fn decrypt(&self, encoded: &str) -> Result<String, IntegrationSecretError> {
        let stored = STANDARD
            .decode(encoded)
            .map_err(|_| IntegrationSecretError::InvalidCiphertext)?;
        if stored.len() < NONCE_LENGTH + TAG_LENGTH {
            return Err(IntegrationSecretError::InvalidCiphertext);
        }
        let (nonce, ciphertext) = stored.split_at(NONCE_LENGTH);
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|_| IntegrationSecretError::InvalidMasterKey)?;
        let plaintext = cipher
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|_| IntegrationSecretError::InvalidCiphertext)?;
        String::from_utf8(plaintext).map_err(|_| IntegrationSecretError::InvalidCiphertext)
    }
}

#[must_use]
pub fn integration_secret_ref(organization_id: &str, secret_id: &str) -> String {
    format!("org_secret://{organization_id}/{secret_id}")
}

#[must_use]
pub fn integration_secret_hint(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| {
        format!(
            "...{}",
            value
                .chars()
                .rev()
                .take(4)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<String>()
        )
    })
}

#[must_use]
pub fn integration_secret_id_from_ref<'value>(
    organization_id: &str,
    secret_ref: &'value str,
) -> Option<&'value str> {
    secret_ref
        .strip_prefix(&format!("org_secret://{organization_id}/"))
        .filter(|value| !value.is_empty() && !value.contains('/'))
}

#[cfg(test)]
mod tests {
    use super::{
        integration_secret_id_from_ref, integration_secret_ref, IntegrationSecretCipher,
        IntegrationSecretError,
    };

    const PYTHON_VECTOR_KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    const PYTHON_VECTOR_CIPHERTEXT: &str =
        "AAECAwQFBgcICQoLJGO4baSW72joIuXuxcQODO+j4mW1no3FYXSCh604xhydFOI=";

    #[test]
    fn decrypts_the_python_nonce_ciphertext_tag_storage_format() {
        let cipher = IntegrationSecretCipher::from_base64(PYTHON_VECTOR_KEY).expect("key");
        assert_eq!(
            cipher.decrypt(PYTHON_VECTOR_CIPHERTEXT),
            Ok("canvas-secret-value".to_owned())
        );
        let encrypted = cipher.encrypt("round-trip-secret").expect("encrypt");
        assert_eq!(
            cipher.decrypt(&encrypted),
            Ok("round-trip-secret".to_owned())
        );
        let encrypted_empty = cipher.encrypt("").expect("encrypt empty value");
        assert_eq!(cipher.decrypt(&encrypted_empty), Ok(String::new()));
        assert!(!format!("{cipher:?}").contains(PYTHON_VECTOR_KEY));
        let secret = super::NewIntegrationSecret {
            id: "secret-1".to_owned(),
            organization_id: "org-1".to_owned(),
            name: "Secret".to_owned(),
            provider: "canvas".to_owned(),
            purpose: "oauth_access_token".to_owned(),
            value: "plaintext-sensitive".to_owned(),
            metadata: serde_json::json!({"token": "metadata-sensitive"}),
        };
        let debug = format!("{secret:?}");
        assert!(!debug.contains("plaintext-sensitive"));
        assert!(!debug.contains("metadata-sensitive"));
    }

    #[test]
    fn malformed_keys_ciphertexts_and_cross_tenant_references_fail_closed() {
        assert_eq!(
            IntegrationSecretCipher::from_base64("not-base64").unwrap_err(),
            IntegrationSecretError::InvalidMasterKey
        );
        let cipher = IntegrationSecretCipher::from_base64(PYTHON_VECTOR_KEY).expect("key");
        for malformed in ["", "not-base64", "AAECAwQFBgcICQoL"] {
            assert_eq!(
                cipher.decrypt(malformed),
                Err(IntegrationSecretError::InvalidCiphertext)
            );
        }
        assert_eq!(
            integration_secret_ref("org-1", "secret-1"),
            "org_secret://org-1/secret-1"
        );
        assert_eq!(
            integration_secret_id_from_ref("org-1", "org_secret://org-1/secret-1"),
            Some("secret-1")
        );
        assert_eq!(
            integration_secret_id_from_ref("org-2", "org_secret://org-1/secret-1"),
            None
        );
        assert_eq!(
            integration_secret_id_from_ref("org-1", "org_secret://org-1/path/secret"),
            None
        );
    }
}
