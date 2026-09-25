//! Python-compatible encrypted applicant, MRZ, and data-group artifacts.

use std::collections::BTreeMap;

use fernet::Fernet;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

#[derive(Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PassportSensitiveArtifact {
    pub applicant: Value,
    pub mrz: BTreeMap<String, String>,
    pub data_groups: BTreeMap<String, String>,
}

#[derive(Clone)]
pub struct PassportArtifactCipher {
    fernet: Zeroizing<Fernet>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PassportArtifactError {
    #[error("PHYSICAL_DOCUMENT_ARTIFACT_KEY is invalid")]
    InvalidKey,
    #[error("Secure physical document artifact cannot be decrypted")]
    InvalidArtifact,
}

impl PassportArtifactCipher {
    pub fn from_key(key: &str) -> Result<Self, PassportArtifactError> {
        let fernet = Fernet::new(key.trim()).ok_or(PassportArtifactError::InvalidKey)?;
        Ok(Self {
            fernet: Zeroizing::new(fernet),
        })
    }

    pub fn encrypt(
        &self,
        artifact: &PassportSensitiveArtifact,
    ) -> Result<String, PassportArtifactError> {
        let plaintext = Zeroizing::new(
            serde_json::to_vec(artifact).map_err(|_| PassportArtifactError::InvalidArtifact)?,
        );
        Ok(self.fernet.encrypt(&plaintext))
    }

    pub fn decrypt(&self, token: &str) -> Result<PassportSensitiveArtifact, PassportArtifactError> {
        let plaintext = Zeroizing::new(
            self.fernet
                .decrypt(token)
                .map_err(|_| PassportArtifactError::InvalidArtifact)?,
        );
        serde_json::from_slice(&plaintext).map_err(|_| PassportArtifactError::InvalidArtifact)
    }

    #[must_use]
    pub fn encrypted_scrubbed_artifact(&self) -> String {
        self.fernet.encrypt(b"{}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Synthetic artifact encrypted by Python cryptography 50.0.0 using compact
    // JSON, matching the released physical_document_routes.py artifact writer.
    const PYTHON_KEY: &str = "GHmdjsX17P5kD4XxT6b8g2f9cxoBPBCuqmjBpphVpow=";
    const PYTHON_TOKEN: &str = "gAAAAABqtWG96h6Ot_C3sUQx3itXg9XPBGoc8eEoNXYCaq5_iaK78WjRopt0MQER6-AZsktDTGTHIGsnT58K0Q2S8jWJ0YxZZEr3S5F22q-W083DoOuqmZl3IdzHy95gcmxYEihuZ30UDrFZ45DWxHhozsJ4m-dKmYIO9Ye3bws1NXrOZ8dCg28UINJF4laW5AnCfExFO2aeQRexxxlgws09QJuL-iZhm40JeZ-n-9ltFVKqpvMC7B5CMBkQzfGqgzG8i45dS_Xd";

    #[test]
    fn reads_python_cryptography_artifact_and_preserves_scrub_format() {
        let cipher = PassportArtifactCipher::from_key(PYTHON_KEY).unwrap();
        let artifact = cipher.decrypt(PYTHON_TOKEN).unwrap();
        assert_eq!(artifact.applicant["synthetic"], "test-person");
        assert_eq!(artifact.mrz["line_1"], "P<TEST");
        assert_eq!(artifact.data_groups["DG1"], "UkR4");
        let native_token = cipher.encrypt(&artifact).unwrap();
        assert_eq!(
            cipher.decrypt(&native_token).unwrap().data_groups,
            artifact.data_groups
        );
        let scrubbed = cipher.encrypted_scrubbed_artifact();
        assert_eq!(cipher.fernet.decrypt(&scrubbed).unwrap(), b"{}");
        assert!(matches!(
            cipher.decrypt(&scrubbed),
            Err(PassportArtifactError::InvalidArtifact)
        ));
    }

    #[test]
    fn wrong_key_and_tampering_fail_without_exposing_artifact() {
        assert!(matches!(
            PassportArtifactCipher::from_key("weak"),
            Err(PassportArtifactError::InvalidKey)
        ));
        let other = PassportArtifactCipher::from_key(&Fernet::generate_key()).unwrap();
        assert!(matches!(
            other.decrypt(PYTHON_TOKEN),
            Err(PassportArtifactError::InvalidArtifact)
        ));
        let cipher = PassportArtifactCipher::from_key(PYTHON_KEY).unwrap();
        let mut tampered = PYTHON_TOKEN.to_owned();
        let replacement = if &tampered[30..31] == "A" { "B" } else { "A" };
        tampered.replace_range(30..31, replacement);
        assert!(matches!(
            cipher.decrypt(&tampered),
            Err(PassportArtifactError::InvalidArtifact)
        ));
    }

    #[test]
    fn official_fernet_verification_vector_remains_compatible() {
        // https://github.com/fernet/spec/blob/master/verify.json
        let key = "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=";
        let token = "gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA==";
        let fernet = Fernet::new(key).unwrap();
        assert_eq!(fernet.decrypt(token).unwrap(), b"hello");
    }
}
