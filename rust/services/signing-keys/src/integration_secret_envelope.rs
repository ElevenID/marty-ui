//! Purpose-bound integration-secret storage under the selected remote KMS.

use std::{collections::BTreeMap, env, time::Duration};

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use marty_service_runtime::{SecretKmsNames, SecretKmsSelection};
use mmf_aws_kms::{AwsKmsKey, KeyCapability};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;

use crate::flow_envelope::OpenBaoEnvelopeProvider;

const SCHEMA: &str = "marty.integration-secret-envelope/v1";
const KEY_ID: &str = "integration-secret-envelope-marty-aes256";
const MAX_SECRET_BYTES: usize = 64 * 1024;
const MAX_ENVELOPE_BYTES: usize = 96 * 1024;
const MAX_CIPHERTEXT_BYTES: usize = 200 * 1024;
const AWS_MAX_BOUND_PLAINTEXT_BYTES: usize = 4096;

/// The platform's storage authority. Ciphertext and tenant requests never
/// choose a provider, key, endpoint, or credential.
#[derive(Clone)]
pub enum IntegrationSecretProvider {
    OpenBao(OpenBaoEnvelopeProvider),
    Aws(AwsKmsKey),
}

impl From<OpenBaoEnvelopeProvider> for IntegrationSecretProvider {
    fn from(provider: OpenBaoEnvelopeProvider) -> Self {
        Self::OpenBao(provider)
    }
}

impl IntegrationSecretProvider {
    pub async fn from_environment(
        openbao: Option<OpenBaoEnvelopeProvider>,
    ) -> Result<Option<Self>, IntegrationSecretEnvelopeError> {
        let mut values = BTreeMap::new();
        for name in [
            "SIGNING_KEYS_INTEGRATION_SECRET_KMS_PROVIDER",
            "SIGNING_KEYS_INTEGRATION_SECRET_AWS_REGION",
            "SIGNING_KEYS_INTEGRATION_SECRET_AWS_KEY_ARN",
        ] {
            if let Some(value) = setting(name)? {
                values.insert(name, value);
            }
        }
        let selected = SecretKmsSelection::from_values(
            |name| values.get(name).map(String::as_str),
            SecretKmsNames {
                prefix: "SIGNING_KEYS_INTEGRATION_SECRET",
                openbao_fields: &[],
            },
            Duration::from_secs(10),
        )
        .map_err(|_| IntegrationSecretEnvelopeError::InvalidConfig)?;
        match selected {
            SecretKmsSelection::OpenBao => Ok(openbao.map(Self::OpenBao)),
            SecretKmsSelection::AwsKms { config, key_arn } => {
                let key = AwsKmsKey::connect(config, key_arn)
                    .await
                    .map_err(|_| IntegrationSecretEnvelopeError::Unavailable)?;
                key.validate(KeyCapability::SymmetricEncryption)
                    .await
                    .map_err(|_| IntegrationSecretEnvelopeError::Unavailable)?;
                Ok(Some(Self::Aws(key)))
            }
        }
    }
}

fn setting(name: &str) -> Result<Option<String>, IntegrationSecretEnvelopeError> {
    match env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => Err(IntegrationSecretEnvelopeError::InvalidConfig),
    }
}

fn aws_context() -> BTreeMap<String, String> {
    // Context is logged by AWS; secret and tenant identifiers stay in the
    // encrypted BoundSecret. Its four identity fields are checked below.
    BTreeMap::from([("marty-envelope-schema".into(), SCHEMA.into())])
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptRequest {
    pub organization_id: String,
    pub secret_id: String,
    pub provider: String,
    pub purpose: String,
    pub plaintext_b64: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecryptRequest {
    pub organization_id: String,
    pub secret_id: String,
    pub provider: String,
    pub purpose: String,
    pub envelope: Value,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredEnvelope {
    schema: String,
    ciphertext: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BoundSecret {
    schema: String,
    organization_id: String,
    secret_id: String,
    provider: String,
    purpose: String,
    plaintext_b64: String,
}

#[derive(Debug, Error)]
pub enum IntegrationSecretEnvelopeError {
    #[error("Invalid internal signing API key.")]
    Unauthorized,
    #[error("Integration-secret KMS configuration is invalid.")]
    InvalidConfig,
    #[error("{0}")]
    CapabilityUnavailable(&'static str),
    #[error("Integration-secret identity or value is invalid.")]
    InvalidSecret,
    #[error("Integration-secret envelope is invalid.")]
    InvalidEnvelope,
    #[error("Integration-secret envelope binding does not match this secret.")]
    BindingMismatch,
    #[error("KMS integration-secret encryption failed.")]
    EncryptFailed,
    #[error("KMS integration-secret decryption failed.")]
    DecryptFailed,
    #[error("KMS integration-secret provider is unavailable.")]
    Unavailable,
}

impl IntoResponse for IntegrationSecretEnvelopeError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::InvalidSecret | Self::InvalidEnvelope | Self::CapabilityUnavailable(_) => {
                StatusCode::UNPROCESSABLE_ENTITY
            }
            Self::BindingMismatch => StatusCode::CONFLICT,
            Self::EncryptFailed | Self::DecryptFailed | Self::Unavailable | Self::InvalidConfig => {
                StatusCode::SERVICE_UNAVAILABLE
            }
        };
        let mut body = json!({"detail": self.to_string()});
        if matches!(self, Self::CapabilityUnavailable(_)) {
            body["code"] = json!("capability_unavailable");
            body["capability"] = json!("integration_secret_encryption");
        }
        (status, Json(body)).into_response()
    }
}

fn valid_identity(organization_id: &str, secret_id: &str, provider: &str, purpose: &str) -> bool {
    [organization_id, secret_id, provider, purpose]
        .iter()
        .all(|part| !part.trim().is_empty())
        && organization_id.len() <= 256
        && secret_id.len() <= 256
        && provider.len() <= 80
        && purpose.len() <= 80
}

fn prepare(request: &EncryptRequest) -> Result<Vec<u8>, IntegrationSecretEnvelopeError> {
    if !valid_identity(
        &request.organization_id,
        &request.secret_id,
        &request.provider,
        &request.purpose,
    ) || request.plaintext_b64.len() > MAX_SECRET_BYTES.div_ceil(3) * 4
    {
        return Err(IntegrationSecretEnvelopeError::InvalidSecret);
    }
    let plaintext = STANDARD
        .decode(&request.plaintext_b64)
        .map_err(|_| IntegrationSecretEnvelopeError::InvalidSecret)?;
    if plaintext.len() > MAX_SECRET_BYTES {
        return Err(IntegrationSecretEnvelopeError::InvalidSecret);
    }
    serde_json::to_vec(&BoundSecret {
        schema: SCHEMA.into(),
        organization_id: request.organization_id.clone(),
        secret_id: request.secret_id.clone(),
        provider: request.provider.clone(),
        purpose: request.purpose.clone(),
        plaintext_b64: STANDARD.encode(plaintext),
    })
    .map_err(|_| IntegrationSecretEnvelopeError::InvalidSecret)
}

fn validate(
    request: &DecryptRequest,
    plaintext: &[u8],
) -> Result<Value, IntegrationSecretEnvelopeError> {
    if plaintext.len() > MAX_ENVELOPE_BYTES {
        return Err(IntegrationSecretEnvelopeError::DecryptFailed);
    }
    let bound: BoundSecret = serde_json::from_slice(plaintext)
        .map_err(|_| IntegrationSecretEnvelopeError::DecryptFailed)?;
    if bound.schema != SCHEMA
        || bound.organization_id != request.organization_id
        || bound.secret_id != request.secret_id
        || bound.provider != request.provider
        || bound.purpose != request.purpose
    {
        return Err(IntegrationSecretEnvelopeError::BindingMismatch);
    }
    let secret = STANDARD
        .decode(bound.plaintext_b64)
        .map_err(|_| IntegrationSecretEnvelopeError::DecryptFailed)?;
    if secret.len() > MAX_SECRET_BYTES {
        return Err(IntegrationSecretEnvelopeError::DecryptFailed);
    }
    Ok(json!({"plaintext_b64": STANDARD.encode(secret)}))
}

fn ciphertext(request: &DecryptRequest) -> Result<String, IntegrationSecretEnvelopeError> {
    if !valid_identity(
        &request.organization_id,
        &request.secret_id,
        &request.provider,
        &request.purpose,
    ) {
        return Err(IntegrationSecretEnvelopeError::InvalidSecret);
    }
    let envelope: StoredEnvelope = serde_json::from_value(request.envelope.clone())
        .map_err(|_| IntegrationSecretEnvelopeError::InvalidEnvelope)?;
    if envelope.schema != SCHEMA
        || !(envelope.ciphertext.starts_with("vault:v")
            || mmf_aws_kms::decode_ciphertext(&envelope.ciphertext).is_ok())
        || envelope.ciphertext.len() > MAX_CIPHERTEXT_BYTES
    {
        return Err(IntegrationSecretEnvelopeError::InvalidEnvelope);
    }
    Ok(envelope.ciphertext)
}

pub async fn encrypt(
    provider: &IntegrationSecretProvider,
    request: EncryptRequest,
) -> Result<Value, IntegrationSecretEnvelopeError> {
    let plaintext = prepare(&request)?;
    let ciphertext = match provider {
        IntegrationSecretProvider::OpenBao(provider) => {
            encrypt_openbao(provider, &plaintext).await?
        }
        IntegrationSecretProvider::Aws(key) => {
            require_aws_plaintext_size(&plaintext)?;
            let encrypted = key
                .encrypt(&plaintext, &aws_context())
                .await
                .map_err(|_| IntegrationSecretEnvelopeError::EncryptFailed)?;
            mmf_aws_kms::encode_ciphertext(&encrypted)
                .map_err(|_| IntegrationSecretEnvelopeError::EncryptFailed)?
        }
    };
    Ok(json!(StoredEnvelope {
        schema: SCHEMA.into(),
        ciphertext,
    }))
}

fn require_aws_plaintext_size(plaintext: &[u8]) -> Result<(), IntegrationSecretEnvelopeError> {
    if plaintext.len() > AWS_MAX_BOUND_PLAINTEXT_BYTES {
        return Err(IntegrationSecretEnvelopeError::CapabilityUnavailable(
            "AWS KMS integration-secret encryption supports a bound envelope of at most 4096 bytes.",
        ));
    }
    Ok(())
}

async fn encrypt_openbao(
    provider: &OpenBaoEnvelopeProvider,
    plaintext: &[u8],
) -> Result<String, IntegrationSecretEnvelopeError> {
    require_non_exportable_key(provider).await?;
    let response = provider
        .post(
            &format!("/v1/transit/encrypt/{KEY_ID}"),
            json!({"plaintext": STANDARD.encode(plaintext)}),
        )
        .await
        .map_err(|_| IntegrationSecretEnvelopeError::EncryptFailed)?;
    let ciphertext = response
        .pointer("/data/ciphertext")
        .and_then(Value::as_str)
        .filter(|value| value.starts_with("vault:v") && value.len() <= MAX_CIPHERTEXT_BYTES)
        .ok_or(IntegrationSecretEnvelopeError::EncryptFailed)?;
    Ok(ciphertext.into())
}

pub async fn decrypt(
    provider: &IntegrationSecretProvider,
    request: DecryptRequest,
) -> Result<Value, IntegrationSecretEnvelopeError> {
    let ciphertext = ciphertext(&request)?;
    let plaintext = match provider {
        IntegrationSecretProvider::OpenBao(provider) => {
            if !ciphertext.starts_with("vault:v") {
                return Err(IntegrationSecretEnvelopeError::InvalidEnvelope);
            }
            decrypt_openbao(provider, &ciphertext).await?
        }
        IntegrationSecretProvider::Aws(key) => {
            let ciphertext = mmf_aws_kms::decode_ciphertext(&ciphertext)
                .map_err(|_| IntegrationSecretEnvelopeError::InvalidEnvelope)?;
            key.decrypt(&ciphertext, &aws_context())
                .await
                .map_err(|_| IntegrationSecretEnvelopeError::DecryptFailed)?
        }
    };
    validate(&request, &plaintext)
}

async fn decrypt_openbao(
    provider: &OpenBaoEnvelopeProvider,
    ciphertext: &str,
) -> Result<Vec<u8>, IntegrationSecretEnvelopeError> {
    require_non_exportable_key(provider).await?;
    let response = provider
        .post(
            &format!("/v1/transit/decrypt/{KEY_ID}"),
            json!({"ciphertext": ciphertext}),
        )
        .await
        .map_err(|_| IntegrationSecretEnvelopeError::DecryptFailed)?;
    let plaintext = response
        .pointer("/data/plaintext")
        .and_then(Value::as_str)
        .ok_or(IntegrationSecretEnvelopeError::DecryptFailed)
        .and_then(|value| {
            STANDARD
                .decode(value)
                .map_err(|_| IntegrationSecretEnvelopeError::DecryptFailed)
        })?;
    Ok(plaintext)
}

async fn require_non_exportable_key(
    provider: &OpenBaoEnvelopeProvider,
) -> Result<(), IntegrationSecretEnvelopeError> {
    let metadata = provider
        .get(&format!("/v1/transit/keys/{KEY_ID}"))
        .await
        .map_err(|_| IntegrationSecretEnvelopeError::Unavailable)?;
    if !non_exportable_aes256_key(&metadata) {
        return Err(IntegrationSecretEnvelopeError::Unavailable);
    }
    Ok(())
}

fn non_exportable_aes256_key(metadata: &Value) -> bool {
    metadata.pointer("/data/type").and_then(Value::as_str) == Some("aes256-gcm96")
        && metadata
            .pointer("/data/exportable")
            .and_then(Value::as_bool)
            == Some(false)
        && metadata
            .pointer("/data/allow_plaintext_backup")
            .and_then(Value::as_bool)
            == Some(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mmf_aws_kms::{AwsAuth, AwsKmsConfig};

    const AWS_KEY: &str =
        "arn:aws:kms:us-east-2:123456789012:key/11111111-1111-1111-1111-111111111111";

    fn request() -> EncryptRequest {
        EncryptRequest {
            organization_id: "org-1".into(),
            secret_id: "secret-1".into(),
            provider: "canvas".into(),
            purpose: "oauth_client_secret".into(),
            plaintext_b64: STANDARD.encode("test-secret"),
        }
    }

    #[test]
    fn decrypted_value_is_bound_to_all_four_identity_fields() {
        let input = request();
        let bound = prepare(&input).unwrap();
        let mut decrypt = DecryptRequest {
            organization_id: input.organization_id,
            secret_id: input.secret_id,
            provider: input.provider,
            purpose: input.purpose,
            envelope: json!({"schema": SCHEMA, "ciphertext": "vault:v1:synthetic"}),
        };
        assert_eq!(
            validate(&decrypt, &bound).unwrap(),
            json!({"plaintext_b64": STANDARD.encode("test-secret")})
        );
        for changed in ["organization", "id", "provider", "purpose"] {
            match changed {
                "organization" => decrypt.organization_id = "org-2".into(),
                "id" => decrypt.secret_id = "secret-2".into(),
                "provider" => decrypt.provider = "other".into(),
                _ => decrypt.purpose = "other".into(),
            }
            assert!(matches!(
                validate(&decrypt, &bound),
                Err(IntegrationSecretEnvelopeError::BindingMismatch)
            ));
            decrypt.organization_id = "org-1".into();
            decrypt.secret_id = "secret-1".into();
            decrypt.provider = "canvas".into();
            decrypt.purpose = "oauth_client_secret".into();
        }
    }

    #[test]
    fn invalid_value_and_envelope_are_rejected() {
        let mut input = request();
        input.plaintext_b64 = "%%%".into();
        assert!(prepare(&input).is_err());
        input.plaintext_b64 = STANDARD.encode(vec![0; MAX_SECRET_BYTES + 1]);
        assert!(prepare(&input).is_err());
        let mut decrypt = DecryptRequest {
            organization_id: "org-1".into(),
            secret_id: "secret-1".into(),
            provider: "canvas".into(),
            purpose: "oauth_client_secret".into(),
            envelope: json!({"schema": SCHEMA, "ciphertext": "vault:v1:synthetic"}),
        };
        assert_eq!(ciphertext(&decrypt).unwrap(), "vault:v1:synthetic");
        for invalid in [
            json!({"schema": "unknown", "ciphertext": "vault:v1:synthetic"}),
            json!({"schema": SCHEMA, "ciphertext": "raw-key"}),
            json!({"schema": SCHEMA, "ciphertext": "vault:v1:synthetic", "key": "private"}),
        ] {
            decrypt.envelope = invalid;
            assert!(matches!(
                ciphertext(&decrypt),
                Err(IntegrationSecretEnvelopeError::InvalidEnvelope)
            ));
        }
    }

    #[test]
    fn aws_limit_covers_the_complete_bound_document_without_reducing_transit_limit() {
        let mut request = request();
        request.plaintext_b64 = STANDARD.encode(vec![0; MAX_SECRET_BYTES]);
        let bound = prepare(&request).unwrap();
        assert!(matches!(
            require_aws_plaintext_size(&bound),
            Err(IntegrationSecretEnvelopeError::CapabilityUnavailable(_))
        ));
        assert!(require_aws_plaintext_size(&vec![0; 4096]).is_ok());
        assert!(matches!(
            require_aws_plaintext_size(&vec![0; 4097]),
            Err(IntegrationSecretEnvelopeError::CapabilityUnavailable(_))
        ));
    }

    #[tokio::test]
    async fn configured_provider_never_follows_the_stored_ciphertext_tag() {
        let openbao = IntegrationSecretProvider::OpenBao(
            OpenBaoEnvelopeProvider::new("http://127.0.0.1:1", "synthetic-token").unwrap(),
        );
        let aws = IntegrationSecretProvider::Aws(
            AwsKmsKey::connect(
                AwsKmsConfig {
                    region: "us-east-2".into(),
                    authentication: AwsAuth::AccessKey {
                        access_key_id: "synthetic-access".into(),
                        secret_access_key: "synthetic-secret".into(),
                        session_token: None,
                    },
                    endpoint: Some("http://127.0.0.1:1".into()),
                    request_timeout: Duration::from_secs(1),
                },
                AWS_KEY.into(),
            )
            .await
            .unwrap(),
        );
        let decrypt_request = |ciphertext: String| DecryptRequest {
            organization_id: "org-1".into(),
            secret_id: "secret-1".into(),
            provider: "canvas".into(),
            purpose: "oauth_client_secret".into(),
            envelope: json!({"schema": SCHEMA, "ciphertext": ciphertext}),
        };
        assert!(matches!(
            decrypt(
                &openbao,
                decrypt_request(mmf_aws_kms::encode_ciphertext(b"opaque").unwrap())
            )
            .await,
            Err(IntegrationSecretEnvelopeError::InvalidEnvelope)
        ));
        assert!(matches!(
            decrypt(&aws, decrypt_request("vault:v1:opaque".into())).await,
            Err(IntegrationSecretEnvelopeError::InvalidEnvelope)
        ));
        let mut too_large = request();
        too_large.plaintext_b64 = STANDARD.encode(vec![0; 4096]);
        assert!(matches!(
            encrypt(&aws, too_large).await,
            Err(IntegrationSecretEnvelopeError::CapabilityUnavailable(_))
        ));
    }

    #[test]
    fn key_metadata_must_prove_non_exportable_aes() {
        let valid = json!({"data": {
            "type": "aes256-gcm96", "exportable": false,
            "allow_plaintext_backup": false
        }});
        assert!(non_exportable_aes256_key(&valid));
        for changed in [
            json!({"data": {"type": "aes256-gcm96", "exportable": true, "allow_plaintext_backup": false}}),
            json!({"data": {"type": "aes256-gcm96", "exportable": false, "allow_plaintext_backup": true}}),
            json!({"data": {"type": "ecdsa-p256", "exportable": false, "allow_plaintext_backup": false}}),
            json!({"data": {"type": "aes256-gcm96", "exportable": false}}),
        ] {
            assert!(!non_exportable_aes256_key(&changed));
        }
    }
}
