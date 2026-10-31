//! Tenant policy projection over the shared AWS KMS transport.
use super::*;

use mmf_aws_kms::{AwsAuth, AwsKmsConfig, AwsKmsError, AwsKmsKey, SigningAlgorithm};

pub(super) fn parse_aws_auth(config: &Value) -> Result<AwsAuth, KmsError> {
    AwsAuth::from_reference(
        string(config, "auth_mode").unwrap_or("iam_role"),
        string(config, "auth_reference").unwrap_or_default(),
    )
    .map_err(|_| KmsError::InvalidConfig("AWS authentication configuration is invalid.".into()))
}

pub(crate) fn validate_aws_auth_config(config: &Value) -> Result<(), KmsError> {
    parse_aws_auth(config).map(|_| ())
}

async fn aws_key(config: &Value) -> Result<AwsKmsKey, KmsError> {
    AwsKmsKey::connect(
        AwsKmsConfig {
            region: aws_region(config)?.into(),
            authentication: parse_aws_auth(config)?,
            endpoint: string(config, "endpoint")
                .filter(|value| !value.is_empty())
                .map(str::to_owned),
            request_timeout: HTTP_TIMEOUT,
        },
        aws_key_arn(config)?.into(),
    )
    .await
    .map_err(aws_error)
}

fn aws_error(error: AwsKmsError) -> KmsError {
    match error {
        AwsKmsError::InvalidConfiguration | AwsKmsError::InvalidInput => {
            KmsError::InvalidConfig("AWS KMS configuration or input is invalid.".into())
        }
        AwsKmsError::InvalidResponse | AwsKmsError::InvalidCiphertext => {
            KmsError::InvalidResponse("AWS KMS returned an invalid bound response.".into())
        }
        AwsKmsError::Unavailable | AwsKmsError::Timeout => {
            KmsError::Provider("AWS KMS operation failed.".into())
        }
    }
}

pub(super) fn aws_region(config: &Value) -> Result<&str, KmsError> {
    let region = string(config, "region")
        .filter(|value| !value.is_empty())
        .unwrap_or("us-east-1");
    mmf_aws_kms::validate_region(region)
        .map_err(|_| KmsError::InvalidConfig("AWS region is invalid.".into()))?;
    Ok(region)
}

pub(crate) fn aws_key_arn(config: &Value) -> Result<&str, KmsError> {
    let reference = required(
        config,
        "key_reference",
        "AWS KMS requires a key ARN, not a movable alias or key ID.",
    )?;
    mmf_aws_kms::validate_key_arn(reference, aws_region(config)?).map_err(|_| {
        KmsError::InvalidConfig(
            "AWS KMS key reference must be a key ARN in the configured region.".into(),
        )
    })?;
    Ok(reference)
}

pub(super) async fn sign_aws(config: &Value, payload: &[u8]) -> Result<Vec<u8>, KmsError> {
    aws_key_arn(config)?;
    let jose_algorithm = string(config, "algorithm").unwrap_or("ES256");
    let algorithm = aws_signing_algorithm(jose_algorithm)?;
    if string(config, "aws_signing_algorithm").is_some_and(|configured| configured != algorithm) {
        return Err(KmsError::InvalidConfig(format!(
            "AWS signing algorithm must be {algorithm} for {jose_algorithm}."
        )));
    }
    // JOSE payload preparation stays with Signing Keys. The shared transport
    // sends the exact digest using AWS DIGEST mode and binds the response.
    let (_, digest) = signing_digest(jose_algorithm, payload)?;
    aws_key(config)
        .await?
        .sign_digest(
            SigningAlgorithm::from_aws_name(algorithm).map_err(aws_error)?,
            &digest,
        )
        .await
        .map_err(aws_error)
}

pub(crate) fn aws_signing_algorithm(algorithm: &str) -> Result<&'static str, KmsError> {
    match algorithm {
        "ES256" => Ok("ECDSA_SHA_256"),
        "ES384" => Ok("ECDSA_SHA_384"),
        "ES512" => Ok("ECDSA_SHA_512"),
        "RS256" => Ok("RSASSA_PKCS1_V1_5_SHA_256"),
        "RS384" => Ok("RSASSA_PKCS1_V1_5_SHA_384"),
        "RS512" => Ok("RSASSA_PKCS1_V1_5_SHA_512"),
        "PS256" => Ok("RSASSA_PSS_SHA_256"),
        "PS384" => Ok("RSASSA_PSS_SHA_384"),
        "PS512" => Ok("RSASSA_PSS_SHA_512"),
        other => Err(KmsError::InvalidConfig(format!(
            "Unsupported AWS signing algorithm '{other}'."
        ))),
    }
}

pub(super) async fn public_key_aws(config: &Value) -> Result<Value, KmsError> {
    let key_id = aws_key_arn(config)?;
    let output = aws_key(config)
        .await?
        .public_key()
        .await
        .map_err(aws_error)?;
    let der = output.spki_der;
    let public_jwk = jwk_value(
        public_key_der_to_jwk(&der).map_err(|error| {
            KmsError::InvalidResponse(format!("AWS returned an invalid public key: {error}"))
        })?,
        key_id,
    )?;
    Ok(json!({
        "provider": "aws",
        "key_reference": key_id,
        "public_key_der_b64": STANDARD.encode(&der),
        "signing_algorithms": output.signing_algorithms,
        "key_spec": output.key_spec,
        "key_usage": output.key_usage,
        "public_jwk": public_jwk,
    }))
}

pub(super) async fn verify_aws(config: &Value) -> CapabilityResult {
    let key_id = match aws_key_arn(config) {
        Ok(value) => value,
        Err(error) => return CapabilityResult::fail("Key reference", error.to_string()),
    };
    let mut result = CapabilityResult::ok();
    let key = match aws_key(config).await {
        Ok(key) => key,
        Err(error) => return CapabilityResult::fail("Authentication", error.to_string()),
    };
    match key.metadata().await {
        Ok(metadata) => {
            if !metadata.enabled
                || metadata.key_state != "Enabled"
                || metadata.key_usage != "SIGN_VERIFY"
            {
                result.add_check(
                    "Signing key state",
                    "fail",
                    "AWS KMS key must be enabled with SIGN_VERIFY usage.",
                );
            } else {
                result.add_check(
                    "Key exists",
                    "pass",
                    format!("AWS KMS key '{key_id}' is reachable."),
                );
            }
        }
        Err(AwsKmsError::InvalidResponse) => result.add_check(
            "Key exists",
            "fail",
            "AWS KMS returned metadata for a different key.",
        ),
        Err(_) => result.add_check("Connectivity", "fail", "AWS KMS verification failed."),
    }
    result
}
