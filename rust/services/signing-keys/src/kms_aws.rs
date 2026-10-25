//! AWS remote KMS adapter.
use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AwsAccessKey {
    pub(super) access_key_id: String,
    pub(super) secret_access_key: String,
    #[serde(default)]
    pub(super) session_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AwsAssumeRole {
    pub(super) role_arn: String,
    #[serde(default)]
    pub(super) external_id: Option<String>,
}

pub(super) enum AwsAuth {
    IamRole,
    AccessKey(AwsAccessKey),
    AssumeRole(AwsAssumeRole),
}

pub(super) fn parse_aws_auth(config: &Value) -> Result<AwsAuth, KmsError> {
    match string(config, "auth_mode").unwrap_or("iam_role") {
        "iam_role" => {
            if string(config, "auth_reference").is_some_and(|reference| !reference.is_empty()) {
                return Err(KmsError::InvalidConfig(
                    "AWS IAM role mode does not accept a credential reference.".into(),
                ));
            }
            Ok(AwsAuth::IamRole)
        }
        "access_key" => {
            let encoded = required(
                config,
                "auth_reference",
                "AWS access key credential is required",
            )?;
            if encoded.len() > 16_384 {
                return Err(KmsError::InvalidConfig(
                    "AWS access key credential is invalid.".into(),
                ));
            }
            let credential: AwsAccessKey = serde_json::from_str(encoded).map_err(|_| {
                KmsError::InvalidConfig("AWS access key credential is invalid.".into())
            })?;
            if credential.access_key_id.trim().is_empty()
                || credential.secret_access_key.trim().is_empty()
            {
                return Err(KmsError::InvalidConfig(
                    "AWS access key credential is invalid.".into(),
                ));
            }
            Ok(AwsAuth::AccessKey(credential))
        }
        "assume_role" => {
            let encoded = required(config, "auth_reference", "AWS role reference is required")?;
            if encoded.len() > 4096 {
                return Err(KmsError::InvalidConfig(
                    "AWS role reference is invalid.".into(),
                ));
            }
            let role: AwsAssumeRole = serde_json::from_str(encoded)
                .map_err(|_| KmsError::InvalidConfig("AWS role reference is invalid.".into()))?;
            if !valid_aws_role_arn(&role.role_arn) {
                return Err(KmsError::InvalidConfig("AWS role ARN is invalid.".into()));
            }
            Ok(AwsAuth::AssumeRole(role))
        }
        _ => Err(KmsError::InvalidConfig(
            "AWS authentication mode is unsupported.".into(),
        )),
    }
}

pub(crate) fn validate_aws_auth_config(config: &Value) -> Result<(), KmsError> {
    parse_aws_auth(config).map(|_| ())
}

pub(super) fn aws_role_source(
    loader: aws_config::ConfigLoader,
) -> Result<aws_config::ConfigLoader, KmsError> {
    let present = |name: &str| env::var(name).is_ok_and(|value| !value.trim().is_empty());
    let web_identity = present("AWS_WEB_IDENTITY_TOKEN_FILE") || present("AWS_ROLE_ARN");
    if web_identity {
        if !present("AWS_WEB_IDENTITY_TOKEN_FILE") || !present("AWS_ROLE_ARN") {
            return Err(KmsError::InvalidConfig(
                "AWS workload role identity is incomplete.".into(),
            ));
        }
        return Ok(loader.credentials_provider(
            aws_config::web_identity_token::WebIdentityTokenCredentialsProvider::builder().build(),
        ));
    }
    if present("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
        || present("AWS_CONTAINER_CREDENTIALS_FULL_URI")
    {
        return Ok(
            loader.credentials_provider(aws_config::ecs::EcsCredentialsProvider::builder().build())
        );
    }
    if env::var("AWS_EC2_METADATA_DISABLED").is_ok_and(|value| value.eq_ignore_ascii_case("true")) {
        return Err(KmsError::InvalidConfig(
            "AWS IAM role identity is unavailable.".into(),
        ));
    }
    Ok(loader.credentials_provider(
        aws_config::imds::credentials::ImdsCredentialsProvider::builder().build(),
    ))
}

pub(super) async fn aws_client(config: &Value) -> Result<aws_sdk_kms::Client, KmsError> {
    let region = aws_region(config)?.to_string();
    let mut loader =
        aws_config::defaults(BehaviorVersion::latest()).region(Region::new(region.clone()));
    if let Some(endpoint) = string(config, "endpoint").filter(|value| !value.is_empty()) {
        loader = loader.endpoint_url(endpoint);
        if endpoint.starts_with("http://") {
            loader = loader.http_client(aws_smithy_http_client::Builder::new().build_http());
        }
    }
    let sdk_config = match parse_aws_auth(config)? {
        AwsAuth::IamRole => aws_role_source(loader)?.load().await,
        AwsAuth::AccessKey(credential) => {
            loader
                .credentials_provider(Credentials::new(
                    credential.access_key_id,
                    credential.secret_access_key,
                    credential.session_token,
                    None,
                    "marty-tenant-credential",
                ))
                .load()
                .await
        }
        AwsAuth::AssumeRole(role) => {
            let source = aws_role_source(
                aws_config::defaults(BehaviorVersion::latest()).region(Region::new(region)),
            )?
            .load()
            .await;
            let mut builder = aws_config::sts::AssumeRoleProvider::builder(role.role_arn)
                .session_name("marty-signing-keys")
                .configure(&source);
            if let Some(external_id) = role.external_id.filter(|value| !value.is_empty()) {
                builder = builder.external_id(external_id);
            }
            loader
                .credentials_provider(builder.build().await)
                .load()
                .await
        }
    };
    Ok(aws_sdk_kms::Client::new(&sdk_config))
}

pub(super) fn aws_region(config: &Value) -> Result<&str, KmsError> {
    let region = string(config, "region")
        .filter(|value| !value.is_empty())
        .unwrap_or("us-east-1");
    if region.len() > 64
        || !region
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || !region
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_lowercase)
        || !region.as_bytes().last().is_some_and(u8::is_ascii_digit)
    {
        return Err(KmsError::InvalidConfig("AWS region is invalid.".into()));
    }
    Ok(region)
}

pub(super) fn valid_aws_role_arn(value: &str) -> bool {
    let parts = value.split(':').collect::<Vec<_>>();
    parts.len() == 6
        && parts[0] == "arn"
        && matches!(parts[1], "aws" | "aws-us-gov" | "aws-cn")
        && parts[2] == "iam"
        && parts[3].is_empty()
        && parts[4].len() == 12
        && parts[4].bytes().all(|byte| byte.is_ascii_digit())
        && parts[5].starts_with("role/")
        && parts[5].len() > 5
        && !value.chars().any(char::is_whitespace)
}

pub(crate) fn aws_key_arn(config: &Value) -> Result<&str, KmsError> {
    let reference = required(
        config,
        "key_reference",
        "AWS KMS requires a key ARN, not a movable alias or key ID.",
    )?;
    let parts: Vec<_> = reference.split(':').collect();
    let valid = parts.len() == 6
        && parts[0] == "arn"
        && matches!(parts[1], "aws" | "aws-us-gov" | "aws-cn")
        && parts[2] == "kms"
        && parts[3] == aws_region(config)?
        && parts[4].len() == 12
        && parts[4].bytes().all(|byte| byte.is_ascii_digit())
        && parts[5].strip_prefix("key/").is_some_and(|key| {
            !key.is_empty()
                && key
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        });
    if !valid {
        return Err(KmsError::InvalidConfig(
            "AWS KMS key reference must be a key ARN in the configured region.".into(),
        ));
    }
    Ok(reference)
}

pub(super) async fn sign_aws(config: &Value, payload: &[u8]) -> Result<Vec<u8>, KmsError> {
    let key_id = aws_key_arn(config)?;
    let jose_algorithm = string(config, "algorithm").unwrap_or("ES256");
    let algorithm = aws_signing_algorithm(jose_algorithm)?;
    if string(config, "aws_signing_algorithm").is_some_and(|configured| configured != algorithm) {
        return Err(KmsError::InvalidConfig(format!(
            "AWS signing algorithm must be {algorithm} for {jose_algorithm}."
        )));
    }
    // AWS KMS caps RAW messages at 4096 bytes. Its DIGEST mode signs the
    // pre-hashed input without hashing it a second time.
    let (_, digest) = signing_digest(jose_algorithm, payload)?;
    let output = aws_client(config)
        .await?
        .sign()
        .key_id(key_id)
        .message(Blob::new(digest))
        .message_type(MessageType::Digest)
        .signing_algorithm(SigningAlgorithmSpec::from(algorithm))
        .send()
        .await
        .map_err(|_| KmsError::Provider("AWS KMS sign failed.".into()))?;
    require_aws_response_key(output.key_id(), key_id)?;
    if output.signing_algorithm().map(|value| value.as_str()) != Some(algorithm) {
        return Err(KmsError::InvalidResponse(
            "AWS KMS sign response algorithm did not match the requested algorithm.".into(),
        ));
    }
    output
        .signature()
        .map(|signature| signature.as_ref().to_vec())
        .ok_or_else(|| {
            KmsError::InvalidResponse(
                "AWS KMS sign response did not include binary Signature".to_string(),
            )
        })
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

pub(super) fn require_aws_response_key(
    actual: Option<&str>,
    expected: &str,
) -> Result<(), KmsError> {
    if actual == Some(expected) {
        Ok(())
    } else {
        Err(KmsError::InvalidResponse(
            "AWS KMS response key ARN did not match the pinned key.".into(),
        ))
    }
}

pub(super) async fn public_key_aws(config: &Value) -> Result<Value, KmsError> {
    let key_id = aws_key_arn(config)?;
    let output = aws_client(config)
        .await?
        .get_public_key()
        .key_id(key_id)
        .send()
        .await
        .map_err(|_| KmsError::Provider("AWS KMS get public key failed.".into()))?;
    require_aws_response_key(output.key_id(), key_id)?;
    let der = output
        .public_key()
        .map(|value| value.as_ref())
        .unwrap_or_default();
    let public_jwk = jwk_value(
        public_key_der_to_jwk(der).map_err(|error| {
            KmsError::InvalidResponse(format!("AWS returned an invalid public key: {error}"))
        })?,
        key_id,
    )?;
    Ok(json!({
        "provider": "aws",
        "key_reference": key_id,
        "public_key_der_b64": STANDARD.encode(der),
        "signing_algorithms": output.signing_algorithms().iter().map(|value| value.as_str()).collect::<Vec<_>>(),
        "key_spec": output.key_spec().map(|value| value.as_str()),
        "key_usage": output.key_usage().map(|value| value.as_str()),
        "public_jwk": public_jwk,
    }))
}

pub(super) async fn verify_aws(config: &Value) -> CapabilityResult {
    let key_id = match aws_key_arn(config) {
        Ok(value) => value,
        Err(error) => return CapabilityResult::fail("Key reference", error.to_string()),
    };
    let mut result = CapabilityResult::ok();
    let client = match aws_client(config).await {
        Ok(client) => client,
        Err(error) => return CapabilityResult::fail("Authentication", error.to_string()),
    };
    match client.describe_key().key_id(key_id).send().await {
        Ok(output) if output.key_metadata().and_then(|metadata| metadata.arn()) == Some(key_id) => {
            result.add_check(
                "Key exists",
                "pass",
                format!("AWS KMS key '{key_id}' is reachable."),
            )
        }
        Ok(_) => result.add_check(
            "Key exists",
            "fail",
            "AWS KMS returned metadata for a different key.",
        ),
        Err(_) => result.add_check("Connectivity", "fail", "AWS KMS verification failed."),
    }
    result
}
