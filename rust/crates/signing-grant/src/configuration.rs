//! Trusted platform selection for signing-grant authority.
//!
//! This is deployment configuration for seven fixed authorization origins,
//! not a tenant key registry. Tenant requests cannot alter these bindings.

use std::{
    collections::BTreeSet,
    fs::File,
    io::Read as _,
    path::{Path, PathBuf},
};

use serde::Deserialize;

use crate::{
    aws::AwsGrantClient, minter::GrantMinter, provider::GrantProviderError,
    replay::RedisGrantReplayStore, verifier::GrantVerifier, SigningOrigin,
};

const MAX_CONFIG_BYTES: u64 = 16 * 1024;
const AWS_SCHEMA: &str = "marty.aws-signing-grant-authorities/v1";

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwsGrantConfiguration {
    schema: String,
    region: String,
    keys: AwsOriginKeys,
}

// A closed struct rejects duplicate/unknown origin fields during decoding.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct AwsOriginKeys {
    gateway_service: String,
    gateway_issuer_did: String,
    flow_wallet_request: String,
    issuance_credential: String,
    issuance_canvas: String,
    issuance_readiness: String,
    issuance_passport: String,
}

impl AwsGrantConfiguration {
    pub fn decode(bytes: &[u8]) -> Result<Self, GrantProviderError> {
        if bytes.len() > MAX_CONFIG_BYTES as usize {
            return Err(GrantProviderError::InvalidConfig);
        }
        let config: Self =
            serde_json::from_slice(bytes).map_err(|_| GrantProviderError::InvalidConfig)?;
        if config.schema != AWS_SCHEMA {
            return Err(GrantProviderError::InvalidConfig);
        }
        let mut unique = BTreeSet::new();
        for origin in SigningOrigin::ALL {
            let key = config.key_arn(origin);
            mmf_aws_kms::validate_key_arn(key, &config.region)
                .map_err(|_| GrantProviderError::InvalidConfig)?;
            if !unique.insert(key) {
                return Err(GrantProviderError::InvalidConfig);
            }
        }
        Ok(config)
    }

    fn read(path: &Path) -> Result<Self, GrantProviderError> {
        if !path.is_absolute() {
            return Err(GrantProviderError::InvalidConfig);
        }
        let file = File::open(path).map_err(|_| GrantProviderError::InvalidConfig)?;
        let metadata = file
            .metadata()
            .map_err(|_| GrantProviderError::InvalidConfig)?;
        if !metadata.is_file() || metadata.len() > MAX_CONFIG_BYTES {
            return Err(GrantProviderError::InvalidConfig);
        }
        let mut bytes = Vec::new();
        file.take(MAX_CONFIG_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| GrantProviderError::InvalidConfig)?;
        Self::decode(&bytes)
    }

    fn key_arn(&self, origin: SigningOrigin) -> &str {
        match origin {
            SigningOrigin::GatewayService => &self.keys.gateway_service,
            SigningOrigin::GatewayIssuerDid => &self.keys.gateway_issuer_did,
            SigningOrigin::FlowWalletRequest => &self.keys.flow_wallet_request,
            SigningOrigin::IssuanceCredential => &self.keys.issuance_credential,
            SigningOrigin::IssuanceCanvas => &self.keys.issuance_canvas,
            SigningOrigin::IssuanceReadiness => &self.keys.issuance_readiness,
            SigningOrigin::IssuancePassport => &self.keys.issuance_passport,
        }
    }

    pub(crate) fn client(
        &self,
        origin: SigningOrigin,
    ) -> Result<AwsGrantClient, GrantProviderError> {
        AwsGrantClient::new(origin, self.region.clone(), self.key_arn(origin).into())
    }
}

#[derive(Clone)]
pub enum GrantAuthority {
    OpenBao,
    Aws(Box<AwsGrantConfiguration>),
}

impl GrantAuthority {
    pub fn from_environment() -> Result<Self, GrantProviderError> {
        let provider = match std::env::var("MARTY_SIGNING_GRANT_PROVIDER") {
            Ok(value) => Some(value),
            Err(std::env::VarError::NotPresent) => None,
            Err(_) => return Err(GrantProviderError::InvalidConfig),
        };
        let config = std::env::var_os("MARTY_SIGNING_GRANT_AWS_CONFIG_FILE").map(PathBuf::from);
        Self::from_selection(provider.as_deref(), config.as_deref())
    }

    pub fn from_selection(
        provider: Option<&str>,
        aws_config_file: Option<&Path>,
    ) -> Result<Self, GrantProviderError> {
        match provider {
            None | Some("openbao-transit") if aws_config_file.is_none() => Ok(Self::OpenBao),
            Some("aws-kms") => Ok(Self::Aws(Box::new(AwsGrantConfiguration::read(
                aws_config_file.ok_or(GrantProviderError::InvalidConfig)?,
            )?))),
            _ => Err(GrantProviderError::InvalidConfig),
        }
    }

    pub fn is_openbao(&self) -> bool {
        matches!(self, Self::OpenBao)
    }

    pub fn minter(
        &self,
        origin: SigningOrigin,
        openbao_endpoint: Option<&str>,
        openbao_token_file: Option<PathBuf>,
    ) -> Result<GrantMinter, GrantProviderError> {
        match self {
            Self::OpenBao => GrantMinter::for_managed_openbao(
                openbao_endpoint.ok_or(GrantProviderError::InvalidConfig)?,
                origin,
                openbao_token_file.ok_or(GrantProviderError::InvalidConfig)?,
            ),
            Self::Aws(config) => Ok(GrantMinter::for_aws(config.client(origin)?)),
        }
    }

    pub fn verifier(
        &self,
        openbao_endpoint: Option<&str>,
        openbao_token_file: Option<PathBuf>,
        replay: RedisGrantReplayStore,
    ) -> Result<GrantVerifier, GrantProviderError> {
        match self {
            Self::OpenBao => GrantVerifier::for_managed_openbao(
                openbao_endpoint.ok_or(GrantProviderError::InvalidConfig)?,
                openbao_token_file.ok_or(GrantProviderError::InvalidConfig)?,
                replay,
            ),
            Self::Aws(config) => GrantVerifier::for_aws(config, replay),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use serde_json::{json, Value};

    use super::*;

    fn config() -> Value {
        let keys: serde_json::Map<String, Value> = SigningOrigin::ALL
            .into_iter()
            .enumerate()
            .map(|(index, origin)| {
                let name = serde_json::to_value(origin)
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_owned();
                (
                    name,
                    json!(format!(
                        "arn:aws:kms:us-east-2:111122223333:key/key-{index}"
                    )),
                )
            })
            .collect();
        json!({"schema": AWS_SCHEMA, "region":"us-east-2", "keys":keys})
    }

    fn decode(value: &Value) -> Result<AwsGrantConfiguration, GrantProviderError> {
        AwsGrantConfiguration::decode(&serde_json::to_vec(value).unwrap())
    }

    #[test]
    fn all_seven_origins_need_distinct_immutable_regional_keys() {
        let value = config();
        assert!(decode(&value).is_ok());
        let mut changed = value.clone();
        changed["keys"]["flow_wallet_request"] = changed["keys"]["gateway_service"].clone();
        assert!(decode(&changed).is_err());
        let mut changed = value.clone();
        changed["keys"]
            .as_object_mut()
            .unwrap()
            .remove("issuance_passport");
        assert!(decode(&changed).is_err());
        for invalid in [
            "arn:aws:kms:us-east-2:111122223333:alias/movable",
            "arn:aws:kms:us-west-2:111122223333:key/wrong-region",
            "not-an-arn",
        ] {
            let mut changed = value.clone();
            changed["keys"]["gateway_service"] = json!(invalid);
            assert!(decode(&changed).is_err());
        }
        let mut changed = value;
        changed["auth_reference"] = json!("never-accepted");
        assert!(decode(&changed).is_err());
    }

    #[test]
    fn unknown_and_duplicate_origin_fields_are_rejected() {
        let value = config();
        let mut changed = value.clone();
        changed["keys"]["other_origin"] = json!("unused");
        assert!(decode(&changed).is_err());
        let bytes = serde_json::to_string(&value).unwrap();
        let duplicate = bytes.replacen(
            "\"gateway_service\":",
            "\"gateway_service\":\"arn:aws:kms:us-east-2:111122223333:key/other\",\"gateway_service\":",
            1,
        );
        assert!(AwsGrantConfiguration::decode(duplicate.as_bytes()).is_err());
    }

    #[test]
    fn selection_is_explicit_and_cannot_fall_back_after_configuration_error() {
        assert!(GrantAuthority::from_selection(None, None)
            .unwrap()
            .is_openbao());
        assert!(GrantAuthority::from_selection(Some("aws-kms"), None).is_err());
        assert!(GrantAuthority::from_selection(Some("unknown"), None).is_err());
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&serde_json::to_vec(&config()).unwrap())
            .unwrap();
        assert!(GrantAuthority::from_selection(None, Some(file.path())).is_err());
        let aws = GrantAuthority::from_selection(Some("aws-kms"), Some(file.path())).unwrap();
        assert!(!aws.is_openbao());
        assert!(aws
            .minter(SigningOrigin::GatewayService, None, None)
            .is_ok());
    }
}
