//! Configuration selection shared by existing remote secret-envelope owners.

use std::time::Duration;

use mmf_aws_kms::{validate_key_arn, AwsAuth, AwsKmsConfig};

/// A provider is selected by trusted deployment settings, never ciphertext.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SecretKmsSelection {
    OpenBao,
    AwsKms {
        config: AwsKmsConfig,
        key_arn: String,
    },
}

pub struct SecretKmsNames<'a> {
    pub prefix: &'a str,
    /// Only settings dedicated to this envelope belong here. Shared OpenBao
    /// settings may still serve another operation in a hybrid deployment.
    pub openbao_fields: &'a [&'a str],
}

impl SecretKmsSelection {
    pub fn from_values<'a>(
        get: impl Fn(&str) -> Option<&'a str>,
        names: SecretKmsNames<'_>,
        request_timeout: Duration,
    ) -> Result<Self, String> {
        let provider_name = format!("{}_KMS_PROVIDER", names.prefix);
        let region_name = format!("{}_AWS_REGION", names.prefix);
        let arn_name = format!("{}_AWS_KEY_ARN", names.prefix);
        match (get(&provider_name), get(&region_name), get(&arn_name)) {
            (None | Some("openbao-transit"), None, None) => Ok(Self::OpenBao),
            (Some("aws-kms"), Some(region), Some(key_arn)) => {
                if names.openbao_fields.iter().any(|name| get(name).is_some()) {
                    return Err(format!(
                        "{} cannot mix AWS and dedicated OpenBao secret settings",
                        names.prefix
                    ));
                }
                validate_key_arn(key_arn, region).map_err(|_| {
                    format!("{arn_name} must be an immutable key ARN in {region_name}")
                })?;
                let config = AwsKmsConfig {
                    region: region.into(),
                    authentication: AwsAuth::IamRole,
                    endpoint: None,
                    request_timeout,
                };
                config
                    .validate()
                    .map_err(|_| format!("{} AWS secret settings are invalid", names.prefix))?;
                Ok(Self::AwsKms {
                    config,
                    key_arn: key_arn.into(),
                })
            }
            _ => Err(format!(
                "{provider_name} must select openbao-transit or a complete aws-kms identity"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    const ARN: &str = "arn:aws:kms:us-east-2:111122223333:key/existing-envelope";

    fn selection(values: &BTreeMap<&str, &str>) -> Result<SecretKmsSelection, String> {
        SecretKmsSelection::from_values(
            |name| values.get(name).copied(),
            SecretKmsNames {
                prefix: "NOTIFICATION_SECRET",
                openbao_fields: &[
                    "NOTIFICATION_OPENBAO_TOKEN",
                    "NOTIFICATION_OPENBAO_TOKEN_FILE",
                    "NOTIFICATION_OPENBAO_CA_CERT_FILE",
                ],
            },
            Duration::from_secs(8),
        )
    }

    fn aws() -> BTreeMap<&'static str, &'static str> {
        BTreeMap::from([
            ("NOTIFICATION_SECRET_KMS_PROVIDER", "aws-kms"),
            ("NOTIFICATION_SECRET_AWS_REGION", "us-east-2"),
            ("NOTIFICATION_SECRET_AWS_KEY_ARN", ARN),
        ])
    }

    #[test]
    fn explicit_aws_identity_is_iam_only_and_keeps_shared_hybrid_settings() {
        let mut values = aws();
        values.insert("BAO_ADDR", "https://openbao:8200");
        let SecretKmsSelection::AwsKms { config, key_arn } = selection(&values).unwrap() else {
            panic!("AWS selection was lost");
        };
        assert_eq!(key_arn, ARN);
        assert_eq!(config.authentication, AwsAuth::IamRole);
        assert_eq!(config.endpoint, None);
        assert_eq!(config.request_timeout, Duration::from_secs(8));
    }

    #[test]
    fn selection_rejects_ambiguous_missing_and_wrong_provider_fields() {
        assert_eq!(
            selection(&BTreeMap::new()).unwrap(),
            SecretKmsSelection::OpenBao
        );
        assert_eq!(
            selection(&BTreeMap::from([(
                "NOTIFICATION_SECRET_KMS_PROVIDER",
                "openbao-transit"
            )]))
            .unwrap(),
            SecretKmsSelection::OpenBao
        );
        for field in [
            "NOTIFICATION_SECRET_KMS_PROVIDER",
            "NOTIFICATION_SECRET_AWS_REGION",
            "NOTIFICATION_SECRET_AWS_KEY_ARN",
        ] {
            let mut values = aws();
            values.remove(field);
            assert!(selection(&values).is_err());
            values.insert(field, "");
            assert!(selection(&values).is_err());
        }
        for field in [
            "NOTIFICATION_OPENBAO_TOKEN",
            "NOTIFICATION_OPENBAO_TOKEN_FILE",
            "NOTIFICATION_OPENBAO_CA_CERT_FILE",
        ] {
            let mut values = aws();
            values.insert(field, "");
            assert!(selection(&values).is_err());
        }
        for (field, value) in [
            ("NOTIFICATION_SECRET_KMS_PROVIDER", "local"),
            ("NOTIFICATION_SECRET_KMS_PROVIDER", "openbao-transit"),
            ("NOTIFICATION_SECRET_AWS_KEY_ARN", "alias/envelope"),
            ("NOTIFICATION_SECRET_AWS_REGION", "us-west-2"),
        ] {
            let mut values = aws();
            values.insert(field, value);
            assert!(selection(&values).is_err());
        }
    }
}
