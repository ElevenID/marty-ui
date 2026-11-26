//! Closed workflow selections for the native, managed-PostgreSQL feature profile.
//! Infrastructure selection does not create a policy, human consent, credential,
//! application ownership or delegated authority. Those remain owner API writes.
#![cfg(target_os = "linux")]

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path, PathBuf},
};

type Result<T> = std::result::Result<T, String>;
const REFUSED: &str =
    "workflow feature selection or retained inputs are invalid; preserve installation evidence";
pub(crate) const CATALOG: &str = "feature_public_verification_catalog";
pub(crate) const HOLDER_MINT_TOKEN: &str = "feature_public_verification_holder_mint_token";
pub(crate) const PREREQUISITE_TOKEN: &str = "feature_flow_issuance_service_token";
pub(crate) const TRUST_CERTIFICATE: &str = "feature_trust_profile_server_cert";
pub(crate) const TRUST_TOKEN: &str = "feature_trust_profile_tls_kms_token";
pub(crate) const TRUST_KEY: &str = "feature-workload-tls-trust-profile-server";
pub(crate) const GRANT_VERIFY_TOKEN: &str = "feature_sign_grant_verify_token";
pub(crate) const SIGNING_CUSTODY_TOKEN: &str = "feature_signing_keys_openbao_token";
pub(crate) const SIGNING_READ_KEY: &str = "feature_signing_keys_read_key";
const SIGNING_READ_CONSUMERS: &[&str] = &[
    "gateway",
    "credential-template",
    "trust-profile",
    "issuance",
    "issuance-native",
    "presentation-policy",
    "signing-keys",
    "flow",
    "delegated-use",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Configuration {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_verification: Option<PublicVerification>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet_governance: Option<WalletGovernance>,
    #[serde(default)]
    pub verification_prerequisite: bool,
    #[serde(default)]
    pub application_ownership: bool,
    #[serde(default)]
    pub external_associations: bool,
    #[serde(default)]
    pub external_observations: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "activation", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum PublicVerification {
    /// No catalog is mounted and Flow continues to return its explicit
    /// unavailable response. This is not a completed verification journey.
    AwaitingOwnerConfiguration {},
    Configured {
        application_origin: String,
        catalog_file: PathBuf,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WalletGovernance {
    pub flow_producer_id: String,
}

/// Evidence bound by the native activation owner after authenticated owner API
/// provisioning. A file matching this shape alone is not remote qualification.
/// Generation creation and restart must retain this receipt and the exact
/// catalog bytes; neither may overwrite the initial profile or prior generation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PublicVerificationActivation {
    pub schema: String,
    pub installation_id: uuid::Uuid,
    pub feature_profile_sha256: String,
    pub catalog_sha256: String,
    pub owner_api_receipt_sha256: String,
    pub application_origin: String,
    pub organization_id: uuid::Uuid,
    pub principal_id: String,
}

fn require(value: bool) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
}

fn https_origin(value: &str) -> bool {
    url::Url::parse(value).is_ok_and(|url| {
        url.scheme() == "https"
            && url.has_host()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() == "/"
            && url.origin().ascii_serialization() == value
    })
}

fn private_path(path: &Path) -> bool {
    path.is_absolute()
        && path != Path::new("/")
        && path
            .components()
            .all(|v| matches!(v, Component::RootDir | Component::Normal(_)))
        && path.to_str().is_some_and(|text| {
            text.len() <= 4096
                && !text.ends_with('/')
                && !text
                    .chars()
                    .any(|c| c.is_control() || c == '\\' || c == '\'')
                && text
                    .split('/')
                    .skip(1)
                    .all(|p| !p.is_empty() && p != "." && p != "..")
        })
}

fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn bounded_catalog(raw: &[u8], origin: &str) -> Result<Value> {
    require(!raw.is_empty() && raw.len() <= 65_536)?;
    let value = crate::installer_json::decode(raw).map_err(|_| REFUSED)?;
    let object = value.as_object().ok_or(REFUSED)?;
    require(object.keys().all(|key| {
        matches!(
            key.as_str(),
            "catalog" | "principal_id" | "issuer_did" | "demo_holder_did" | "limits"
        )
    }))?;
    require(value["principal_id"].as_str().is_some_and(identifier))?;
    require(value["catalog"]["application_origin"].as_str() == Some(origin))?;
    require(
        value["catalog"]["organization_id"]
            .as_str()
            .is_some_and(|v| uuid::Uuid::parse_str(v).is_ok_and(|id| !id.is_nil())),
    )?;
    require(
        value["catalog"]["scenarios"]
            .as_array()
            .is_some_and(|v| (1..=8).contains(&v.len())),
    )?;
    require(value["issuer_did"].as_str().is_some_and(|v| {
        v.starts_with("did:")
            && v.len() <= 512
            && !v.chars().any(|c| c.is_whitespace() || c.is_control())
    }))?;
    for (key, maximum) in [
        ("starts_per_minute", 240),
        ("starts_per_day", 10_000),
        ("maximum_active", 1_000),
    ] {
        require(
            value["limits"][key]
                .as_u64()
                .is_some_and(|v| (1..=maximum).contains(&v)),
        )?;
    }
    // The Flow owner's PublicVerificationOptions remains the full catalog and
    // policy-reference validator. This boundary binds its private bytes and
    // prevents origin/organization substitution; it does not reimplement Flow.
    Ok(value)
}

impl Configuration {
    pub(crate) fn validate(&self) -> Result<()> {
        require(
            self.public_verification.is_some()
                || self.wallet_governance.is_some()
                || self.verification_prerequisite
                || self.needs_issuance_roles(),
        )?;
        if let Some(wallet) = &self.wallet_governance {
            require(identifier(&wallet.flow_producer_id))?;
        }
        if let Some(PublicVerification::Configured {
            application_origin,
            catalog_file,
        }) = &self.public_verification
        {
            require(https_origin(application_origin) && private_path(catalog_file))?;
        }
        // Consent confirmation consumes current canonical application ownership.
        require(!self.external_associations || self.application_ownership)
    }

    pub(crate) fn needs_issuance_roles(&self) -> bool {
        self.application_ownership || self.external_associations || self.external_observations
    }

    pub(crate) fn input_files(&self) -> Result<BTreeMap<String, PathBuf>> {
        self.validate()?;
        let mut files = BTreeMap::new();
        if let Some(PublicVerification::Configured { catalog_file, .. }) = &self.public_verification
        {
            files.insert(CATALOG.into(), catalog_file.clone());
        }
        Ok(files)
    }

    pub(crate) fn generated_secret_names(&self) -> BTreeSet<&'static str> {
        let mut names = BTreeSet::new();
        if self.public_verification.is_some() {
            names.extend([
                HOLDER_MINT_TOKEN,
                GRANT_VERIFY_TOKEN,
                SIGNING_CUSTODY_TOKEN,
                SIGNING_READ_KEY,
            ]);
        }
        if self.wallet_governance.is_some() {
            names.extend([TRUST_CERTIFICATE, TRUST_TOKEN]);
        }
        if self.verification_prerequisite {
            names.insert(PREREQUISITE_TOKEN);
        }
        if self.needs_issuance_roles() {
            names.extend([
                "feature_issuance_runtime_database_url",
                "feature_postgres_ca",
            ]);
        }
        if self.external_associations {
            names.insert("feature_association_database_url");
        }
        if self.external_observations {
            names.insert("feature_observation_database_url");
        }
        names
    }

    pub(crate) fn validate_imported(&self, files: &BTreeMap<String, Vec<u8>>) -> Result<()> {
        self.validate()?;
        if let Some(PublicVerification::Configured {
            application_origin, ..
        }) = &self.public_verification
        {
            bounded_catalog(files.get(CATALOG).ok_or(REFUSED)?, application_origin)?;
        } else {
            require(!files.contains_key(CATALOG))?;
        }
        Ok(())
    }

    pub(crate) fn apply_environment(&self, values: &mut BTreeMap<String, String>) -> Result<()> {
        self.validate()?;
        if let Some(PublicVerification::Configured {
            application_origin, ..
        }) = &self.public_verification
        {
            require(values.get("UI_BASE_URL") == Some(application_origin))?;
        }
        for (key, selected) in [
            (
                "MARTY_APPLICATION_OWNERSHIP_ENABLED",
                self.application_ownership,
            ),
            (
                "MARTY_EXTERNAL_ASSOCIATIONS_ENABLED",
                self.external_associations,
            ),
            (
                "MARTY_EXTERNAL_OBSERVATIONS_ENABLED",
                self.external_observations,
            ),
        ] {
            values.insert(key.into(), selected.to_string());
        }
        if let Some(wallet) = &self.wallet_governance {
            values.insert(
                "WALLET_FLOW_PRODUCER_ID".into(),
                wallet.flow_producer_id.clone(),
            );
        }
        Ok(())
    }

    pub(crate) fn layers(&self) -> Vec<&'static str> {
        let mut layers = Vec::new();
        if self.wallet_governance.is_some() || self.verification_prerequisite {
            layers.push(concat!(
                "deploy-config/compose/selfhost-installer/feature-profile/",
                "compose.workflow-flow-https.yml"
            ));
        }
        if self.wallet_governance.is_some() {
            layers.push(concat!(
                "deploy-config/compose/selfhost-installer/feature-profile/",
                "compose.workflow-wallet.yml"
            ));
        }
        if self.verification_prerequisite {
            layers.push(concat!(
                "deploy-config/compose/selfhost-installer/feature-profile/",
                "compose.workflow-prerequisite.yml"
            ));
        }
        if self.needs_issuance_roles() {
            layers.push(concat!(
                "deploy-config/compose/selfhost-installer/feature-profile/",
                "compose.workflow-issuance.yml"
            ));
        }
        if self.external_associations {
            layers.push(concat!(
                "deploy-config/compose/selfhost-installer/feature-profile/",
                "compose.workflow-associations.yml"
            ));
        }
        if self.external_observations {
            layers.push(concat!(
                "deploy-config/compose/selfhost-installer/feature-profile/",
                "compose.workflow-observations.yml"
            ));
        }
        if self.public_verification.is_some() {
            layers.push(concat!(
                "deploy-config/compose/selfhost-installer/feature-profile/",
                "compose.feature-signing.yml"
            ));
        }
        if matches!(
            self.public_verification,
            Some(PublicVerification::Configured { .. })
        ) {
            layers.push(concat!(
                "deploy-config/compose/selfhost-installer/feature-profile/",
                "compose.workflow-public-verification.yml"
            ));
        }
        layers
    }

    pub(crate) fn validate_model(&self, model: &Value) -> Result<()> {
        self.validate()?;
        let services = model["services"].as_object().ok_or(REFUSED)?;
        if let Some(flow) = services.get("flow") {
            authenticated(flow)?;
            if self.wallet_governance.is_some() || self.verification_prerequisite {
                flow_https(flow)?;
            }
            if matches!(
                self.public_verification,
                Some(PublicVerification::Configured { .. })
            ) {
                file_environment(flow, "FLOW_PUBLIC_VERIFICATION_CONFIG_FILE", CATALOG)?;
                file_environment(
                    flow,
                    "FLOW_DEMO_HOLDER_SIGN_GRANT_MINT_TOKEN_FILE",
                    HOLDER_MINT_TOKEN,
                )?;
                expect(flow, "MARTY_SIGNING_GRANT_PROVIDER", "openbao-transit")?;
            } else {
                absent(flow, "FLOW_PUBLIC_VERIFICATION_CONFIG_FILE")?;
                absent(flow, "FLOW_DEMO_HOLDER_SIGN_GRANT_MINT_TOKEN_FILE")?;
            }
            if self.verification_prerequisite {
                file_environment(flow, "FLOW_ISSUANCE_SERVICE_TOKEN_FILE", PREREQUISITE_TOKEN)?;
                absent(flow, "FLOW_ISSUANCE_SERVICE_TOKEN")?;
            }
        }
        if let Some(wallet) = &self.wallet_governance {
            if let Some(trust) = services.get("trust-profile") {
                authenticated(trust)?;
                expect(trust, "WALLET_FLOW_PRODUCER_ID", &wallet.flow_producer_id)?;
                expect(trust, "WALLET_FLOW_OWNER_URL", "https://flow:8443")?;
                file_environment(
                    trust,
                    "WALLET_FLOW_OWNER_CA_FILE",
                    "workload_identity_ca_cert",
                )?;
                expect(trust, "MANAGED_AUTHORITY_HTTPS_ADDR", "0.0.0.0:8443")?;
                expect(
                    trust,
                    "MANAGED_AUTHORITY_TLS_KMS_PROVIDER",
                    "openbao-transit",
                )?;
                expect(
                    trust,
                    "MANAGED_AUTHORITY_TLS_KMS_ADDR",
                    "https://openbao:8200",
                )?;
                expect(trust, "MANAGED_AUTHORITY_TLS_KMS_KEY_NAME", TRUST_KEY)?;
                expect(trust, "MANAGED_AUTHORITY_TLS_KMS_KEY_VERSION", "1")?;
                file_environment(trust, "MANAGED_AUTHORITY_TLS_CERT_FILE", TRUST_CERTIFICATE)?;
                file_environment(trust, "MANAGED_AUTHORITY_TLS_KMS_TOKEN_FILE", TRUST_TOKEN)?;
                file_environment(
                    trust,
                    "MANAGED_AUTHORITY_TLS_KMS_CA_CERT_FILE",
                    "openbao_tls_ca_cert",
                )?;
                absent(trust, "MANAGED_AUTHORITY_TLS_KEY_FILE")?;
                no_published_owner_port(trust)?;
            }
            if let Some(device) = services.get("device-registration") {
                authenticated(device)?;
                for prefix in ["WALLET_ISSUER_TRUST_OWNER", "WALLET_VERIFIER_TRUST_OWNER"] {
                    expect(
                        device,
                        &format!("{prefix}_URL"),
                        "https://trust-profile:8443",
                    )?;
                    file_environment(device, &format!("{prefix}_CA"), "workload_identity_ca_cert")?;
                }
            }
        }
        if self.public_verification.is_some() {
            validate_feature_signing_model(model)?;
        }
        for name in ["issuance", "issuance-native"] {
            let Some(issuance) = services.get(name) else {
                continue;
            };
            for (key, enabled) in [
                (
                    "MARTY_APPLICATION_OWNERSHIP_ENABLED",
                    self.application_ownership,
                ),
                (
                    "MARTY_EXTERNAL_ASSOCIATIONS_ENABLED",
                    self.external_associations,
                ),
                (
                    "MARTY_EXTERNAL_OBSERVATIONS_ENABLED",
                    self.external_observations,
                ),
            ] {
                if enabled {
                    expect(issuance, key, "true")?;
                } else {
                    disabled(issuance, key)?;
                }
            }
            if self.needs_issuance_roles() {
                file_environment(
                    issuance,
                    "DATABASE_URL_FILE",
                    "feature_issuance_runtime_database_url",
                )?;
                file_environment(issuance, "PGSSLROOTCERT", "feature_postgres_ca")?;
                expect(issuance, "MARTY_SCHEMA_STARTUP_MODE", "validate")?;
                for key in [
                    "DATABASE_URL",
                    "DATABASE_URL_TEMPLATE",
                    "MARTY_DB_PASSWORD",
                    "MARTY_DB_PASSWORD_FILE",
                ] {
                    absent(issuance, key)?;
                }
                require(!has_secret(issuance, "marty_db_password"))?;
                let broad_password = model["secrets"]["marty_db_password"]["file"]
                    .as_str()
                    .ok_or(REFUSED)?;
                require(issuance["volumes"].as_array().is_none_or(|mounts| {
                    mounts.iter().all(|mount| {
                        mount["target"].as_str() != Some("/run/secrets")
                            && mount["source"]
                                .as_str()
                                .is_none_or(|source| !Path::new(broad_password).starts_with(source))
                    })
                }))?;
                file_environment(issuance, "ISSUANCE_API_KEY_FILE", "issuance_api_key")?;
            }
            for (enabled, prefix, secret) in [
                (
                    self.external_associations,
                    "ISSUANCE_EXTERNAL_ASSOCIATION",
                    "feature_association_database_url",
                ),
                (
                    self.external_observations,
                    "ISSUANCE_EXTERNAL_OBSERVATION",
                    "feature_observation_database_url",
                ),
            ] {
                if enabled {
                    file_environment(issuance, &format!("{prefix}_DATABASE_URL_FILE"), secret)?;
                    expect(issuance, &format!("{prefix}_POOL_MAX_CONNECTIONS"), "1")?;
                } else {
                    absent(issuance, &format!("{prefix}_DATABASE_URL_FILE"))?;
                }
                absent(issuance, &format!("{prefix}_DATABASE_URL"))?;
            }
            if self.verification_prerequisite {
                expect(issuance, "FLOW_PREREQUISITE_OWNER_URL", "https://flow:8443")?;
                file_environment(
                    issuance,
                    "FLOW_PREREQUISITE_OWNER_CA_FILE",
                    "workload_identity_ca_cert",
                )?;
                file_environment(
                    issuance,
                    "FLOW_ISSUANCE_SERVICE_TOKEN_FILE",
                    PREREQUISITE_TOKEN,
                )?;
                absent(issuance, "FLOW_ISSUANCE_SERVICE_TOKEN")?;
            }
        }
        for (secret, recipients) in [
            (CATALOG, &["flow"][..]),
            (HOLDER_MINT_TOKEN, &["flow"][..]),
            (
                PREREQUISITE_TOKEN,
                &["flow", "issuance", "issuance-native"][..],
            ),
            (TRUST_CERTIFICATE, &["trust-profile"][..]),
            (TRUST_TOKEN, &["trust-profile"][..]),
            (GRANT_VERIFY_TOKEN, &["signing-keys"][..]),
            (SIGNING_CUSTODY_TOKEN, &["signing-keys"][..]),
            (
                "feature_issuance_runtime_database_url",
                &["issuance", "issuance-native"][..],
            ),
            (
                "feature_association_database_url",
                &["issuance", "issuance-native"][..],
            ),
            (
                "feature_observation_database_url",
                &["issuance", "issuance-native"][..],
            ),
        ] {
            for (name, service) in services {
                if has_secret(service, secret) || has_feature_file(service, secret) {
                    require(recipients.contains(&name.as_str()))?;
                }
            }
        }
        Ok(())
    }

    pub(crate) fn activate_public_verification(
        &self,
        activation: &PublicVerificationActivation,
        catalog: &[u8],
        retained_catalog: PathBuf,
        installation_id: uuid::Uuid,
        feature_profile_sha256: &str,
        application_origin: &str,
    ) -> Result<Self> {
        self.validate()?;
        require(matches!(
            self.public_verification,
            Some(PublicVerification::AwaitingOwnerConfiguration {})
        ))?;
        require(
            activation.schema == "elevenid.installer-public-verification-activation/v1"
                && activation.installation_id == installation_id
                && !installation_id.is_nil()
                && hash(feature_profile_sha256)
                && activation.feature_profile_sha256 == feature_profile_sha256
                && hash(&activation.owner_api_receipt_sha256)
                && activation.catalog_sha256 == crate::installer_release::sha256(catalog)
                && https_origin(application_origin)
                && activation.application_origin == application_origin,
        )?;
        let value = bounded_catalog(catalog, application_origin)?;
        require(
            value["catalog"]["organization_id"].as_str()
                == Some(activation.organization_id.to_string().as_str())
                && value["principal_id"].as_str() == Some(activation.principal_id.as_str()),
        )?;
        let mut configured = self.clone();
        configured.public_verification = Some(PublicVerification::Configured {
            application_origin: application_origin.into(),
            catalog_file: retained_catalog,
        });
        configured.validate()?;
        Ok(configured)
    }
}

fn expect(service: &Value, key: &str, value: &str) -> Result<()> {
    require(service["environment"][key].as_str() == Some(value))
}

/// The same signing boundary is selected by delegated-use even without the
/// public verification workflow. The primary feature owner calls this then.
pub(crate) fn validate_feature_signing_model(model: &Value) -> Result<()> {
    let services = model["services"].as_object().ok_or(REFUSED)?;
    if let Some(signing) = services.get("signing-keys") {
        file_environment(signing, "BAO_TOKEN_FILE", SIGNING_CUSTODY_TOKEN)?;
        file_environment(
            signing,
            "SIGNING_KEYS_GRANT_VERIFY_TOKEN_FILE",
            GRANT_VERIFY_TOKEN,
        )?;
        absent(signing, "BAO_TOKEN")?;
    }
    for (name, service) in services {
        if SIGNING_READ_CONSUMERS.contains(&name.as_str()) {
            if name == "delegated-use" {
                for prefix in ["DELEGATED_USE_REQUEST", "DELEGATED_USE_RECEIPT"] {
                    file_environment(
                        service,
                        &format!("{prefix}_READ_CREDENTIAL_FILE"),
                        SIGNING_READ_KEY,
                    )?;
                    absent(service, &format!("{prefix}_READ_CREDENTIAL"))?;
                }
            } else {
                file_environment(
                    service,
                    "SIGNING_KEYS_INTERNAL_API_KEY_FILE",
                    SIGNING_READ_KEY,
                )?;
                absent(service, "SIGNING_KEYS_INTERNAL_API_KEY")?;
            }
        } else {
            require(
                !has_feature_file(service, SIGNING_READ_KEY)
                    && !has_secret(service, SIGNING_READ_KEY),
            )?;
        }
        for restricted in [GRANT_VERIFY_TOKEN, SIGNING_CUSTODY_TOKEN] {
            if has_feature_file(service, restricted) || has_secret(service, restricted) {
                require(name == "signing-keys")?;
            }
        }
    }
    Ok(())
}
fn absent(service: &Value, key: &str) -> Result<()> {
    require(
        service["environment"]
            .get(key)
            .is_none_or(|v| v.is_null() || v == ""),
    )
}
fn disabled(service: &Value, key: &str) -> Result<()> {
    require(
        service["environment"]
            .get(key)
            .is_none_or(|v| v.is_null() || v == "" || v == "false"),
    )
}
fn has_secret(service: &Value, secret: &str) -> bool {
    service["secrets"].as_array().is_some_and(|items| {
        items
            .iter()
            .any(|value| value.as_str() == Some(secret) || value["source"].as_str() == Some(secret))
    })
}
fn file_environment(service: &Value, key: &str, secret: &str) -> Result<()> {
    if secret.starts_with("feature_") {
        expect(service, key, &format!("/run/feature-profile/{secret}"))?;
        return require(service["volumes"].as_array().is_some_and(|items| {
            items.iter().any(|value| {
                value["type"] == "bind"
                    && value["read_only"] == true
                    && value["target"].as_str()
                        == Some(format!("/run/feature-profile/{secret}").as_str())
                    && value["source"].as_str().is_some_and(|path| {
                        Path::new(path).is_absolute()
                            && Path::new(path).file_name().and_then(|v| v.to_str()) == Some(secret)
                    })
                    && value["bind"]
                        .get("create_host_path")
                        .is_none_or(|v| v == false)
            })
        }));
    }
    expect(service, key, &format!("/run/secrets/{secret}"))?;
    require(service["secrets"].as_array().is_some_and(|items| {
        items.iter().any(|value| {
            value.as_str() == Some(secret)
                || (value["source"].as_str() == Some(secret)
                    && value.get("target").is_none_or(|target| {
                        target.as_str() == Some(secret)
                            || target.as_str() == Some(format!("/run/secrets/{secret}").as_str())
                    }))
        })
    }))
}
fn has_feature_file(service: &Value, name: &str) -> bool {
    service["volumes"].as_array().is_some_and(|items| {
        items.iter().any(|value| {
            value["target"].as_str() == Some(format!("/run/feature-profile/{name}").as_str())
                || value["source"].as_str().is_some_and(|path| {
                    Path::new(path).file_name().and_then(|v| v.to_str()) == Some(name)
                })
        })
    })
}
fn authenticated(service: &Value) -> Result<()> {
    file_environment(service, "GRPC_SERVICE_TOKEN_FILE", "grpc_service_token")?;
    absent(service, "GRPC_SERVICE_TOKEN")
}
fn no_published_owner_port(service: &Value) -> Result<()> {
    require(service["ports"].as_array().is_none_or(|ports| {
        ports.iter().all(|port| {
            port["target"].as_u64() != Some(8443)
                && port["target"].as_str() != Some("8443")
                && port.as_str().is_none()
        })
    }))
}
fn flow_https(flow: &Value) -> Result<()> {
    expect(flow, "MANAGED_AUTHORITY_HTTPS_ADDR", "0.0.0.0:8443")?;
    expect(
        flow,
        "MANAGED_AUTHORITY_TLS_KMS_PROVIDER",
        "openbao-transit",
    )?;
    for (managed, existing) in [
        (
            "MANAGED_AUTHORITY_TLS_KMS_ADDR",
            "GRPC_WORKLOAD_TLS_SERVER_KMS_ADDR",
        ),
        (
            "MANAGED_AUTHORITY_TLS_KMS_KEY_NAME",
            "GRPC_WORKLOAD_TLS_SERVER_KMS_KEY_NAME",
        ),
        (
            "MANAGED_AUTHORITY_TLS_KMS_KEY_VERSION",
            "GRPC_WORKLOAD_TLS_SERVER_KMS_KEY_VERSION",
        ),
    ] {
        let expected = flow["environment"][existing]
            .as_str()
            .filter(|v| !v.is_empty())
            .ok_or(REFUSED)?;
        expect(flow, managed, expected)?;
    }
    file_environment(
        flow,
        "MANAGED_AUTHORITY_TLS_CERT_FILE",
        "flow_workload_server_cert",
    )?;
    file_environment(
        flow,
        "MANAGED_AUTHORITY_TLS_KMS_TOKEN_FILE",
        "flow_server_tls_kms_token",
    )?;
    file_environment(
        flow,
        "MANAGED_AUTHORITY_TLS_KMS_CA_CERT_FILE",
        "openbao_tls_ca_cert",
    )?;
    absent(flow, "MANAGED_AUTHORITY_TLS_KEY_FILE")?;
    no_published_owner_port(flow)
}

#[cfg(test)]
#[path = "installer_workflow_features_tests.rs"]
mod tests;
