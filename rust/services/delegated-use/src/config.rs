//! Explicit, default-off configuration for the internal delegated-use host.
//! Parsing never connects a service or provisions a schema/key/permission.
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use marty_delegated_authority::{
    approval::organization_principal,
    use_mtls::{DelegatedUseWorkloadBinding, DelegatedUseWorkloadBindings},
    ApprovalAdapterPin, Authority, AuthorityMode, ManagedDelegatedReceiptKey,
    OrganizationApprovalConfiguration, Principal, PrincipalType,
};
use marty_flow::{
    DelegatedVerificationStartConfiguration, RequestObjectOptions, VerificationDefinitionBinding,
    VerificationStartOptions, VerifierDidMethod, WorkloadClientTlsFiles,
};
use marty_service_runtime::{RemoteTlsIdentityFiles, TlsIdentityNames};
use serde::{de, Deserialize, Deserializer};
use serde_json::{Map, Value};
use uuid::Uuid;

const ENABLED: &str = "MARTY_DELEGATED_USE_ENABLED";
const MAX_SECRET_BYTES: usize = 8_192;
const MAX_JSON_BYTES: usize = 262_144;
const DATABASE_NAMES: [&str; 14] = [
    "DELEGATED_USE_USE_WRITER_DATABASE_URL",
    "DELEGATED_USE_RUNTIME_READER_DATABASE_URL",
    "DELEGATED_USE_ORGANIZATION_AUTHORITY_DATABASE_URL",
    "DELEGATED_USE_REGISTRY_SOURCE_DATABASE_URL",
    "DELEGATED_USE_ACCESS_SOURCE_DATABASE_URL",
    "DELEGATED_USE_MACHINE_POLICY_SOURCE_DATABASE_URL",
    "DELEGATED_USE_MACHINE_POLICY_EVIDENCE_DATABASE_URL",
    "DELEGATED_USE_DELEGATION_POLICY_SOURCE_DATABASE_URL",
    "DELEGATED_USE_MACHINE_AUDIT_DATABASE_URL",
    "DELEGATED_USE_FLOW_READER_DATABASE_URL",
    "DELEGATED_USE_FLOW_INGRESS_DATABASE_URL",
    "DELEGATED_USE_CREDENTIAL_TRUST_DATABASE_URL",
    "DELEGATED_USE_CREDENTIAL_STATUS_DATABASE_URL",
    "DELEGATED_USE_CREDENTIAL_EVIDENCE_DATABASE_URL",
];
const CREDENTIAL_NAMES: [&str; 6] = [
    "DELEGATED_USE_SERVICE_TOKEN",
    "DELEGATED_USE_ISSUANCE_API_KEY",
    "DELEGATED_USE_REQUEST_READ_CREDENTIAL",
    "DELEGATED_USE_REQUEST_SIGN_CREDENTIAL",
    "DELEGATED_USE_RECEIPT_READ_CREDENTIAL",
    "DELEGATED_USE_RECEIPT_SIGN_CREDENTIAL",
];
const JSON_NAMES: [&str; 3] = [
    "DELEGATED_USE_WORKLOAD_BINDINGS",
    "DELEGATED_USE_CLIENT_CA_FILES",
    "DELEGATED_USE_RECEIPT_PUBLIC_JWK",
];
const PUBLIC_NAMES: &[&str] = &[
    "DELEGATED_USE_LISTEN_ADDR",
    "DELEGATED_USE_ORGANIZATION_ID",
    "DELEGATED_USE_DEPLOYMENT_PROFILE_ID",
    "DELEGATED_USE_DELEGATION_POLICY_ID",
    "DELEGATED_USE_APPROVAL_PROFILE",
    "DELEGATED_USE_APPROVAL_VERSION",
    "DELEGATED_USE_APPROVAL_ARTIFACT_DIGEST",
    "DELEGATED_USE_CONFIRMATION_MAX_AGE_SECONDS",
    "DELEGATED_USE_AUTHORITY_VALIDITY_SECONDS",
    "DELEGATED_USE_STATUS_REF",
    "DELEGATED_USE_FLOW_DEFINITION_ID",
    "DELEGATED_USE_FLOW_DEFINITION_VERSION",
    "DELEGATED_USE_PUBLIC_BASE_URL",
    "DELEGATED_USE_VERIFIER_DID",
    "DELEGATED_USE_VERIFIER_DISPLAY_NAME",
    "DELEGATED_USE_VERIFIER_LOGO_URI",
    "DELEGATED_USE_CHALLENGE_LIFETIME_SECONDS",
    "DELEGATED_USE_RECEIPT_LIFETIME_SECONDS",
    "DELEGATED_USE_CREDENTIAL_TEMPLATE_GRPC_TARGET",
    "DELEGATED_USE_PRESENTATION_POLICY_GRPC_TARGET",
    "DELEGATED_USE_ISSUANCE_NATIVE_URL",
    "DELEGATED_USE_CREDENTIAL_TEMPLATE_URL",
    "DELEGATED_USE_TRUST_PROFILE_URL",
    "DELEGATED_USE_DEPLOYMENT_PROFILE_URL",
    "DELEGATED_USE_REQUEST_SIGNING_ORIGIN",
    "DELEGATED_USE_REQUEST_GRANT_OPENBAO_ORIGIN",
    "DELEGATED_USE_REQUEST_MINT_TOKEN_FILE",
    "DELEGATED_USE_RECEIPT_SIGNING_ORIGIN",
    "DELEGATED_USE_RECEIPT_GRANT_OPENBAO_ORIGIN",
    "DELEGATED_USE_RECEIPT_MINT_TOKEN_FILE",
    "DELEGATED_USE_RECEIPT_ISSUER_DID",
    "DELEGATED_USE_RECEIPT_ALGORITHM",
    "DELEGATED_USE_RECEIPT_KEY_ID",
    "DELEGATED_USE_RECEIPT_KEY_REFERENCE",
    "DELEGATED_USE_WORKLOAD_TLS_CA_CERT_FILE",
];

#[derive(Clone)]
pub struct DatabaseUrls {
    pub use_writer: String,
    pub runtime_reader: String,
    pub organization_authority: String,
    pub registry_source: String,
    pub access_source: String,
    pub machine_policy_source: String,
    pub machine_policy_evidence: String,
    pub delegation_policy_source: String,
    pub machine_audit: String,
    pub flow_reader: String,
    pub flow_ingress: String,
    pub credential_trust: String,
    pub credential_status: String,
    pub credential_evidence: String,
}
impl fmt::Debug for DatabaseUrls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatabaseUrls").finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct RequestSigningConfig {
    pub origin: String,
    pub read_credential: String,
    pub sign_credential: String,
    pub grant_openbao_origin: String,
    pub mint_token_file: PathBuf,
}
#[derive(Clone)]
pub struct ReceiptSigningConfig {
    pub origin: String,
    pub read_credential: String,
    pub sign_credential: String,
    pub grant_openbao_origin: String,
    pub mint_token_file: PathBuf,
    pub key: ManagedDelegatedReceiptKey,
    pub issuer: Principal,
}
impl fmt::Debug for RequestSigningConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestSigningConfig")
            .finish_non_exhaustive()
    }
}
impl fmt::Debug for ReceiptSigningConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReceiptSigningConfig")
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct DelegatedUseHostConfig {
    pub listen_addr: SocketAddr,
    pub organization_id: Uuid,
    pub deployment_profile_id: Uuid,
    pub delegation_policy_id: Uuid,
    pub database_urls: DatabaseUrls,
    pub approval_configuration: OrganizationApprovalConfiguration,
    pub authority: Authority,
    pub flow_start: DelegatedVerificationStartConfiguration,
    pub request_options: RequestObjectOptions,
    pub public_base_url: String,
    pub challenge_lifetime_seconds: i64,
    pub receipt_lifetime_seconds: i64,
    pub credential_template_grpc_target: String,
    pub presentation_policy_grpc_target: String,
    pub workload_client_tls: WorkloadClientTlsFiles,
    pub service_token: String,
    pub issuance_native_url: String,
    pub issuance_api_key: String,
    pub credential_template_url: String,
    pub trust_profile_url: String,
    pub deployment_profile_url: String,
    pub request_signing: RequestSigningConfig,
    pub receipt_signing: ReceiptSigningConfig,
    pub tls_identity: RemoteTlsIdentityFiles,
    pub client_ca_der: Vec<Vec<u8>>,
    pub workload_bindings: DelegatedUseWorkloadBindings,
}
impl fmt::Debug for DelegatedUseHostConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DelegatedUseHostConfig")
            .field("listen_addr", &self.listen_addr)
            .field("organization_id", &self.organization_id)
            .field("deployment_profile_id", &self.deployment_profile_id)
            .field("delegation_policy_id", &self.delegation_policy_id)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HostConfigError {
    #[error("delegated use requires explicit MARTY_DELEGATED_USE_ENABLED=true")]
    Disabled,
    #[error("delegated use configuration is missing or invalid: {0}")]
    Invalid(&'static str),
    #[error("delegated use configuration contains an unknown or duplicate field")]
    UnknownField,
    #[error("delegated use file is unavailable, oversized or conflicts with an inline value: {0}")]
    File(&'static str),
}

impl DelegatedUseHostConfig {
    pub fn from_env() -> Result<Self, HostConfigError> {
        // Even decoding another environment value waits for the opt-in. An
        // unrelated non-Unicode environment entry must not panic this process.
        match std::env::var(ENABLED) {
            Ok(value) if value == "true" => {}
            Ok(value) if value == "false" => return Err(HostConfigError::Disabled),
            Err(std::env::VarError::NotPresent) => return Err(HostConfigError::Disabled),
            _ => return Err(HostConfigError::Invalid(ENABLED)),
        }
        let mut values = Vec::new();
        for (name, value) in std::env::vars_os() {
            let Some(name) = name.to_str() else {
                continue;
            };
            if name == ENABLED || name.starts_with("DELEGATED_USE_") {
                let value = value
                    .to_str()
                    .ok_or(HostConfigError::Invalid("environment text"))?;
                values.push((name.to_owned(), value.to_owned()));
            }
        }
        Self::from_values(values)
    }

    pub fn from_values(
        values: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, HostConfigError> {
        Self::parse(values, bounded_file)
    }

    fn parse(
        values: impl IntoIterator<Item = (String, String)>,
        mut read: impl FnMut(&Path, usize) -> Result<Vec<u8>, ()>,
    ) -> Result<Self, HostConfigError> {
        let mut input = BTreeMap::new();
        let mut duplicate = false;
        for (name, value) in values {
            if name == ENABLED || name.starts_with("DELEGATED_USE_") {
                duplicate |= input.insert(name, value).is_some();
            }
        }
        // This check precedes every path inspection, file read and provider
        // constructor. Merely mounting credentials never enables the process.
        match input.get(ENABLED).map(String::as_str) {
            Some("true") => {}
            None | Some("false") => return Err(HostConfigError::Disabled),
            _ => return Err(HostConfigError::Invalid(ENABLED)),
        }
        if duplicate || input.keys().any(|name| !known_name(name)) {
            return Err(HostConfigError::UnknownField);
        }
        if input.iter().any(|(name, value)| {
            value.len()
                > if JSON_NAMES.contains(&name.as_str()) {
                    MAX_JSON_BYTES
                } else {
                    MAX_SECRET_BYTES
                }
        }) {
            return Err(HostConfigError::Invalid("configuration value size"));
        }
        for name in DATABASE_NAMES.into_iter().chain(CREDENTIAL_NAMES) {
            load_value(&mut input, name, MAX_SECRET_BYTES, &mut read)?;
        }
        for name in JSON_NAMES {
            load_value(&mut input, name, MAX_JSON_BYTES, &mut read)?;
        }
        let organization_id = uuid(&input, "DELEGATED_USE_ORGANIZATION_ID")?;
        let deployment_profile_id = uuid(&input, "DELEGATED_USE_DEPLOYMENT_PROFILE_ID")?;
        let delegation_policy_id = uuid(&input, "DELEGATED_USE_DELEGATION_POLICY_ID")?;
        let listen_addr = input
            .get("DELEGATED_USE_LISTEN_ADDR")
            .map(String::as_str)
            .unwrap_or("127.0.0.1:8021")
            .parse::<SocketAddr>()
            .ok()
            .filter(|address| address.port() != 0)
            .ok_or(HostConfigError::Invalid("DELEGATED_USE_LISTEN_ADDR"))?;
        let database_urls = DatabaseUrls {
            use_writer: database(&input, DATABASE_NAMES[0])?,
            runtime_reader: database(&input, DATABASE_NAMES[1])?,
            organization_authority: database(&input, DATABASE_NAMES[2])?,
            registry_source: database(&input, DATABASE_NAMES[3])?,
            access_source: database(&input, DATABASE_NAMES[4])?,
            machine_policy_source: database(&input, DATABASE_NAMES[5])?,
            machine_policy_evidence: database(&input, DATABASE_NAMES[6])?,
            delegation_policy_source: database(&input, DATABASE_NAMES[7])?,
            machine_audit: database(&input, DATABASE_NAMES[8])?,
            flow_reader: database(&input, DATABASE_NAMES[9])?,
            flow_ingress: database(&input, DATABASE_NAMES[10])?,
            credential_trust: database(&input, DATABASE_NAMES[11])?,
            credential_status: database(&input, DATABASE_NAMES[12])?,
            credential_evidence: database(&input, DATABASE_NAMES[13])?,
        };
        let mut selected_urls = BTreeSet::new();
        if DATABASE_NAMES
            .iter()
            .any(|name| !selected_urls.insert(input.get(*name).expect("validated database URL")))
        {
            return Err(HostConfigError::Invalid("distinct database identities"));
        }
        let approval_configuration = OrganizationApprovalConfiguration::new(
            organization_id,
            organization_principal(organization_id),
            ApprovalAdapterPin {
                profile: required(&input, "DELEGATED_USE_APPROVAL_PROFILE", 512)?.into(),
                version: required(&input, "DELEGATED_USE_APPROVAL_VERSION", 64)?.into(),
                artifact_digest: required(&input, "DELEGATED_USE_APPROVAL_ARTIFACT_DIGEST", 71)?
                    .into(),
            },
            120,
            seconds(
                &input,
                "DELEGATED_USE_CONFIRMATION_MAX_AGE_SECONDS",
                300,
                1,
                300,
            )? as u32,
            seconds(
                &input,
                "DELEGATED_USE_AUTHORITY_VALIDITY_SECONDS",
                15,
                1,
                15,
            )? as u32,
        )
        .map_err(|_| HostConfigError::Invalid("DELEGATED_USE_APPROVAL_PROFILE"))?;
        let authority = Authority {
            mode: AuthorityMode::Managed,
            issuer: organization_principal(organization_id),
            status_ref: https(&input, "DELEGATED_USE_STATUS_REF", false)?,
            source_profile: None,
            source_evidence_ref: None,
            source_evidence_digest: None,
            source_expires_at: None,
        };
        let public_base_url = https(&input, "DELEGATED_USE_PUBLIC_BASE_URL", false)?;
        if public_base_url.ends_with('/') {
            return Err(HostConfigError::Invalid("DELEGATED_USE_PUBLIC_BASE_URL"));
        }
        let verifier = did(&input, "DELEGATED_USE_VERIFIER_DID")?;
        let verifier_did_method = if verifier.starts_with("did:web:") {
            VerifierDidMethod::Web
        } else if verifier.starts_with("did:jwk:") {
            VerifierDidMethod::Jwk
        } else if verifier.starts_with("did:key:") {
            VerifierDidMethod::Key
        } else {
            return Err(HostConfigError::Invalid("DELEGATED_USE_VERIFIER_DID"));
        };
        let logo = input
            .contains_key("DELEGATED_USE_VERIFIER_LOGO_URI")
            .then(|| https(&input, "DELEGATED_USE_VERIFIER_LOGO_URI", false))
            .transpose()?;
        let request_options = RequestObjectOptions {
            verifier_client_id: Some(verifier.clone()),
            verifier_did_method,
            strict_client_metadata: true,
            verifier_display_name: required(&input, "DELEGATED_USE_VERIFIER_DISPLAY_NAME", 128)?
                .into(),
            verifier_logo_uri: logo,
            ..RequestObjectOptions::default()
        };
        let definition_id = required(&input, "DELEGATED_USE_FLOW_DEFINITION_ID", 128)?;
        if !definition_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':'))
        {
            return Err(HostConfigError::Invalid("DELEGATED_USE_FLOW_DEFINITION_ID"));
        }
        let flow_start = DelegatedVerificationStartConfiguration {
            definition: VerificationDefinitionBinding {
                organization_id: organization_id.to_string(),
                definition_id: definition_id.into(),
                version: seconds(
                    &input,
                    "DELEGATED_USE_FLOW_DEFINITION_VERSION",
                    1,
                    1,
                    i64::from(u32::MAX),
                )? as u32,
            },
            issuer_did: verifier,
            public_base_url: public_base_url.clone(),
            allow_http_loopback: false,
            options: VerificationStartOptions {
                request_object: request_options.clone(),
                ..VerificationStartOptions::default()
            },
        };
        let request_signing = RequestSigningConfig {
            origin: https(&input, "DELEGATED_USE_REQUEST_SIGNING_ORIGIN", true)?,
            read_credential: credential(&input, CREDENTIAL_NAMES[2])?,
            sign_credential: credential(&input, CREDENTIAL_NAMES[3])?,
            grant_openbao_origin: https(
                &input,
                "DELEGATED_USE_REQUEST_GRANT_OPENBAO_ORIGIN",
                true,
            )?,
            mint_token_file: absolute(&input, "DELEGATED_USE_REQUEST_MINT_TOKEN_FILE")?,
        };
        let issuer = Principal {
            principal_type: PrincipalType::Organization,
            id: did(&input, "DELEGATED_USE_RECEIPT_ISSUER_DID")?,
        };
        let public_jwk: PublicJwk = json(&input, "DELEGATED_USE_RECEIPT_PUBLIC_JWK")?;
        let key = ManagedDelegatedReceiptKey::new(
            organization_id,
            issuer.clone(),
            required(&input, "DELEGATED_USE_RECEIPT_ALGORITHM", 8)?.into(),
            required(&input, "DELEGATED_USE_RECEIPT_KEY_ID", 512)?.into(),
            required(&input, "DELEGATED_USE_RECEIPT_KEY_REFERENCE", 512)?.into(),
            public_jwk.0,
        )
        .map_err(|_| HostConfigError::Invalid("DELEGATED_USE_RECEIPT_PUBLIC_JWK"))?;
        let receipt_signing = ReceiptSigningConfig {
            origin: https(&input, "DELEGATED_USE_RECEIPT_SIGNING_ORIGIN", true)?,
            read_credential: credential(&input, CREDENTIAL_NAMES[4])?,
            sign_credential: credential(&input, CREDENTIAL_NAMES[5])?,
            grant_openbao_origin: https(
                &input,
                "DELEGATED_USE_RECEIPT_GRANT_OPENBAO_ORIGIN",
                true,
            )?,
            mint_token_file: absolute(&input, "DELEGATED_USE_RECEIPT_MINT_TOKEN_FILE")?,
            key,
            issuer,
        };
        let service_token = credential(&input, CREDENTIAL_NAMES[0])?;
        let issuance_api_key = credential(&input, CREDENTIAL_NAMES[1])?;
        // One Signing Keys deployment has one issuer-sign HTTP credential.
        // Request and receipt callers may share it only for the same origin;
        // their independent signing-grant origins/token policies still differ.
        // Resolver and signer roles must never share a credential.
        let read_values = [
            &request_signing.read_credential,
            &receipt_signing.read_credential,
        ];
        let sign_values = [
            &request_signing.sign_credential,
            &receipt_signing.sign_credential,
        ];
        let service_values = [&service_token, &issuance_api_key];
        let same_origin = url::Url::parse(&request_signing.origin).ok()
            == url::Url::parse(&receipt_signing.origin).ok();
        if sign_values.iter().any(|value| read_values.contains(value))
            || service_values.iter().enumerate().any(|(i, value)| {
                read_values.contains(value)
                    || sign_values.contains(value)
                    || service_values[..i].contains(value)
            })
            || (!same_origin
                && (read_values[0] == read_values[1] || sign_values[0] == sign_values[1]))
            || request_signing.mint_token_file == receipt_signing.mint_token_file
        {
            return Err(HostConfigError::Invalid(
                "distinct signing and service credentials",
            ));
        }
        let tls_identity = remote_tls(&input, "DELEGATED_USE_TLS")?;
        let workload_identity = remote_tls(&input, "DELEGATED_USE_WORKLOAD_TLS")?;
        let workload_client_tls = WorkloadClientTlsFiles {
            ca_certificate: absolute(&input, "DELEGATED_USE_WORKLOAD_TLS_CA_CERT_FILE")?,
            identity: workload_identity,
        };
        let ca_files: Vec<String> = json(&input, "DELEGATED_USE_CLIENT_CA_FILES")?;
        if ca_files.is_empty() || ca_files.len() > 16 {
            return Err(HostConfigError::Invalid("DELEGATED_USE_CLIENT_CA_FILES"));
        }
        let mut client_ca_der = Vec::new();
        let mut ca_paths = BTreeSet::new();
        for name in ca_files {
            let path = valid_path(&name)
                .ok_or(HostConfigError::Invalid("DELEGATED_USE_CLIENT_CA_FILES"))?;
            if !ca_paths.insert(path.clone()) {
                return Err(HostConfigError::Invalid("DELEGATED_USE_CLIENT_CA_FILES"));
            }
            let der = read(&path, 65_536)
                .map_err(|_| HostConfigError::File("DELEGATED_USE_CLIENT_CA_FILES"))?;
            if der.is_empty() || der.len() > 65_536 || client_ca_der.contains(&der) {
                return Err(HostConfigError::Invalid("DELEGATED_USE_CLIENT_CA_FILES"));
            }
            client_ca_der.push(der);
        }
        let wires: Vec<WorkloadBindingWire> = json(&input, "DELEGATED_USE_WORKLOAD_BINDINGS")?;
        let bindings = wires
            .into_iter()
            .map(|wire| {
                DelegatedUseWorkloadBinding::new(
                    wire.workload_uri,
                    wire.leaf_sha256,
                    wire.principal_id,
                )
                .map_err(|_| HostConfigError::Invalid("DELEGATED_USE_WORKLOAD_BINDINGS"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let workload_bindings = DelegatedUseWorkloadBindings::new(bindings)
            .map_err(|_| HostConfigError::Invalid("DELEGATED_USE_WORKLOAD_BINDINGS"))?;
        Ok(Self {
            listen_addr,
            organization_id,
            deployment_profile_id,
            delegation_policy_id,
            database_urls,
            approval_configuration,
            authority,
            flow_start,
            request_options,
            public_base_url,
            challenge_lifetime_seconds: seconds(
                &input,
                "DELEGATED_USE_CHALLENGE_LIFETIME_SECONDS",
                120,
                30,
                600,
            )?,
            receipt_lifetime_seconds: seconds(
                &input,
                "DELEGATED_USE_RECEIPT_LIFETIME_SECONDS",
                30,
                1,
                30,
            )?,
            credential_template_grpc_target: https(
                &input,
                "DELEGATED_USE_CREDENTIAL_TEMPLATE_GRPC_TARGET",
                true,
            )?,
            presentation_policy_grpc_target: https(
                &input,
                "DELEGATED_USE_PRESENTATION_POLICY_GRPC_TARGET",
                true,
            )?,
            workload_client_tls,
            service_token,
            issuance_native_url: https(&input, "DELEGATED_USE_ISSUANCE_NATIVE_URL", true)?,
            issuance_api_key,
            credential_template_url: https(&input, "DELEGATED_USE_CREDENTIAL_TEMPLATE_URL", true)?,
            trust_profile_url: https(&input, "DELEGATED_USE_TRUST_PROFILE_URL", true)?,
            deployment_profile_url: https(&input, "DELEGATED_USE_DEPLOYMENT_PROFILE_URL", true)?,
            request_signing,
            receipt_signing,
            tls_identity,
            client_ca_der,
            workload_bindings,
        })
    }
}

fn known_name(name: &str) -> bool {
    if name == ENABLED || PUBLIC_NAMES.contains(&name) {
        return true;
    }
    if DATABASE_NAMES
        .into_iter()
        .chain(CREDENTIAL_NAMES)
        .chain(JSON_NAMES)
        .any(|field| name == field || name == format!("{field}_FILE"))
    {
        return true;
    }
    ["DELEGATED_USE_TLS", "DELEGATED_USE_WORKLOAD_TLS"]
        .into_iter()
        .any(|prefix| {
            [
                "CERT_FILE",
                "KMS_PROVIDER",
                "KMS_ADDR",
                "KMS_CA_CERT_FILE",
                "KMS_TOKEN_FILE",
                "KMS_KEY_NAME",
                "KMS_KEY_VERSION",
                "KMS_REGION",
                "KMS_KEY_ARN",
                "KEY",
                "KEY_FILE",
                "PRIVATE_KEY",
                "PRIVATE_KEY_FILE",
            ]
            .into_iter()
            .any(|suffix| name == format!("{prefix}_{suffix}"))
        })
}
fn required<'a>(
    values: &'a BTreeMap<String, String>,
    name: &'static str,
    maximum: usize,
) -> Result<&'a str, HostConfigError> {
    values
        .get(name)
        .map(String::as_str)
        .filter(|v| {
            !v.is_empty()
                && v.len() <= maximum
                && v.trim() == *v
                && !v.chars().any(char::is_control)
        })
        .ok_or(HostConfigError::Invalid(name))
}
fn uuid(values: &BTreeMap<String, String>, name: &'static str) -> Result<Uuid, HostConfigError> {
    let text = required(values, name, 36)?;
    Uuid::parse_str(text)
        .ok()
        .filter(|id| !id.is_nil() && id.to_string() == text)
        .ok_or(HostConfigError::Invalid(name))
}
fn database(
    values: &BTreeMap<String, String>,
    name: &'static str,
) -> Result<String, HostConfigError> {
    let text = required(values, name, MAX_SECRET_BYTES)?;
    let url = url::Url::parse(text).map_err(|_| HostConfigError::Invalid(name))?;
    let mut parameters = BTreeSet::new();
    if !matches!(url.scheme(), "postgres" | "postgresql")
        || url.host_str().is_none()
        || url.username().is_empty()
        || url.path().trim_matches('/').is_empty()
        || url.path().trim_start_matches('/').contains('/')
        || url.fragment().is_some()
        || url.query_pairs().any(|(key, _)| {
            ![
                "sslmode",
                "sslrootcert",
                "sslcert",
                "sslkey",
                "connect_timeout",
                "application_name",
                "statement-cache-capacity",
            ]
            .contains(&key.as_ref())
                || !parameters.insert(key.into_owned())
        })
    {
        return Err(HostConfigError::Invalid(name));
    }
    Ok(text.into())
}
fn https(
    values: &BTreeMap<String, String>,
    name: &'static str,
    origin: bool,
) -> Result<String, HostConfigError> {
    let text = required(values, name, 2_048)?;
    let url = url::Url::parse(text).map_err(|_| HostConfigError::Invalid(name))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || (origin && url.path() != "/")
    {
        return Err(HostConfigError::Invalid(name));
    }
    Ok(text.into())
}
fn did(values: &BTreeMap<String, String>, name: &'static str) -> Result<String, HostConfigError> {
    let text = required(values, name, 500)?;
    let parsed = url::Url::parse(text).map_err(|_| HostConfigError::Invalid(name))?;
    let method_and_id = text.strip_prefix("did:").and_then(|s| s.split_once(':'));
    if parsed.scheme() != "did"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !text.bytes().all(|b| b.is_ascii_graphic())
        || method_and_id.is_none_or(|(method, id)| {
            method.is_empty()
                || id.is_empty()
                || !method
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        })
    {
        return Err(HostConfigError::Invalid(name));
    }
    Ok(text.into())
}
fn credential(
    values: &BTreeMap<String, String>,
    name: &'static str,
) -> Result<String, HostConfigError> {
    let text = required(values, name, 1_024)?;
    if text.len() < 32 || !text.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(HostConfigError::Invalid(name));
    }
    Ok(text.into())
}
fn seconds(
    values: &BTreeMap<String, String>,
    name: &'static str,
    default: i64,
    minimum: i64,
    maximum: i64,
) -> Result<i64, HostConfigError> {
    let Some(text) = values.get(name) else {
        return Ok(default);
    };
    let value = text
        .parse::<i64>()
        .map_err(|_| HostConfigError::Invalid(name))?;
    if value < minimum || value > maximum || value.to_string() != *text {
        return Err(HostConfigError::Invalid(name));
    }
    Ok(value)
}
fn valid_path(value: &str) -> Option<PathBuf> {
    (!value.is_empty()
        && value.len() <= 4_096
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && Path::new(value).is_absolute())
    .then(|| PathBuf::from(value))
}
fn absolute(
    values: &BTreeMap<String, String>,
    name: &'static str,
) -> Result<PathBuf, HostConfigError> {
    valid_path(required(values, name, 4_096)?).ok_or(HostConfigError::Invalid(name))
}
fn remote_tls(
    values: &BTreeMap<String, String>,
    prefix: &'static str,
) -> Result<RemoteTlsIdentityFiles, HostConfigError> {
    let identity = RemoteTlsIdentityFiles::from_values_typed(
        |name| values.get(name).map(String::as_str),
        TlsIdentityNames::files(prefix),
        Duration::from_secs(5),
        16,
    )
    .map_err(|_| HostConfigError::Invalid(prefix))?
    .ok_or(HostConfigError::Invalid(prefix))?;
    let paths: Vec<&Path> = match &identity {
        RemoteTlsIdentityFiles::OpenBao(files) => vec![
            &files.certificate_chain_file,
            &files.kms_ca_cert_file,
            &files.kms_token_file,
        ],
        RemoteTlsIdentityFiles::AwsKms(files) => vec![&files.certificate_chain_file],
    };
    if paths
        .iter()
        .any(|path| path.to_str().and_then(valid_path).is_none())
    {
        return Err(HostConfigError::Invalid(prefix));
    }
    Ok(identity)
}
fn load_value(
    values: &mut BTreeMap<String, String>,
    name: &'static str,
    maximum: usize,
    read: &mut impl FnMut(&Path, usize) -> Result<Vec<u8>, ()>,
) -> Result<(), HostConfigError> {
    let file_name = format!("{name}_FILE");
    if let Some(path) = values.get(&file_name) {
        if values.contains_key(name) {
            return Err(HostConfigError::File(name));
        }
        let path = valid_path(path).ok_or(HostConfigError::File(name))?;
        let bytes = read(&path, maximum + 2).map_err(|_| HostConfigError::File(name))?;
        if bytes.len() > maximum + 2 {
            return Err(HostConfigError::File(name));
        }
        let value = String::from_utf8(bytes).map_err(|_| HostConfigError::File(name))?;
        let value = value.trim_end_matches(['\r', '\n']);
        if value.is_empty() || value.len() > maximum {
            return Err(HostConfigError::File(name));
        }
        values.insert(name.into(), value.into());
    }
    if values.get(name).is_some_and(|v| v.len() > maximum) {
        return Err(HostConfigError::Invalid(name));
    }
    Ok(())
}
fn bounded_file(path: &Path, maximum: usize) -> Result<Vec<u8>, ()> {
    let metadata = fs::metadata(path).map_err(|_| ())?;
    if !metadata.is_file() || metadata.len() > maximum as u64 {
        return Err(());
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|_| ())?
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.len() > maximum {
        return Err(());
    }
    Ok(bytes)
}
fn json<T: serde::de::DeserializeOwned>(
    values: &BTreeMap<String, String>,
    name: &'static str,
) -> Result<T, HostConfigError> {
    let value = values
        .get(name)
        .filter(|value| !value.is_empty() && value.len() <= MAX_JSON_BYTES)
        .ok_or(HostConfigError::Invalid(name))?;
    serde_json::from_str(value).map_err(|_| HostConfigError::Invalid(name))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkloadBindingWire {
    workload_uri: String,
    leaf_sha256: String,
    principal_id: String,
}
struct PublicJwk(Value);
impl<'de> Deserialize<'de> for PublicJwk {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = PublicJwk;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a closed public JWK")
            }
            fn visit_map<A: de::MapAccess<'de>>(
                self,
                mut access: A,
            ) -> Result<Self::Value, A::Error> {
                let mut map = Map::new();
                while let Some((key, value)) = access.next_entry::<String, String>()? {
                    if !["kty", "crv", "x", "y"].contains(&key.as_str())
                        || value.len() > 128
                        || map.insert(key, Value::String(value)).is_some()
                    {
                        return Err(de::Error::custom("invalid public JWK field"));
                    }
                }
                Ok(PublicJwk(Value::Object(map)))
            }
        }
        deserializer.deserialize_map(Visitor)
    }
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;
