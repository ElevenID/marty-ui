//! Internal consumer of the optional Marty principal/runtime-binding profile.
//!
//! This crate checks consistency of independently supplied inputs. It does not
//! authenticate an issuer, a caller, a certificate, a session, or a workload;
//! perform a live status/freshness check; or grant permission. Its opaque result
//! must not be treated as a bearer capability or persisted authorization.
//!
//! Existing API-key and human-session contexts do not establish proof of
//! possession. There are deliberately no conversions from either context,
//! public HTTP headers, or transport metadata into the validated result.

#![forbid(unsafe_code)]

mod model;
mod strict_json;
mod thumbprint;
mod validation;

use std::fmt;

use serde::Deserialize;

pub use strict_json::MAX_DOCUMENT_BYTES;
pub use thumbprint::{jwk_sha256_thumbprint, jwk_thumbprint_to_digest, TypedThumbprint};
pub use validation::validate_binding;

pub const PROFILE: &str = "urn:marty:principal-runtime-binding:v1";
pub const CONFIGURATION_PROFILE: &str = "urn:marty:principal-runtime-binding-configuration:v1";
pub const PROTOCOL_REVISION: &str = "6126da7619e057be2ff58dd38a5d50f49891d1b3";

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PrincipalType {
    ServiceAccount,
    MachineIdentity,
    External,
}

impl PrincipalType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ServiceAccount => "SERVICE_ACCOUNT",
            Self::MachineIdentity => "MACHINE_IDENTITY",
            Self::External => "EXTERNAL",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuntimeKind {
    Managed,
    External,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
pub enum KeyAlgorithm {
    ES256,
    EdDSA,
    Ed25519,
}

impl KeyAlgorithm {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ES256 => "ES256",
            Self::EdDSA => "EdDSA",
            Self::Ed25519 => "Ed25519",
        }
    }

    pub(crate) fn compatible_with(self, declared: &str) -> bool {
        match self {
            Self::ES256 => declared == "ES256",
            Self::EdDSA | Self::Ed25519 => matches!(declared, "EdDSA" | "Ed25519"),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
pub enum HashBasis {
    #[serde(rename = "JWK_RFC7638_SHA256")]
    JwkRfc7638Sha256,
    #[serde(rename = "X509_CERTIFICATE_DER_SHA256")]
    X509CertificateDerSha256,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
pub enum ThumbprintEncoding {
    #[serde(rename = "BASE64URL_SHA256")]
    Base64urlSha256,
    #[serde(rename = "MIP_SHA256_HEX")]
    MipSha256Hex,
    #[serde(rename = "MIP_SHA256_BASE64URL")]
    MipSha256Base64url,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    InvalidJson,
    DuplicateJsonField,
    SchemaInvalid,
    NonCanonicalEncoding,
    InvalidPublicKey,
    UnsupportedPublicKey,
    InvalidPublicKeyMetadata,
    PrivateKeyMaterial,
    WrongHashBasis,
    TenantMismatch,
    PrincipalMismatch,
    SourceIdentityMismatch,
    AudienceMismatch,
    SelectedAlgorithmMismatch,
    RuntimeMismatch,
    KeyBindingMismatch,
    MissingMachineState,
    MachineIdentityMismatch,
    DeploymentAssignmentMismatch,
    MachinePrincipalMismatch,
    InactiveMachine,
    ActiveKeyMismatch,
    ActiveKeyAlgorithmMismatch,
    RegisteredKeyMismatch,
    ExternalMachineEnrollment,
    MissingSubjectSession,
    SessionBindingMismatch,
    SessionRuntimeMismatch,
}

impl ErrorKind {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidJson => "INVALID_JSON",
            Self::DuplicateJsonField => "DUPLICATE_JSON_FIELD",
            Self::SchemaInvalid => "SCHEMA_INVALID",
            Self::NonCanonicalEncoding => "NON_CANONICAL_ENCODING",
            Self::InvalidPublicKey => "INVALID_PUBLIC_KEY",
            Self::UnsupportedPublicKey => "UNSUPPORTED_PUBLIC_KEY",
            Self::InvalidPublicKeyMetadata => "INVALID_PUBLIC_KEY_METADATA",
            Self::PrivateKeyMaterial => "PRIVATE_KEY_MATERIAL",
            Self::WrongHashBasis => "WRONG_HASH_BASIS",
            Self::TenantMismatch => "TENANT_MISMATCH",
            Self::PrincipalMismatch => "PRINCIPAL_MISMATCH",
            Self::SourceIdentityMismatch => "SOURCE_IDENTITY_MISMATCH",
            Self::AudienceMismatch => "AUDIENCE_MISMATCH",
            Self::SelectedAlgorithmMismatch => "SELECTED_ALGORITHM_MISMATCH",
            Self::RuntimeMismatch => "RUNTIME_MISMATCH",
            Self::KeyBindingMismatch => "KEY_BINDING_MISMATCH",
            Self::MissingMachineState => "MISSING_MACHINE_STATE",
            Self::MachineIdentityMismatch => "MACHINE_IDENTITY_MISMATCH",
            Self::DeploymentAssignmentMismatch => "DEPLOYMENT_ASSIGNMENT_MISMATCH",
            Self::MachinePrincipalMismatch => "MACHINE_PRINCIPAL_MISMATCH",
            Self::InactiveMachine => "INACTIVE_MACHINE",
            Self::ActiveKeyMismatch => "ACTIVE_KEY_MISMATCH",
            Self::ActiveKeyAlgorithmMismatch => "ACTIVE_KEY_ALGORITHM_MISMATCH",
            Self::RegisteredKeyMismatch => "REGISTERED_KEY_MISMATCH",
            Self::ExternalMachineEnrollment => "EXTERNAL_MACHINE_ENROLLMENT",
            Self::MissingSubjectSession => "MISSING_SUBJECT_SESSION",
            Self::SessionBindingMismatch => "SESSION_BINDING_MISMATCH",
            Self::SessionRuntimeMismatch => "SESSION_RUNTIME_MISMATCH",
        }
    }
}

/// Error diagnostics contain only static codes and field names, never input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BindingError {
    kind: ErrorKind,
    field: &'static str,
}

impl BindingError {
    pub(crate) const fn new(kind: ErrorKind, field: &'static str) -> Self {
        Self { kind, field }
    }

    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    pub const fn code(&self) -> &'static str {
        self.kind.code()
    }

    pub const fn field(&self) -> &'static str {
        self.field
    }
}

impl fmt::Display for BindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} at {}", self.code(), self.field)
    }
}

impl std::error::Error for BindingError {}

/// Parsed shape, not authenticated identity. Only the bounded parser creates it.
#[derive(Clone)]
pub struct BindingRecord(pub(crate) model::Record);

/// Parsed private configuration; the caller must establish its trust and scope.
#[derive(Clone)]
pub struct ProfileConfiguration(pub(crate) model::Configuration);

/// Parsed current-machine snapshot, not an enrollment or status authority.
#[derive(Clone)]
pub struct MachineIdentitySnapshot(pub(crate) model::Machine);

/// Parsed exact subject-session tuple. The caller verifies its source/freshness.
#[derive(Clone)]
pub struct SubjectSessionEvidence(pub(crate) model::Session);

macro_rules! redacted_debug {
    ($($name:ident),+ $(,)?) => {$(
        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), " { <private> }"))
            }
        }
    )+};
}

redacted_debug!(
    BindingRecord,
    ProfileConfiguration,
    MachineIdentitySnapshot,
    SubjectSessionEvidence,
    ValidatedPrincipalBinding
);

pub fn parse_binding_record(raw: &[u8]) -> Result<BindingRecord, BindingError> {
    let record = strict_json::decode(raw, "record")?;
    validation::record_shape(&record)?;
    Ok(BindingRecord(record))
}

pub fn parse_configuration(raw: &[u8]) -> Result<ProfileConfiguration, BindingError> {
    let configuration = strict_json::decode(raw, "configuration")?;
    validation::configuration_shape(&configuration)?;
    Ok(ProfileConfiguration(configuration))
}

pub fn parse_machine_snapshot(raw: &[u8]) -> Result<MachineIdentitySnapshot, BindingError> {
    let machine = strict_json::decode(raw, "machine_identity")?;
    validation::machine_shape(&machine)?;
    Ok(MachineIdentitySnapshot(machine))
}

pub fn parse_session_evidence(raw: &[u8]) -> Result<SubjectSessionEvidence, BindingError> {
    let session = strict_json::decode(raw, "expected_session")?;
    validation::session_shape(&session, "expected_session")?;
    Ok(SubjectSessionEvidence(session))
}

pub fn parse_thumbprint(raw: &[u8]) -> Result<TypedThumbprint, BindingError> {
    let document = strict_json::decode(raw, "thumbprint")?;
    TypedThumbprint::from_document(&document)
}

/// Independent caller inputs, never a public request body.
///
/// The name states the caller's obligation: this constructor does not
/// authenticate these values. Obtain the tenant from authorization processing,
/// and load configuration/current state/session evidence through trusted ports.
pub struct TrustedBindingInputs<'a> {
    pub(crate) organization_id: &'a str,
    pub(crate) configuration: &'a ProfileConfiguration,
    pub(crate) machine: Option<&'a MachineIdentitySnapshot>,
    pub(crate) session: Option<&'a SubjectSessionEvidence>,
}

impl<'a> TrustedBindingInputs<'a> {
    pub fn new(
        authorized_organization_id: &'a str,
        configuration: &'a ProfileConfiguration,
    ) -> Result<Self, BindingError> {
        validation::uuid(authorized_organization_id, "authorized_organization_id")?;
        Ok(Self {
            organization_id: authorized_organization_id,
            configuration,
            machine: None,
            session: None,
        })
    }

    pub fn with_machine(mut self, machine: &'a MachineIdentitySnapshot) -> Self {
        self.machine = Some(machine);
        self
    }

    pub fn with_session(mut self, session: &'a SubjectSessionEvidence) -> Self {
        self.session = Some(session);
        self
    }
}

/// Opaque consistency result, not proof of authentication or authorization.
///
/// It deliberately cannot be deserialized, created from public fields, or
/// converted automatically from an API-key or browser-session identity.
/// A consumer still authenticates source evidence and applies current status,
/// freshness, grant, tenant and operation authorization requirements at use.
///
/// ```compile_fail
/// use marty_principal_runtime_binding::ValidatedPrincipalBinding;
/// let forged: ValidatedPrincipalBinding = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Clone)]
#[must_use]
pub struct ValidatedPrincipalBinding {
    pub(crate) record: model::Record,
    pub(crate) key: TypedThumbprint,
    pub(crate) deployment_profile_id: String,
}

impl ValidatedPrincipalBinding {
    pub fn organization_id(&self) -> &str {
        &self.record.organization_id
    }
    pub fn principal_type(&self) -> PrincipalType {
        self.record.principal.kind
    }
    pub fn principal_id(&self) -> &str {
        &self.record.principal.id
    }
    pub fn issuer(&self) -> &str {
        &self.record.authentication.issuer
    }
    pub fn subject(&self) -> &str {
        &self.record.authentication.subject
    }
    pub fn audience(&self) -> &str {
        &self.record.authentication.audience
    }
    pub fn runtime_kind(&self) -> RuntimeKind {
        self.record.runtime.kind
    }
    pub fn runtime_instance_ref(&self) -> &str {
        &self.record.runtime.instance_ref
    }
    pub fn machine_identity_id(&self) -> Option<&str> {
        self.record.runtime.machine_identity_id.as_deref()
    }
    pub fn deployment_profile_id(&self) -> &str {
        &self.deployment_profile_id
    }
    pub fn key_algorithm(&self) -> KeyAlgorithm {
        self.record.authentication.key_algorithm
    }
    pub fn key_thumbprint(&self) -> &TypedThumbprint {
        &self.key
    }
    pub fn represented_subject_type(&self) -> Option<&'static str> {
        self.record
            .session_binding
            .as_ref()
            .map(|session| match session.represented_subject.kind {
                model::SubjectType::User => "USER",
                model::SubjectType::Organization => "ORGANIZATION",
            })
    }
    pub fn represented_subject_id(&self) -> Option<&str> {
        self.record
            .session_binding
            .as_ref()
            .map(|session| session.represented_subject.id.as_str())
    }
    pub fn session_ref(&self) -> Option<&str> {
        self.record
            .session_binding
            .as_ref()
            .map(|session| session.session_ref.as_str())
    }
    pub fn session_establishment_evidence_ref(&self) -> Option<&str> {
        self.record
            .session_binding
            .as_ref()
            .map(|session| session.establishment_evidence_ref.as_str())
    }
}
