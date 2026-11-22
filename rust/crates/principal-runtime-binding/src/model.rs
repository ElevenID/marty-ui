//! Private pinned-contract DTOs. Public wrappers must pass the bounded decoder.

use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};

use crate::{HashBasis, KeyAlgorithm, PrincipalType, RuntimeKind, ThumbprintEncoding};

// Optional fields whose schema excludes null must distinguish absent from null.
pub(crate) fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Principal {
    #[serde(rename = "type")]
    pub kind: PrincipalType,
    pub id: String,
}

#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Thumbprint {
    pub basis: HashBasis,
    pub encoding: ThumbprintEncoding,
    pub value: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Authentication {
    pub issuer: String,
    pub subject: String,
    pub audience: String,
    pub key_algorithm: KeyAlgorithm,
    pub key_thumbprint: Thumbprint,
}

#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Runtime {
    pub kind: RuntimeKind,
    pub instance_ref: String,
    #[serde(default, deserialize_with = "present")]
    pub machine_identity_id: Option<String>,
}

#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RepresentedSubject {
    #[serde(rename = "type")]
    pub kind: SubjectType,
    pub id: String,
}

#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum SubjectType {
    User,
    Organization,
}

#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Session {
    pub represented_subject: RepresentedSubject,
    pub principal: Principal,
    pub runtime_instance_ref: String,
    pub key_thumbprint: Thumbprint,
    pub session_ref: String,
    pub establishment_evidence_ref: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Record {
    pub profile: String,
    pub organization_id: String,
    pub principal: Principal,
    pub authentication: Authentication,
    pub runtime: Runtime,
    #[serde(default, deserialize_with = "present")]
    pub session_binding: Option<Session>,
    #[serde(default, deserialize_with = "present")]
    pub agent_definition_ref: Option<String>,
    #[serde(default, deserialize_with = "present")]
    pub run_ref: Option<String>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuthenticationSource {
    pub issuer: String,
    pub subject: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConfiguredRuntime {
    pub kind: RuntimeKind,
    pub instance_ref: String,
    #[serde(default, deserialize_with = "present")]
    pub machine_identity_id: Option<String>,
    #[serde(default, deserialize_with = "present")]
    pub active_key_id: Option<String>,
    #[serde(default, deserialize_with = "present")]
    pub stored_thumbprint_encoding: Option<ThumbprintEncoding>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Configuration {
    pub profile: String,
    pub organization_id: String,
    pub deployment_profile_id: String,
    pub principal: Principal,
    pub authentication_source: AuthenticationSource,
    pub allowed_audiences: Vec<String>,
    pub runtime: ConfiguredRuntime,
    pub expected_key_algorithm: KeyAlgorithm,
    pub expected_key_thumbprint: Thumbprint,
    pub shared_runtime: bool,
}

#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct MachineKey {
    pub key_id: String,
    pub thumbprint: String,
    pub algorithm: String,
    pub status: String,
    #[serde(default, deserialize_with = "present")]
    pub public_key_jwk: Option<Map<String, Value>>,
    #[serde(default, deserialize_with = "present")]
    pub certificate_chain_ref: Option<String>,
    pub valid_from: Option<String>,
    pub valid_until: Option<String>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Assignments {
    pub deployment_profile_id: Option<String>,
    pub site_id: Option<String>,
    pub operator_organization_id: Option<String>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AttestationIdentity {
    #[serde(default, deserialize_with = "present")]
    pub attestation_key_ids: Option<Vec<String>>,
    #[serde(default, deserialize_with = "present")]
    pub evidence_formats: Option<Vec<String>>,
    #[serde(default, deserialize_with = "present")]
    pub endorsement_refs: Option<Vec<String>>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Machine {
    pub id: String,
    pub organization_id: String,
    pub machine_id: String,
    pub display_name: String,
    #[serde(default, deserialize_with = "present")]
    pub description: Option<String>,
    pub machine_type: String,
    pub status: String,
    pub identity_keys: Vec<MachineKey>,
    #[serde(default, deserialize_with = "present")]
    pub assignments: Option<Assignments>,
    #[serde(default, deserialize_with = "present")]
    pub credential_ids: Option<Vec<String>>,
    #[serde(default, deserialize_with = "present")]
    pub attestation_identity: Option<AttestationIdentity>,
    pub created_at: String,
    #[serde(default, deserialize_with = "present")]
    pub updated_at: Option<String>,
    pub suspended_at: Option<String>,
    pub revoked_at: Option<String>,
    pub retired_at: Option<String>,
    pub status_reason: Option<String>,
}
