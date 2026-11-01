//! Authenticated source material for a recurring installer-managed private CA
//! generation. The fixed producer retains its existing scoped AppRole and all
//! 43 inputs; this plan grants no enrollment, issuer rotation or root authority.
#![cfg(target_os = "linux")]
use crate::{
    installer_compose::{ComposeInputs, ComposeSession},
    installer_generation_binding::{self as generation, GenerationBinding},
    installer_hosting::{self, CertificateSource},
    installer_ingress_outputs::{self, IngressMetadata},
    installer_ingress_provision::{self as ingress, IngressIdentity},
    installer_json, installer_renewal, installer_renewal_bootstrap,
    installer_state::{LockedInspection, LockedMaintenance, RuntimeBinding},
};
use marty_selfhost_identity::origin::PublicOrigin;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use spki::der::{Encode, EncodePem};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

pub const PLAN_INPUT: &str = "/input/managed-renewal-plan.json";
pub const PLAN_DIGEST_ENV: &str = "MARTY_INSTALLER_MANAGED_RENEWAL_PLAN_SHA256";
const SCHEMA: &str = "elevenid.installer-managed-renewal-plan/v1";
const MAX_BYTES: usize = 128 * 1024;
const REFUSED: &str = "Managed private-CA renewal source refused; preserve the selected generation and scoped enrollment";
const IDENTITY: [&str; 3] = [
    "renewal-role-id",
    "renewal-secret-id",
    "renewal-leaf-policies.json",
];
type Result<T> = std::result::Result<T, String>;
fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}
fn hash(bytes: &[u8]) -> String {
    crate::installer_release::sha256(bytes)
}
fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ManagedRenewalPlan(PlanData);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanData {
    schema: String,
    certificate_source: CertificateSource,
    installation_id: String,
    engine_id: String,
    initial_configuration_sha256: String,
    hosting_selection_sha256: Option<String>,
    hosting_source_sha256: String,
    canonical_origin: String,
    public_entry_origin: Option<String>,
    sequence: u64,
    attempt: u64,
    parent_attempt: u64,
    parent_binding_sha256: String,
    renewal_enrolment_receipt_sha256: String,
    original_generation_intent_sha256: String,
    identity_sha256: BTreeMap<String, String>,
    leaf_policies: Vec<String>,
    input_sha256: BTreeMap<String, String>,
    input_observed_at: u64,
    ingress: IngressMetadata,
    ingress_ca_pem: String,
    ingress_leaf_pem: String,
    ingress_spki_sha256: String,
    keycloak_receipt_sha256: String,
}

impl ManagedRenewalPlan {
    /// This constructor is the pending host integration seam. It requires an
    /// actually selected private generation and its original completed scoped
    /// enrollment. It cannot be built from an imported foundation or public CA.
    pub fn from_selected(
        state: &LockedInspection,
        installation: &Path,
        parent: &GenerationBinding,
        attempt: u64,
    ) -> Result<Self> {
        state.require_path_binding(installation)?;
        let owner = state.journal().installation_id().to_string();
        let runtime = state.journal().runtime().ok_or(REFUSED)?;
        require(
            parent.managed_ingress()
                && parent.installation_id == owner
                && parent.engine_id == runtime.engine_id,
        )?;
        require(
            generation::load_verified(installation, &owner, &runtime.engine_id)?.as_ref()
                == Some(parent),
        )?;
        let hosting = installer_hosting::resolve(state)?;
        require(hosting.certificate_source() == CertificateSource::ManagedCa)?;
        let initial = crate::installer_doctor::load_initial_session(state, installation)?;
        let listener =
            crate::installer_compose::bound_ingress_listener(&initial.model, &initial.inputs)?;
        let enrolment = installer_renewal::require_managed_enrolment(state, installation)?;
        let ingress = parent.ingress_metadata(installation)?.ok_or(REFUSED)?;
        let input_sha256 = installer_renewal_bootstrap::managed_inputs()
            .into_iter()
            .map(|name| Ok((name.clone(), hash(&parent.read(installation, &name)?))))
            .collect::<Result<BTreeMap<_, _>>>()?;
        let ingress_ca_pem = String::from_utf8(parent.read(installation, ingress::OUTPUTS[0])?)
            .map_err(|_| REFUSED)?;
        let ingress_leaf_pem = String::from_utf8(parent.read(installation, ingress::OUTPUTS[1])?)
            .map_err(|_| REFUSED)?;
        let cert = ingress::certificate(&ingress_leaf_pem)?;
        let plan = Self(PlanData {
            schema: SCHEMA.into(),
            certificate_source: CertificateSource::ManagedCa,
            installation_id: owner,
            engine_id: runtime.engine_id.clone(),
            initial_configuration_sha256: initial.configuration_sha256,
            hosting_selection_sha256: state
                .journal()
                .hosting_selection_sha256()
                .map(str::to_owned),
            hosting_source_sha256: hosting.source_sha256().into(),
            canonical_origin: hosting.resolve_origin(listener.port)?.as_str().into(),
            public_entry_origin: hosting
                .public_entry_origin()
                .map(|origin| origin.as_str().into()),
            sequence: parent.sequence().checked_add(1).ok_or(REFUSED)?,
            attempt,
            parent_attempt: parent.attempt(),
            parent_binding_sha256: parent.sha256()?,
            renewal_enrolment_receipt_sha256: enrolment.receipt_sha256,
            original_generation_intent_sha256: enrolment.generation_intent_sha256,
            identity_sha256: enrolment.identity_sha256,
            leaf_policies: enrolment.leaf_policies,
            input_sha256,
            input_observed_at: ingress.token_observed_at,
            ingress,
            ingress_ca_pem,
            ingress_leaf_pem,
            ingress_spki_sha256: hash(
                &cert
                    .tbs_certificate
                    .subject_public_key_info
                    .to_der()
                    .map_err(|_| REFUSED)?,
            ),
            keycloak_receipt_sha256: hash(&state.read_evidence("keycloak-observation.json")?),
        });
        plan.validate()?;
        plan.require_configuration(state, installation)?;
        plan.require_parent(installation, parent)?;
        state.require_unchanged()?;
        Ok(plan)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| REFUSED)?;
        require(bytes.len() <= MAX_BYTES)?;
        Ok(bytes)
    }
    pub fn sha256(&self) -> Result<String> {
        Ok(hash(&self.to_bytes()?))
    }
    pub fn parse_authenticated(bytes: &[u8], expected_sha256: &str) -> Result<Self> {
        require(
            !bytes.is_empty()
                && bytes.len() <= MAX_BYTES
                && valid_hash(expected_sha256)
                && hash(bytes) == expected_sha256,
        )?;
        let plan = Self(
            serde_json::from_value(installer_json::decode(bytes).map_err(|_| REFUSED)?)
                .map_err(|_| REFUSED)?,
        );
        plan.validate()?;
        require(plan.to_bytes()? == bytes)?;
        Ok(plan)
    }
    pub fn installation_id(&self) -> &str {
        &self.0.installation_id
    }
    pub fn sequence(&self) -> u64 {
        self.0.sequence
    }
    pub fn attempt(&self) -> u64 {
        self.0.attempt
    }
    pub fn parent_attempt(&self) -> u64 {
        self.0.parent_attempt
    }
    pub fn parent_binding_sha256(&self) -> &str {
        &self.0.parent_binding_sha256
    }
    pub fn input_hashes(&self) -> &BTreeMap<String, String> {
        &self.0.input_sha256
    }
    pub fn identity_hashes(&self) -> &BTreeMap<String, String> {
        &self.0.identity_sha256
    }
    pub fn input_observed_at(&self) -> u64 {
        self.0.input_observed_at
    }
    pub fn enrolment_receipt_sha256(&self) -> &str {
        &self.0.renewal_enrolment_receipt_sha256
    }
    pub fn canonical_origin(&self) -> &str {
        &self.0.canonical_origin
    }
    pub fn public_entry_origin(&self) -> Option<&str> {
        self.0.public_entry_origin.as_deref()
    }
    pub fn record_name(&self) -> String {
        crate::installer_generation_maintenance::attempt::Attempt::new(
            self.0.sequence,
            self.0.attempt,
        )
        .record("managed-renewal-plan")
    }
    pub fn ingress_identity(&self) -> Result<IngressIdentity> {
        identity_from_origins(
            &self.0.canonical_origin,
            self.0.public_entry_origin.as_deref(),
        )
    }
    pub fn workload_policies(&self) -> Vec<String> {
        self.0
            .leaf_policies
            .iter()
            .filter(|name| name.as_str() != self.0.ingress.key_name)
            .cloned()
            .collect()
    }

    pub(crate) fn record_for_maintenance(&self, state: &mut LockedMaintenance) -> Result<PathBuf> {
        let installation =
            crate::installer_generation_maintenance::installation_path(state.inspection())?;
        self.require_configuration(state.inspection(), &installation)?;
        let parent =
            generation::load_verified(&installation, self.installation_id(), &self.0.engine_id)?
                .ok_or(REFUSED)?;
        self.require_parent(&installation, &parent)?;
        let bytes = self.to_bytes()?;
        let name = self.record_name();
        match state.read_evidence(&name)? {
            Some(old) => require(old == bytes)?,
            None => state.write_evidence_exclusive(&name, &bytes)?,
        }
        self.require_saved(state.inspection())?;
        Ok(installation.join("evidence").join(name))
    }

    /// Authenticate saved source provenance. The transaction separately checks
    /// its selected parent; historical generation walks use the already
    /// verified predecessor rather than recursively reopening all ancestors.
    pub fn require_saved(&self, state: &LockedInspection) -> Result<()> {
        let installation = crate::installer_generation_maintenance::installation_path(state)?;
        require(state.read_evidence(&self.record_name())? == self.to_bytes()?)?;
        self.require_configuration(state, &installation)?;
        state.require_unchanged()
    }
    fn require_configuration(&self, state: &LockedInspection, installation: &Path) -> Result<()> {
        self.validate()?;
        state.require_path_binding(installation)?;
        let hosting = installer_hosting::resolve(state)?;
        let initial = crate::installer_doctor::load_initial_session(state, installation)?;
        let listener =
            crate::installer_compose::bound_ingress_listener(&initial.model, &initial.inputs)?;
        let enrolled = installer_renewal::require_managed_enrolment(state, installation)?;
        require(
            hosting.certificate_source() == CertificateSource::ManagedCa
                && self.0.installation_id == state.journal().installation_id().to_string()
                && self.0.engine_id == state.journal().runtime().ok_or(REFUSED)?.engine_id
                && self.0.initial_configuration_sha256 == initial.configuration_sha256
                && self.0.hosting_selection_sha256.as_deref()
                    == state.journal().hosting_selection_sha256()
                && self.0.hosting_source_sha256 == hosting.source_sha256()
                && self.0.canonical_origin == hosting.resolve_origin(listener.port)?.as_str()
                && self.0.public_entry_origin.as_deref()
                    == hosting.public_entry_origin().map(PublicOrigin::as_str)
                && self.0.renewal_enrolment_receipt_sha256 == enrolled.receipt_sha256
                && self.0.original_generation_intent_sha256 == enrolled.generation_intent_sha256
                && self.0.identity_sha256 == enrolled.identity_sha256
                && self.0.leaf_policies == enrolled.leaf_policies
                && self.0.keycloak_receipt_sha256
                    == hash(&state.read_evidence("keycloak-observation.json")?),
        )
    }
    pub fn require_parent(&self, installation: &Path, parent: &GenerationBinding) -> Result<()> {
        let metadata = parent.ingress_metadata(installation)?.ok_or(REFUSED)?;
        self.require_verified_parent(installation, parent, &metadata)
    }
    /// The caller's forward generation walk has already authenticated the
    /// immediate parent and metadata. This comparison has no ancestry reload.
    pub(crate) fn require_verified_parent(
        &self,
        installation: &Path,
        parent: &GenerationBinding,
        metadata: &IngressMetadata,
    ) -> Result<()> {
        self.validate()?;
        require(
            parent.managed_ingress()
                && parent.installation_id == self.0.installation_id
                && parent.engine_id == self.0.engine_id
                && parent.sequence().checked_add(1) == Some(self.0.sequence)
                && parent.attempt() == self.0.parent_attempt
                && parent.sha256()? == self.0.parent_binding_sha256
                && metadata == &self.0.ingress,
        )?;
        for (name, digest) in &self.0.input_sha256 {
            require(hash(&parent.read(installation, name)?) == *digest)?;
        }
        Ok(())
    }

    /// Exact source and durable identity before any login or issuance. Old
    /// token bytes are compared, never presented to OpenBao as authority.
    pub(crate) fn require_snapshot(
        &self,
        owner: &str,
        current: &BTreeMap<String, Vec<u8>>,
        identity: &BTreeMap<String, Vec<u8>>,
        keycloak_receipt: &[u8],
    ) -> Result<()> {
        self.validate()?;
        installer_renewal_bootstrap::validate_current(current)?;
        require(
            owner == self.installation_id()
                && crate::installer_generation::hashes(current) == self.0.input_sha256
                && crate::installer_generation::hashes(identity) == self.0.identity_sha256
                && hash(keycloak_receipt) == self.0.keycloak_receipt_sha256
                && current.get(ingress::OUTPUTS[0]).map(Vec::as_slice)
                    == Some(self.0.ingress_ca_pem.as_bytes())
                && current.get(ingress::OUTPUTS[1]).map(Vec::as_slice)
                    == Some(self.0.ingress_leaf_pem.as_bytes()),
        )?;
        crate::installer_generation::original_nonce(keycloak_receipt, owner)?;
        let policies: Vec<String> =
            serde_json::from_slice(identity.get(IDENTITY[2]).ok_or(REFUSED)?)
                .map_err(|_| REFUSED)?;
        require(policies == self.0.leaf_policies)
    }

    fn validate(&self) -> Result<()> {
        require(
            self.0.schema == SCHEMA
                && self.0.certificate_source == CertificateSource::ManagedCa
                && self.0.sequence > 0
                && (self.0.sequence > 1 || self.0.parent_attempt == 0)
                && !self.0.engine_id.is_empty()
                && self.0.engine_id.len() <= 128
                && self.0.engine_id.bytes().all(|b| b.is_ascii_graphic())
                && self.0.input_observed_at > 0
                && self.0.input_observed_at == self.0.ingress.token_observed_at
                && self
                    .0
                    .hosting_selection_sha256
                    .as_deref()
                    .is_none_or(valid_hash),
        )?;
        for value in [
            &self.0.initial_configuration_sha256,
            &self.0.hosting_source_sha256,
            &self.0.parent_binding_sha256,
            &self.0.renewal_enrolment_receipt_sha256,
            &self.0.original_generation_intent_sha256,
            &self.0.ingress_spki_sha256,
            &self.0.keycloak_receipt_sha256,
        ] {
            require(valid_hash(value))?;
        }
        require(
            self.0.input_sha256.keys().cloned().collect::<BTreeSet<_>>()
                == installer_renewal_bootstrap::managed_inputs()
                && self
                    .0
                    .identity_sha256
                    .keys()
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>()
                    == IDENTITY.into()
                && self
                    .0
                    .input_sha256
                    .values()
                    .chain(self.0.identity_sha256.values())
                    .all(|v| valid_hash(v)),
        )?;
        let name = ingress::resource_name(&self.0.installation_id)?;
        let names = &self.0.leaf_policies;
        require(
            names.len() == 22
                && names.windows(2).all(|pair| pair[0] < pair[1])
                && names.iter().all(|value| {
                    !value.is_empty()
                        && value.len() <= 160
                        && !["root", "default", "selfhost-kms-renewal"].contains(&value.as_str())
                        && value
                            .bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                })
                && names
                    .iter()
                    .filter(|name| name.starts_with("installer-ingress-"))
                    .collect::<Vec<_>>()
                    == [&name],
        )?;
        let identity = self.ingress_identity()?;
        let metadata = installer_ingress_outputs::metadata_for_identity(
            &serde_json::to_vec(&self.0.ingress).map_err(|_| REFUSED)?,
            self.installation_id(),
            self.0.input_observed_at,
            &identity,
        )?;
        let leaf = ingress::certificate(&self.0.ingress_leaf_pem)?;
        let ca = ingress::certificate(&self.0.ingress_ca_pem)?;
        let spki = &leaf.tbs_certificate.subject_public_key_info;
        let public = spki
            .to_pem(spki::der::pem::LineEnding::LF)
            .map_err(|_| REFUSED)?;
        require(
            hash(&spki.to_der().map_err(|_| REFUSED)?) == self.0.ingress_spki_sha256
                && metadata.ca_pem_sha256 == hash(self.0.ingress_ca_pem.as_bytes())
                && metadata.certificate_pem_sha256 == hash(self.0.ingress_leaf_pem.as_bytes())
                && metadata.ca_der_sha256 == hash(&ca.to_der().map_err(|_| REFUSED)?)
                && metadata.certificate_der_sha256 == hash(&leaf.to_der().map_err(|_| REFUSED)?)
                && self.0.input_sha256.get(ingress::OUTPUTS[0]) == Some(&metadata.ca_pem_sha256)
                && self.0.input_sha256.get(ingress::OUTPUTS[1])
                    == Some(&metadata.certificate_pem_sha256),
        )?;
        // Expired source material remains historically inspectable. The live
        // producer independently proves the current issuer/key and all fresh
        // replacements; this observation cannot make an old leaf fresh again.
        require(
            ingress::check_certificates_for(
                &self.0.ingress_ca_pem,
                &self.0.ingress_leaf_pem,
                &public,
                &name,
                self.0.input_observed_at,
                &identity,
            )? == (metadata.ca_expires_at, metadata.certificate_expires_at),
        )
    }

    pub fn require_job_inputs(
        &self,
        docker: &Path,
        runtime: &RuntimeBinding,
        inputs: &ComposeInputs,
    ) -> Result<()> {
        self.validate()?;
        require(
            inputs.services == ["installer-generation"]
                && inputs.project
                    == format!("marty-install-{}", self.installation_id().replace('-', ""))
                && runtime.engine_id == self.0.engine_id,
        )?;
        let expected = inputs
            .installation
            .join("evidence")
            .join(self.record_name());
        let digest = self.sha256()?;
        let bound: Vec<_> = inputs
            .bound_inputs
            .iter()
            .filter(|file| file.path == expected)
            .collect();
        require(bound.len() == 1 && bound[0].sha256 == digest)?;
        let session = ComposeSession::new_generation(docker, runtime, inputs.clone())?;
        require_job_model(
            &session.model()["services"]["installer-generation"],
            &expected,
            &digest,
        )
    }
}

fn identity_from_origins(canonical: &str, alias: Option<&str>) -> Result<IngressIdentity> {
    let origin = PublicOrigin::parse(canonical).map_err(|_| REFUSED)?;
    require(origin.as_str() == canonical)?;
    let ip = if let Some(alias_text) = alias {
        let alias = PublicOrigin::parse(alias_text).map_err(|_| REFUSED)?;
        require(
            alias.as_str() == alias_text
                && alias.as_str() != canonical
                && origin.dns_name().is_some()
                && origin.host() != "localhost"
                && !alias.is_loopback(),
        )?;
        Some(alias.ip_address().ok_or(REFUSED)?)
    } else {
        origin.ip_address().or_else(|| {
            (origin.host() == "localhost").then_some(std::net::Ipv4Addr::LOCALHOST.into())
        })
    };
    IngressIdentity::new(origin.dns_name(), ip)
}

fn require_job_model(service: &Value, expected: &Path, digest: &str) -> Result<()> {
    require(service["environment"][PLAN_DIGEST_ENV] == digest)?;
    for env in [
        crate::installer_public_ingress::PLAN_DIGEST_ENV,
        crate::installer_public_ingress::AUTHORITY_PLAN_DIGEST_ENV,
    ] {
        require(service["environment"].get(env).is_none())?;
    }
    let target = Path::new(PLAN_INPUT);
    let forbidden = [
        crate::installer_public_ingress::PLAN_INPUT,
        crate::installer_public_ingress::AUTHORITY_PLAN_INPUT,
    ];
    let does_not_shadow = |destination: &Path| {
        !target.starts_with(destination)
            && !destination.starts_with(target)
            && forbidden.iter().all(|path| {
                !Path::new(path).starts_with(destination) && !destination.starts_with(path)
            })
    };
    let mut found = false;
    for mount in service["volumes"].as_array().ok_or(REFUSED)? {
        let destination = Path::new(mount["target"].as_str().ok_or(REFUSED)?);
        require(forbidden.iter().all(|path| {
            !Path::new(path).starts_with(destination) && !destination.starts_with(path)
        }))?;
        if destination == target {
            require(
                !found
                    && mount["type"] == "bind"
                    && mount["read_only"] == true
                    && mount["bind"]["create_host_path"] == false
                    && crate::installer_compose::config_path(&mount["source"])? == expected,
            )?;
            found = true;
        } else {
            require(does_not_shadow(destination))?;
        }
    }
    require(found)?;
    for entry in service["tmpfs"].as_array().into_iter().flatten() {
        let destination = Path::new(
            entry
                .as_str()
                .ok_or(REFUSED)?
                .split(':')
                .next()
                .ok_or(REFUSED)?,
        );
        require(does_not_shadow(destination))?;
    }
    for kind in ["secrets", "configs"] {
        for mount in service[kind].as_array().into_iter().flatten() {
            let target_text = mount["target"].as_str().ok_or(REFUSED)?;
            if target_text.starts_with('/') {
                let destination = Path::new(target_text);
                require(does_not_shadow(destination))?;
            }
        }
    }
    Ok(())
}

pub(crate) fn helper_plan(owner: &str, input_owner: u32) -> Result<Option<ManagedRenewalPlan>> {
    let digest = match std::env::var(PLAN_DIGEST_ENV) {
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Ok(value) => value,
        Err(_) => return Err(REFUSED.into()),
    };
    require(valid_hash(&digest))?;
    let bytes = installer_renewal_bootstrap::input(
        Path::new(PLAN_INPUT),
        MAX_BYTES as u64,
        &[0, input_owner],
        &[0o600],
    )?;
    let plan = ManagedRenewalPlan::parse_authenticated(&bytes, &digest)?;
    require(
        plan.installation_id() == owner
            && plan.ingress_identity()? == IngressIdentity::from_environment()?,
    )?;
    Ok(Some(plan))
}

#[cfg(test)]
#[path = "installer_managed_renewal_tests.rs"]
pub(crate) mod tests;
