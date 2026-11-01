//! Public ACME ingress inside the existing immutable generation transaction.
//! This module never obtains a CSR, creates an ACME order, publishes live files,
//! changes a key or grants installation readiness. Its only remote mutation is
//! replacement of the separately scoped, short-lived TLS signing credential.
#![cfg(target_os = "linux")]

use crate::{
    installer_acme::AcmeCandidate,
    installer_acme_certificates::{
        self as certificates, CertificateIdentity, RetainedIngressKey, ValidatedCertificate,
    },
    installer_acme_configuration::AcmeEnvironment,
    installer_acme_state::{self as enrolment, Ledger, Stage},
    installer_ingress_provision::{self as ingress, IngressIdentity},
    installer_json, installer_release,
    installer_state::{InstallerState, LockedInspection, Phase},
    operator_http::request,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use marty_openbao_http::OpenBaoHttp;
use marty_selfhost_identity::origin::PublicOrigin;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use spki::{
    der::{Decode, EncodePem},
    SubjectPublicKeyInfoOwned,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[path = "installer_public_renewal.rs"]
mod authority;
pub(crate) use authority::helper_authority_plan;
pub use authority::{
    PublicRenewalAuthorityPlan, AUTHORITY_PLAN_DIGEST_ENV, AUTHORITY_PLAN_INPUT,
    PUBLIC_RENEWAL_AUTHORITY_PLAN_RECORD,
};

type Result<T> = std::result::Result<T, String>;
const REFUSED: &str = "Public ingress generation refused; preserve the candidate, plan and generation receipts. No live certificate was replaced";
pub const PUBLIC_INGRESS_PLAN_RECORD: &str = "generation-public-ingress-plan.json";
pub const PLAN_DIGEST_ENV: &str = "MARTY_INSTALLER_PUBLIC_INGRESS_PLAN_SHA256";
pub const PLAN_INPUT: &str = "/input/public-ingress-plan.json";
pub const PUBLIC_OUTPUTS: [&str; 2] = [
    "installer_ingress_tls_cert",
    "installer_ingress_tls_kms_token",
];
const PLAN_SCHEMA: &str = "elevenid.installer-public-ingress-plan/v1";
const METADATA_SCHEMA: &str = "elevenid.installer-public-ingress/v1";
const MAX_PLAN_BYTES: usize = 128 * 1024;
const MAX_LIFETIME: u64 = 160 * 3600;

fn require(value: bool) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}
fn hash(bytes: &[u8]) -> String {
    installer_release::sha256(bytes)
}
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|value| value.is_ascii_digit() || (b'a'..=b'f').contains(&value))
}
fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|_| REFUSED.into())
}

/// Authenticated public input for one initial or carried-certificate generation.
/// Private fields and the authenticated parser prevent an unchecked public
/// deserialization path. Actual key custody is re-observed before token minting.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct PublicIngressPlan(PlanData);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanData {
    schema: String,
    installation_id: String,
    environment: AcmeEnvironment,
    hosting_selection_sha256: String,
    canonical_origin: String,
    public_entry_origin: Option<String>,
    enrolment_receipt_sha256: String,
    enrolment_binding_sha256: String,
    order_url: String,
    csr_sha256: String,
    key_name: String,
    key_version: u64,
    public_spki_base64: String,
    fullchain_pem: String,
    certificate_admission: Value,
    renewal_authority_plan_sha256: String,
    renewal_enrolment_receipt_sha256: String,
    initial_input_sha256: BTreeMap<String, String>,
    initial_inputs_observed_at: u64,
    initial_ingress_observed_at: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    enrolment_cycle: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    successor: Option<Successor>,
}
fn is_zero(value: &u64) -> bool {
    *value == 0
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Successor {
    sequence: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    attempt: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    parent_attempt: u64,
    parent_binding_sha256: String,
    input_sha256: BTreeMap<String, String>,
    input_observed_at: u64,
    ingress: PublicIngressMetadata,
}
impl PublicIngressPlan {
    pub fn from_candidate(
        state: &LockedInspection,
        candidate: &AcmeCandidate,
        key: &RetainedIngressKey,
    ) -> Result<Self> {
        require(candidate.environment() == AcmeEnvironment::Production)?;
        let saved = Ledger::load_cycle(state, AcmeEnvironment::Production, candidate.cycle())?
            .ok_or(REFUSED)?;
        let plan = Self::from_completed(state, &saved)?;
        require(
            plan.0.enrolment_receipt_sha256 == candidate.enrolment_receipt_sha256()
                && plan.0.fullchain_pem == candidate.fullchain_pem()
                && plan.0.certificate_admission == *candidate.metadata()
                && plan.0.key_name == key.transit_key_name()
                && plan.0.key_version == key.key_version()
                && plan.0.public_spki_base64 == STANDARD.encode(key.public_spki_der()),
        )?;
        plan.validate_current_certificate()?;
        state.require_unchanged()?;
        Ok(plan)
    }
    fn from_completed(state: &LockedInspection, saved: &Ledger) -> Result<Self> {
        require(
            saved.state.stage == Stage::Complete
                && saved.binding.environment == AcmeEnvironment::Production,
        )?;
        let configuration = saved.binding.configuration(state)?;
        let authority = PublicRenewalAuthorityPlan::load(state)?;
        let renewal_receipt =
            crate::installer_renewal::require_public_enrolment(state, &authority)?;
        let certificate = saved.state.certificate.as_ref().ok_or(REFUSED)?;
        let plan = Self(PlanData {
            schema: PLAN_SCHEMA.into(),
            installation_id: saved.binding.installation_id.to_string(),
            environment: saved.binding.environment,
            hosting_selection_sha256: configuration.hosting_selection_sha256().into(),
            canonical_origin: configuration.canonical_origin().into(),
            public_entry_origin: configuration.public_entry_origin().map(str::to_owned),
            enrolment_receipt_sha256: saved.digest.clone(),
            enrolment_binding_sha256: saved.binding.digest()?,
            order_url: saved.state.order.as_ref().ok_or(REFUSED)?.url.clone(),
            csr_sha256: saved.binding.csr_sha256.clone(),
            key_name: saved.binding.ingress_key_name.clone(),
            key_version: saved.binding.ingress_key_version,
            public_spki_base64: saved.binding.ingress_spki_base64.clone(),
            fullchain_pem: certificate.fullchain_pem.clone(),
            certificate_admission: certificate.metadata.clone(),
            renewal_authority_plan_sha256: authority.sha256()?,
            renewal_enrolment_receipt_sha256: renewal_receipt,
            initial_input_sha256: authority.input_hashes().clone(),
            initial_inputs_observed_at: authority.initial_inputs_observed_at(),
            initial_ingress_observed_at: authority.initial_ingress_observed_at(),
            enrolment_cycle: saved.binding.cycle,
            successor: None,
        });
        plan.validate()?;
        plan.require_authority(&authority)?;
        Ok(plan)
    }
    /// Persist the admitted certificate once after pre-CA renewal enrollment
    /// and before generation. The existing installer writer owns publication.
    pub fn record_for_install(
        &self,
        installation: &Path,
        state: &mut InstallerState,
    ) -> Result<PathBuf> {
        state.require_live_phase(Phase::Provisioning)?;
        state.with_inspection(|view| {
            view.require_path_binding(installation)?;
            self.require_recorded_candidate(view)
        })?;
        self.validate_current_certificate()?;
        let bytes = self.to_bytes()?;
        state.write_evidence(PUBLIC_INGRESS_PLAN_RECORD, &bytes)?;
        state.with_inspection(|view| {
            require(view.read_evidence(PUBLIC_INGRESS_PLAN_RECORD)? == bytes)?;
            self.require_recorded_candidate(view)
        })?;
        Ok(installation
            .join("evidence")
            .join(PUBLIC_INGRESS_PLAN_RECORD))
    }
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| REFUSED)?;
        require(bytes.len() <= MAX_PLAN_BYTES)?;
        Ok(bytes)
    }
    pub fn sha256(&self) -> Result<String> {
        Ok(hash(&self.to_bytes()?))
    }
    pub fn parse_authenticated(bytes: &[u8], expected_sha256: &str) -> Result<Self> {
        require(
            !bytes.is_empty()
                && bytes.len() <= MAX_PLAN_BYTES
                && valid_digest(expected_sha256)
                && hash(bytes) == expected_sha256,
        )?;
        let plan = Self(
            serde_json::from_value(installer_json::decode(bytes).map_err(|_| REFUSED)?)
                .map_err(|_| REFUSED)?,
        );
        plan.validate()?;
        // A single canonical public representation is used by the host and
        // fixed helper; equivalent but rewritten input is not silently adopted.
        require(plan.to_bytes()? == bytes)?;
        Ok(plan)
    }
    pub fn installation_id(&self) -> &str {
        &self.0.installation_id
    }
    pub fn canonical_origin(&self) -> &str {
        &self.0.canonical_origin
    }
    pub fn public_entry_origin(&self) -> Option<&str> {
        self.0.public_entry_origin.as_deref()
    }
    pub fn certificate_admission(&self) -> &Value {
        &self.0.certificate_admission
    }
    pub(crate) fn fullchain_pem(&self) -> &str {
        &self.0.fullchain_pem
    }
    pub(crate) fn require_recorded_candidate(&self, state: &LockedInspection) -> Result<()> {
        let saved = Ledger::load_cycle(state, AcmeEnvironment::Production, self.0.enrolment_cycle)?
            .ok_or(REFUSED)?;
        let mut base = self.clone();
        base.0.successor = None;
        require(Self::from_completed(state, &saved)? == base)?;
        state.require_unchanged()
    }
    pub(crate) fn require_saved(&self, state: &LockedInspection) -> Result<()> {
        require(state.read_evidence(&self.record_name())? == self.to_bytes()?)?;
        self.require_recorded_candidate(state)?;
        if let Some(successor) = &self.0.successor {
            let path = crate::installer_generation_maintenance::installation_path(state)?;
            let parent = crate::installer_generation_binding::load_attempt(
                &path,
                successor.sequence - 1,
                successor.parent_attempt,
            )?;
            self.require_parent(&path, &parent)?;
        }
        Ok(())
    }
    pub(crate) fn record_name(&self) -> String {
        self.0.successor.as_ref().map_or_else(
            || PUBLIC_INGRESS_PLAN_RECORD.into(),
            |value| {
                crate::installer_generation_maintenance::attempt::Attempt::new(
                    value.sequence,
                    value.attempt,
                )
                .record("public-ingress-plan")
            },
        )
    }
    pub(crate) fn enrolment_cycle(&self) -> u64 {
        self.0.enrolment_cycle
    }
    pub(crate) fn from_successor_attempt(
        state: &LockedInspection,
        installation: &Path,
        candidate: &AcmeCandidate,
        parent: &crate::installer_generation_binding::GenerationBinding,
        attempt: u64,
    ) -> Result<Self> {
        require(candidate.environment() == AcmeEnvironment::Production && parent.public_ingress())?;
        state.require_path_binding(installation)?;
        let saved = Ledger::load_cycle(state, AcmeEnvironment::Production, candidate.cycle())?
            .ok_or(REFUSED)?;
        let mut plan = Self::from_completed(state, &saved)?;
        require(
            plan.0.enrolment_receipt_sha256 == candidate.enrolment_receipt_sha256()
                && plan.0.fullchain_pem == candidate.fullchain_pem()
                && plan.0.certificate_admission == *candidate.metadata(),
        )?;
        let ingress = parent
            .public_ingress_metadata(installation)?
            .ok_or(REFUSED)?;
        let input_sha256 = crate::installer_renewal_bootstrap::public_inputs()
            .into_iter()
            .map(|name| Ok((name.clone(), hash(&parent.read(installation, &name)?))))
            .collect::<Result<BTreeMap<_, _>>>()?;
        plan.0.successor = Some(Successor {
            sequence: parent.sequence().checked_add(1).ok_or(REFUSED)?,
            attempt,
            parent_attempt: parent.attempt(),
            parent_binding_sha256: parent.sha256()?,
            input_sha256,
            input_observed_at: ingress.token_observed_at,
            ingress,
        });
        plan.require_parent(installation, parent)?;
        plan.validate_current_certificate()?;
        Ok(plan)
    }
    pub(crate) fn record_for_maintenance(
        &self,
        state: &mut crate::installer_state::LockedMaintenance,
    ) -> Result<PathBuf> {
        require(self.0.successor.is_some())?;
        self.require_recorded_candidate(state.inspection())?;
        let path = crate::installer_generation_maintenance::installation_path(state.inspection())?;
        let parent = crate::installer_generation_binding::load_attempt(
            &path,
            self.0.successor.as_ref().ok_or(REFUSED)?.sequence - 1,
            self.0.successor.as_ref().ok_or(REFUSED)?.parent_attempt,
        )?;
        self.require_parent(&path, &parent)?;
        let name = self.record_name();
        let bytes = self.to_bytes()?;
        if let Some(existing) = state.read_evidence(&name)? {
            require(existing == bytes)?;
        } else {
            state.write_evidence_exclusive(&name, &bytes)?;
        }
        self.require_saved(state.inspection())?;
        Ok(path.join("evidence").join(name))
    }
    pub(crate) fn require_parent(
        &self,
        installation: &Path,
        parent: &crate::installer_generation_binding::GenerationBinding,
    ) -> Result<()> {
        let metadata = parent
            .public_ingress_metadata(installation)?
            .ok_or(REFUSED)?;
        self.require_parent_metadata(installation, parent, &metadata)
    }
    /// The generation owner's forward walk has already validated this parent.
    /// Reuse that operation-local observation instead of recursively walking
    /// its entire ancestry again for each child.
    pub(crate) fn require_verified_parent(
        &self,
        installation: &Path,
        parent: &crate::installer_generation_binding::VerifiedGeneration,
    ) -> Result<()> {
        self.require_parent_metadata(
            installation,
            parent.binding(),
            parent.public_metadata().ok_or(REFUSED)?,
        )
    }
    fn require_parent_metadata(
        &self,
        installation: &Path,
        parent: &crate::installer_generation_binding::GenerationBinding,
        metadata: &PublicIngressMetadata,
    ) -> Result<()> {
        let expected = self.0.successor.as_ref().ok_or(REFUSED)?;
        require(
            parent.public_ingress()
                && parent.sequence().checked_add(1) == Some(expected.sequence)
                && parent.attempt() == expected.parent_attempt
                && parent.sha256()? == expected.parent_binding_sha256
                && parent.installation_id == self.0.installation_id
                && metadata == &expected.ingress,
        )?;
        for (name, digest) in &expected.input_sha256 {
            require(hash(&parent.read(installation, name)?) == *digest)?;
        }
        self.validate()
    }
    /// Render and authenticate the existing Compose inputs without creating a
    /// helper. Missing overlays cannot silently run the private-CA branch first.
    pub(crate) fn require_job_inputs(
        &self,
        docker: &Path,
        runtime: &crate::installer_state::RuntimeBinding,
        inputs: &crate::installer_compose::ComposeInputs,
        service: &str,
    ) -> Result<()> {
        require(service == "installer-generation")?;
        let path = inputs
            .installation
            .join("evidence")
            .join(PUBLIC_RENEWAL_AUTHORITY_PLAN_RECORD);
        let bytes = crate::installer_verify::read_private_bytes(&path, 128 * 1024)?;
        let authority = PublicRenewalAuthorityPlan::parse_authenticated(
            &bytes,
            &self.0.renewal_authority_plan_sha256,
        )?;
        self.require_authority(&authority)?;
        let successor = self.0.successor.is_some();
        require_bound_job_inputs_with_model(
            docker,
            runtime,
            inputs,
            service,
            authority.installation_id(),
            (
                PUBLIC_RENEWAL_AUTHORITY_PLAN_RECORD,
                AUTHORITY_PLAN_INPUT,
                AUTHORITY_PLAN_DIGEST_ENV,
                &authority.sha256()?,
            ),
            successor,
        )?;
        require_bound_job_inputs_with_model(
            docker,
            runtime,
            inputs,
            service,
            self.installation_id(),
            (
                &self.record_name(),
                PLAN_INPUT,
                PLAN_DIGEST_ENV,
                &self.sha256()?,
            ),
            successor,
        )
    }
    pub(crate) fn renewal_authority_plan_sha256(&self) -> &str {
        &self.0.renewal_authority_plan_sha256
    }
    pub(crate) fn renewal_enrolment_receipt_sha256(&self) -> &str {
        &self.0.renewal_enrolment_receipt_sha256
    }
    pub(crate) fn initial_inputs_observed_at(&self) -> u64 {
        self.0
            .successor
            .as_ref()
            .map_or(self.0.initial_inputs_observed_at, |value| {
                value.input_observed_at
            })
    }
    fn require_authority(&self, authority: &PublicRenewalAuthorityPlan) -> Result<()> {
        require(
            authority.sha256()? == self.0.renewal_authority_plan_sha256
                && authority.installation_id() == self.installation_id()
                && authority.environment() == AcmeEnvironment::Production
                && authority.canonical_origin() == self.canonical_origin()
                && authority.public_entry_origin() == self.public_entry_origin()
                && authority.retained_key()? == self.retained_key()?
                && authority.input_hashes() == &self.0.initial_input_sha256
                && authority.initial_inputs_observed_at() == self.0.initial_inputs_observed_at
                && authority.initial_ingress_observed_at() == self.0.initial_ingress_observed_at,
        )
    }
    pub(crate) fn require_initial_snapshot(
        &self,
        values: &BTreeMap<String, Vec<u8>>,
    ) -> Result<()> {
        require(crate::installer_generation::hashes(values) == self.0.initial_input_sha256)
    }

    fn retained_key(&self) -> Result<RetainedIngressKey> {
        let spki = STANDARD
            .decode(&self.0.public_spki_base64)
            .map_err(|_| REFUSED)?;
        require(spki.len() <= 1024 && STANDARD.encode(&spki) == self.0.public_spki_base64)?;
        let key = RetainedIngressKey::from_recorded_public_key(
            &self.0.installation_id,
            self.0.key_version,
            &spki,
        )?;
        require(key.transit_key_name() == self.0.key_name)?;
        Ok(key)
    }
    pub(crate) fn ingress_identity(&self) -> Result<IngressIdentity> {
        identity_from_origins(
            &self.0.canonical_origin,
            self.0.public_entry_origin.as_deref(),
        )
    }

    fn certificate_identity(&self) -> Result<CertificateIdentity> {
        CertificateIdentity::from_ingress(&self.ingress_identity()?)
    }
    fn validate(&self) -> Result<()> {
        if let Some(previous) = &self.0.successor {
            require(
                previous.sequence > 0
                    && (previous.sequence > 1 || previous.parent_attempt == 0)
                    && valid_digest(&previous.parent_binding_sha256)
                    && previous
                        .input_sha256
                        .keys()
                        .cloned()
                        .collect::<BTreeSet<_>>()
                        == crate::installer_renewal_bootstrap::public_inputs()
                    && previous
                        .input_sha256
                        .values()
                        .all(|value| valid_digest(value))
                    && previous.input_observed_at == previous.ingress.token_observed_at
                    && previous.input_observed_at > 0
                    && previous.ingress.installation_id == self.0.installation_id
                    && previous.ingress.key_name == self.0.key_name
                    && previous.ingress.key_version == self.0.key_version
                    && previous.ingress.public_spki_base64 == self.0.public_spki_base64
                    && previous.ingress.dns_names == self.ingress_identity()?.dns_names()
                    && previous.ingress.ip_addresses == self.ingress_identity()?.ip_addresses(),
            )?;
        }
        require(
            self.0.schema == PLAN_SCHEMA
                && self.0.environment == AcmeEnvironment::Production
                && [
                    &self.0.hosting_selection_sha256,
                    &self.0.enrolment_receipt_sha256,
                    &self.0.enrolment_binding_sha256,
                    &self.0.csr_sha256,
                    &self.0.renewal_authority_plan_sha256,
                    &self.0.renewal_enrolment_receipt_sha256,
                ]
                .into_iter()
                .all(|value| valid_digest(value)),
        )?;
        require(
            self.0
                .initial_input_sha256
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>()
                == crate::installer_renewal_bootstrap::managed_inputs()
                && self
                    .0
                    .initial_input_sha256
                    .values()
                    .all(|s| valid_digest(s))
                && self.0.initial_ingress_observed_at > 0
                && self.0.initial_inputs_observed_at >= self.0.initial_ingress_observed_at,
        )?;
        enrolment::same_origin_url(
            AcmeEnvironment::Production.directory_url(),
            &self.0.order_url,
        )?;
        let observed = self.0.certificate_admission["observed_at"]
            .as_u64()
            .ok_or(REFUSED)?;
        require(observed >= self.0.initial_inputs_observed_at)?;
        let certificate = certificates::admit_production_at(
            self.0.fullchain_pem.as_bytes(),
            &self.certificate_identity()?,
            &self.retained_key()?,
            Duration::from_secs(observed),
        )?;
        require(
            certificate.fullchain_pem() == self.0.fullchain_pem
                && *certificate.metadata() == self.0.certificate_admission,
        )?;
        let before = self.0.certificate_admission["not_before"]
            .as_u64()
            .ok_or(REFUSED)?;
        let after = self.0.certificate_admission["not_after"]
            .as_u64()
            .ok_or(REFUSED)?;
        require(
            after
                .checked_sub(before)
                .is_some_and(|value| value <= MAX_LIFETIME),
        )
    }
    pub(crate) fn validate_current_certificate(&self) -> Result<ValidatedCertificate> {
        self.validate_certificate_at(now()?)
    }
    fn validate_certificate_at(&self, observed: u64) -> Result<ValidatedCertificate> {
        self.validate()?;
        let admit = if self.0.successor.as_ref().is_some_and(|previous| {
            previous.input_sha256.get(PUBLIC_OUTPUTS[0])
                == Some(&hash(self.0.fullchain_pem.as_bytes()))
        }) {
            certificates::validate_selected_production_at
        } else {
            certificates::admit_production_at
        };
        let certificate = admit(
            self.0.fullchain_pem.as_bytes(),
            &self.certificate_identity()?,
            &self.retained_key()?,
            Duration::from_secs(observed),
        )?;
        require(equivalent_admission(
            certificate.metadata(),
            &self.0.certificate_admission,
        ))?;
        Ok(certificate)
    }
}

fn identity_from_origins(canonical: &str, alias: Option<&str>) -> Result<IngressIdentity> {
    let canonical = PublicOrigin::parse(canonical).map_err(|_| REFUSED)?;
    let dns = canonical.dns_name().ok_or(REFUSED)?;
    require(!canonical.is_loopback())?;
    canonical.did_web_authority().map_err(|_| REFUSED)?;
    let ip = alias
        .map(|value| {
            let origin = PublicOrigin::parse(value).map_err(|_| REFUSED)?;
            require(!origin.is_loopback())?;
            origin.ip_address().ok_or_else(|| REFUSED.to_owned())
        })
        .transpose()?;
    IngressIdentity::new(Some(dns), ip)
}
fn require_bound_job_inputs(
    docker: &Path,
    runtime: &crate::installer_state::RuntimeBinding,
    inputs: &crate::installer_compose::ComposeInputs,
    service: &str,
    owner: &str,
    binding: (&str, &str, &str),
    digest: &str,
) -> Result<()> {
    require_bound_job_inputs_with_model(
        docker,
        runtime,
        inputs,
        service,
        owner,
        (binding.0, binding.1, binding.2, digest),
        false,
    )
}

/// A recurring producer keeps the selected installation's complete native
/// admission model, including its bound public listener. Its mutation selection
/// remains the single named helper; initial enrollment keeps its filtered model.
fn require_bound_job_inputs_with_model(
    docker: &Path,
    runtime: &crate::installer_state::RuntimeBinding,
    inputs: &crate::installer_compose::ComposeInputs,
    service: &str,
    owner: &str,
    binding: (&str, &str, &str, &str),
    successor: bool,
) -> Result<()> {
    require(
        ["installer-renewal", "installer-generation"].contains(&service)
            && inputs.services == [service]
            && (!successor || service == "installer-generation")
            && inputs.project == format!("marty-install-{}", owner.replace('-', "")),
    )?;
    let (record, target, environment, digest) = binding;
    let expected = inputs.installation.join("evidence").join(record);
    let bound = inputs
        .bound_inputs
        .iter()
        .filter(|file| file.path == expected)
        .collect::<Vec<_>>();
    require(bound.len() == 1 && bound[0].sha256 == digest)?;
    let session = if successor {
        crate::installer_compose::ComposeSession::new_generation(docker, runtime, inputs.clone())?
    } else {
        crate::installer_compose::ComposeSession::new(docker, runtime, inputs.clone())?
    };
    require_bound_job_model(
        &session.model()["services"][service],
        &expected,
        digest,
        target,
        environment,
    )
}
#[cfg(test)]
fn require_job_model(service: &Value, expected_source: &Path, digest: &str) -> Result<()> {
    require_bound_job_model(
        service,
        expected_source,
        digest,
        PLAN_INPUT,
        PLAN_DIGEST_ENV,
    )
}
fn require_bound_job_model(
    service: &Value,
    expected_source: &Path,
    digest: &str,
    target: &str,
    environment: &str,
) -> Result<()> {
    require(service["environment"][environment] == digest)?;
    let target = Path::new(target);
    let mut found = false;
    for mount in service["volumes"].as_array().ok_or(REFUSED)? {
        let destination = Path::new(mount["target"].as_str().ok_or(REFUSED)?);
        if destination == target {
            require(
                !found
                    && mount["type"] == "bind"
                    && mount["read_only"] == true
                    && mount["bind"]["create_host_path"] == false
                    && crate::installer_compose::config_path(&mount["source"])? == expected_source,
            )?;
            found = true;
        } else {
            require(!target.starts_with(destination) && !destination.starts_with(target))?;
        }
    }
    require(found)?;
    for mount in service["tmpfs"].as_array().into_iter().flatten() {
        let destination = Path::new(
            mount
                .as_str()
                .ok_or(REFUSED)?
                .split(':')
                .next()
                .ok_or(REFUSED)?,
        );
        require(!target.starts_with(destination) && !destination.starts_with(target))?;
    }
    for kind in ["secrets", "configs"] {
        for mount in service[kind].as_array().into_iter().flatten() {
            let destination = mount["target"].as_str().ok_or(REFUSED)?;
            if destination.starts_with('/') {
                let destination = Path::new(destination);
                require(!target.starts_with(destination) && !destination.starts_with(target))?;
            }
        }
    }
    Ok(())
}

fn equivalent_admission(current: &Value, original: &Value) -> bool {
    let mut current = current.clone();
    let mut original = original.clone();
    let Some(current) = current.as_object_mut() else {
        return false;
    };
    let Some(original) = original.as_object_mut() else {
        return false;
    };
    current.remove("observed_at");
    original.remove("observed_at");
    current.remove("minimum_remaining_seconds");
    original.remove("minimum_remaining_seconds");
    current == original
}

/// Public provenance of a new signer token carrying the exact admitted chain.
/// Production trust, private-CA trust and imported foundation trust use distinct
/// schema branches; this record cannot be converted into private IngressMetadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicIngressMetadata {
    pub schema: String,
    pub installation_id: String,
    pub plan_sha256: String,
    pub enrolment_receipt_sha256: String,
    pub key_name: String,
    pub key_version: u64,
    pub public_spki_base64: String,
    pub dns_names: Vec<String>,
    pub ip_addresses: Vec<String>,
    pub certificate_admission: Value,
    pub certificate_reused: bool,
    pub token_ttl_seconds: u64,
    pub token_observed_at: u64,
    pub activation_performed: bool,
    pub installation_ready: bool,
}
impl PublicIngressMetadata {
    pub(crate) fn validate_selected_at(
        &self,
        fullchain: &[u8],
        observed: u64,
    ) -> Result<ValidatedCertificate> {
        require(
            self.schema == METADATA_SCHEMA
                && valid_digest(&self.plan_sha256)
                && valid_digest(&self.enrolment_receipt_sha256)
                && (3600..=28800).contains(&self.token_ttl_seconds)
                && self.token_observed_at > 0
                && !self.activation_performed
                && !self.installation_ready,
        )?;
        let spki = STANDARD
            .decode(&self.public_spki_base64)
            .map_err(|_| REFUSED)?;
        require(spki.len() <= 1024 && STANDARD.encode(&spki) == self.public_spki_base64)?;
        let key = RetainedIngressKey::from_recorded_public_key(
            &self.installation_id,
            self.key_version,
            &spki,
        )?;
        require(key.transit_key_name() == self.key_name)?;
        let identity = CertificateIdentity::from_ingress(&IngressIdentity::from_metadata(
            &self.dns_names,
            &self.ip_addresses,
        )?)?;
        let certificate = certificates::validate_selected_production_at(
            fullchain,
            &identity,
            &key,
            Duration::from_secs(observed),
        )?;
        require(equivalent_admission(
            certificate.metadata(),
            &self.certificate_admission,
        ))?;
        Ok(certificate)
    }
}

pub(crate) fn helper_plan(owner: &str, input_owner: u32) -> Result<Option<PublicIngressPlan>> {
    let digest = match std::env::var(PLAN_DIGEST_ENV) {
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Ok(value) => value,
        Err(_) => return Err(REFUSED.into()),
    };
    require(valid_digest(&digest))?;
    let bytes = crate::installer_renewal_bootstrap::input(
        Path::new(PLAN_INPUT),
        MAX_PLAN_BYTES as u64,
        &[0, input_owner],
        &[0o600],
    )?;
    let plan = PublicIngressPlan::parse_authenticated(&bytes, &digest)?;
    require(
        plan.0.installation_id == owner
            && plan.ingress_identity()? == IngressIdentity::from_environment()?,
    )?;
    let authority = helper_authority_plan(owner, input_owner)?.ok_or(REFUSED)?;
    plan.require_authority(&authority)?;
    plan.validate_current_certificate()?;
    Ok(Some(plan))
}

fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value[field]
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| REFUSED.into())
}
fn input<'a>(values: &'a BTreeMap<String, Vec<u8>>, name: &str) -> Result<&'a str> {
    std::str::from_utf8(values.get(name).ok_or(REFUSED)?).map_err(|_| REFUSED.into())
}

/// Preserve private-CA validation for the initial transition. A carried public
/// source must already contain the exact admitted fullchain and no private CA.
fn source_reused(plan: &PublicIngressPlan, before: &BTreeMap<String, Vec<u8>>) -> Result<bool> {
    let names: BTreeSet<_> = before.keys().cloned().collect();
    if names == crate::installer_renewal_bootstrap::public_inputs() {
        if let Some(previous) = &plan.0.successor {
            require(crate::installer_generation::hashes(before) == previous.input_sha256)?;
            previous.ingress.validate_selected_at(
                before.get(PUBLIC_OUTPUTS[0]).ok_or(REFUSED)?,
                previous.input_observed_at,
            )?;
        } else {
            require(input(before, PUBLIC_OUTPUTS[0])? == plan.0.fullchain_pem)?;
        }
        return Ok(input(before, PUBLIC_OUTPUTS[0])? == plan.0.fullchain_pem);
    }
    require(names == crate::installer_renewal_bootstrap::managed_inputs())?;
    plan.require_initial_snapshot(before)?;
    let key = plan.retained_key()?;
    let public = SubjectPublicKeyInfoOwned::from_der(key.public_spki_der())
        .map_err(|_| REFUSED)?
        .to_pem(spki::der::pem::LineEnding::LF)
        .map_err(|_| REFUSED)?;
    ingress::validate_retained_private_identity_at(
        input(before, ingress::OUTPUTS[0])?,
        input(before, ingress::OUTPUTS[1])?,
        &public,
        &plan.0.key_name,
        &plan.ingress_identity()?,
        plan.0.initial_ingress_observed_at,
    )?;
    Ok(false)
}

async fn observe_custody(
    bao: &OpenBaoHttp,
    authority: &str,
    key: &RetainedIngressKey,
) -> Result<()> {
    let name = key.transit_key_name();
    let response = request(
        bao,
        Method::GET,
        &format!("transit/keys/{name}"),
        None,
        Some(authority),
    )
    .await
    .map_err(|_| REFUSED)?;
    key.require_metadata(&response["data"])?;
    let response = request(
        bao,
        Method::GET,
        &format!("sys/policies/acl/{name}"),
        None,
        Some(authority),
    )
    .await
    .map_err(|_| REFUSED)?;
    require(text(&response["data"], "policy")? == ingress::signer_policy(name)?)
}
async fn custody(
    bao: &OpenBaoHttp,
    authority: &str,
    plan: &PublicIngressPlan,
) -> Result<RetainedIngressKey> {
    let key = plan.retained_key()?;
    observe_custody(bao, authority, &key).await?;
    Ok(key)
}

pub(crate) struct ProducedPublicIngress {
    pub files: BTreeMap<String, Vec<u8>>,
    pub metadata: PublicIngressMetadata,
}

/// The containing generation must persist its intent before this is called.
/// A lost token mint response remains generation uncertainty. No certificate
/// request, newOrder or account-signer credential is reachable from this API.
pub(crate) async fn produce(
    bao: &OpenBaoHttp,
    authority: &str,
    owner: &str,
    current: &BTreeMap<String, Vec<u8>>,
    plan: &PublicIngressPlan,
) -> Result<ProducedPublicIngress> {
    require(plan.0.installation_id == owner)?;
    plan.validate_current_certificate()?;
    let certificate_reused = source_reused(plan, current)?;
    crate::activation_preflight::authority(bao, authority, false)
        .await
        .map_err(|_| REFUSED)?;
    let key = custody(bao, authority, plan).await?;
    let public = SubjectPublicKeyInfoOwned::from_der(key.public_spki_der())
        .map_err(|_| REFUSED)?
        .to_pem(spki::der::pem::LineEnding::LF)
        .map_err(|_| REFUSED)?;
    let token = ingress::mint_tls_signer(
        bao,
        authority,
        &plan.0.key_name,
        &public,
        input(current, PUBLIC_OUTPUTS[1])?,
    )
    .await?;
    let after = request(
        bao,
        Method::GET,
        &format!("transit/keys/{}", plan.0.key_name),
        None,
        Some(authority),
    )
    .await
    .map_err(|_| REFUSED)?;
    key.require_metadata(&after["data"])?;
    plan.validate_certificate_at(token.observed_at)?;
    let identity = plan.ingress_identity()?;
    let metadata = PublicIngressMetadata {
        schema: METADATA_SCHEMA.into(),
        installation_id: owner.into(),
        plan_sha256: plan.sha256()?,
        enrolment_receipt_sha256: plan.0.enrolment_receipt_sha256.clone(),
        key_name: plan.0.key_name.clone(),
        key_version: plan.0.key_version,
        public_spki_base64: plan.0.public_spki_base64.clone(),
        dns_names: identity.dns_names(),
        ip_addresses: identity.ip_addresses(),
        certificate_admission: plan.0.certificate_admission.clone(),
        certificate_reused,
        token_ttl_seconds: token.ttl_seconds,
        token_observed_at: token.observed_at,
        activation_performed: false,
        installation_ready: false,
    };
    let files = BTreeMap::from([
        (
            PUBLIC_OUTPUTS[0].into(),
            plan.0.fullchain_pem.as_bytes().to_vec(),
        ),
        (PUBLIC_OUTPUTS[1].into(), token.token.into_bytes()),
    ]);
    validate_recorded_replacement(owner, current, &files, &metadata, plan)?;
    Ok(ProducedPublicIngress { files, metadata })
}

pub(crate) fn validate_recorded_replacement(
    owner: &str,
    before: &BTreeMap<String, Vec<u8>>,
    after: &BTreeMap<String, Vec<u8>>,
    metadata: &PublicIngressMetadata,
    plan: &PublicIngressPlan,
) -> Result<()> {
    plan.validate()?;
    let identity = plan.ingress_identity()?;
    require(
        plan.0.installation_id == owner
            && metadata.installation_id == owner
            && metadata.plan_sha256 == plan.sha256()?
            && metadata.enrolment_receipt_sha256 == plan.0.enrolment_receipt_sha256
            && metadata.key_name == plan.0.key_name
            && metadata.key_version == plan.0.key_version
            && metadata.public_spki_base64 == plan.0.public_spki_base64
            && metadata.dns_names == identity.dns_names()
            && metadata.ip_addresses == identity.ip_addresses()
            && metadata.certificate_admission == plan.0.certificate_admission
            && metadata.token_observed_at
                >= plan.0.certificate_admission["observed_at"]
                    .as_u64()
                    .ok_or(REFUSED)?
            && metadata.certificate_reused == source_reused(plan, before)?
            && after
                .get(PUBLIC_OUTPUTS[0])
                .is_some_and(|value| *value == plan.0.fullchain_pem.as_bytes())
            && before.get(PUBLIC_OUTPUTS[1]) != after.get(PUBLIC_OUTPUTS[1])
            && !after.contains_key(ingress::OUTPUTS[0]),
    )?;
    metadata.validate_selected_at(plan.0.fullchain_pem.as_bytes(), metadata.token_observed_at)?;
    let token = input(after, PUBLIC_OUTPUTS[1])?;
    require(
        (20..=4096).contains(&token.len())
            && token
                .bytes()
                .all(|value| value.is_ascii_alphanumeric() || b"._-".contains(&value)),
    )
}

#[cfg(test)]
#[path = "installer_public_ingress_tests.rs"]
pub(crate) mod tests;
