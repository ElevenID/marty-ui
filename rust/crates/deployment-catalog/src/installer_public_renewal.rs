//! Pre-CA enrollment of the existing workload and public-ingress renewal owner.
//! This public plan contains no issued ACME certificate or private credential.
use super::{hash, identity_from_origins, ingress, now, require, valid_digest, Result, REFUSED};
use crate::{
    installer_acme_certificates::RetainedIngressKey,
    installer_acme_configuration::{AcmeEnvironment, BoundAcmeConfiguration},
    installer_compose::ComposeInputs,
    installer_host_fs as fs,
    installer_ingress_outputs::{self, IngressMetadata},
    installer_json,
    installer_state::{InstallerState, LockedInspection, Phase, RuntimeBinding},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use marty_openbao_http::OpenBaoHttp;
use serde::{Deserialize, Serialize};
use spki::{
    der::{Decode, Encode, EncodePem},
    SubjectPublicKeyInfoOwned,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

pub const PUBLIC_RENEWAL_AUTHORITY_PLAN_RECORD: &str = "renewal-public-authority-plan.json";
pub const AUTHORITY_PLAN_DIGEST_ENV: &str = "MARTY_INSTALLER_PUBLIC_RENEWAL_AUTHORITY_PLAN_SHA256";
pub const AUTHORITY_PLAN_INPUT: &str = "/input/public-renewal-authority-plan.json";
const SCHEMA: &str = "elevenid.installer-public-renewal-authority-plan/v1";
const MAX_BYTES: usize = 128 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct PublicRenewalAuthorityPlan(AuthorityData);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityData {
    schema: String,
    installation_id: String,
    environment: AcmeEnvironment,
    configuration_sha256: String,
    hosting_selection_sha256: String,
    canonical_origin: String,
    public_entry_origin: Option<String>,
    ingress_receipt_sha256: String,
    initial_inputs_observed_at: u64,
    initial_input_sha256: BTreeMap<String, String>,
    public_spki_base64: String,
    initial_ingress: IngressMetadata,
    initial_ca_pem: String,
    initial_leaf_pem: String,
}

impl PublicRenewalAuthorityPlan {
    /// Assemble only from the already recorded source selection and initial
    /// public ingress evidence. The bootstrap helper subsequently observes
    /// current remote custody and proves every still-live initial credential.
    pub fn from_initial(state: &LockedInspection, installation: &Path) -> Result<Self> {
        state.require_path_binding(installation)?;
        let configuration = BoundAcmeConfiguration::from_selection(state)?;
        let ingress_bytes = state.read_evidence("installer-ingress.json")?;
        let initial_ingress: IngressMetadata =
            serde_json::from_value(installer_json::decode(&ingress_bytes).map_err(|_| REFUSED)?)
                .map_err(|_| REFUSED)?;
        require(initial_ingress.token_observed_at <= now()?)?;
        let secrets = fs::directory(&installation.join("secrets"), REFUSED)?;
        let inputs = crate::installer_renewal_bootstrap::managed_inputs()
            .into_iter()
            .map(|name| {
                Ok((
                    name.clone(),
                    fs::read_entry(&secrets, &name, 0o444, true, REFUSED)?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        crate::installer_renewal_bootstrap::validate_current(&inputs)?;
        let initial_ca_pem =
            String::from_utf8(inputs["installer_ingress_ca_cert"].clone()).map_err(|_| REFUSED)?;
        let initial_leaf_pem =
            String::from_utf8(inputs["installer_ingress_tls_cert"].clone()).map_err(|_| REFUSED)?;
        let cert = ingress::certificate(&initial_leaf_pem)?;
        let plan = Self(AuthorityData {
            schema: SCHEMA.into(),
            installation_id: configuration.installation_id().to_string(),
            environment: configuration.parameters().environment(),
            configuration_sha256: hash(&serde_json::to_vec(&configuration).map_err(|_| REFUSED)?),
            hosting_selection_sha256: configuration.hosting_selection_sha256().into(),
            canonical_origin: configuration.canonical_origin().into(),
            public_entry_origin: configuration.public_entry_origin().map(str::to_owned),
            ingress_receipt_sha256: hash(&ingress_bytes),
            initial_inputs_observed_at: now()?,
            initial_input_sha256: crate::installer_generation::hashes(&inputs),
            public_spki_base64: STANDARD.encode(
                cert.tbs_certificate
                    .subject_public_key_info
                    .to_der()
                    .map_err(|_| REFUSED)?,
            ),
            initial_ingress,
            initial_ca_pem,
            initial_leaf_pem,
        });
        plan.validate()?;
        plan.require_configuration(state)?;
        fs::require_directory_binding(&installation.join("secrets"), &secrets, REFUSED)?;
        state.require_unchanged()?;
        Ok(plan)
    }
    pub fn load(state: &LockedInspection) -> Result<Self> {
        let bytes = state.read_evidence(PUBLIC_RENEWAL_AUTHORITY_PLAN_RECORD)?;
        let plan = Self::parse_authenticated(&bytes, &hash(&bytes))?;
        plan.require_saved(state)?;
        Ok(plan)
    }
    pub fn record_for_install(
        &self,
        installation: &Path,
        state: &mut InstallerState,
    ) -> Result<PathBuf> {
        state.require_live_phase(Phase::Provisioning)?;
        state.with_inspection(|view| {
            view.require_path_binding(installation)?;
            let mut current = Self::from_initial(view, installation)?;
            require(current.0.initial_inputs_observed_at >= self.0.initial_inputs_observed_at)?;
            current.0.initial_inputs_observed_at = self.0.initial_inputs_observed_at;
            require(current == *self)
        })?;
        state.write_evidence(PUBLIC_RENEWAL_AUTHORITY_PLAN_RECORD, &self.to_bytes()?)?;
        state.with_inspection(|view| self.require_saved(view))?;
        Ok(installation
            .join("evidence")
            .join(PUBLIC_RENEWAL_AUTHORITY_PLAN_RECORD))
    }
    pub fn require_saved(&self, state: &LockedInspection) -> Result<()> {
        self.require_configuration(state)?;
        require(state.read_evidence(PUBLIC_RENEWAL_AUTHORITY_PLAN_RECORD)? == self.to_bytes()?)?;
        state.require_unchanged()
    }
    fn require_configuration(&self, state: &LockedInspection) -> Result<()> {
        self.validate()?;
        let configuration = BoundAcmeConfiguration::from_selection(state)?;
        require(
            self.0.installation_id == state.journal().installation_id().to_string()
                && self.0.environment == configuration.parameters().environment()
                && self.0.configuration_sha256
                    == hash(&serde_json::to_vec(&configuration).map_err(|_| REFUSED)?)
                && self.0.hosting_selection_sha256 == configuration.hosting_selection_sha256()
                && self.0.canonical_origin == configuration.canonical_origin()
                && self.0.public_entry_origin.as_deref() == configuration.public_entry_origin()
                && self.0.ingress_receipt_sha256
                    == hash(&state.read_evidence("installer-ingress.json")?),
        )
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
                && valid_digest(expected_sha256)
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
    pub fn environment(&self) -> AcmeEnvironment {
        self.0.environment
    }
    pub fn canonical_origin(&self) -> &str {
        &self.0.canonical_origin
    }
    pub fn public_entry_origin(&self) -> Option<&str> {
        self.0.public_entry_origin.as_deref()
    }
    pub(crate) fn input_hashes(&self) -> &BTreeMap<String, String> {
        &self.0.initial_input_sha256
    }
    pub(crate) fn initial_inputs_observed_at(&self) -> u64 {
        self.0.initial_inputs_observed_at
    }
    pub(crate) fn initial_ingress_observed_at(&self) -> u64 {
        self.0.initial_ingress.token_observed_at
    }
    pub(crate) fn ingress_identity(&self) -> Result<ingress::IngressIdentity> {
        identity_from_origins(
            &self.0.canonical_origin,
            self.0.public_entry_origin.as_deref(),
        )
    }
    pub(crate) fn retained_key(&self) -> Result<RetainedIngressKey> {
        let spki = STANDARD
            .decode(&self.0.public_spki_base64)
            .map_err(|_| REFUSED)?;
        require(spki.len() <= 1024 && STANDARD.encode(&spki) == self.0.public_spki_base64)?;
        let key = RetainedIngressKey::from_recorded_public_key(&self.0.installation_id, 1, &spki)?;
        require(key.transit_key_name() == self.0.initial_ingress.key_name)?;
        Ok(key)
    }
    fn validate(&self) -> Result<()> {
        require(
            self.0.schema == SCHEMA
                && [
                    &self.0.configuration_sha256,
                    &self.0.hosting_selection_sha256,
                    &self.0.ingress_receipt_sha256,
                ]
                .into_iter()
                .all(|s| valid_digest(s))
                && self
                    .0
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
                && self.0.initial_inputs_observed_at >= self.0.initial_ingress.token_observed_at,
        )?;
        let metadata = installer_ingress_outputs::metadata_for_identity(
            &serde_json::to_vec(&self.0.initial_ingress).map_err(|_| REFUSED)?,
            &self.0.installation_id,
            self.0.initial_ingress.token_observed_at,
            &self.ingress_identity()?,
        )?;
        let key = self.retained_key()?;
        let spki =
            SubjectPublicKeyInfoOwned::from_der(key.public_spki_der()).map_err(|_| REFUSED)?;
        let public = spki
            .to_pem(spki::der::pem::LineEnding::LF)
            .map_err(|_| REFUSED)?;
        // These are the original successfully admitted bytes at the original
        // observation, not a demand that obsolete leaf credentials stay live.
        let expiry = ingress::check_certificates_for(
            &self.0.initial_ca_pem,
            &self.0.initial_leaf_pem,
            &public,
            key.transit_key_name(),
            metadata.token_observed_at,
            &self.ingress_identity()?,
        )?;
        require(
            expiry == (metadata.ca_expires_at, metadata.certificate_expires_at)
                && hash(self.0.initial_ca_pem.as_bytes()) == metadata.ca_pem_sha256
                && hash(self.0.initial_leaf_pem.as_bytes()) == metadata.certificate_pem_sha256
                && hash(
                    &ingress::certificate(&self.0.initial_ca_pem)?
                        .to_der()
                        .map_err(|_| REFUSED)?,
                ) == metadata.ca_der_sha256
                && hash(
                    &ingress::certificate(&self.0.initial_leaf_pem)?
                        .to_der()
                        .map_err(|_| REFUSED)?,
                ) == metadata.certificate_der_sha256
                && self.0.initial_input_sha256["installer_ingress_ca_cert"]
                    == metadata.ca_pem_sha256
                && self.0.initial_input_sha256["installer_ingress_tls_cert"]
                    == metadata.certificate_pem_sha256,
        )
    }
    pub(crate) fn require_initial_snapshot(
        &self,
        current: &BTreeMap<String, Vec<u8>>,
    ) -> Result<()> {
        self.validate()?;
        require(crate::installer_generation::hashes(current) == self.0.initial_input_sha256)
    }
    pub(crate) fn require_job_inputs(
        &self,
        docker: &Path,
        runtime: &RuntimeBinding,
        inputs: &ComposeInputs,
        service: &str,
    ) -> Result<()> {
        super::require_bound_job_inputs(
            docker,
            runtime,
            inputs,
            service,
            self.installation_id(),
            (
                PUBLIC_RENEWAL_AUTHORITY_PLAN_RECORD,
                AUTHORITY_PLAN_INPUT,
                AUTHORITY_PLAN_DIGEST_ENV,
            ),
            &self.sha256()?,
        )
    }
    /// Initial enrollment only: expiration is not excused at this boundary.
    pub(crate) async fn initial_inventory(
        &self,
        bao: &OpenBaoHttp,
        authority: &str,
        owner: &str,
        current: &BTreeMap<String, Vec<u8>>,
    ) -> Result<String> {
        require(owner == self.installation_id())?;
        self.require_initial_snapshot(current)?;
        let key = self.retained_key()?;
        super::observe_custody(bao, authority, &key).await?;
        ingress::prove_retained_tls_signer(
            bao,
            authority,
            key.transit_key_name(),
            key.public_spki_der(),
            std::str::from_utf8(
                current
                    .get("installer_ingress_tls_kms_token")
                    .ok_or(REFUSED)?,
            )
            .map_err(|_| REFUSED)?,
        )
        .await?;
        Ok(key.transit_key_name().into())
    }
}

pub(crate) fn helper_authority_plan(
    owner: &str,
    input_owner: u32,
) -> Result<Option<PublicRenewalAuthorityPlan>> {
    let digest = match std::env::var(AUTHORITY_PLAN_DIGEST_ENV) {
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Ok(value) => value,
        Err(_) => return Err(REFUSED.into()),
    };
    require(valid_digest(&digest))?;
    let bytes = crate::installer_renewal_bootstrap::input(
        Path::new(AUTHORITY_PLAN_INPUT),
        MAX_BYTES as u64,
        &[0, input_owner],
        &[0o600],
    )?;
    let plan = PublicRenewalAuthorityPlan::parse_authenticated(&bytes, &digest)?;
    require(
        plan.installation_id() == owner
            && plan.ingress_identity()? == ingress::IngressIdentity::from_environment()?,
    )?;
    Ok(Some(plan))
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use serde_json::json;
    pub(crate) fn from_inputs(
        plan: &super::super::PublicIngressPlan,
        inputs: &BTreeMap<String, Vec<u8>>,
    ) -> PublicRenewalAuthorityPlan {
        let ca = std::str::from_utf8(&inputs["installer_ingress_ca_cert"]).unwrap();
        let leaf = std::str::from_utf8(&inputs["installer_ingress_tls_cert"]).unwrap();
        let key = plan.retained_key().unwrap();
        let public = SubjectPublicKeyInfoOwned::from_der(key.public_spki_der())
            .unwrap()
            .to_pem(spki::der::pem::LineEnding::LF)
            .unwrap();
        let observed = super::super::tests::OBSERVED;
        let expiry = ingress::check_certificates_for(
            ca,
            leaf,
            &public,
            key.transit_key_name(),
            observed,
            &plan.ingress_identity().unwrap(),
        )
        .unwrap();
        let metadata = IngressMetadata {
            schema: "elevenid.installer-ingress/v2".into(),
            installation_id: plan.installation_id().into(),
            key_name: key.transit_key_name().into(),
            key_version: 1,
            pki_mount: key.transit_key_name().into(),
            dns_names: plan.ingress_identity().unwrap().dns_names(),
            ip_addresses: plan.ingress_identity().unwrap().ip_addresses(),
            ca_der_sha256: hash(&ingress::certificate(ca).unwrap().to_der().unwrap()),
            certificate_der_sha256: hash(&ingress::certificate(leaf).unwrap().to_der().unwrap()),
            ca_pem_sha256: hash(ca.as_bytes()),
            certificate_pem_sha256: hash(leaf.as_bytes()),
            ca_expires_at: expiry.0,
            certificate_expires_at: expiry.1,
            token_ttl_seconds: 28800,
            token_observed_at: observed,
            trust_installed: false,
            installation_ready: false,
        };
        PublicRenewalAuthorityPlan(AuthorityData {
            schema: SCHEMA.into(),
            installation_id: plan.installation_id().into(),
            environment: AcmeEnvironment::Production,
            configuration_sha256: "a".repeat(64),
            hosting_selection_sha256: plan.0.hosting_selection_sha256.clone(),
            canonical_origin: plan.canonical_origin().into(),
            public_entry_origin: plan.public_entry_origin().map(str::to_owned),
            ingress_receipt_sha256: hash(&serde_json::to_vec(&metadata).unwrap()),
            initial_inputs_observed_at: observed,
            initial_input_sha256: crate::installer_generation::hashes(inputs),
            public_spki_base64: STANDARD.encode(key.public_spki_der()),
            initial_ingress: metadata,
            initial_ca_pem: ca.into(),
            initial_leaf_pem: leaf.into(),
        })
    }
    #[test]
    fn enrollment_plan_preserves_expired_original_proofs_without_renewing_or_using_old_tokens() {
        let (plan, inputs) = super::super::tests::fixture();
        let authority = from_inputs(&plan, &inputs);
        assert!(authority.0.initial_ingress.certificate_expires_at < now().unwrap());
        authority.validate().unwrap();
        authority.require_initial_snapshot(&inputs).unwrap();
        let bytes = authority.to_bytes().unwrap();
        assert_eq!(
            PublicRenewalAuthorityPlan::parse_authenticated(&bytes, &hash(&bytes)).unwrap(),
            authority
        );
        assert!(!String::from_utf8(bytes.clone())
            .unwrap()
            .contains("old-private-fixture-token"));
        let mut changed = inputs;
        changed
            .get_mut("installer_ingress_tls_kms_token")
            .unwrap()
            .push(b'x');
        assert!(authority.require_initial_snapshot(&changed).is_err());
        for (field, value) in [
            ("initial_inputs_observed_at", json!(1)),
            ("public_spki_base64", json!("invalid")),
            ("initial_input_sha256", json!({})),
            ("unknown", json!(true)),
        ] {
            let mut bad = serde_json::to_value(&authority).unwrap();
            bad[field] = value;
            let bytes = serde_json::to_vec(&bad).unwrap();
            assert!(
                PublicRenewalAuthorityPlan::parse_authenticated(&bytes, &hash(&bytes)).is_err(),
                "{field}"
            );
        }
    }
}
