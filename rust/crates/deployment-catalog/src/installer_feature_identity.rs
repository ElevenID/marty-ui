//! Admit only the completed, exact native feature identity helper's output.
//! No provider mutation, output adoption or credential replacement is retried.
#![cfg(target_os = "linux")]

use crate::{
    installer_compose::{ComposeInputs, ComposeReceipt},
    installer_filesystem::DeviceBinding,
    installer_helper_output, installer_host_fs as fs, installer_jobs,
    installer_openbao::OpenBaoInventory,
    installer_state::{InstallerState, LockedInspection, Phase},
};
use marty_selfhost_identity::features::{self, Identity, Operation, Selection};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read,
    os::unix::fs::MetadataExt,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use x509_cert::{
    der::{Decode, DecodePem, Encode},
    ext::pkix::{name::GeneralName, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAltName},
    Certificate,
};

type Result<T> = std::result::Result<T, String>;
const REFUSED: &str = "native feature identity output is incomplete or changed; preserve installation and helper evidence";
pub(crate) const SERVICE: &str = "installer-feature-identities";
pub(crate) const OUTPUT_DIRECTORY: &str = "feature-identity-output";
pub(crate) const RECORD: &str = "feature-identities-result.json";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectoryIdentity {
    device: DeviceBinding,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}
impl DirectoryIdentity {
    fn observe(file: &File) -> Result<Self> {
        let metadata = file.metadata().map_err(|_| REFUSED)?;
        require(metadata.is_dir() && metadata.mode() & 0o7777 == 0o700)?;
        Ok(Self {
            device: DeviceBinding::observe(file, REFUSED)?,
            inode: metadata.ino(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.mode(),
        })
    }
    fn matches(&self, mut current: Self) -> bool {
        if !self.device.matches(current.device) {
            return false;
        }
        current.device = self.device;
        current == *self
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct IdentityReceipt {
    schema: String,
    installation_id: String,
    feature_profile_sha256: String,
    engine_id: String,
    container_id: String,
    container_name: String,
    image: String,
    compose_receipt_sha256: String,
    files: BTreeMap<String, String>,
    output_directory: DirectoryIdentity,
    qualified_at_unix_seconds: u64,
    job_completed_successfully: bool,
    governed_authority_created: bool,
    installation_ready: bool,
}

fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}

fn leaf(ca: &Certificate, raw: &[u8], role: Identity, now: u64) -> Result<()> {
    let cert = Certificate::from_pem(raw).map_err(|_| REFUSED)?;
    let tbs = &cert.tbs_certificate;
    let start = tbs.validity.not_before.to_unix_duration().as_secs();
    let end = tbs.validity.not_after.to_unix_duration().as_secs();
    require(
        tbs.subject.to_string() == format!("CN={}", role.common_name)
            && tbs.issuer == ca.tbs_certificate.subject
            && start <= now
            && end > now.saturating_add(60)
            && end.saturating_sub(start) <= features::MAX_LEAF_SECONDS + 60,
    )?;
    require(
        tbs.get::<BasicConstraints>()
            .map_err(|_| REFUSED)?
            .is_none_or(|(_, v)| !v.ca && v.path_len_constraint.is_none()),
    )?;
    let usage = tbs
        .get::<KeyUsage>()
        .map_err(|_| REFUSED)?
        .ok_or(REFUSED)?
        .1;
    require(usage.digital_signature() && !usage.key_cert_sign() && !usage.crl_sign())?;
    let eku = tbs
        .get::<ExtendedKeyUsage>()
        .map_err(|_| REFUSED)?
        .ok_or(REFUSED)?
        .1;
    let expected_eku = if role.server {
        "1.3.6.1.5.5.7.3.1"
    } else {
        "1.3.6.1.5.5.7.3.2"
    };
    require(eku.0.len() == 1 && eku.0[0].to_string() == expected_eku)?;
    let names = tbs
        .get::<SubjectAltName>()
        .map_err(|_| REFUSED)?
        .ok_or(REFUSED)?
        .1;
    let mut dns = BTreeSet::new();
    let mut uris = BTreeSet::new();
    for name in names.0 {
        match name {
            GeneralName::DnsName(value) if dns.insert(value.as_str().to_string()) => {}
            GeneralName::UniformResourceIdentifier(value)
                if uris.insert(value.as_str().to_string()) => {}
            _ => return Err(REFUSED.into()),
        }
    }
    require(
        dns == BTreeSet::from([role.common_name.to_string()])
            && uris
                == (if role.uri.is_empty() {
                    BTreeSet::new()
                } else {
                    BTreeSet::from([role.uri.to_string()])
                }),
    )?;
    let key = marty_crypto::jwk::public_key_der_to_jwk(
        &tbs.subject_public_key_info.to_der().map_err(|_| REFUSED)?,
    )
    .map_err(|_| REFUSED)?;
    require(key.kty == "EC" && key.crv.as_deref() == Some("P-256"))?;
    let ca_der = CertificateDer::from(ca.to_der().map_err(|_| REFUSED)?);
    let cert_der = CertificateDer::from(cert.to_der().map_err(|_| REFUSED)?);
    let anchors = [webpki::anchor_from_trusted_cert(&ca_der).map_err(|_| REFUSED)?];
    let verifier = webpki::EndEntityCert::try_from(&cert_der).map_err(|_| REFUSED)?;
    verifier
        .verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &anchors,
            &[],
            UnixTime::since_unix_epoch(Duration::from_secs(now)),
            if role.server {
                webpki::KeyUsage::server_auth()
            } else {
                webpki::KeyUsage::client_auth()
            },
            None,
            None,
        )
        .map_err(|_| REFUSED)?;
    if role.server {
        verifier
            .verify_is_valid_for_subject_name(
                &ServerName::try_from(role.common_name).map_err(|_| REFUSED)?,
            )
            .map_err(|_| REFUSED)?;
    }
    Ok(())
}

/// Also reusable by native renewal before accepting a newly staged feature
/// generation. The caller must separately bind its exact completed helper job.
pub(crate) fn validate_payloads(
    selection: &Selection,
    files: &BTreeMap<String, Vec<u8>>,
    workload_ca: &[u8],
    forbidden_tokens: &[Vec<u8>],
    now: u64,
) -> Result<()> {
    selection.validate().map_err(|_| REFUSED)?;
    require(files.keys().cloned().collect::<BTreeSet<_>>() == selection.output_names())?;
    let ca = Certificate::from_pem(workload_ca).map_err(|_| REFUSED)?;
    let actual_ca = Certificate::from_pem(files.get(features::WORKLOAD_CA).ok_or(REFUSED)?)
        .map_err(|_| REFUSED)?;
    require(ca == actual_ca)?;
    require(
        ca.tbs_certificate
            .get::<BasicConstraints>()
            .map_err(|_| REFUSED)?
            .is_some_and(|(_, v)| v.ca),
    )?;
    let metadata = crate::installer_json::decode(files.get(features::METADATA).ok_or(REFUSED)?)
        .map_err(|_| REFUSED)?;
    require(metadata == selection.receipt())?;
    if selection.delegated_use {
        let der = files.get(features::CLIENT_CA_DER).ok_or(REFUSED)?;
        require(Certificate::from_der(der).map_err(|_| REFUSED)? == ca)?;
    }
    let certificates: BTreeMap<_, _> = selection
        .identities()
        .into_iter()
        .map(|role| (role.certificate, role))
        .collect();
    let mut tokens = BTreeSet::new();
    for (name, bytes) in files {
        require(
            !bytes.is_empty()
                && bytes.len() <= 65_536
                && !bytes.windows(11).any(|v| v == b"PRIVATE KEY"),
        )?;
        if name == features::CLIENT_CA_DER {
            continue;
        }
        require(bytes.is_ascii() && !bytes.contains(&0))?;
        if let Some(role) = certificates.get(name.as_str()) {
            leaf(&ca, bytes, *role, now)?;
        } else if ![features::WORKLOAD_CA, features::METADATA].contains(&name.as_str()) {
            require(
                (20..=1024).contains(&bytes.len())
                    && bytes.iter().all(u8::is_ascii_graphic)
                    && tokens.insert(bytes.clone())
                    && forbidden_tokens.iter().all(|token| token != bytes),
            )?;
        }
    }
    Ok(())
}

/// Current-time certificate admission before starting a newly selected runtime
/// projection. The feature owner must first authenticate the material's exact
/// receipt and file inventory. This is not a live OpenBao token-lease probe.
pub(crate) fn validate_current_material(
    selection: &Selection,
    values: &BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| REFUSED)?
        .as_secs();
    validate_material_at(selection, values, now)
}

/// Historical admission at a timestamp authenticated by the native activation
/// owner. Mutation callers must continue to use `validate_current_material`;
/// an old receipt never authorizes starting an expired runtime projection.
pub(crate) fn validate_material_at(
    selection: &Selection,
    values: &BTreeMap<String, Vec<u8>>,
    now: u64,
) -> Result<()> {
    selection.validate().map_err(|_| REFUSED)?;
    let metadata = crate::installer_json::decode(values.get(features::METADATA).ok_or(REFUSED)?)
        .map_err(|_| REFUSED)?;
    let recorded: Selection =
        serde_json::from_value(metadata["selection"].clone()).map_err(|_| REFUSED)?;
    let mut expected = selection.clone();
    expected.operation = recorded.operation;
    require(expected == recorded)?;
    let files = expected
        .output_names()
        .into_iter()
        .map(|name| {
            values
                .get(&name)
                .cloned()
                .map(|bytes| (name, bytes))
                .ok_or_else(|| REFUSED.to_string())
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let forbidden = if expected.operation == Operation::Renew {
        vec![
            values
                .get(features::RENEWAL_ROLE_ID)
                .ok_or(REFUSED)?
                .clone(),
            values
                .get(features::RENEWAL_SECRET_ID)
                .ok_or(REFUSED)?
                .clone(),
        ]
    } else {
        Vec::new()
    };
    validate_payloads(
        &expected,
        &files,
        values.get(features::WORKLOAD_CA).ok_or(REFUSED)?,
        &forbidden,
        now,
    )
}

fn payloads(output: &File, owner: u32, selection: &Selection) -> Result<BTreeMap<String, Vec<u8>>> {
    require(fs::file_names(output, REFUSED)? == selection.output_names())?;
    let mut result = BTreeMap::new();
    for name in selection.output_names() {
        let file = fs::open_child(output, &name, libc::O_RDONLY | libc::O_NONBLOCK, REFUSED)?;
        let metadata = file.metadata().map_err(|_| REFUSED)?;
        require(
            metadata.is_file()
                && metadata.uid() == owner
                && metadata.nlink() == 1
                && metadata.mode() & 0o7777 == 0o444
                && metadata.len() > 0
                && metadata.len() <= 65_536,
        )?;
        let mut raw = Vec::new();
        file.take(65_537)
            .read_to_end(&mut raw)
            .map_err(|_| REFUSED)?;
        require(raw.len() as u64 == metadata.len())?;
        result.insert(name, raw);
    }
    Ok(result)
}

#[expect(
    clippy::too_many_arguments,
    reason = "Keep independently bound installation, helper and custody inputs explicit."
)]
pub(crate) fn bootstrap_feature_identities(
    dockerpath: &Path,
    installation: &Path,
    bundle: &Path,
    state: &mut InstallerState,
    bao: &OpenBaoInventory,
    services_image: &str,
    inputs: ComposeInputs,
    expected_operator_sha: &str,
    selection: &Selection,
    mut accept: impl FnMut(&str, &[u8]) -> Result<()>,
) -> Result<(ComposeReceipt, IdentityReceipt)> {
    state.require_live_phase(Phase::Provisioning)?;
    state.with_inspection(|view| view.require_path_binding(installation))?;
    selection.validate().map_err(|_| REFUSED)?;
    require(
        selection.operation == Operation::Provision
            && selection.installation_id == state.journal().installation_id().to_string()
            && state.journal().feature_profile_sha256()
                == Some(selection.feature_profile_sha256.as_str()),
    )?;
    let binding = state.journal().runtime().ok_or(REFUSED)?.clone();
    let output = state.create_feature_directory(OUTPUT_DIRECTORY)?;
    let path = installation.join(OUTPUT_DIRECTORY);
    let original = output.metadata().map_err(|_| REFUSED)?;
    let original_identity = (
        original.dev(),
        original.ino(),
        original.uid(),
        original.gid(),
        original.mode(),
    );
    let directory_identity = DirectoryIdentity::observe(&output)?;
    require(fs::file_names(&output, REFUSED)?.is_empty())?;
    let baseline = fs::directory(&installation.join("secrets"), REFUSED)?;
    let workload_ca = fs::read_entry(
        &baseline,
        "workload_identity_ca_cert",
        0o444,
        false,
        REFUSED,
    )?;
    state.write_evidence(
        "feature-identities-pending.json",
        &serde_json::to_vec(&json!({
            "schema":"elevenid.installer-feature-identities-intent/v1","selection":selection,
            "engine_id":binding.engine_id,"operator_sha256":expected_operator_sha,
            "output_directory":OUTPUT_DIRECTORY,"output_inode":original.ino(),
        }))
        .map_err(|_| REFUSED)?,
    )?;
    let job = installer_jobs::run(
        dockerpath,
        installation,
        bundle,
        state,
        Some(bao),
        inputs,
        SERVICE,
        services_image,
        expected_operator_sha,
    )?;
    fs::require_directory_binding(&path, &output, REFUSED)?;
    let after = output.metadata().map_err(|_| REFUSED)?;
    require(
        (
            after.dev(),
            after.ino(),
            after.uid(),
            after.gid(),
            after.mode(),
        ) == original_identity,
    )?;
    let files = payloads(
        &output,
        installer_helper_output::expected_host_uid(&binding)?.uid(),
        selection,
    )?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| REFUSED)?
        .as_secs();
    validate_payloads(selection, &files, &workload_ca, &[], now)?;
    for (name, bytes) in &files {
        accept(name, bytes)?;
    }
    fs::require_directory_binding(&path, &output, REFUSED)?;
    let receipt = IdentityReceipt {
        schema: "elevenid.installer-feature-identities/v1".into(),
        installation_id: selection.installation_id.clone(),
        feature_profile_sha256: selection.feature_profile_sha256.clone(),
        engine_id: binding.engine_id,
        container_id: job.container_id,
        container_name: job.container_name,
        image: job.image,
        compose_receipt_sha256: installer_jobs::receipt_digest(&job.compose)?,
        files: files
            .iter()
            .map(|(name, raw)| (name.clone(), crate::installer_release::sha256(raw)))
            .collect(),
        output_directory: directory_identity,
        qualified_at_unix_seconds: now,
        job_completed_successfully: true,
        governed_authority_created: false,
        installation_ready: false,
    };
    state.write_evidence(RECORD, &serde_json::to_vec(&receipt).map_err(|_| REFUSED)?)?;
    Ok((job.compose, receipt))
}

/// Historical setup output remains retained even after its leaf certificates
/// expire or a later generation is activated. Check it at the receipt's original
/// qualification time, while authenticating its immutable job and file hashes.
pub(crate) fn verify_retained(
    view: &LockedInspection,
    installation: &Path,
    selection: &Selection,
) -> Result<()> {
    view.require_path_binding(installation)?;
    verify_retained_records(
        view.journal(),
        installation,
        selection,
        &view.read_evidence(RECORD)?,
        &view.read_evidence("compose-setup-installer-feature-identities-result.json")?,
    )?;
    view.require_path_binding(installation)?;
    view.require_unchanged()
}

/// Common historical admission for the locked and no-second-lock readers. Both
/// callers bind their installation/evidence descriptors around this inspection.
fn verify_retained_records(
    journal: &crate::installer_state::Journal,
    installation: &Path,
    selection: &Selection,
    raw: &[u8],
    job_raw: &[u8],
) -> Result<IdentityReceipt> {
    let receipt: IdentityReceipt =
        serde_json::from_value(crate::installer_json::decode(raw).map_err(|_| REFUSED)?)
            .map_err(|_| REFUSED)?;
    require(
        receipt.schema == "elevenid.installer-feature-identities/v1"
            && receipt.installation_id == journal.installation_id().to_string()
            && receipt.installation_id == selection.installation_id
            && journal.feature_profile_sha256() == Some(receipt.feature_profile_sha256.as_str())
            && receipt.feature_profile_sha256 == selection.feature_profile_sha256
            && journal
                .runtime()
                .is_some_and(|binding| binding.engine_id == receipt.engine_id)
            && receipt.job_completed_successfully
            && !receipt.governed_authority_created
            && !receipt.installation_ready,
    )?;
    require(crate::installer_release::sha256(job_raw) == receipt.compose_receipt_sha256)?;
    let job: ComposeReceipt =
        serde_json::from_value(crate::installer_json::decode(job_raw).map_err(|_| REFUSED)?)
            .map_err(|_| REFUSED)?;
    let container = job
        .resources
        .as_ref()
        .and_then(|resources| resources.containers.get(SERVICE))
        .ok_or(REFUSED)?;
    require(
        job.schema == "elevenid.installer-compose-operation/v1"
            && job.operation == format!("setup-{SERVICE}")
            && job.engine_id == receipt.engine_id
            && job.project == journal.compose_project()
            && job.command_succeeded
            && job.observation_validated
            && job.client_exit_code == Some(0)
            && job.failure_class.is_none()
            && !job.installation_ready
            && container.setup
            && container.id == receipt.container_id
            && container.image == receipt.image
            && receipt.container_name == format!("{}-{SERVICE}-1", job.project),
    )?;
    let output_path = installation.join(OUTPUT_DIRECTORY);
    let output = fs::directory(&output_path, REFUSED)?;
    require(
        receipt
            .output_directory
            .matches(DirectoryIdentity::observe(&output)?),
    )?;
    let binding = journal.runtime().ok_or(REFUSED)?;
    let files = payloads(
        &output,
        installer_helper_output::expected_host_uid(binding)?.uid(),
        selection,
    )?;
    require(
        files
            .iter()
            .map(|(name, raw)| (name.clone(), crate::installer_release::sha256(raw)))
            .collect::<BTreeMap<_, _>>()
            == receipt.files,
    )?;
    let ca = files.get(features::WORKLOAD_CA).ok_or(REFUSED)?;
    validate_payloads(
        selection,
        &files,
        ca,
        &[],
        receipt.qualified_at_unix_seconds,
    )?;
    fs::require_directory_binding(&output_path, &output, REFUSED)?;
    Ok(receipt)
}

#[cfg(test)]
#[path = "installer_feature_identity_tests.rs"]
mod tests;

#[path = "installer_feature_identity_renewal.rs"]
mod renewal;
pub(crate) use renewal::{
    admit_renewal_output, hold_renewal_output, prepare_renewal, prepare_renewal_at,
    renewal_input_names, resume_renewal_output, validate_renewal_model, validate_renewal_model_at,
    verify_renewal_receipt, verify_renewal_receipt_at, HeldRenewalOutput, RenewalMaterial,
    RenewalOutputBinding, RenewalReceipt,
};
