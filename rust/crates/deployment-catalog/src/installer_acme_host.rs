//! Fresh-install host transaction for an explicitly selected ACME source.
//! Privileged setup is confined to two fixed owned Compose jobs. A complete
//! prepared boundary precedes every CA request and permits order continuation
//! without recreating either job, keys, policies, or machine identities.
#![cfg(target_os = "linux")]

use crate::{
    installer_acme::{self, EnrolmentInputs, EnrolmentOutcome},
    installer_acme_certificates::RetainedIngressKey,
    installer_acme_configuration::{AcmeEnvironment, BoundAcmeConfiguration},
    installer_acme_credentials::{self as credentials, CredentialProviders},
    installer_acme_custody as custody,
    installer_compose::{
        self, BoundFile, ComposeInputs, ComposeReceipt, ComposeSession, ProjectResources,
    },
    installer_helper_output, installer_host_fs as fs, installer_hosting, installer_ingress_outputs,
    installer_ingress_provision, installer_jobs,
    installer_openbao::{self, OpenBaoInventory},
    installer_release,
    installer_state::{
        Identity, InstallerState, LockedInspection, Phase, RuntimeBinding, RuntimeProfile,
    },
};
use marty_openbao_http::OpenBaoHttp;
use reqwest::Method;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use spki::der::{pem::LineEnding, Encode, EncodePem};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

type Result<T> = std::result::Result<T, String>;
const REFUSED: &str = "ACME host transaction evidence or owned runtime differs; preserve the installation for reconciliation";
const SETUP_HOLD: &str =
    "ACME initial setup is incomplete; do not repeat its owned setup jobs or adopt partial outputs";
pub(crate) const LAYER: &str = "deploy-config/compose/selfhost-installer/compose.acme.yml";
const CUSTODY: &str = "installer-acme-custody";
const CREDENTIALS: &str = "installer-acme-credentials";
const RESPONDER: &str = "installer-acme-http01";
const PROJECTION: &str = "acme-http01";
const RESPONDER_OPERATION: &str = "acme-http01";
const CUSTODY_PLAN: &str = "acme-custody-plan.json";
const CREDENTIAL_PLAN: &str = "acme-credentials-plan.json";
const RENEWAL_ENVIRONMENT: &str = "acme-public-renewal-authority.env";
const RENEWAL_PLAN: &str = "renewal-public-authority-plan.json";
const STAGING_ROOTS: &str = "staging-acme-roots.pem";

#[path = "installer_acme_host_diagnostics.rs"]
mod diagnostics;
pub(crate) use diagnostics::preparation_status;
use diagnostics::{checked, checkpoint, Check, Checked};

#[path = "installer_acme_initial_rollover.rs"]
mod initial_rollover;
pub(crate) use initial_rollover::InitialRolloverPermit;

/// All executable, image and infrastructure selections come from the existing
/// authenticated installer. There is no authority, URL or helper-path override.
pub struct HostInputs<'a> {
    pub docker: &'a Path,
    pub installation: &'a Path,
    pub bundle: &'a Path,
    pub infrastructure: &'a OpenBaoInventory,
    pub services_image: &'a str,
    pub operator_sha256: &'a str,
}

/// Cumulative Compose ownership and an admitted candidate, if issuance finished.
/// The caller owns the separate generation/activation/readiness transaction.
pub struct AcmeHostOutcome {
    pub compose_inputs: ComposeInputs,
    pub compose_receipt: ComposeReceipt,
    pub ingress_key: RetainedIngressKey,
    pub enrolment: EnrolmentOutcome,
}

/// Public selections reconstructed from the complete retained boundary. The
/// command owner supplies the already authenticated local Docker executable;
/// resume performs live engine/resource observations before using authority.
pub(crate) struct ContinuationContext {
    pub bundle: PathBuf,
    pub infrastructure: OpenBaoInventory,
    pub services_image: String,
    pub operator_sha256: String,
    pub compose_inputs: ComposeInputs,
}

fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}
fn encode(value: &impl Serialize) -> Result<Vec<u8>> {
    serde_json::to_vec(&serde_json::to_value(value).map_err(|_| REFUSED)?)
        .map_err(|_| REFUSED.into())
}
fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_json::from_value(crate::installer_json::decode(bytes).map_err(|_| REFUSED)?)
        .map_err(|_| REFUSED.into())
}
fn value(value: &impl Serialize) -> Result<Value> {
    serde_json::to_value(value).map_err(|_| REFUSED.into())
}
fn sha(bytes: &[u8]) -> String {
    installer_release::sha256(bytes)
}
fn hash_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn runtime() -> Result<tokio::runtime::Runtime> {
    require(tokio::runtime::Handle::try_current().is_err())?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| REFUSED.into())
}
fn name(environment: AcmeEnvironment, suffix: &str) -> String {
    format!("acme-host-{}-{suffix}.json", environment.as_str())
}
fn environment_name(environment: AcmeEnvironment, phase: &str) -> String {
    format!("acme-{}-{phase}.env", environment.as_str())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicKey {
    version: u64,
    spki_der: Vec<u8>,
}
impl PublicKey {
    fn new(key: &RetainedIngressKey) -> Self {
        Self {
            version: key.key_version(),
            spki_der: key.public_spki_der().into(),
        }
    }
    fn bind(&self, installation: uuid::Uuid) -> Result<RetainedIngressKey> {
        RetainedIngressKey::from_recorded_public_key(
            &installation.to_string(),
            self.version,
            &self.spki_der,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    schema: String,
    installation_id: uuid::Uuid,
    configuration: Value,
    release: Identity,
    runtime: RuntimeBinding,
    bootstrap: ComposeInputs,
    prior: ComposeReceipt,
    infrastructure: OpenBaoInventory,
    bundle: PathBuf,
    services_image: String,
    operator_sha256: String,
    ingress_key: PublicKey,
    openbao_ca_pem_sha256: String,
    server_cluster_id: String,
    application_preparation_sha256: String,
    public_renewal_enrolment_sha256: String,
    staging_roots_sha256: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectionDirectory {
    device: u64,
    inode: u64,
    owner: u32,
    group: u32,
}
impl ProjectionDirectory {
    fn observe(state: &LockedInspection, installation: &Path) -> Result<Self> {
        state.require_path_binding(installation)?;
        let directory = fs::open_child(
            state.installation_directory(),
            PROJECTION,
            libc::O_RDONLY | libc::O_DIRECTORY,
            REFUSED,
        )?;
        let metadata = directory.metadata().map_err(|_| REFUSED)?;
        require(
            metadata.is_dir()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o7777 == 0o755,
        )?;
        require(
            installation
                .join(PROJECTION)
                .canonicalize()
                .map_err(|_| REFUSED)?
                == installation.join(PROJECTION),
        )?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
            group: metadata.gid(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Job {
    schema: String,
    installation_id: uuid::Uuid,
    service: String,
    plan_sha256: String,
    container_id: String,
    container_name: String,
    image: String,
    compose_receipt_sha256: String,
    completed_successfully: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Prepared {
    schema: String,
    installation_id: uuid::Uuid,
    environment: AcmeEnvironment,
    evidence_sha256: BTreeMap<String, String>,
    projection: ProjectionDirectory,
    inputs: ComposeInputs,
    receipt: ComposeReceipt,
    initial_setup_complete: bool,
    activation_performed: bool,
    installation_ready: bool,
}

fn successful(receipt: &ComposeReceipt, project: &str, engine: &str) -> Result<()> {
    require(
        receipt.schema == "elevenid.installer-compose-operation/v1"
            && receipt.project == project
            && receipt.engine_id == engine
            && receipt.command_succeeded
            && receipt.observation_validated
            && receipt.client_exit_code == Some(0)
            && receipt.failure_class.is_none()
            && receipt.resources.is_some()
            && !receipt.installation_ready,
    )
}

fn current_context(
    context: &HostInputs<'_>,
    state: &InstallerState,
) -> Result<BoundAcmeConfiguration> {
    state.require_live_phase(Phase::Provisioning)?;
    let binding = state.journal().runtime().ok_or(REFUSED)?;
    require(binding.profile == RuntimeProfile::Rootless && hash_valid(context.operator_sha256))?;
    binding.validate()?;
    installer_openbao::require_binding(state, context.infrastructure)?;
    require(
        context.bundle.starts_with(context.installation)
            && context.bundle.canonicalize().map_err(|_| REFUSED)? == context.bundle
            && crate::installer_verify::operator_digest(
                &context.installation.join("marty-deploy"),
            )? == context.operator_sha256,
    )?;
    state.with_inspection(|view| {
        view.require_path_binding(context.installation)?;
        crate::installer_acme_preparation::require_supported_scope(view)?;
        crate::installer_application::require_acme_preparation(view, context.installation)?;
        require(
            decode::<Value>(&view.read_evidence("openbao-observation.json")?)?
                == value(context.infrastructure)?,
        )?;
        BoundAcmeConfiguration::from_selection(view)
    })
}

fn roots(environment: AcmeEnvironment, pem: Option<&[u8]>) -> Result<Option<String>> {
    require(pem.is_some() == (environment == AcmeEnvironment::Staging))?;
    pem.map(|pem| {
        require(
            !pem.is_empty()
                && pem.len() <= 65536
                && pem.is_ascii()
                && !pem.contains(&0)
                && !pem.windows(11).any(|part| part == b"PRIVATE KEY"),
        )?;
        crate::installer_acme_certificates::validate_staging_roots(pem)?;
        Ok(sha(pem))
    })
    .transpose()
}

fn retained_roots(
    state: &LockedInspection,
    environment: AcmeEnvironment,
    supplied: Option<&[u8]>,
) -> Result<Option<String>> {
    let saved = state.diagnostic_record(STAGING_ROOTS, true)?;
    require(saved.as_deref() == supplied)?;
    roots(environment, saved.as_deref())
}

struct Connection {
    bao: OpenBaoHttp,
    ca_sha256: String,
    cluster: String,
}
fn connection(
    context: &HostInputs<'_>,
    state: &InstallerState,
    inputs: &ComposeInputs,
) -> Result<Connection> {
    state.with_inspection(|view| connection_view(context, view, inputs))
}
fn connection_view(
    context: &HostInputs<'_>,
    state: &LockedInspection,
    inputs: &ComposeInputs,
) -> Result<Connection> {
    state.require_path_binding(context.installation)?;
    let secrets = fs::directory(&context.installation.join("secrets"), REFUSED)?;
    let pem = fs::read_entry(&secrets, "openbao_tls_ca_cert", 0o644, false, REFUSED)?;
    let ca =
        installer_ingress_provision::certificate(std::str::from_utf8(&pem).map_err(|_| REFUSED)?)?;
    let observed =
        decode::<Value>(&state.read_evidence(crate::installer_openbao_control::OBSERVATION)?)?;
    require(
        observed["schema"] == "elevenid.installer-openbao-control-observation/v1"
            && observed["installation_id"] == state.journal().installation_id().to_string()
            && observed["engine_id"] == context.infrastructure.engine_id
            && observed["enrollment"]["installation_id"]
                == state.journal().installation_id().to_string()
            && observed["enrollment"]["ca_sha256"] == sha(&ca.to_der().map_err(|_| REFUSED)?),
    )?;
    let evidence = fs::directory(&context.installation.join("evidence"), REFUSED)?;
    installer_jobs::previous_job(
        inputs,
        &evidence,
        "installer-control-enroll",
        observed["enrollment_container_id"]
            .as_str()
            .ok_or(REFUSED)?,
        &context.infrastructure.image,
        observed["compose_receipt_sha256"].as_str().ok_or(REFUSED)?,
    )?;
    let cluster = observed["enrollment"]["cluster_id"]
        .as_str()
        .ok_or(REFUSED)?
        .to_owned();
    crate::installer_openbao_seal::require_initialized_cluster(
        state,
        context.installation,
        &cluster,
    )?;
    let origin = format!("https://127.0.0.1:{}", context.infrastructure.host_port);
    let bao = OpenBaoHttp::connect(
        &origin,
        Some(&context.installation.join("secrets/openbao_tls_ca_cert")),
        Duration::from_secs(5),
    )
    .map_err(|_| REFUSED)?;
    require(fs::read_entry(&secrets, "openbao_tls_ca_cert", 0o644, false, REFUSED)? == pem)?;
    fs::require_directory_binding(&context.installation.join("secrets"), &secrets, REFUSED)?;
    Ok(Connection {
        bao,
        ca_sha256: sha(&pem),
        cluster,
    })
}
fn require_server(connection: &Connection) -> Result<()> {
    runtime()?.block_on(async {
        let health = tokio::time::timeout(
            Duration::from_secs(6),
            crate::operator_http::request(&connection.bao, Method::GET, "sys/health", None, None),
        )
        .await
        .map_err(|_| REFUSED)?
        .map_err(|_| REFUSED)?;
        require(
            health["initialized"] == true
                && health["sealed"] == false
                && health["standby"] == false
                && health["cluster_id"] == connection.cluster,
        )
    })
}

/// Only public certificate/metadata from the already authenticated ingress job
/// are read. Its Transit custody is re-observed by the new fixed custody helper.
fn initial_ingress(
    context: &HostInputs<'_>,
    state: &InstallerState,
    inputs: &ComposeInputs,
    configuration: &BoundAcmeConfiguration,
) -> Result<RetainedIngressKey> {
    let owner = state.journal().installation_id().to_string();
    let evidence = fs::directory(&context.installation.join("evidence"), REFUSED)?;
    let result: Value = decode(&fs::read_entry(
        &evidence,
        "ingress-result.json",
        0o600,
        false,
        REFUSED,
    )?)?;
    require(
        result["schema"] == "elevenid.installer-ingress-host/v2"
            && result["installation_id"] == owner
            && result["engine_id"] == context.infrastructure.engine_id
            && result["network_id"] == context.infrastructure.network_id
            && result["image"] == context.services_image
            && result["authority_name"] == installer_ingress_provision::resource_name(&owner)?
            && result["job_completed_successfully"] == true
            && result["container_removed"] == false
            && result["installation_ready"] == false,
    )?;
    installer_jobs::previous_job(
        inputs,
        &evidence,
        "installer-ingress-provision",
        result["container_id"].as_str().ok_or(REFUSED)?,
        context.services_image,
        result["compose_receipt_sha256"].as_str().ok_or(REFUSED)?,
    )?;
    let identity = configuration.certificate_identity()?;
    let ingress_identity = installer_ingress_provision::IngressIdentity::new(
        Some(identity.dns_name()),
        identity.ip_address(),
    )?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| REFUSED)?
        .as_secs();
    let metadata = installer_ingress_outputs::metadata_for_identity(
        &fs::read_entry(&evidence, "installer-ingress.json", 0o600, false, REFUSED)?,
        &owner,
        now,
        &ingress_identity,
    )?;
    let secrets = fs::directory(&context.installation.join("secrets"), REFUSED)?;
    let ca = fs::read_entry(&secrets, "installer_ingress_ca_cert", 0o444, false, REFUSED)?;
    let leaf = fs::read_entry(
        &secrets,
        "installer_ingress_tls_cert",
        0o444,
        false,
        REFUSED,
    )?;
    let ca_text = std::str::from_utf8(&ca).map_err(|_| REFUSED)?;
    let leaf_text = std::str::from_utf8(&leaf).map_err(|_| REFUSED)?;
    let cert = installer_ingress_provision::certificate(leaf_text)?;
    let root = installer_ingress_provision::certificate(ca_text)?;
    let public = cert
        .tbs_certificate
        .subject_public_key_info
        .to_pem(LineEnding::LF)
        .map_err(|_| REFUSED)?;
    let expiry = installer_ingress_provision::check_certificates_for(
        ca_text,
        leaf_text,
        &public,
        &metadata.key_name,
        now,
        &ingress_identity,
    )?;
    require(
        sha(&ca) == metadata.ca_pem_sha256
            && sha(&leaf) == metadata.certificate_pem_sha256
            && sha(&root.to_der().map_err(|_| REFUSED)?) == metadata.ca_der_sha256
            && sha(&cert.to_der().map_err(|_| REFUSED)?) == metadata.certificate_der_sha256
            && expiry == (metadata.ca_expires_at, metadata.certificate_expires_at),
    )?;
    RetainedIngressKey::from_recorded_public_key(
        &owner,
        metadata.key_version,
        &cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(|_| REFUSED)?,
    )
}

fn append(env: &mut Vec<u8>, key: &str, value: &str) -> Result<()> {
    require(
        value.is_ascii()
            && !value
                .chars()
                .any(|ch| ch.is_control() || ch == '\'' || ch == '\\'),
    )?;
    let line = format!("{key}='{value}'");
    let text = std::str::from_utf8(env).map_err(|_| REFUSED)?;
    let old: Vec<_> = text
        .lines()
        .filter(|line| line.starts_with(&format!("{key}=")))
        .collect();
    match old.as_slice() {
        [] => env.extend_from_slice(format!("{line}\n").as_bytes()),
        [existing] => require(*existing == line)?,
        _ => return Err(REFUSED.into()),
    }
    Ok(())
}

fn retained_environment(state: &LockedInspection, inputs: &ComposeInputs) -> Result<Vec<u8>> {
    state.require_path_binding(&inputs.installation)?;
    let path = &inputs.environment.path;
    require(path.parent() == Some(inputs.installation.join("evidence").as_path()))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(REFUSED)?;
    let bytes = state.read_evidence(name)?;
    require(sha(&bytes) == inputs.environment.sha256)?;
    Ok(bytes)
}

fn include_bound(files: &mut Vec<BoundFile>, file: BoundFile) -> Result<()> {
    let existing: Vec<_> = files.iter().filter(|old| old.path == file.path).collect();
    match existing.as_slice() {
        [] => files.push(file),
        [old] => require(old.sha256 == file.sha256)?,
        _ => return Err(REFUSED.into()),
    }
    Ok(())
}

fn require_public_renewal(
    state: &LockedInspection,
    inputs: &ComposeInputs,
    infrastructure: &OpenBaoInventory,
    services_image: &str,
) -> Result<String> {
    let plan = crate::installer_public_ingress::PublicRenewalAuthorityPlan::load(state)?;
    let digest = crate::installer_renewal::require_public_enrolment(state, &plan)?;
    let observation: Value = decode(&state.read_evidence("renewal-observation.json")?)?;
    require(
        observation["image"] == services_image
            && observation["network_id"] == infrastructure.network_id,
    )?;
    let evidence = fs::directory(&inputs.installation.join("evidence"), REFUSED)?;
    installer_jobs::previous_job(
        inputs,
        &evidence,
        "installer-renewal",
        observation["container_id"].as_str().ok_or(REFUSED)?,
        services_image,
        observation["compose_receipt_sha256"]
            .as_str()
            .ok_or(REFUSED)?,
    )?;
    let saved = retained_environment(state, inputs)?;
    let mut confirmed = saved.clone();
    let configuration = BoundAcmeConfiguration::from_selection(state)?;
    let port = installer_hosting::resolve(state)?
        .http01_host_port()
        .ok_or(REFUSED)?;
    for (key, value) in [
        (
            crate::installer_public_ingress::AUTHORITY_PLAN_DIGEST_ENV,
            plan.sha256()?,
        ),
        (
            "MARTY_ACME_CANONICAL_ORIGIN",
            configuration.canonical_origin().into(),
        ),
        (
            "MARTY_ACME_PUBLIC_ENTRY_ORIGIN",
            configuration
                .public_entry_origin()
                .unwrap_or_default()
                .into(),
        ),
        ("MARTY_ACME_HTTP01_HOST_PORT", port.to_string()),
    ] {
        append(&mut confirmed, key, &value)?;
    }
    require(confirmed == saved && inputs.allowed_loopback_ports.contains(&port))?;
    Ok(digest)
}
fn derived_environment(
    bootstrap: &[u8],
    configuration: &BoundAcmeConfiguration,
    port: u16,
    custody_hash: &str,
    credential_hash: Option<&str>,
) -> Result<Vec<u8>> {
    require(
        !bootstrap.is_empty()
            && bootstrap.len() <= 65536
            && bootstrap
                .iter()
                .all(|byte| *byte == b'\n' || (b' '..=b'~').contains(byte))
            && bootstrap.ends_with(b"\n")
            && hash_valid(custody_hash)
            && credential_hash.is_none_or(hash_valid)
            && port >= 1024,
    )?;
    let mut env = bootstrap.to_vec();
    for (key, value) in [
        (
            "MARTY_ACME_CANONICAL_ORIGIN",
            configuration.canonical_origin().to_owned(),
        ),
        (
            "MARTY_ACME_PUBLIC_ENTRY_ORIGIN",
            configuration
                .public_entry_origin()
                .unwrap_or_default()
                .into(),
        ),
        ("MARTY_ACME_HTTP01_HOST_PORT", port.to_string()),
        ("MARTY_ACME_CUSTODY_PLAN_SHA256", custody_hash.into()),
    ] {
        append(&mut env, key, &value)?;
    }
    if let Some(hash) = credential_hash {
        append(&mut env, "MARTY_ACME_CREDENTIAL_PLAN_SHA256", hash)?;
    }
    Ok(env)
}

fn augmented_inputs(
    context: &HostInputs<'_>,
    state: &InstallerState,
    bootstrap: &ComposeInputs,
    port: u16,
) -> Result<ComposeInputs> {
    require(
        bootstrap.installation == context.installation
            && bootstrap.project == state.journal().compose_project()
            && bootstrap.environment.path
                == context
                    .installation
                    .join("evidence")
                    .join(RENEWAL_ENVIRONMENT)
            && bootstrap.profiles == ["setup"]
            && bootstrap.approved_images.contains(context.services_image)
            && port >= 1024
            && port != context.infrastructure.host_port,
    )?;
    state.with_inspection(|view| retained_environment(view, bootstrap).map(|_| ()))?;
    let selection = state.with_inspection(installer_hosting::resolve)?;
    require(selection.http01_host_port() == Some(port) && port != selection.listener().port)?;
    let layer = crate::installer_tls_outputs::bundle_text(context.bundle, LAYER, 2 * 1024 * 1024)?;
    let mut inputs = bootstrap.clone();
    include_bound(
        &mut inputs.files,
        BoundFile {
            path: context.bundle.join(LAYER),
            sha256: sha(layer.as_bytes()),
        },
    )?;
    inputs.allowed_loopback_ports.insert(port);
    inputs
        .readonly_bind_roots
        .insert(context.installation.join(PROJECTION));
    for path in ["acme-custody-transfer", "acme-credentials-transfer"] {
        inputs
            .writable_bind_roots
            .insert(context.installation.join(path));
    }
    Ok(inputs)
}

fn prepare_projection(state: &InstallerState, installation: &Path) -> Result<ProjectionDirectory> {
    state.with_inspection(|view| {
        view.require_path_binding(installation)?;
        let name = CString::new(PROJECTION).map_err(|_| REFUSED)?;
        require(
            unsafe {
                libc::mkdirat(
                    view.installation_directory().as_raw_fd(),
                    name.as_ptr(),
                    0o755,
                )
            } == 0,
        )?;
        let child = fs::open_child(
            view.installation_directory(),
            PROJECTION,
            libc::O_RDONLY | libc::O_DIRECTORY,
            REFUSED,
        )?;
        require(
            fs::file_names(&child, REFUSED)?.is_empty()
                && unsafe { libc::fchmod(child.as_raw_fd(), 0o755) } == 0,
        )?;
        child
            .sync_all()
            .and_then(|_| view.installation_directory().sync_all())
            .map_err(|_| REFUSED)?;
        ProjectionDirectory::observe(view, installation)
    })
}

#[expect(
    clippy::too_many_arguments,
    reason = "Keep the immutable plan hashes, prior ownership receipt and selected setup role explicit."
)]
fn phase_inputs(
    state: &mut InstallerState,
    intent: &Intent,
    base: &ComposeInputs,
    configuration: &BoundAcmeConfiguration,
    phase: &str,
    custody_hash: &str,
    credential_hash: Option<&str>,
    prior: ComposeReceipt,
    service: &str,
) -> Result<ComposeInputs> {
    require(matches!(
        (phase, service, credential_hash.is_some()),
        ("custody", CUSTODY, false)
            | ("credentials", CREDENTIALS, true)
            | ("responder", RESPONDER, true)
    ))?;
    let bootstrap = state.with_inspection(|view| retained_environment(view, &intent.bootstrap))?;
    let port = state
        .with_inspection(installer_hosting::resolve)?
        .http01_host_port()
        .ok_or(REFUSED)?;
    let env = derived_environment(
        &bootstrap,
        configuration,
        port,
        custody_hash,
        credential_hash,
    )?;
    let env_name = environment_name(configuration.parameters().environment(), phase);
    state.write_evidence(&env_name, &env)?;
    let mut inputs = base.clone();
    inputs.environment =
        crate::installer_application::bound(inputs.installation.join("evidence").join(env_name))?;
    inputs.prior = Some(prior);
    inputs.services = vec![service.into()];
    for filename in [
        Some(name(configuration.parameters().environment(), "intent")),
        Some(crate::installer_acme_preparation::RECORD.into()),
        (configuration.parameters().environment() == AcmeEnvironment::Staging)
            .then(|| STAGING_ROOTS.into()),
        Some(CUSTODY_PLAN.into()),
        credential_hash.map(|_| CREDENTIAL_PLAN.into()),
    ]
    .into_iter()
    .flatten()
    {
        let bound = crate::installer_application::bound(
            inputs.installation.join("evidence").join(filename),
        )?;
        include_bound(&mut inputs.bound_inputs, bound)?;
    }
    Ok(inputs)
}

fn record_job(
    state: &mut InstallerState,
    environment: AcmeEnvironment,
    phase: &str,
    service: &str,
    plan_hash: &str,
    completed: &installer_jobs::CompletedJob,
) -> Result<()> {
    successful(
        &completed.compose,
        &state.journal().compose_project(),
        &state.journal().runtime().ok_or(REFUSED)?.engine_id,
    )?;
    require(
        completed.container_name == format!("{}-{service}-1", state.journal().compose_project()),
    )?;
    let record = Job {
        schema: "elevenid.installer-acme-host-job/v1".into(),
        installation_id: state.journal().installation_id(),
        service: service.into(),
        plan_sha256: plan_hash.into(),
        container_id: completed.container_id.clone(),
        container_name: completed.container_name.clone(),
        image: completed.image.clone(),
        compose_receipt_sha256: installer_jobs::receipt_digest(&completed.compose)?,
        completed_successfully: true,
    };
    state.write_evidence(&name(environment, phase), &encode(&record)?)
}

fn responder_model(
    model: &Value,
    inputs: &ComposeInputs,
    configuration: &BoundAcmeConfiguration,
    port: u16,
) -> Result<()> {
    let services = model["services"].as_object().ok_or(REFUSED)?;
    require(services.len() == 1 && services.contains_key(RESPONDER))?;
    let service = &services[RESPONDER];
    require(
        service["environment"]["MARTY_ACME_HTTP01_BIND"] == "0.0.0.0:8080"
            && service["environment"]["MARTY_ACME_HTTP01_CANONICAL_ORIGIN"]
                == configuration.canonical_origin()
            && service["environment"]["MARTY_ACME_HTTP01_PUBLIC_ENTRY_ORIGIN"]
                == configuration.public_entry_origin().unwrap_or_default()
            && service["environment"]["MARTY_ACME_HTTP01_DIRECTORY"] == "/run/acme-http01",
    )?;
    let ports = service["ports"].as_array().ok_or(REFUSED)?;
    let published = port.to_string();
    require(
        ports.len() == 1
            && ports[0]["target"] == 8080
            && ports[0]["host_ip"] == "127.0.0.1"
            && ports[0]["protocol"] == "tcp"
            && (ports[0]["published"].as_str() == Some(published.as_str())
                || ports[0]["published"] == port),
    )?;
    let mounts = service["volumes"].as_array().ok_or(REFUSED)?;
    require(
        mounts.len() == 1
            && mounts[0]["type"] == "bind"
            && mounts[0]["read_only"] == true
            && mounts[0]["target"] == "/run/acme-http01"
            && installer_compose::config_path(&mounts[0]["source"])?
                == inputs.installation.join(PROJECTION),
    )
}

fn evidence_names(environment: AcmeEnvironment) -> BTreeSet<String> {
    let env = environment.as_str();
    let mut names = BTreeSet::from([
        name(environment, "intent"),
        name(environment, "custody"),
        name(environment, "credentials"),
        crate::installer_acme_preparation::RECORD.into(),
        RENEWAL_PLAN.into(),
        "renewal-result.json".into(),
        "renewal-observation.json".into(),
        CUSTODY_PLAN.into(),
        CREDENTIAL_PLAN.into(),
        format!("acme-custody-{env}-intent.json"),
        format!("acme-custody-{env}-plan.json"),
        format!("acme-custody-{env}-public.json"),
        format!("acme-custody-{env}-result.json"),
        format!("acme-credentials-{env}-intent.json"),
        format!("acme-credentials-{env}-result.json"),
        format!("compose-{RESPONDER_OPERATION}-result.json"),
    ]);
    if environment == AcmeEnvironment::Staging {
        names.insert(STAGING_ROOTS.into());
    }
    names
}
fn fingerprints(
    state: &LockedInspection,
    environment: AcmeEnvironment,
) -> Result<BTreeMap<String, String>> {
    evidence_names(environment)
        .into_iter()
        .map(|name| Ok((name.clone(), sha(&state.read_evidence(&name)?))))
        .collect()
}

/// Initial setup only. An interrupted setup is never inferred to be absent.
pub fn provision(
    context: &HostInputs<'_>,
    state: &mut InstallerState,
    bootstrap: &ComposeInputs,
    prior: ComposeReceipt,
    staging_roots: Option<&[u8]>,
) -> Result<AcmeHostOutcome> {
    let configuration = checkpoint(Check::Context, || current_context(context, state))?;
    let environment = configuration.parameters().environment();
    let staging_roots_sha256 = checkpoint(Check::StagingTrust, || {
        state.with_inspection(|view| retained_roots(view, environment, staging_roots))
    })?;
    let port = checkpoint(Check::Http01Port, || {
        state
            .with_inspection(installer_hosting::resolve)?
            .http01_host_port()
            .ok_or_else(|| REFUSED.into())
    })?;
    let base = checkpoint(Check::InitialInputs, || {
        augmented_inputs(context, state, bootstrap, port)
    })?;
    checkpoint(Check::PriorOperation, || {
        successful(
            &prior,
            &bootstrap.project,
            &context.infrastructure.engine_id,
        )
    })?;
    state.with_inspection(|view| {
        for (directory, evidence) in [
            (
                view.installation_directory()
                    .try_clone()
                    .map_err(|_| REFUSED)?,
                false,
            ),
            (
                fs::directory(&context.installation.join("evidence"), REFUSED)?,
                true,
            ),
        ] {
            if fs::file_names(&directory, REFUSED)?.iter().any(|filename| {
                filename.starts_with("acme-")
                    && !(evidence
                        && matches!(
                            filename.as_str(),
                            crate::installer_acme_preparation::RECORD | RENEWAL_ENVIRONMENT
                        ))
            }) {
                return Err(SETUP_HOLD.into());
            }
        }
        Ok(())
    })?;
    let mut before = bootstrap.clone();
    before.prior = Some(prior.clone());
    let public_renewal_enrolment_sha256 = checkpoint(Check::PublicRenewal, || {
        state.with_inspection(|view| {
            require_public_renewal(
                view,
                &before,
                context.infrastructure,
                context.services_image,
            )
        })
    })?;
    let ingress = checkpoint(Check::InitialIngress, || {
        initial_ingress(context, state, &before, &configuration)
    })?;
    let connection = checkpoint(Check::OpenbaoConnection, || {
        connection(context, state, &before)
    })?;
    checkpoint(Check::OpenbaoServer, || require_server(&connection))?;
    let intent = Intent {
        schema: "elevenid.installer-acme-host-intent/v1".into(),
        installation_id: state.journal().installation_id(),
        configuration: value(&configuration)?,
        release: state.journal().identity().clone(),
        runtime: state.journal().runtime().ok_or(REFUSED)?.clone(),
        bootstrap: bootstrap.clone(),
        prior,
        infrastructure: context.infrastructure.clone(),
        bundle: context.bundle.into(),
        services_image: context.services_image.into(),
        operator_sha256: context.operator_sha256.into(),
        ingress_key: PublicKey::new(&ingress),
        openbao_ca_pem_sha256: connection.ca_sha256.clone(),
        server_cluster_id: connection.cluster.clone(),
        application_preparation_sha256: state.with_inspection(|view| {
            Ok(sha(&view.read_evidence(
                crate::installer_acme_preparation::RECORD,
            )?))
        })?,
        public_renewal_enrolment_sha256,
        staging_roots_sha256,
    };
    state.write_evidence(&name(environment, "intent"), &encode(&intent)?)?;
    let projection = checkpoint(Check::Projection, || {
        prepare_projection(state, context.installation)
    })?;
    state.create_private_directory("acme-custody-transfer")?;
    let custody_plan =
        custody::prepare_for_install(state, &configuration, &ingress, &connection.bao)?;
    let custody_hash = custody_plan.sha256()?;
    state.write_evidence(CUSTODY_PLAN, &custody_plan.public_bytes()?)?;
    let inputs = phase_inputs(
        state,
        &intent,
        &base,
        &configuration,
        "custody",
        &custody_hash,
        None,
        intent.prior.clone(),
        CUSTODY,
    )?;
    let output = fs::directory(&context.installation.join("acme-custody-transfer"), REFUSED)?;
    require(
        installer_helper_output::expected_host_uid(&intent.runtime)?.uid()
            == unsafe { libc::geteuid() },
    )?;
    let job = installer_jobs::run(
        context.docker,
        context.installation,
        context.bundle,
        state,
        Some(context.infrastructure),
        inputs,
        CUSTODY,
        context.services_image,
        context.operator_sha256,
    )?;
    fs::require_directory_binding(
        &context.installation.join("acme-custody-transfer"),
        &output,
        REFUSED,
    )?;
    checkpoint(Check::CustodyJob, || {
        record_job(state, environment, "custody", CUSTODY, &custody_hash, &job)
    })?;
    let custody = custody::admit_for_install(
        state,
        &configuration,
        &ingress,
        &custody_plan,
        &context.installation.join("acme-custody-transfer"),
    )?;
    fs::require_directory_binding(
        &context.installation.join("acme-custody-transfer"),
        &output,
        REFUSED,
    )?;
    let credential_plan = credentials::prepare_for_install(
        state,
        context.installation,
        &configuration,
        custody.account_key(),
        &ingress,
        &connection.bao,
    )?;
    let credential_hash = credential_plan.sha256()?;
    state.write_evidence(CREDENTIAL_PLAN, &credential_plan.public_bytes()?)?;
    state.create_private_directory("acme-credentials-transfer")?;
    let inputs = phase_inputs(
        state,
        &intent,
        &base,
        &configuration,
        "credentials",
        &custody_hash,
        Some(&credential_hash),
        job.compose,
        CREDENTIALS,
    )?;
    let output = fs::directory(
        &context.installation.join("acme-credentials-transfer"),
        REFUSED,
    )?;
    let job = installer_jobs::run(
        context.docker,
        context.installation,
        context.bundle,
        state,
        Some(context.infrastructure),
        inputs,
        CREDENTIALS,
        context.services_image,
        context.operator_sha256,
    )?;
    fs::require_directory_binding(
        &context.installation.join("acme-credentials-transfer"),
        &output,
        REFUSED,
    )?;
    checkpoint(Check::CredentialsJob, || {
        record_job(
            state,
            environment,
            "credentials",
            CREDENTIALS,
            &credential_hash,
            &job,
        )
    })?;
    let providers = credentials::admit_for_install(
        state,
        context.installation,
        &configuration,
        &connection.bao,
        &context.installation.join("acme-credentials-transfer"),
    )?;
    fs::require_directory_binding(
        &context.installation.join("acme-credentials-transfer"),
        &output,
        REFUSED,
    )?;
    let mut inputs = phase_inputs(
        state,
        &intent,
        &base,
        &configuration,
        "responder",
        &custody_hash,
        Some(&credential_hash),
        job.compose,
        RESPONDER,
    )?;
    let session = ComposeSession::new(context.docker, &intent.runtime, inputs.clone())?;
    checkpoint(Check::ResponderModel, || {
        responder_model(session.model(), &inputs, &configuration, port)
    })?;
    session.pull()?;
    let receipt = session.up_wait(state, RESPONDER_OPERATION, Duration::from_secs(60))?;
    checkpoint(Check::ResponderOperation, || {
        successful(&receipt, &inputs.project, &intent.runtime.engine_id)
    })?;
    inputs.prior = Some(receipt.clone());
    let prepared = Prepared {
        schema: "elevenid.installer-acme-host-prepared/v1".into(),
        installation_id: intent.installation_id,
        environment,
        evidence_sha256: state.with_inspection(|view| fingerprints(view, environment))?,
        projection,
        inputs,
        receipt,
        initial_setup_complete: true,
        activation_performed: false,
        installation_ready: false,
    };
    state.write_evidence(&name(environment, "prepared"), &encode(&prepared)?)?;
    // This readback is also the offline admission used by the continuation gate.
    state.with_inspection(|view| load_prepared(view).map(|_| ()))?;
    drive(
        context,
        state,
        &configuration,
        &intent,
        prepared,
        connection,
        providers,
        staging_roots,
    )
}

fn require_job(
    state: &LockedInspection,
    prepared: &Prepared,
    phase: &str,
    service: &str,
    plan_name: &str,
    image: &str,
) -> Result<()> {
    let job: Job = decode(&state.read_evidence(&name(prepared.environment, phase))?)?;
    require(
        job.schema == "elevenid.installer-acme-host-job/v1"
            && job.installation_id == prepared.installation_id
            && job.service == service
            && job.image == image
            && job.completed_successfully
            && job.container_name == format!("{}-{service}-1", prepared.inputs.project)
            && job.plan_sha256 == sha(&state.read_evidence(plan_name)?),
    )?;
    let evidence = fs::directory(&prepared.inputs.installation.join("evidence"), REFUSED)?;
    installer_jobs::previous_job(
        &prepared.inputs,
        &evidence,
        service,
        &job.container_id,
        &job.image,
        &job.compose_receipt_sha256,
    )
}

fn load_prepared(state: &LockedInspection) -> Result<(Intent, Prepared, BoundAcmeConfiguration)> {
    load_retained_setup(state, true)
}

/// Bind an initial order to the original completed host preparation. Historical
/// reads retain immutable setup/custody provenance after application storage has
/// changed; creating retry authority additionally requires pristine preparation.
pub(crate) fn initial_order_authority(
    state: &LockedInspection,
    binding: &crate::installer_acme_state::Binding,
    pristine: bool,
) -> Result<Option<crate::installer_acme_state::InitialAuthority>> {
    use crate::installer_acme_state::{InitialAuthority, IssuanceReason};
    use base64::Engine;

    if binding
        .renewal
        .as_ref()
        .is_some_and(|link| matches!(link.reason, IssuanceReason::SelectedGenerationDue { .. }))
    {
        return Ok(None);
    }
    let environment = binding.environment;
    let intent_bytes = state.diagnostic_record(&name(environment, "intent"), true)?;
    let prepared_bytes = state.diagnostic_record(&name(environment, "prepared"), true)?;
    let (intent_bytes, prepared_bytes) = match (intent_bytes, prepared_bytes) {
        (None, None) => return Ok(None),
        (Some(intent), Some(prepared)) => (intent, prepared),
        _ => return Err(REFUSED.into()),
    };
    if pristine {
        initial_rollover::before_application(state)?;
    }
    let (intent, _, configured) = load_retained_setup(state, pristine)?;
    let configuration = binding.configuration(state)?;
    let ingress = intent.ingress_key.bind(intent.installation_id)?;
    let custody_result: Value = decode(&state.read_evidence(&format!(
        "acme-custody-{}-result.json",
        environment.as_str()
    ))?)?;
    require(
        configured == configuration
            && custody_result["schema"] == "elevenid.installer-acme-custody-result/v1"
            && custody_result["account_key"] == binding.account_key
            && binding.ingress_key_name == ingress.transit_key_name()
            && binding.ingress_key_version == ingress.key_version()
            && binding.ingress_spki_base64
                == base64::engine::general_purpose::STANDARD.encode(ingress.public_spki_der())
            && binding.staging_roots_sha256 == intent.staging_roots_sha256,
    )?;
    let authority = InitialAuthority {
        host_intent_sha256: sha(&intent_bytes),
        host_prepared_sha256: sha(&prepared_bytes),
        initial_material_sha256: binding.initial_material_sha256()?,
    };
    authority.validate(binding)?;
    state.require_unchanged()?;
    Ok(Some(authority))
}

fn load_retained_setup(
    state: &LockedInspection,
    before_application_start: bool,
) -> Result<(Intent, Prepared, BoundAcmeConfiguration)> {
    inspect_retained_setup(state, before_application_start).map_err(Check::refusal)
}

/// The diagnostic and execution callers share every check and its ordering.
/// Only fixed codes cross this boundary; original inner errors stay private.
fn inspect_retained_setup(
    state: &LockedInspection,
    before_application_start: bool,
) -> Checked<(Intent, Prepared, BoundAcmeConfiguration)> {
    let configuration = checked(Check::Configuration, || {
        BoundAcmeConfiguration::from_selection(state)
    })?;
    let environment = configuration.parameters().environment();
    let prepared_bytes = checked(Check::PreparedRead, || {
        state.read_evidence(&name(environment, "prepared"))
    })?;
    let prepared: Prepared = checked(Check::PreparedDecode, || decode(&prepared_bytes))?;
    let intent_bytes = checked(Check::IntentRead, || {
        state.read_evidence(&name(environment, "intent"))
    })?;
    let intent: Intent = checked(Check::IntentDecode, || decode(&intent_bytes))?;
    checked(Check::InstallationPath, || {
        state.require_path_binding(&prepared.inputs.installation)
    })?;
    if before_application_start {
        checked(Check::ApplicationPreparation, || {
            crate::installer_acme_preparation::require_supported_scope(state)?;
            crate::installer_application::require_acme_preparation(
                state,
                &prepared.inputs.installation,
            )
        })?;
    } else {
        checked(Check::ApplicationProvenance, || {
            crate::installer_acme_preparation::verify_retained_provenance(
                state,
                &prepared.inputs.installation,
            )
        })?;
    }
    checked(Check::PublicRenewal, || {
        require(
            require_public_renewal(
                state,
                &prepared.inputs,
                &intent.infrastructure,
                &intent.services_image,
            )? == intent.public_renewal_enrolment_sha256,
        )
    })?;
    checked(Check::StagingTrust, || {
        let staging = state.diagnostic_record(STAGING_ROOTS, true)?;
        require(roots(environment, staging.as_deref())? == intent.staging_roots_sha256)
    })?;
    checked(Check::Schemas, || {
        require(
            prepared.schema == "elevenid.installer-acme-host-prepared/v1"
                && intent.schema == "elevenid.installer-acme-host-intent/v1",
        )
    })?;
    checked(Check::InstallationIdentity, || {
        require(
            prepared.installation_id == state.journal().installation_id()
                && intent.installation_id == prepared.installation_id,
        )
    })?;
    checked(Check::ConfigurationBinding, || {
        require(
            prepared.environment == environment && intent.configuration == value(&configuration)?,
        )
    })?;
    checked(Check::ReleaseRuntime, || {
        require(
            intent.release == *state.journal().identity()
                && Some(&intent.runtime) == state.journal().runtime()
                && intent.runtime.profile == RuntimeProfile::Rootless,
        )
    })?;
    checked(Check::PreparationState, || {
        require(
            prepared.initial_setup_complete
                && !prepared.activation_performed
                && !prepared.installation_ready,
        )
    })?;
    checked(Check::ServiceSelection, || {
        require(
            prepared.inputs.project == state.journal().compose_project()
                && prepared.inputs.services == [RESPONDER]
                && prepared.inputs.profiles == ["setup"]
                && prepared.inputs.installation == intent.bootstrap.installation,
        )
    })?;
    checked(Check::EnvironmentPath, || {
        require(
            prepared.inputs.environment.path
                == prepared
                    .inputs
                    .installation
                    .join("evidence")
                    .join(environment_name(environment, "responder")),
        )
    })?;
    checked(Check::EvidenceFingerprints, || {
        require(prepared.evidence_sha256 == fingerprints(state, environment)?)
    })?;
    checked(Check::ApplicationProofDigest, || {
        require(
            prepared
                .evidence_sha256
                .get(crate::installer_acme_preparation::RECORD)
                == Some(&intent.application_preparation_sha256),
        )
    })?;
    checked(Check::PriorReceipt, || {
        require(value(&prepared.inputs.prior)? == value(&Some(&prepared.receipt))?)
    })?;
    checked(Check::Projection, || {
        require(
            prepared.projection
                == ProjectionDirectory::observe(state, &prepared.inputs.installation)?,
        )
    })?;
    checked(Check::AuthorityDigests, || {
        require(
            hash_valid(&intent.operator_sha256)
                && hash_valid(&intent.openbao_ca_pem_sha256)
                && intent.staging_roots_sha256.is_some()
                    == (environment == AcmeEnvironment::Staging)
                && intent
                    .staging_roots_sha256
                    .as_deref()
                    .is_none_or(hash_valid),
        )
    })?;
    checked(Check::IngressKey, || {
        intent.ingress_key.bind(intent.installation_id)
    })?;
    checked(Check::BundleFiles, || {
        require(
            intent.bundle.starts_with(&prepared.inputs.installation)
                && intent.bundle.canonicalize().map_err(|_| REFUSED)? == intent.bundle
                && !intent.bootstrap.files.is_empty()
                && intent
                    .bootstrap
                    .files
                    .iter()
                    .all(|file| file.path.starts_with(&intent.bundle))
                && intent.bootstrap.project == prepared.inputs.project
                && intent.bootstrap.environment.path
                    == prepared
                        .inputs
                        .installation
                        .join("evidence")
                        .join(RENEWAL_ENVIRONMENT),
        )
    })?;
    checked(Check::OperatorBinding, || {
        require(
            crate::installer_verify::operator_digest(
                &prepared.inputs.installation.join("marty-deploy"),
            )? == intent.operator_sha256,
        )
    })?;
    checked(Check::PriorOperation, || {
        successful(
            &intent.prior,
            &prepared.inputs.project,
            &intent.runtime.engine_id,
        )
    })?;
    checked(Check::ResponderOperation, || {
        successful(
            &prepared.receipt,
            &prepared.inputs.project,
            &intent.runtime.engine_id,
        )
    })?;
    checked(Check::ResponderReceipt, || {
        require(
            prepared.receipt.operation == RESPONDER_OPERATION
                && installer_jobs::receipt_digest(&prepared.receipt)?
                    == sha(&state
                        .read_evidence(&format!("compose-{RESPONDER_OPERATION}-result.json"))?),
        )
    })?;
    checked(Check::CurrentInputReceipt, || {
        for file in prepared
            .inputs
            .files
            .iter()
            .chain([&prepared.inputs.environment])
            .chain(&prepared.inputs.bound_inputs)
        {
            require(prepared.receipt.input_files.get(&file.path) == Some(&file.sha256))?;
        }
        Ok(())
    })?;
    checked(Check::HistoricalInputReceipt, || {
        require(
            intent
                .prior
                .input_files
                .iter()
                .all(|(path, hash)| prepared.receipt.input_files.get(path) == Some(hash)),
        )
    })?;
    checked(Check::InputCustody, || {
        installer_compose::verify_input_files(
            &prepared.inputs.installation,
            &prepared.receipt.input_files,
        )
    })?;
    checked(Check::CustodyJob, || {
        require_job(
            state,
            &prepared,
            "custody",
            CUSTODY,
            CUSTODY_PLAN,
            &intent.services_image,
        )
    })?;
    checked(Check::CredentialsJob, || {
        require_job(
            state,
            &prepared,
            "credentials",
            CREDENTIALS,
            CREDENTIAL_PLAN,
            &intent.services_image,
        )
    })?;
    let port = checked(Check::Http01Port, || {
        installer_hosting::resolve(state)?
            .http01_host_port()
            .ok_or_else(|| REFUSED.into())
    })?;
    checked(Check::EnvironmentDerivation, || {
        let base_env = retained_environment(state, &intent.bootstrap)?;
        require(
            sha(&base_env) == intent.bootstrap.environment.sha256
                && state.read_evidence(&environment_name(environment, "responder"))?
                    == derived_environment(
                        &base_env,
                        &configuration,
                        port,
                        &sha(&state.read_evidence(CUSTODY_PLAN)?),
                        Some(&sha(&state.read_evidence(CREDENTIAL_PLAN)?)),
                    )?,
        )
    })?;
    checked(Check::ComposeLayers, || {
        let mut expected_files = intent.bootstrap.files.clone();
        let layer =
            crate::installer_tls_outputs::bundle_text(&intent.bundle, LAYER, 2 * 1024 * 1024)?;
        include_bound(
            &mut expected_files,
            BoundFile {
                path: intent.bundle.join(LAYER),
                sha256: sha(layer.as_bytes()),
            },
        )?;
        require(value(&prepared.inputs.files)? == value(&expected_files)?)
    })?;
    checked(Check::BoundInputs, || {
        let mut expected_bounds = intent.bootstrap.bound_inputs.clone();
        for filename in [
            Some(name(environment, "intent")),
            Some(crate::installer_acme_preparation::RECORD.into()),
            (environment == AcmeEnvironment::Staging).then(|| STAGING_ROOTS.into()),
            Some(CUSTODY_PLAN.into()),
            Some(CREDENTIAL_PLAN.into()),
        ]
        .into_iter()
        .flatten()
        {
            include_bound(
                &mut expected_bounds,
                BoundFile {
                    path: prepared
                        .inputs
                        .installation
                        .join("evidence")
                        .join(&filename),
                    sha256: sha(&state.read_evidence(&filename)?),
                },
            )?;
        }
        require(value(&prepared.inputs.bound_inputs)? == value(&expected_bounds)?)
    })?;
    checked(Check::RuntimeInputs, || {
        let mut readonly = intent.bootstrap.readonly_bind_roots.clone();
        readonly.insert(prepared.inputs.installation.join(PROJECTION));
        let mut writable = intent.bootstrap.writable_bind_roots.clone();
        for name in ["acme-custody-transfer", "acme-credentials-transfer"] {
            writable.insert(prepared.inputs.installation.join(name));
        }
        let mut loopback = intent.bootstrap.allowed_loopback_ports.clone();
        require(port != intent.runtime.openbao_port)?;
        loopback.insert(port);
        require(
            prepared.inputs.readonly_bind_roots == readonly
                && prepared.inputs.writable_bind_roots == writable
                && prepared.inputs.allowed_loopback_ports == loopback
                && prepared.inputs.approved_images == intent.bootstrap.approved_images
                && prepared.inputs.ingress_listener == intent.bootstrap.ingress_listener,
        )?;
        #[cfg(feature = "installer-development")]
        require(
            value(&prepared.inputs.development_image)?
                == value(&intent.bootstrap.development_image)?,
        )?;
        Ok(())
    })?;
    checked(Check::Resources, || {
        let resources = prepared.receipt.resources.as_ref().ok_or(REFUSED)?;
        require(
            resources
                .containers
                .get(RESPONDER)
                .is_some_and(|identity| !identity.setup && identity.image == intent.services_image)
                && intent.prior.resources.as_ref().is_some_and(|prior| {
                    prior
                        .containers
                        .iter()
                        .all(|(name, identity)| resources.containers.get(name) == Some(identity))
                        && prior
                            .networks
                            .iter()
                            .all(|(name, id)| resources.networks.get(name) == Some(id))
                        && prior.volumes.is_subset(&resources.volumes)
                }),
        )
    })?;
    checked(Check::Unchanged, || state.require_unchanged())?;
    Ok((intent, prepared, configuration))
}

/// Read-only local gate for the installer's narrow Provisioning continuation.
/// Live engine, images, all retained resources and current health are checked by
/// resume before authentication or a CA request. Partial setup returns false.
pub(crate) fn continuation_available(state: &LockedInspection) -> Result<bool> {
    let Some(hosting) = installer_hosting::load(state)? else {
        return Ok(false);
    };
    let Some(parameters) = hosting.acme_parameters() else {
        return Ok(false);
    };
    if state
        .diagnostic_record(&name(parameters.environment(), "prepared"), true)?
        .is_none()
    {
        return Ok(false);
    }
    load_prepared(state)?;
    Ok(true)
}

/// Read-only reconstruction for the command continuation path. Intent parsing
/// remains private to this module and grants no general setup replay capability.
pub(crate) fn continuation_context(state: &LockedInspection) -> Result<ContinuationContext> {
    let (intent, prepared, _) = load_prepared(state)?;
    Ok(ContinuationContext {
        bundle: intent.bundle,
        infrastructure: intent.infrastructure,
        services_image: intent.services_image,
        operator_sha256: intent.operator_sha256,
        compose_inputs: prepared.inputs,
    })
}

/// Historical setup context for the generation owner's maintenance capability.
/// This does not reconstruct any storage-creation or initial-root authority.
pub(crate) fn maintenance_context(state: &LockedInspection) -> Result<ContinuationContext> {
    let (intent, prepared, _) = load_retained_setup(state, false)?;
    Ok(ContinuationContext {
        bundle: intent.bundle,
        infrastructure: intent.infrastructure,
        services_image: intent.services_image,
        operator_sha256: intent.operator_sha256,
        compose_inputs: prepared.inputs,
    })
}

fn running(resources: &ProjectResources, statuses: &[Value]) -> Result<()> {
    require(statuses.len() == resources.containers.len())?;
    let mut seen = BTreeSet::new();
    for row in statuses {
        let role = row["Service"].as_str().ok_or(REFUSED)?;
        let identity = resources.containers.get(role).ok_or(REFUSED)?;
        require(seen.insert(role) && row["ID"] == identity.id)?;
        if identity.setup {
            require(
                row["State"] == "exited"
                    && row["ExitCode"] == 0
                    && identity
                        .setup_execution
                        .as_ref()
                        .is_some_and(|execution| execution.completed_without_restart),
            )?;
        } else {
            require(
                row["State"] == "running"
                    && (!identity.health_required || row["Health"] == "healthy"),
            )?;
        }
    }
    Ok(())
}

/// Continue a normal pending order only from the complete retained boundary.
/// Only existing runtime resources may be started; setup is never recreated.
pub fn resume(
    context: &HostInputs<'_>,
    state: &mut InstallerState,
    staging_roots: Option<&[u8]>,
) -> Result<AcmeHostOutcome> {
    let configuration = checkpoint(Check::Context, || current_context(context, state))?;
    let (intent, prepared, saved_configuration) = state.with_inspection(load_prepared)?;
    checkpoint(Check::ContinuationBinding, || {
        require(
            saved_configuration == configuration
                && intent.bundle == context.bundle
                && intent.services_image == context.services_image
                && intent.operator_sha256 == context.operator_sha256
                && value(&intent.infrastructure)? == value(context.infrastructure)?
                && roots(configuration.parameters().environment(), staging_roots)?
                    == intent.staging_roots_sha256,
        )
    })?;
    let session = ComposeSession::new(context.docker, &intent.runtime, prepared.inputs.clone())?;
    let port = state
        .with_inspection(installer_hosting::resolve)?
        .http01_host_port()
        .ok_or(REFUSED)?;
    checkpoint(Check::ResponderModel, || {
        responder_model(session.model(), &prepared.inputs, &configuration, port)
    })?;
    checkpoint(Check::RuntimeModel, || {
        require(session.configuration_sha256() == prepared.receipt.configuration_sha256)
    })?;
    let observed = checkpoint(Check::LiveResources, || {
        let observed = session.observe_resources()?;
        require(Some(&observed) == prepared.receipt.resources.as_ref())?;
        Ok(observed)
    })?;
    state.with_maintenance(|maintenance| {
        recovery::recover_runtime(context, maintenance, &prepared.inputs)
    })?;
    checkpoint(Check::RuntimeHealth, || {
        running(&observed, &session.status()?)
    })?;
    let connection = checkpoint(Check::OpenbaoConnection, || {
        let connection = connection(context, state, &prepared.inputs)?;
        require(
            connection.ca_sha256 == intent.openbao_ca_pem_sha256
                && connection.cluster == intent.server_cluster_id,
        )?;
        Ok(connection)
    })?;
    checkpoint(Check::OpenbaoServer, || require_server(&connection))?;
    let providers = state.with_inspection(|view| {
        credentials::restore(
            view,
            context.installation,
            &configuration,
            connection.bao.clone(),
        )
    })?;
    drive(
        context,
        state,
        &configuration,
        &intent,
        prepared,
        connection,
        providers,
        staging_roots,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "Keep retained preparation separate from freshly observed OpenBao and scoped credentials."
)]
fn drive(
    context: &HostInputs<'_>,
    state: &mut InstallerState,
    configuration: &BoundAcmeConfiguration,
    intent: &Intent,
    prepared: Prepared,
    connection: Connection,
    providers: CredentialProviders,
    staging_roots: Option<&[u8]>,
) -> Result<AcmeHostOutcome> {
    checkpoint(Check::StagingTrust, || {
        require(
            roots(configuration.parameters().environment(), staging_roots)?
                == intent.staging_roots_sha256,
        )
    })?;
    let runtime = checkpoint(Check::RuntimeContext, runtime)?;
    let (account, ingress) = runtime.block_on(async {
        Ok::<_, String>((
            providers.account_credentials().verified_key().await?,
            providers.csr().retained_key().await?,
        ))
    })?;
    checkpoint(Check::IngressKey, || {
        require(ingress == intent.ingress_key.bind(intent.installation_id)?)
    })?;
    let csr = match state
        .with_inspection(|view| installer_acme::retained_csr(view, configuration, &ingress))?
    {
        Some(csr) => csr,
        None => runtime.block_on(providers.csr().signed_csr())?,
    };
    drop(runtime);
    state.with_inspection(|view| {
        checkpoint(Check::Projection, || {
            require(
                prepared.projection == ProjectionDirectory::observe(view, context.installation)?,
            )
        })?;
        load_prepared(view).map(|_| ())
    })?;
    let inputs = EnrolmentInputs {
        installation: context.installation,
        configuration,
        account_key: &account,
        ingress_key: &ingress,
        csr: &csr,
        staging_roots_pem: staging_roots,
    };
    let enrolment = state.with_maintenance(|maintenance| {
        match initial_rollover::select(maintenance, configuration, &ingress)? {
            Some(permit) => installer_acme::run_initial_rollover_locked(
                maintenance,
                &inputs,
                connection.bao,
                providers.account(),
                &permit,
            ),
            None => installer_acme::run_locked(
                maintenance,
                &inputs,
                connection.bao,
                providers.account(),
            ),
        }
    })?;
    Ok(AcmeHostOutcome {
        compose_inputs: prepared.inputs,
        compose_receipt: prepared.receipt,
        ingress_key: ingress,
        enrolment,
    })
}

/// Issue or resume exactly the due cycle authorized by the selected generation.
/// Runtime recovery, account/CSR authentication and CA work use independent
/// scoped identities; no initial setup job or root authority is replayed.
pub(crate) fn renew_for_maintenance(
    context: &HostInputs<'_>,
    state: &mut crate::installer_state::LockedMaintenance,
    current_inputs: &ComposeInputs,
    permit: &crate::installer_generation_maintenance::RenewalPermit,
) -> Result<EnrolmentOutcome> {
    renew_with_authority(
        context,
        state,
        RenewalRuntime::Selected(current_inputs),
        permit,
    )
}

/// A stale generation attempt may leave an authenticated mixed native census.
/// Its typed baseline is runtime authority only; the renewal permit still binds
/// the real selected logical session and exact preceding certificate/order.
pub(crate) fn renew_for_generation_recovery(
    context: &HostInputs<'_>,
    state: &mut crate::installer_state::LockedMaintenance,
    baseline: &crate::installer_generation_maintenance::GenerationRecoveryBaseline,
    permit: &crate::installer_generation_maintenance::RenewalPermit,
) -> Result<EnrolmentOutcome> {
    renew_with_authority(context, state, RenewalRuntime::Recovery(baseline), permit)
}

enum RenewalRuntime<'a> {
    Selected(&'a ComposeInputs),
    Recovery(&'a crate::installer_generation_maintenance::GenerationRecoveryBaseline),
}
impl RenewalRuntime<'_> {
    fn inputs(&self) -> &ComposeInputs {
        match self {
            Self::Selected(inputs) => inputs,
            Self::Recovery(baseline) => baseline.inputs(),
        }
    }
    fn require_current(
        &self,
        context: &HostInputs<'_>,
        state: &LockedInspection,
        permit: &crate::installer_generation_maintenance::RenewalPermit,
        configuration: &BoundAcmeConfiguration,
        ingress: &RetainedIngressKey,
    ) -> Result<()> {
        match self {
            Self::Selected(inputs) => {
                permit.require_current(state, context.installation, inputs, configuration, ingress)
            }
            Self::Recovery(baseline) => {
                baseline.require_current(
                    state,
                    context.installation,
                    permit,
                    configuration,
                    ingress,
                )?;
                baseline.require_live(context.docker, state.journal().runtime().ok_or(REFUSED)?)
            }
        }
    }
}

fn renew_with_authority(
    context: &HostInputs<'_>,
    state: &mut crate::installer_state::LockedMaintenance,
    authority: RenewalRuntime<'_>,
    permit: &crate::installer_generation_maintenance::RenewalPermit,
) -> Result<EnrolmentOutcome> {
    let current_inputs = authority.inputs();
    let (intent, prepared, configuration) = load_retained_setup(state.inspection(), false)?;
    require(
        configuration.parameters().environment() == AcmeEnvironment::Production
            && intent.bundle == context.bundle
            && intent.services_image == context.services_image
            && intent.operator_sha256 == context.operator_sha256
            && value(&intent.infrastructure)? == value(context.infrastructure)?
            && current_inputs.installation == context.installation
            && prepared.projection
                == ProjectionDirectory::observe(state.inspection(), context.installation)?,
    )?;
    let retained_key = intent.ingress_key.bind(intent.installation_id)?;
    authority.require_current(
        context,
        state.inspection(),
        permit,
        &configuration,
        &retained_key,
    )?;
    recovery::recover_runtime(context, state, current_inputs)?;
    authority.require_current(
        context,
        state.inspection(),
        permit,
        &configuration,
        &retained_key,
    )?;
    let connection = connection_view(context, state.inspection(), current_inputs)?;
    require(
        connection.ca_sha256 == intent.openbao_ca_pem_sha256
            && connection.cluster == intent.server_cluster_id,
    )?;
    require_server(&connection)?;
    let providers = credentials::restore(
        state.inspection(),
        context.installation,
        &configuration,
        connection.bao.clone(),
    )?;
    let runtime = runtime()?;
    let (account, ingress) = runtime.block_on(async {
        Ok::<_, String>((
            providers.account_credentials().verified_key().await?,
            providers.csr().retained_key().await?,
        ))
    })?;
    require(ingress == retained_key)?;
    let csr = installer_acme::retained_csr_for_renewal(
        state.inspection(),
        &configuration,
        &ingress,
        permit,
    )?;
    drop(runtime);
    require(
        prepared.projection
            == ProjectionDirectory::observe(state.inspection(), context.installation)?,
    )?;
    authority.require_current(
        context,
        state.inspection(),
        permit,
        &configuration,
        &ingress,
    )?;
    installer_acme::run_renewal_locked(
        state,
        &EnrolmentInputs {
            installation: context.installation,
            configuration: &configuration,
            account_key: &account,
            ingress_key: &ingress,
            csr: &csr,
            staging_roots_pem: None,
        },
        connection.bao,
        providers.account(),
        permit,
    )
}

#[cfg(test)]
#[path = "installer_acme_host_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "installer_acme_host_boundary_tests.rs"]
mod boundary_tests;

#[path = "installer_acme_host_recovery.rs"]
mod recovery;
