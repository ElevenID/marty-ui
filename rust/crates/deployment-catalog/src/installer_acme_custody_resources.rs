//! Public plan and fixed-container transaction for initial ACME key custody.
//! The host owns its intent/flock; the helper consumes root only inside OpenBao's
//! owned setup container and returns public evidence, never initial authority.
use super::*;
use crate::{
    installer_acme_certificates::CertificateIdentity, installer_acme_configuration::AcmeParameters,
    installer_host_fs, installer_ingress_provision::IngressIdentity,
};
use marty_selfhost_identity::origin::PublicOrigin;
use serde::Deserialize;
use std::{
    collections::BTreeSet,
    ffi::CString,
    fs::File,
    io::Write,
    os::fd::{AsRawFd, FromRawFd},
    path::Path,
    time::Duration,
};

fn hash_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn cluster_valid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| id.to_string() == value && !id.is_nil())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    installation_id: uuid::Uuid,
    environment: AcmeEnvironment,
    intent_sha256: String,
    configuration_sha256: String,
    hosting_selection_sha256: String,
    canonical_origin: String,
    public_entry_origin: Option<String>,
    parameters: AcmeParameters,
    server_cluster_id: String,
    ingress_public_spki_der: Vec<u8>,
}

/// Validated public input for the fixed custody helper. Its digest must be
/// supplied from the host's independently retained setup evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CustodyResourcePlan(Plan);
impl CustodyResourcePlan {
    fn from_bound(
        configuration: &BoundAcmeConfiguration,
        ingress: &RetainedIngressKey,
        cluster: &str,
    ) -> Result<Self> {
        let intent = expected_intent(configuration, ingress)?;
        let plan = Self(Plan {
            schema: "elevenid.installer-acme-custody-resource-plan/v1".into(),
            installation_id: configuration.installation_id(),
            environment: configuration.parameters().environment(),
            intent_sha256: installer_release::sha256(&intent),
            configuration_sha256: configuration_digest(configuration)?,
            hosting_selection_sha256: configuration.hosting_selection_sha256().into(),
            canonical_origin: configuration.canonical_origin().into(),
            public_entry_origin: configuration.public_entry_origin().map(str::to_owned),
            parameters: configuration.parameters().clone(),
            server_cluster_id: cluster.into(),
            ingress_public_spki_der: ingress.public_spki_der().into(),
        });
        plan.validate()?;
        Ok(plan)
    }
    pub fn parse_authenticated(bytes: &[u8], expected_sha256: &str) -> Result<Self> {
        require(
            !bytes.is_empty()
                && bytes.len() <= 32 * 1024
                && hash_valid(expected_sha256)
                && installer_release::sha256(bytes) == expected_sha256,
        )?;
        let raw =
            serde_json::from_value(crate::installer_json::decode(bytes).map_err(|_| REFUSED)?)
                .map_err(|_| REFUSED)?;
        let plan = Self(raw);
        plan.validate()?;
        Ok(plan)
    }
    pub fn public_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(&serde_json::to_value(self).map_err(|_| REFUSED)?)
            .map_err(|_| REFUSED.into())
    }
    pub fn sha256(&self) -> Result<String> {
        Ok(installer_release::sha256(&self.public_bytes()?))
    }
    pub fn installation_id(&self) -> uuid::Uuid {
        self.0.installation_id
    }
    pub fn environment(&self) -> AcmeEnvironment {
        self.0.environment
    }
    fn validate(&self) -> Result<()> {
        require(
            self.0.schema == "elevenid.installer-acme-custody-resource-plan/v1"
                && !self.0.installation_id.is_nil()
                && cluster_valid(&self.0.server_cluster_id)
                && hash_valid(&self.0.intent_sha256)
                && hash_valid(&self.0.configuration_sha256)
                && hash_valid(&self.0.hosting_selection_sha256)
                && self.0.environment == self.0.parameters.environment(),
        )?;
        owner(&self.0.installation_id.to_string())?;
        require(
            AcmeParameters::parse(&serde_json::to_vec(&self.0.parameters).map_err(|_| REFUSED)?)?
                == self.0.parameters,
        )?;
        require(
            !self.0.ingress_public_spki_der.is_empty()
                && self.0.ingress_public_spki_der.len() <= 1024,
        )?;
        let public = marty_crypto::jwk::public_key_der_to_jwk(&self.0.ingress_public_spki_der)
            .map_err(|_| REFUSED)?;
        require(public.kty == "EC" && public.crv.as_deref() == Some("P-256"))?;
        self.identity()?;
        Ok(())
    }
    fn identity(&self) -> Result<CertificateIdentity> {
        let origin = PublicOrigin::parse(&self.0.canonical_origin).map_err(|_| REFUSED)?;
        require(
            origin.as_str() == self.0.canonical_origin
                && origin.as_str().starts_with("https://")
                && origin.dns_name().is_some()
                && !origin.is_loopback(),
        )?;
        origin.did_web_authority().map_err(|_| REFUSED)?;
        let ip = self
            .0
            .public_entry_origin
            .as_deref()
            .map(|value| {
                let entry = PublicOrigin::parse(value).map_err(|_| REFUSED)?;
                require(
                    entry.as_str() == value
                        && value.starts_with("https://")
                        && !entry.is_loopback(),
                )?;
                entry.ip_address().ok_or_else(|| REFUSED.to_owned())
            })
            .transpose()?;
        CertificateIdentity::from_ingress(&IngressIdentity::new(origin.dns_name(), ip)?)
    }
    fn ingress(&self, metadata: &Value) -> Result<RetainedIngressKey> {
        RetainedIngressKey::bind(
            &self.0.installation_id.to_string(),
            1,
            &self.0.ingress_public_spki_der,
            metadata,
        )
    }
    fn account_name(&self) -> Result<String> {
        account_resource_name(&self.0.installation_id.to_string(), self.0.environment)
    }
    fn csr_name(&self) -> Result<String> {
        csr_policy_name(&self.0.installation_id.to_string(), self.0.environment)
    }
    fn account_policy(&self) -> Result<String> {
        account_signer_policy(&self.0.installation_id.to_string(), self.0.environment)
    }
    fn csr_policy(&self, ingress: &RetainedIngressKey) -> Result<String> {
        ingress_csr_policy_for(&self.identity()?, ingress)
    }
}

fn expected_intent(
    configuration: &BoundAcmeConfiguration,
    ingress: &RetainedIngressKey,
) -> Result<Vec<u8>> {
    let id = configuration.installation_id().to_string();
    let environment = configuration.parameters().environment();
    serde_json::to_vec(&intent(
        configuration,
        ingress,
        &account_resource_name(&id, environment)?,
        &csr_policy_name(&id, environment)?,
        &account_signer_policy(&id, environment)?,
        &ingress_csr_policy(configuration, ingress)?,
    )?)
    .map_err(|_| REFUSED.into())
}
fn names(environment: AcmeEnvironment) -> (String, String, String, String) {
    let environment = environment.as_str();
    (
        format!("acme-custody-{environment}-intent.json"),
        format!("acme-custody-{environment}-plan.json"),
        format!("acme-custody-{environment}-public.json"),
        format!("acme-custody-{environment}-result.json"),
    )
}
async fn verified_cluster(bao: &OpenBaoHttp) -> Result<String> {
    let health = request(bao, Method::GET, "sys/health", None, None)
        .await
        .map_err(|_| REFUSED)?;
    let cluster = health["cluster_id"].as_str().ok_or(REFUSED)?;
    require(
        cluster_valid(cluster)
            && health["initialized"] == true
            && health["sealed"] == false
            && health["standby"] == false,
    )?;
    Ok(cluster.into())
}

/// Host preparation is root-free. The original writer retains its installation
/// lock and phase; the fixed helper starts only after both records are durable.
pub fn prepare_for_install(
    state: &mut InstallerState,
    configuration: &BoundAcmeConfiguration,
    ingress: &RetainedIngressKey,
    bao: &OpenBaoHttp,
) -> Result<CustodyResourcePlan> {
    state.require_live_phase(Phase::Provisioning)?;
    require(tokio::runtime::Handle::try_current().is_err())?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| REFUSED)?;
    state.with_maintenance(|state| {
        runtime.block_on(prepare_locked(state, configuration, ingress, bao))
    })
}
pub(crate) async fn prepare_locked(
    state: &mut LockedMaintenance,
    configuration: &BoundAcmeConfiguration,
    ingress: &RetainedIngressKey,
    bao: &OpenBaoHttp,
) -> Result<CustodyResourcePlan> {
    current_configuration(state, configuration)?;
    require(state.journal().phase() == Phase::Provisioning)?;
    let (intent_name, plan_name, public_name, result_name) =
        names(configuration.parameters().environment());
    for name in [&intent_name, &plan_name, &public_name, &result_name] {
        if state.read_evidence(name)?.is_some() {
            return Err(RECOVERY.into());
        }
    }
    let cluster = tokio::time::timeout(Duration::from_secs(6), verified_cluster(bao))
        .await
        .map_err(|_| REFUSED)??;
    let plan = CustodyResourcePlan::from_bound(configuration, ingress, &cluster)?;
    state.write_evidence_exclusive(&intent_name, &expected_intent(configuration, ingress)?)?;
    state.write_evidence_exclusive(&plan_name, &plan.public_bytes()?)?;
    current_configuration(state, configuration)?;
    Ok(plan)
}

const PUBLIC_FIELDS: &[&str] = &[
    "name",
    "type",
    "derived",
    "imported_key",
    "supports_signing",
    "exportable",
    "allow_plaintext_backup",
    "deletion_allowed",
    "soft_deleted",
    "auto_rotate_period",
    "latest_version",
];
fn public_metadata(source: &Value) -> Result<Value> {
    let mut metadata = serde_json::Map::new();
    for field in PUBLIC_FIELDS {
        let value = source.get(field).ok_or(REFUSED)?;
        require(match *field {
            "name" => value.as_str().is_some_and(|value| {
                value.len() <= 160 && value.bytes().all(|b| b.is_ascii_graphic())
            }),
            "type" => value == "ecdsa-p256",
            "auto_rotate_period" | "latest_version" => value.as_u64().is_some(),
            _ => value.as_bool().is_some(),
        })?;
        metadata.insert((*field).into(), value.clone());
    }
    let key = source["keys"]["1"]["public_key"].as_str().ok_or(REFUSED)?;
    require(key.is_ascii() && key.len() <= 2048 && !key.contains("PRIVATE KEY"))?;
    metadata.insert("keys".into(), json!({"1":{"public_key":key}}));
    Ok(Value::Object(metadata))
}
fn require_public_metadata(metadata: &Value) -> Result<()> {
    require(public_metadata(metadata)? == *metadata)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Output {
    schema: String,
    plan_sha256: String,
    account_metadata: Value,
    ingress_metadata: Value,
    account_policy: String,
    csr_policy: String,
    private_key_exported: bool,
    credentials_issued: bool,
    activation_performed: bool,
}
/// Public-only readback from the authenticated fixed helper. No private key,
/// root authority, RoleID, SecretID or workload token is contained in this type.
#[derive(Clone, Debug, Serialize)]
pub struct PublicCustodyOutput {
    plan: CustodyResourcePlan,
    output: Output,
}
impl PublicCustodyOutput {
    fn bind(plan: &CustodyResourcePlan, output: Output) -> Result<Self> {
        require(
            output.schema == "elevenid.installer-acme-custody-public/v1"
                && output.plan_sha256 == plan.sha256()?
                && !output.private_key_exported
                && !output.credentials_issued
                && !output.activation_performed,
        )?;
        require_public_metadata(&output.account_metadata)?;
        require_public_metadata(&output.ingress_metadata)?;
        let ingress = plan.ingress(&output.ingress_metadata)?;
        let account = AccountKeyBinding::bind(
            &plan.installation_id().to_string(),
            plan.environment(),
            1,
            &metadata_spki(&output.account_metadata)?,
            &output.account_metadata,
        )?;
        require(
            account.public_spki_der() != ingress.public_spki_der()
                && output.account_policy == plan.account_policy()?
                && output.csr_policy == plan.csr_policy(&ingress)?,
        )?;
        Ok(Self {
            plan: plan.clone(),
            output,
        })
    }
    fn custody(&self) -> Result<ProvisionedAcmeCustody> {
        let validated = Self::bind(&self.plan, self.output.clone())?;
        let account = AccountKeyBinding::bind(
            &validated.plan.installation_id().to_string(),
            validated.plan.environment(),
            1,
            &metadata_spki(&validated.output.account_metadata)?,
            &validated.output.account_metadata,
        )?;
        Ok(ProvisionedAcmeCustody {
            account_key: account,
            account_policy_name: self.plan.account_name()?,
            csr_policy_name: self.plan.csr_name()?,
        })
    }
    /// The fixed helper writes exactly these two public 0600 files to its empty
    /// 0700 output folder. The host separately authenticates that completed job.
    pub fn write_public_transfer(&self, destination: &Path) -> Result<()> {
        Self::bind(&self.plan, self.output.clone())?;
        let directory = installer_host_fs::directory(destination, REFUSED)?;
        require(installer_host_fs::file_names(&directory, REFUSED)?.is_empty())?;
        write_public(&directory, "plan.json", &self.plan.public_bytes()?)?;
        write_public(
            &directory,
            "custody.json",
            &serde_json::to_vec(&self.output).map_err(|_| REFUSED)?,
        )
    }
}
fn write_public(directory: &File, name: &str, bytes: &[u8]) -> Result<()> {
    require(
        !bytes.is_empty()
            && bytes.len() <= 65536
            && bytes.is_ascii()
            && !bytes.windows(11).any(|v| v == b"PRIVATE KEY"),
    )?;
    let name_c = CString::new(name).map_err(|_| REFUSED)?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name_c.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    require(fd >= 0)?;
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .and_then(|_| directory.sync_all())
        .map_err(|_| REFUSED)?;
    require(installer_host_fs::read_entry(directory, name, 0o600, false, REFUSED)? == bytes)
}

/// Fixed-container core: no host installation path, flock or receipt writer is
/// accepted here. A surviving setup intent prevents the host from replaying it.
pub async fn provision_resources(
    plan: &CustodyResourcePlan,
    bao: &OpenBaoHttp,
    initial_authority: &str,
) -> Result<PublicCustodyOutput> {
    plan.validate()?;
    require(
        (20..=4096).contains(&initial_authority.len())
            && initial_authority.bytes().all(|b| b.is_ascii_graphic()),
    )?;
    let lookup = request(
        bao,
        Method::GET,
        "auth/token/lookup-self",
        None,
        Some(initial_authority),
    )
    .await
    .map_err(|_| REFUSED)?;
    require(
        lookup["data"]["policies"] == json!(["root"])
            && verified_cluster(bao).await? == plan.0.server_cluster_id,
    )?;
    let ingress_name =
        crate::installer_ingress_provision::resource_name(&plan.installation_id().to_string())?;
    let ingress = plan.ingress(&metadata(bao, initial_authority, &ingress_name).await?)?;
    let account_name = plan.account_name()?;
    let csr_name = plan.csr_name()?;
    let account_policy = plan.account_policy()?;
    let csr_policy = plan.csr_policy(&ingress)?;
    for path in [
        format!("transit/keys/{account_name}"),
        format!("sys/policies/acl/{account_name}"),
        format!("sys/policies/acl/{csr_name}"),
    ] {
        require_absent(bao, initial_authority, &path).await?;
    }
    let outcome = async {
        request(bao, Method::POST, &format!("transit/keys/{account_name}"),
            Some(&json!({"type":"ecdsa-p256","derived":false,"exportable":false,"allow_plaintext_backup":false,"auto_rotate_period":0})), Some(initial_authority)).await.map_err(|_| REFUSED)?;
        let account_metadata = metadata(bao, initial_authority, &account_name).await?;
        let account = AccountKeyBinding::bind(&plan.installation_id().to_string(), plan.environment(), 1, &metadata_spki(&account_metadata)?, &account_metadata)?;
        require(account.public_spki_der() != ingress.public_spki_der())?;
        for (name, policy) in [(&account_name, &account_policy), (&csr_name, &csr_policy)] {
            request(bao, Method::PUT, &format!("sys/policies/acl/{name}"), Some(&json!({"policy":policy})), Some(initial_authority)).await.map_err(|_| REFUSED)?;
            require_policy(bao, initial_authority, name, policy).await?;
        }
        let account_metadata = metadata(bao, initial_authority, &account_name).await?;
        account.require_metadata(&account_metadata)?;
        let ingress_metadata = metadata(bao, initial_authority, &ingress_name).await?;
        ingress.require_metadata(&ingress_metadata)?;
        PublicCustodyOutput::bind(plan, Output { schema: "elevenid.installer-acme-custody-public/v1".into(), plan_sha256: plan.sha256()?,
            account_metadata: public_metadata(&account_metadata)?, ingress_metadata: public_metadata(&ingress_metadata)?, account_policy, csr_policy,
            private_key_exported: false, credentials_issued: false, activation_performed: false })
    }.await;
    outcome.map_err(|_| RECOVERY.into())
}

/// Host admission after the existing job/image/ownership checks and transfer.
/// This records authenticated helper observations; the credential owner later
/// rechecks actual live key/ACL metadata using scoped authority before use.
pub fn admit_for_install(
    state: &mut InstallerState,
    configuration: &BoundAcmeConfiguration,
    ingress: &RetainedIngressKey,
    plan: &CustodyResourcePlan,
    transferred: &Path,
) -> Result<ProvisionedAcmeCustody> {
    state.require_live_phase(Phase::Provisioning)?;
    state.with_maintenance(|state| admit_locked(state, configuration, ingress, plan, transferred))
}
pub(crate) fn admit_locked(
    state: &mut LockedMaintenance,
    configuration: &BoundAcmeConfiguration,
    ingress: &RetainedIngressKey,
    plan: &CustodyResourcePlan,
    transferred: &Path,
) -> Result<ProvisionedAcmeCustody> {
    current_configuration(state, configuration)?;
    require(
        state.journal().phase() == Phase::Provisioning
            && CustodyResourcePlan::from_bound(configuration, ingress, &plan.0.server_cluster_id)?
                == *plan,
    )?;
    let (intent_name, plan_name, public_name, result_name) = names(plan.environment());
    let saved_intent = state.read_evidence(&intent_name)?.ok_or(RECOVERY)?;
    require(
        saved_intent == expected_intent(configuration, ingress)?
            && installer_release::sha256(&saved_intent) == plan.0.intent_sha256
            && state.read_evidence(&plan_name)?.as_deref() == Some(plan.public_bytes()?.as_slice())
            && state.read_evidence(&public_name)?.is_none()
            && state.read_evidence(&result_name)?.is_none(),
    )?;
    let directory = installer_host_fs::directory(transferred, REFUSED)?;
    require(
        installer_host_fs::file_names(&directory, REFUSED)?
            == BTreeSet::from(["plan.json".into(), "custody.json".into()]),
    )?;
    require(
        installer_host_fs::read_entry(&directory, "plan.json", 0o600, false, REFUSED)?
            == plan.public_bytes()?,
    )?;
    let bytes = installer_host_fs::read_entry(&directory, "custody.json", 0o600, false, REFUSED)?;
    let raw: Output =
        serde_json::from_value(crate::installer_json::decode(&bytes).map_err(|_| REFUSED)?)
            .map_err(|_| REFUSED)?;
    let output = PublicCustodyOutput::bind(plan, raw)?;
    let custody = output.custody()?;
    state.write_evidence_exclusive(&public_name, &bytes)?;
    state.write_evidence_exclusive(
        &result_name,
        &serde_json::to_vec(&completion(&saved_intent, &custody)).map_err(|_| REFUSED)?,
    )?;
    current_configuration(state, configuration)?;
    Ok(custody)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLUSTER: &str = "ba4ea6d7-1a04-4575-a331-e1b0ea178426";

    #[test]
    fn helper_plan_preserves_host_intent_identity_and_exact_agreement() {
        let (_files, _state, config) = super::super::tests::fixture();
        let ingress = super::super::tests::fixture_ingress(&config);
        let plan = CustodyResourcePlan::from_bound(&config, &ingress, CLUSTER).unwrap();
        assert_eq!(
            plan.0.intent_sha256,
            installer_release::sha256(&expected_intent(&config, &ingress).unwrap())
        );
        assert_eq!(
            CustodyResourcePlan::parse_authenticated(
                &plan.public_bytes().unwrap(),
                &plan.sha256().unwrap()
            )
            .unwrap(),
            plan
        );
        assert!(CustodyResourcePlan::parse_authenticated(
            &plan.public_bytes().unwrap(),
            &"0".repeat(64)
        )
        .is_err());
        assert_eq!(
            plan.csr_policy(&ingress).unwrap(),
            ingress_csr_policy(&config, &ingress).unwrap()
        );
        for (field, value) in [
            ("canonical_origin", json!("https://198.51.100.7")),
            ("public_entry_origin", json!("https://foreign.example.com")),
            ("server_cluster_id", json!("bad")),
            ("policy_override", json!("root")),
            ("environment", json!("production")),
        ] {
            let mut raw = serde_json::to_value(&plan).unwrap();
            raw[field] = value;
            let bytes = serde_json::to_vec(&raw).unwrap();
            assert!(
                CustodyResourcePlan::parse_authenticated(
                    &bytes,
                    &installer_release::sha256(&bytes)
                )
                .is_err(),
                "{field}"
            );
        }
        let mut raw = serde_json::to_value(&plan).unwrap();
        raw["parameters"]["terms_agreed"] = json!(false);
        let bytes = serde_json::to_vec(&raw).unwrap();
        assert!(CustodyResourcePlan::parse_authenticated(
            &bytes,
            &installer_release::sha256(&bytes)
        )
        .is_err());
    }

    #[test]
    fn public_output_metadata_excludes_unrecognized_and_private_fields() {
        let mut source = json!({"name":"installer-key","type":"ecdsa-p256","derived":false,"imported_key":false,
            "supports_signing":true,"exportable":false,"allow_plaintext_backup":false,"deletion_allowed":false,
            "soft_deleted":false,"auto_rotate_period":0,"latest_version":1,
            "keys":{"1":{"public_key":"public-only-fixture","private_key":"must-never-transfer"}},"private_value":"must-never-transfer"});
        let clean = public_metadata(&source).unwrap();
        assert!(!clean.to_string().contains("must-never-transfer"));
        assert!(require_public_metadata(&source).is_err());
        require_public_metadata(&clean).unwrap();
        source["deletion_allowed"] = json!({"unexpected":"private-looking material"});
        assert!(public_metadata(&source).is_err());
    }
}
