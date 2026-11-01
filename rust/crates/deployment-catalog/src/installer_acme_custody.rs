//! Initial ACME account-key and narrow policy provisioning under the existing
//! installation lock. No credential issuance, CA request, key export or activation.
#![cfg(target_os = "linux")]

use crate::{
    installer_acme_certificates::{csr_template, RetainedIngressKey},
    installer_acme_configuration::{AcmeEnvironment, BoundAcmeConfiguration},
    installer_release,
    installer_state::{InstallerState, LockedMaintenance, Phase},
    operator,
    operator_http::{builder, request},
};
use marty_openbao_http::OpenBaoHttp;
use reqwest::{Method, StatusCode};
use serde::Serialize;
use serde_json::{json, Value};
use spki::{der::Decode, SubjectPublicKeyInfoOwned};

type Result<T> = std::result::Result<T, String>;
const REFUSED: &str = "ACME custody refused; preserve the environment-scoped key, policy and installation evidence. No private key export or credential issuance was attempted";
const RECOVERY: &str = "ACME custody setup is incomplete; preserve its intent and owned OpenBao resources for explicit recovery. Key creation must not be retried automatically";

#[path = "installer_acme_custody_resources.rs"]
mod resources;
pub use resources::{
    admit_for_install, prepare_for_install, provision_resources, CustodyResourcePlan,
    PublicCustodyOutput,
};
#[cfg(test)]
pub(crate) use resources::{admit_locked, prepare_locked};

fn require(value: bool) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}

fn owner(installation_id: &str) -> Result<uuid::Uuid> {
    crate::installer_ingress_provision::resource_name(installation_id).map_err(|_| REFUSED)?;
    uuid::Uuid::parse_str(installation_id).map_err(|_| REFUSED.into())
}
pub fn account_resource_name(
    installation_id: &str,
    environment: AcmeEnvironment,
) -> Result<String> {
    Ok(format!(
        "installer-acme-{}-account-{}",
        environment.as_str(),
        owner(installation_id)?.simple()
    ))
}
pub fn csr_policy_name(installation_id: &str, environment: AcmeEnvironment) -> Result<String> {
    Ok(format!(
        "installer-acme-{}-csr-{}",
        environment.as_str(),
        owner(installation_id)?.simple()
    ))
}

/// Public evidence for a distinct, environment-scoped, fixed-version account key.
/// Construction validates authenticated metadata against independently retained
/// SPKI. Initial creation below establishes that retained SPKI exactly once.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AccountKeyBinding {
    schema: &'static str,
    installation_id: uuid::Uuid,
    environment: AcmeEnvironment,
    transit_key_name: String,
    transit_key_version: u64,
    public_spki_der: Vec<u8>,
    public_sec1: Vec<u8>,
}
impl AccountKeyBinding {
    pub fn bind(
        installation_id: &str,
        environment: AcmeEnvironment,
        version: u64,
        retained_spki: &[u8],
        metadata: &Value,
    ) -> Result<Self> {
        let name = account_resource_name(installation_id, environment)?;
        require(
            version == 1
                && metadata["name"] == name
                && metadata["derived"] == false
                && metadata["imported_key"] == false
                && metadata["supports_signing"] == true
                && metadata["deletion_allowed"] == false
                && metadata["soft_deleted"] == false
                && metadata["auto_rotate_period"] == 0,
        )?;
        operator::version_one_custody(metadata, "ecdsa-p256").map_err(|_| REFUSED)?;
        let keys = metadata["keys"].as_object().ok_or(REFUSED)?;
        require(keys.len() == 1 && keys.contains_key("1"))?;
        let spki = metadata_spki(metadata)?;
        require(spki == retained_spki && spki.len() <= 1024)?;
        let public = marty_crypto::jwk::public_key_der_to_jwk(&spki).map_err(|_| REFUSED)?;
        require(public.kty == "EC" && public.crv.as_deref() == Some("P-256"))?;
        let parsed = SubjectPublicKeyInfoOwned::from_der(&spki).map_err(|_| REFUSED)?;
        let sec1 = parsed.subject_public_key.as_bytes().ok_or(REFUSED)?;
        require(sec1.len() == 65 && sec1[0] == 4)?;
        Ok(Self {
            schema: "elevenid.installer-acme-account-key/v1",
            installation_id: owner(installation_id)?,
            environment,
            transit_key_name: name,
            transit_key_version: version,
            public_spki_der: spki,
            public_sec1: sec1.to_vec(),
        })
    }
    pub fn installation_id(&self) -> uuid::Uuid {
        self.installation_id
    }
    pub fn environment(&self) -> AcmeEnvironment {
        self.environment
    }
    pub fn transit_key_name(&self) -> &str {
        &self.transit_key_name
    }
    pub fn key_version(&self) -> u64 {
        self.transit_key_version
    }
    pub fn public_spki_der(&self) -> &[u8] {
        &self.public_spki_der
    }
    pub fn public_sec1(&self) -> &[u8] {
        &self.public_sec1
    }
    pub fn binding_metadata(&self) -> Value {
        json!(self)
    }
    pub fn require_metadata(&self, metadata: &Value) -> Result<()> {
        require(
            Self::bind(
                &self.installation_id.to_string(),
                self.environment,
                self.transit_key_version,
                &self.public_spki_der,
                metadata,
            )? == *self,
        )
    }
}

fn metadata_spki(metadata: &Value) -> Result<Vec<u8>> {
    let pem = metadata["keys"]["1"]["public_key"]
        .as_str()
        .filter(|pem| pem.len() <= 2048)
        .ok_or(REFUSED)?;
    operator::public_spki(pem.as_bytes(), false).map_err(|_| REFUSED.into())
}

/// This policy cannot read keys, create CSRs, use the ingress signer, rotate or
/// export. A credential owner must grant this policy alone with no default policy.
pub fn account_signer_policy(
    installation_id: &str,
    environment: AcmeEnvironment,
) -> Result<String> {
    let name = account_resource_name(installation_id, environment)?;
    Ok(format!(
        "path \"transit/sign/{name}\" {{\n  capabilities = [\"update\"]\n  required_parameters = [\"input\", \"key_version\", \"prehashed\", \"hash_algorithm\", \"marshaling_algorithm\"]\n  allowed_parameters = {{\n    \"input\" = []\n    \"key_version\" = [\"1\"]\n    \"prehashed\" = [false]\n    \"hash_algorithm\" = [\"sha2-256\"]\n    \"marshaling_algorithm\" = [\"jws\"]\n  }}\n}}\n"
    ))
}

/// CSR authority is pinned to the exact public template and original ingress
/// key version. It cannot make arbitrary signatures or change requested names.
pub fn ingress_csr_policy(
    configuration: &BoundAcmeConfiguration,
    ingress: &RetainedIngressKey,
) -> Result<String> {
    require(
        ingress.transit_key_name()
            == crate::installer_ingress_provision::resource_name(
                &configuration.installation_id().to_string(),
            )?
            && ingress.key_version() == 1,
    )?;
    ingress_csr_policy_for(&configuration.certificate_identity()?, ingress)
}

pub(crate) fn ingress_csr_policy_for(
    identity: &crate::installer_acme_certificates::CertificateIdentity,
    ingress: &RetainedIngressKey,
) -> Result<String> {
    let template = csr_template(identity, ingress)?;
    let quoted = serde_json::to_string(&template).map_err(|_| REFUSED)?;
    let name = ingress.transit_key_name();
    Ok(format!(
        "path \"transit/keys/{name}\" {{ capabilities = [\"read\"] }}\npath \"transit/keys/{name}/csr\" {{\n  capabilities = [\"update\"]\n  required_parameters = [\"version\", \"csr\"]\n  allowed_parameters = {{\n    \"version\" = [\"1\"]\n    \"csr\" = [{quoted}]\n  }}\n}}\n"
    ))
}

#[derive(Clone, Debug)]
pub struct ProvisionedAcmeCustody {
    account_key: AccountKeyBinding,
    account_policy_name: String,
    csr_policy_name: String,
}
impl ProvisionedAcmeCustody {
    pub fn account_key(&self) -> &AccountKeyBinding {
        &self.account_key
    }
    pub fn account_policy_name(&self) -> &str {
        &self.account_policy_name
    }
    pub fn csr_policy_name(&self) -> &str {
        &self.csr_policy_name
    }
}

fn configuration_digest(configuration: &BoundAcmeConfiguration) -> Result<String> {
    Ok(installer_release::sha256(
        &serde_json::to_vec(configuration).map_err(|_| REFUSED)?,
    ))
}
fn current_configuration(
    state: &LockedMaintenance,
    configuration: &BoundAcmeConfiguration,
) -> Result<()> {
    require(
        BoundAcmeConfiguration::bind(state.inspection(), configuration.parameters().clone())?
            == *configuration,
    )
}
fn intent(
    configuration: &BoundAcmeConfiguration,
    ingress: &RetainedIngressKey,
    account_name: &str,
    csr_name: &str,
    account_policy: &str,
    csr_policy: &str,
) -> Result<Value> {
    Ok(
        json!({"schema":"elevenid.installer-acme-custody-intent/v1", "installation_id":configuration.installation_id(),
        "environment":configuration.parameters().environment(), "configuration_sha256":configuration_digest(configuration)?,
        "configuration":configuration, "account_key_name":account_name, "account_policy_name":account_name,
        "csr_policy_name":csr_name, "account_policy_sha256":installer_release::sha256(account_policy.as_bytes()),
        "csr_policy_sha256":installer_release::sha256(csr_policy.as_bytes()),
        "ingress_key_name":ingress.transit_key_name(), "ingress_key_version":ingress.key_version(),
        "ingress_public_spki_sha256":installer_release::sha256(ingress.public_spki_der()),
        "private_key_exported":false, "credentials_issued":false, "activation_performed":false}),
    )
}
fn completion(intent: &[u8], custody: &ProvisionedAcmeCustody) -> Value {
    json!({"schema":"elevenid.installer-acme-custody-result/v1", "intent_sha256":installer_release::sha256(intent),
        "account_key":custody.account_key.binding_metadata(), "account_policy_name":custody.account_policy_name,
        "csr_policy_name":custody.csr_policy_name, "key_and_policies_verified":true,
        "private_key_exported":false,"credentials_issued":false,"activation_performed":false,"installation_ready":false})
}
async fn metadata(bao: &OpenBaoHttp, authority: &str, name: &str) -> Result<Value> {
    let response = request(
        bao,
        Method::GET,
        &format!("transit/keys/{name}"),
        None,
        Some(authority),
    )
    .await
    .map_err(|_| REFUSED)?;
    Ok(response["data"].clone())
}
async fn require_policy(
    bao: &OpenBaoHttp,
    authority: &str,
    name: &str,
    policy: &str,
) -> Result<()> {
    let response = request(
        bao,
        Method::GET,
        &format!("sys/policies/acl/{name}"),
        None,
        Some(authority),
    )
    .await
    .map_err(|_| REFUSED)?;
    require(response["data"]["policy"] == policy)
}
async fn require_absent(bao: &OpenBaoHttp, authority: &str, path: &str) -> Result<()> {
    let response = builder(bao, Method::GET, path, None, Some(authority))
        .send()
        .await
        .map_err(|_| REFUSED)?;
    require(response.status() == StatusCode::NOT_FOUND)
}

/// First-install entry point under the original writer's lock. This preserves
/// the Provisioning phase, creates no credentials and never retries a mutation.
/// The synchronous native installer calls this outside an async runtime.
pub fn provision_for_install(
    state: &mut InstallerState,
    configuration: &BoundAcmeConfiguration,
    ingress: &RetainedIngressKey,
    bao: &OpenBaoHttp,
    initial_authority: &str,
) -> Result<ProvisionedAcmeCustody> {
    state.require_live_phase(Phase::Provisioning)?;
    require(tokio::runtime::Handle::try_current().is_err())?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| REFUSED)?;
    state.with_maintenance(|view| {
        runtime.block_on(provision_initial(
            view,
            configuration,
            ingress,
            bao,
            initial_authority,
        ))
    })
}

/// The caller supplies the already-authenticated installation lock and initial
/// provisioning authority. The public intent is durable before any remote write.
/// A surviving intent without completion is never replayed. Completed custody
/// is usable only after readback of its exact retained key and policy content.
pub(crate) async fn provision_initial(
    state: &mut LockedMaintenance,
    configuration: &BoundAcmeConfiguration,
    ingress: &RetainedIngressKey,
    bao: &OpenBaoHttp,
    authority: &str,
) -> Result<ProvisionedAcmeCustody> {
    current_configuration(state, configuration)?;
    require(
        (20..=4096).contains(&authority.len())
            && authority.bytes().all(|byte| byte.is_ascii_graphic()),
    )?;
    let installation_id = configuration.installation_id().to_string();
    let environment = configuration.parameters().environment();
    let account_name = account_resource_name(&installation_id, environment)?;
    let csr_name = csr_policy_name(&installation_id, environment)?;
    let account_policy = account_signer_policy(&installation_id, environment)?;
    let csr_policy = ingress_csr_policy(configuration, ingress)?;
    let expected = serde_json::to_vec(&intent(
        configuration,
        ingress,
        &account_name,
        &csr_name,
        &account_policy,
        &csr_policy,
    )?)
    .map_err(|_| REFUSED)?;
    let intent_name = format!("acme-custody-{}-intent.json", environment.as_str());
    let result_name = format!("acme-custody-{}-result.json", environment.as_str());
    let saved_intent = state.read_evidence(&intent_name)?;
    let saved_result = state.read_evidence(&result_name)?;
    match (&saved_intent, &saved_result) {
        (None, None) => {}
        (Some(record), Some(result)) => require(*record == expected && result.len() <= 65536)?,
        (Some(_), None) => return Err(RECOVERY.into()),
        (None, Some(_)) => return Err(REFUSED.into()),
    }
    let authority_info = request(
        bao,
        Method::GET,
        "auth/token/lookup-self",
        None,
        Some(authority),
    )
    .await
    .map_err(|_| REFUSED)?;
    require(authority_info["data"]["policies"] == json!(["root"]))?;
    ingress.require_metadata(&metadata(bao, authority, ingress.transit_key_name()).await?)?;
    if let Some(saved) = saved_result {
        let saved = crate::installer_json::decode(&saved).map_err(|_| REFUSED)?;
        let retained: Vec<u8> =
            serde_json::from_value(saved["account_key"]["public_spki_der"].clone())
                .map_err(|_| REFUSED)?;
        require(!retained.is_empty() && retained.len() <= 1024)?;
        let account = AccountKeyBinding::bind(
            &installation_id,
            environment,
            1,
            &retained,
            &metadata(bao, authority, &account_name).await?,
        )?;
        require(account.public_spki_der() != ingress.public_spki_der())?;
        require_policy(bao, authority, &account_name, &account_policy).await?;
        require_policy(bao, authority, &csr_name, &csr_policy).await?;
        let result = ProvisionedAcmeCustody {
            account_key: account,
            account_policy_name: account_name,
            csr_policy_name: csr_name,
        };
        require(completion(&expected, &result) == saved)?;
        current_configuration(state, configuration)?;
        return Ok(result);
    }
    for path in [
        format!("transit/keys/{account_name}"),
        format!("sys/policies/acl/{account_name}"),
        format!("sys/policies/acl/{csr_name}"),
    ] {
        require_absent(bao, authority, &path).await?;
    }
    state.write_evidence_exclusive(&intent_name, &expected)?;
    let outcome: Result<ProvisionedAcmeCustody> = async {
        current_configuration(state, configuration)?;
        request(bao, Method::POST, &format!("transit/keys/{account_name}"),
            Some(&json!({"type":"ecdsa-p256","derived":false,"exportable":false,"allow_plaintext_backup":false,"auto_rotate_period":0})), Some(authority))
            .await.map_err(|_| REFUSED)?;
        let observed = metadata(bao, authority, &account_name).await?;
        let account = AccountKeyBinding::bind(&installation_id, environment, 1, &metadata_spki(&observed)?, &observed)?;
        require(account.public_spki_der() != ingress.public_spki_der())?;
        for (name, policy) in [(&account_name, &account_policy), (&csr_name, &csr_policy)] {
            request(bao, Method::PUT, &format!("sys/policies/acl/{name}"), Some(&json!({"policy":policy})), Some(authority))
                .await.map_err(|_| REFUSED)?;
            require_policy(bao, authority, name, policy).await?;
        }
        account.require_metadata(&metadata(bao, authority, &account_name).await?)?;
        ingress.require_metadata(&metadata(bao, authority, ingress.transit_key_name()).await?)?;
        current_configuration(state, configuration)?;
        let result = ProvisionedAcmeCustody { account_key: account, account_policy_name: account_name, csr_policy_name: csr_name };
        state.write_evidence_exclusive(&result_name, &serde_json::to_vec(&completion(&expected, &result)).map_err(|_| REFUSED)?)?;
        Ok(result)
    }.await;
    outcome.map_err(|_| RECOVERY.into())
}

#[cfg(test)]
#[path = "installer_acme_custody_tests.rs"]
mod tests;
