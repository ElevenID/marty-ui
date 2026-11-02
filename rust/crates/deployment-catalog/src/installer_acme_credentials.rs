//! Separate durable ACME account/CSR identities and bounded runtime credentials.
//! Initial resource creation is a one-shot setup transaction. Routine AppRole
//! authentication may recover with recorded uncertainty and server-time backoff.
#![cfg(target_os = "linux")]

use crate::{
    installer_acme_certificates::{
        csr_template, validate_signed_csr, CertificateIdentity, RetainedIngressKey, ValidatedCsr,
    },
    installer_acme_configuration::{AcmeEnvironment, BoundAcmeConfiguration},
    installer_acme_custody::{
        account_resource_name, account_signer_policy, csr_policy_name, AccountKeyBinding,
    },
    installer_host_fs,
    installer_ingress_provision::IngressIdentity,
    installer_release,
    installer_state::{InstallerState, LockedInspection, LockedMaintenance, Phase},
    operator_http::{builder, request},
};
use async_trait::async_trait;
use marty_acme_client::{protocol::Error as AcmeError, WorkloadCredentials};
use marty_openbao_http::OpenBaoHttp;
use marty_selfhost_identity::origin::PublicOrigin;
use reqwest::{header::HeaderValue, Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::BTreeSet, path::Path, sync::Arc, time::Duration};

#[path = "installer_acme_credentials_store.rs"]
mod store;

type Result<T> = std::result::Result<T, String>;
const REFUSED: &str = "ACME credentials refused; preserve the environment-scoped identity and public setup/refresh evidence. No policy, role or identity repair was attempted";
const SETUP_HOLD: &str = "ACME credential setup is incomplete; preserve the original setup intent and outputs for explicit recovery. Resource and SecretID creation must not be replayed";
const AUTH_UNAVAILABLE: &str = "ACME scoped authentication unavailable; its bounded attempt and retry state are retained without credentials or backend response details";
const BACKOFF: &str = "ACME scoped authentication is in recorded backoff; retry after the retained OpenBao server-time deadline";
const REFRESH_BUDGET: Duration = Duration::from_secs(6);
const OPERATION_BUDGET: Duration = Duration::from_secs(4);
const OWNER_TTL: u64 = 60;
const LEAF_TTL: u64 = 300;

fn require(value: bool) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}
fn digest(value: &impl Serialize) -> Result<String> {
    Ok(installer_release::sha256(
        &serde_json::to_vec(value).map_err(|_| REFUSED)?,
    ))
}
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn uuid_text(value: &str) -> Result<uuid::Uuid> {
    let id = uuid::Uuid::parse_str(value).map_err(|_| REFUSED)?;
    require(id.to_string() == value && !id.is_nil())?;
    Ok(id)
}
fn empty(value: &Value) -> bool {
    value.is_null() || value.as_array().is_some_and(Vec::is_empty)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Purpose {
    Account,
    Csr,
}
impl Purpose {
    fn name(self) -> &'static str {
        match self {
            Self::Account => "account",
            Self::Csr => "csr",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanData {
    schema: String,
    installation_id: uuid::Uuid,
    environment: AcmeEnvironment,
    configuration_sha256: String,
    hosting_selection_sha256: String,
    canonical_origin: String,
    public_entry_origin: Option<String>,
    server_cluster_id: String,
    account_public_spki_der: Vec<u8>,
    ingress_public_spki_der: Vec<u8>,
}

/// Public setup input for a fixed bootstrap helper. Construction on the host is
/// journal-bound; transferred bytes must match the host's separately retained
/// intent digest. This type contains no initial authority or private credential.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CredentialResourcePlan(PlanData);
impl CredentialResourcePlan {
    fn from_bound(
        configuration: &BoundAcmeConfiguration,
        account: &AccountKeyBinding,
        ingress: &RetainedIngressKey,
        cluster: &str,
    ) -> Result<Self> {
        let id = configuration.installation_id();
        require(
            account.installation_id() == id
                && account.environment() == configuration.parameters().environment()
                && account.key_version() == 1
                && ingress.key_version() == 1
                && ingress.transit_key_name()
                    == crate::installer_ingress_provision::resource_name(&id.to_string())?,
        )?;
        let plan = Self(PlanData {
            schema: "elevenid.installer-acme-credential-plan/v1".into(),
            installation_id: id,
            environment: configuration.parameters().environment(),
            configuration_sha256: digest(configuration)?,
            hosting_selection_sha256: configuration.hosting_selection_sha256().into(),
            canonical_origin: configuration.canonical_origin().into(),
            public_entry_origin: configuration.public_entry_origin().map(str::to_owned),
            server_cluster_id: cluster.into(),
            account_public_spki_der: account.public_spki_der().into(),
            ingress_public_spki_der: ingress.public_spki_der().into(),
        });
        plan.validate()?;
        Ok(plan)
    }
    /// `expected_sha256` must come from the authenticated, immutable host setup
    /// intent, never from the same untrusted input file. No host flock is needed
    /// inside the container helper. Every resource name and ACL is derived here.
    pub fn parse_authenticated(bytes: &[u8], expected_sha256: &str) -> Result<Self> {
        require(
            !bytes.is_empty()
                && bytes.len() <= 32 * 1024
                && valid_digest(expected_sha256)
                && installer_release::sha256(bytes) == expected_sha256,
        )?;
        let data =
            serde_json::from_value(crate::installer_json::decode(bytes).map_err(|_| REFUSED)?)
                .map_err(|_| REFUSED)?;
        let plan = Self(data);
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
            self.0.schema == "elevenid.installer-acme-credential-plan/v1"
                && !self.0.installation_id.is_nil()
                && valid_digest(&self.0.configuration_sha256)
                && valid_digest(&self.0.hosting_selection_sha256)
                && self.0.account_public_spki_der != self.0.ingress_public_spki_der,
        )?;
        uuid_text(&self.0.server_cluster_id)?;
        account_resource_name(&self.0.installation_id.to_string(), self.0.environment)?;
        for der in [
            &self.0.account_public_spki_der,
            &self.0.ingress_public_spki_der,
        ] {
            require(!der.is_empty() && der.len() <= 1024)?;
            let key = marty_crypto::jwk::public_key_der_to_jwk(der).map_err(|_| REFUSED)?;
            require(key.kty == "EC" && key.crv.as_deref() == Some("P-256"))?;
        }
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
                let origin = PublicOrigin::parse(value).map_err(|_| REFUSED)?;
                require(
                    origin.as_str() == value
                        && value.starts_with("https://")
                        && !origin.is_loopback(),
                )?;
                origin.ip_address().ok_or_else(|| REFUSED.to_owned())
            })
            .transpose()?;
        CertificateIdentity::from_ingress(&IngressIdentity::new(origin.dns_name(), ip)?)
    }
    fn require_configuration(
        &self,
        state: &LockedInspection,
        configuration: &BoundAcmeConfiguration,
    ) -> Result<()> {
        require(
            BoundAcmeConfiguration::bind(state, configuration.parameters().clone())?
                == *configuration
                && self.0.installation_id == configuration.installation_id()
                && self.0.environment == configuration.parameters().environment()
                && self.0.configuration_sha256 == digest(configuration)?
                && self.0.hosting_selection_sha256 == configuration.hosting_selection_sha256()
                && self.0.canonical_origin == configuration.canonical_origin()
                && self.0.public_entry_origin.as_deref() == configuration.public_entry_origin(),
        )?;
        self.validate()
    }
    fn mount(&self) -> String {
        format!(
            "installer-acme-{}-{}",
            self.0.environment.as_str(),
            self.0.installation_id.simple()
        )
    }
    fn directory(&self) -> String {
        format!("acme-credentials-{}", self.0.environment.as_str())
    }
    fn key_name(&self, purpose: Purpose) -> Result<String> {
        match purpose {
            Purpose::Account => {
                account_resource_name(&self.0.installation_id.to_string(), self.0.environment)
            }
            Purpose::Csr => crate::installer_ingress_provision::resource_name(
                &self.0.installation_id.to_string(),
            ),
        }
    }
    fn spec(&self, purpose: Purpose) -> Result<Spec> {
        let base = format!(
            "installer-acme-{}-{}",
            self.0.environment.as_str(),
            purpose.name()
        );
        Ok(Spec {
            mount: self.mount(),
            owner_role: format!("{}-owner", purpose.name()),
            owner_policy: format!("{base}-owner-{}", self.0.installation_id.simple()),
            leaf_role: format!("{base}-leaf-{}", self.0.installation_id.simple()),
            leaf_policy: match purpose {
                Purpose::Account => {
                    account_resource_name(&self.0.installation_id.to_string(), self.0.environment)?
                }
                Purpose::Csr => {
                    csr_policy_name(&self.0.installation_id.to_string(), self.0.environment)?
                }
            },
            key_name: self.key_name(purpose)?,
        })
    }
    fn account(&self, metadata: &Value) -> Result<AccountKeyBinding> {
        AccountKeyBinding::bind(
            &self.0.installation_id.to_string(),
            self.0.environment,
            1,
            &self.0.account_public_spki_der,
            metadata,
        )
    }
    fn ingress(&self, metadata: &Value) -> Result<RetainedIngressKey> {
        RetainedIngressKey::bind(
            &self.0.installation_id.to_string(),
            1,
            &self.0.ingress_public_spki_der,
            metadata,
        )
    }
    fn leaf_policy(&self, purpose: Purpose, key_metadata: &Value) -> Result<String> {
        match purpose {
            Purpose::Account => {
                self.account(key_metadata)?;
                account_signer_policy(&self.0.installation_id.to_string(), self.0.environment)
            }
            Purpose::Csr => {
                let key = self.ingress(key_metadata)?;
                let template = serde_json::to_string(&csr_template(&self.identity()?, &key)?)
                    .map_err(|_| REFUSED)?;
                let name = key.transit_key_name();
                Ok(format!("path \"transit/keys/{name}\" {{ capabilities = [\"read\"] }}\npath \"transit/keys/{name}/csr\" {{\n  capabilities = [\"update\"]\n  required_parameters = [\"version\", \"csr\"]\n  allowed_parameters = {{\n    \"version\" = [\"1\"]\n    \"csr\" = [{template}]\n  }}\n}}\n"))
            }
        }
    }
}

struct Spec {
    mount: String,
    owner_role: String,
    owner_policy: String,
    leaf_role: String,
    leaf_policy: String,
    key_name: String,
}
impl Spec {
    fn role_path(&self) -> String {
        format!("auth/{}/role/{}", self.mount, self.owner_role)
    }
    fn owner_policy(&self) -> String {
        let mut policy = [
            self.role_path(),
            format!("{}/role-id", self.role_path()),
            format!("sys/policies/acl/{}", self.owner_policy),
            format!("sys/policies/acl/{}", self.leaf_policy),
            format!("auth/token/roles/{}", self.leaf_role),
            format!("transit/keys/{}", self.key_name),
            "auth/token/lookup-self".into(),
        ]
        .into_iter()
        .map(|path| format!("path \"{path}\" {{ capabilities = [\"read\"] }}\n"))
        .collect::<String>();
        policy.push_str("path \"auth/token/revoke-self\" { capabilities = [\"update\"] }\npath \"auth/token/lookup\" {\n  capabilities = [\"update\"]\n  required_parameters = [\"token\"]\n  allowed_parameters = { \"token\" = [] }\n}\n");
        policy.push_str(&format!("path \"auth/token/create/{}\" {{\n  capabilities = [\"update\"]\n  required_parameters = [\"policies\", \"ttl\", \"explicit_max_ttl\", \"renewable\", \"no_default_policy\"]\n  allowed_parameters = {{\n    \"policies\" = [\"{}\"]\n    \"ttl\" = [\"5m\"]\n    \"explicit_max_ttl\" = [\"5m\"]\n    \"renewable\" = [false]\n    \"no_default_policy\" = [true]\n  }}\n}}\n", self.leaf_role, self.leaf_policy));
        policy
    }
    fn owner_role_body(&self) -> Value {
        json!({"bind_secret_id":true,"secret_id_num_uses":0,"secret_id_ttl":0,"local_secret_ids":false,
            "secret_id_bound_cidrs":[],"token_bound_cidrs":[],"token_policies":[self.owner_policy],
            "token_no_default_policy":true,"token_type":"service","token_num_uses":0,"token_period":0,
            "token_ttl":OWNER_TTL,"token_max_ttl":OWNER_TTL,"token_explicit_max_ttl":OWNER_TTL})
    }
    fn leaf_role_body(&self) -> Value {
        // OpenBao 2.5 token roles support explicit max TTL, not token_ttl or
        // token_max_ttl. Exact TTL is also pinned by the mint ACL and body.
        json!({"allowed_policies":[self.leaf_policy],"disallowed_policies":["default","root"],
            "allowed_policies_glob":[],"disallowed_policies_glob":[],"allowed_entity_aliases":[],
            "orphan":true,"renewable":false,"token_no_default_policy":true,"token_type":"service",
            "token_explicit_max_ttl":LEAF_TTL,"token_period":0,"token_num_uses":0,
            "token_bound_cidrs":[],"path_suffix":""})
    }
    fn mint_body(&self) -> Value {
        // The 2.5 ACL compares a raw JSON value with the HCL allowlist. The
        // token API accepts one policy as a comma-string; an array would be a
        // different value and would not match this exact scalar constraint.
        json!({"policies":self.leaf_policy,"ttl":"5m","explicit_max_ttl":"5m","renewable":false,"no_default_policy":true})
    }
    fn require_owner_role(&self, data: &Value) -> Result<()> {
        for (field, expected) in self.owner_role_body().as_object().ok_or(REFUSED)? {
            if expected.as_array().is_some_and(Vec::is_empty) {
                require(empty(&data[field]))?;
            } else {
                require(data[field] == *expected)?;
            }
        }
        for legacy in ["period", "token_period"] {
            require(data[legacy].is_null() || data[legacy] == 0)?;
        }
        require(data["policies"].is_null() || data["policies"] == json!([self.owner_policy]))
    }
    fn require_leaf_role(&self, data: &Value) -> Result<()> {
        require(data["name"] == self.leaf_role)?;
        for (field, expected) in self.leaf_role_body().as_object().ok_or(REFUSED)? {
            if expected.as_array().is_some_and(Vec::is_empty) {
                require(empty(&data[field]))?;
            } else if field == "token_num_uses" {
                require(data[field].is_null() || data[field] == 0)?;
            } else {
                require(data[field] == *expected)?;
            }
        }
        for legacy in ["period", "explicit_max_ttl"] {
            require(data[legacy].is_null() || data[legacy] == 0)?;
        }
        require(empty(&data["bound_cidrs"]))
    }
}

struct ServerTime {
    seconds: u64,
    cluster: String,
}
fn response_time(response: &reqwest::Response) -> Result<u64> {
    let mut dates = response.headers().get_all(reqwest::header::DATE).iter();
    let value = dates.next().ok_or(REFUSED)?.to_str().map_err(|_| REFUSED)?;
    require(dates.next().is_none() && value.len() <= 64)?;
    let date = chrono::DateTime::parse_from_rfc2822(value).map_err(|_| REFUSED)?;
    require(date.offset().local_minus_utc() == 0 && date.timestamp() > 0)?;
    date.timestamp().try_into().map_err(|_| REFUSED.into())
}
async fn bounded_json(mut response: reqwest::Response) -> Result<Value> {
    require(response.status().is_success())?;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| REFUSED)? {
        require(bytes.len() + chunk.len() <= 65536)?;
        bytes.extend_from_slice(&chunk);
    }
    if bytes.is_empty() {
        Ok(json!({}))
    } else {
        crate::installer_json::decode(&bytes).map_err(|_| REFUSED.into())
    }
}
async fn server_time(bao: &OpenBaoHttp) -> Result<ServerTime> {
    let response = builder(bao, Method::GET, "sys/health", None, None)
        .send()
        .await
        .map_err(|_| REFUSED)?;
    let date = response_time(&response)?;
    let body = bounded_json(response).await?;
    let seconds = body["server_time_utc"].as_u64().ok_or(REFUSED)?;
    let cluster = body["cluster_id"].as_str().ok_or(REFUSED)?;
    require(
        date.abs_diff(seconds) <= 1
            && body["initialized"] == true
            && body["sealed"] == false
            && body["standby"] == false,
    )?;
    uuid_text(cluster)?;
    Ok(ServerTime {
        seconds: date,
        cluster: cluster.into(),
    })
}
async fn data(bao: &OpenBaoHttp, token: &str, path: &str) -> Result<Value> {
    Ok(request(bao, Method::GET, path, None, Some(token))
        .await
        .map_err(|_| REFUSED)?["data"]
        .clone())
}
async fn absent(bao: &OpenBaoHttp, token: &str, path: &str) -> Result<()> {
    let response = builder(bao, Method::GET, path, None, Some(token))
        .send()
        .await
        .map_err(|_| REFUSED)?;
    require(response.status() == StatusCode::NOT_FOUND)
}
fn sensitive(value: &str) -> Result<HeaderValue> {
    require((20..=4096).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_graphic()))?;
    let mut header = HeaderValue::from_str(value).map_err(|_| REFUSED)?;
    header.set_sensitive(true);
    Ok(header)
}
fn header_text(value: &HeaderValue) -> Result<&str> {
    value.to_str().map_err(|_| REFUSED.into())
}

/// The only private setup output. It has no Debug/Serialize implementation.
/// The fixed helper may explicitly write it to an empty private transfer folder;
/// the host then admits copied, installer-owned identities under its own lock.
pub struct ProvisionedCredentialIdentities {
    plan: CredentialResourcePlan,
    account: store::SecretIdentity,
    csr: store::SecretIdentity,
}
impl ProvisionedCredentialIdentities {
    pub fn write_private_transfer(&self, destination: &Path) -> Result<()> {
        let directory = installer_host_fs::directory(destination, REFUSED)?;
        require(installer_host_fs::file_names(&directory, REFUSED)?.is_empty())?;
        store::write_exclusive(
            &directory,
            "account-identity.json",
            &serde_json::to_vec(&self.account).map_err(|_| REFUSED)?,
        )?;
        store::write_exclusive(
            &directory,
            "csr-identity.json",
            &serde_json::to_vec(&self.csr).map_err(|_| REFUSED)?,
        )?;
        store::write_exclusive(&directory, "plan.json", &self.plan.public_bytes()?)
    }
}

/// The fixed bootstrap helper calls this only after the host durably records
/// `plan`. It performs no host lock operation and never returns bootstrap root.
/// Existing mount/policy/token-role resources are refused, never adopted/repaired.
/// Any interrupted transaction requires explicit initial-setup recovery.
pub async fn provision_resources(
    plan: &CredentialResourcePlan,
    bao: &OpenBaoHttp,
    initial_authority: &str,
) -> Result<ProvisionedCredentialIdentities> {
    plan.validate()?;
    sensitive(initial_authority)?;
    require(
        data(bao, initial_authority, "auth/token/lookup-self").await?["policies"]
            == json!(["root"]),
    )?;
    require(server_time(bao).await?.cluster == plan.0.server_cluster_id)?;
    let mounts = data(bao, initial_authority, "sys/auth").await?;
    require(
        !mounts
            .as_object()
            .ok_or(REFUSED)?
            .contains_key(&format!("{}/", plan.mount())),
    )?;
    for purpose in [Purpose::Account, Purpose::Csr] {
        let spec = plan.spec(purpose)?;
        let key = data(
            bao,
            initial_authority,
            &format!("transit/keys/{}", spec.key_name),
        )
        .await?;
        let expected = plan.leaf_policy(purpose, &key)?;
        require(
            data(
                bao,
                initial_authority,
                &format!("sys/policies/acl/{}", spec.leaf_policy),
            )
            .await?["policy"]
                == expected,
        )?;
        absent(
            bao,
            initial_authority,
            &format!("sys/policies/acl/{}", spec.owner_policy),
        )
        .await?;
        absent(
            bao,
            initial_authority,
            &format!("auth/token/roles/{}", spec.leaf_role),
        )
        .await?;
    }
    let outcome = async {
        request(bao, Method::POST, &format!("sys/auth/{}", plan.mount()), Some(&json!({"type":"approle","config":{"default_lease_ttl":"60s","max_lease_ttl":"60s"}})), Some(initial_authority)).await.map_err(|_| REFUSED)?;
        let tune = data(bao, initial_authority, &format!("sys/auth/{}/tune", plan.mount())).await?;
        require(tune["default_lease_ttl"] == OWNER_TTL && tune["max_lease_ttl"] == OWNER_TTL)?;
        let mut identities = Vec::new();
        for purpose in [Purpose::Account, Purpose::Csr] {
            let spec = plan.spec(purpose)?;
            request(bao, Method::PUT, &format!("sys/policies/acl/{}", spec.owner_policy), Some(&json!({"policy":spec.owner_policy()})), Some(initial_authority)).await.map_err(|_| REFUSED)?;
            request(bao, Method::POST, &format!("auth/token/roles/{}", spec.leaf_role), Some(&spec.leaf_role_body()), Some(initial_authority)).await.map_err(|_| REFUSED)?;
            request(bao, Method::POST, &spec.role_path(), Some(&spec.owner_role_body()), Some(initial_authority)).await.map_err(|_| REFUSED)?;
            spec.require_owner_role(&data(bao, initial_authority, &spec.role_path()).await?)?;
            spec.require_leaf_role(&data(bao, initial_authority, &format!("auth/token/roles/{}", spec.leaf_role)).await?)?;
            require(data(bao, initial_authority, &format!("sys/policies/acl/{}", spec.owner_policy)).await?["policy"] == spec.owner_policy())?;
            let role = data(bao, initial_authority, &format!("{}/role-id", spec.role_path())).await?;
            let secret = request(bao, Method::POST, &format!("{}/secret-id", spec.role_path()), Some(&json!({})), Some(initial_authority)).await.map_err(|_| REFUSED)?;
            require(secret["data"]["secret_id_num_uses"] == 0 && secret["data"]["secret_id_ttl"] == 0)?;
            let identity = store::SecretIdentity::new(plan, purpose, role["role_id"].as_str().ok_or(REFUSED)?, secret["data"]["secret_id"].as_str().ok_or(REFUSED)?)?;
            identities.push(identity);
        }
        let csr = identities.pop().ok_or(REFUSED)?;
        let account = identities.pop().ok_or(REFUSED)?;
        Ok(ProvisionedCredentialIdentities { plan: plan.clone(), account, csr })
    }.await;
    outcome.map_err(|_: String| SETUP_HOLD.to_owned())
}

fn intent_name(environment: AcmeEnvironment) -> String {
    format!("acme-credentials-{}-intent.json", environment.as_str())
}
fn result_name(environment: AcmeEnvironment) -> String {
    format!("acme-credentials-{}-result.json", environment.as_str())
}
fn require_custody(state: &LockedInspection, plan: &CredentialResourcePlan) -> Result<()> {
    let environment = plan.environment().as_str();
    let intent_bytes = state.read_evidence(&format!("acme-custody-{environment}-intent.json"))?;
    let intent = crate::installer_json::decode(&intent_bytes).map_err(|_| REFUSED)?;
    let result = crate::installer_json::decode(
        &state.read_evidence(&format!("acme-custody-{environment}-result.json"))?,
    )
    .map_err(|_| REFUSED)?;
    require(
        intent["configuration_sha256"] == plan.0.configuration_sha256
            && intent["installation_id"] == plan.0.installation_id.to_string()
            && intent["environment"] == json!(plan.environment())
            && intent["ingress_key_name"] == plan.key_name(Purpose::Csr)?
            && intent["ingress_key_version"] == 1
            && intent["ingress_public_spki_sha256"]
                == installer_release::sha256(&plan.0.ingress_public_spki_der)
            && result["intent_sha256"] == installer_release::sha256(&intent_bytes)
            && result["key_and_policies_verified"] == true
            && result["account_key"]["installation_id"] == plan.0.installation_id.to_string()
            && result["account_key"]["environment"] == json!(plan.environment())
            && result["account_key"]["transit_key_name"] == plan.key_name(Purpose::Account)?
            && result["account_key"]["transit_key_version"] == 1
            && result["account_key"]["public_spki_der"] == json!(plan.0.account_public_spki_der),
    )
}
fn runtime() -> Result<tokio::runtime::Runtime> {
    require(tokio::runtime::Handle::try_current().is_err())?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| REFUSED.into())
}

/// Host half of the fixed-helper protocol. Read-only preflight precedes the
/// immutable intent; every remote setup mutation happens after this returns.
pub fn prepare_for_install(
    state: &mut InstallerState,
    installation: &Path,
    configuration: &BoundAcmeConfiguration,
    account: &AccountKeyBinding,
    ingress: &RetainedIngressKey,
    bao: &OpenBaoHttp,
) -> Result<CredentialResourcePlan> {
    state.require_live_phase(Phase::Provisioning)?;
    let runtime = runtime()?;
    state.with_maintenance(|state| {
        runtime.block_on(prepare_initial(
            state,
            installation,
            configuration,
            account,
            ingress,
            bao,
        ))
    })
}
async fn prepare_initial(
    state: &mut LockedMaintenance,
    installation: &Path,
    configuration: &BoundAcmeConfiguration,
    account: &AccountKeyBinding,
    ingress: &RetainedIngressKey,
    bao: &OpenBaoHttp,
) -> Result<CredentialResourcePlan> {
    state.inspection().require_path_binding(installation)?;
    require(state.journal().phase() == Phase::Provisioning)?;
    let environment = configuration.parameters().environment();
    if state.read_evidence(&intent_name(environment))?.is_some()
        || state.read_evidence(&result_name(environment))?.is_some()
    {
        return Err(SETUP_HOLD.into());
    }
    let observed = tokio::time::timeout(REFRESH_BUDGET, server_time(bao))
        .await
        .map_err(|_| REFUSED)??;
    let plan =
        CredentialResourcePlan::from_bound(configuration, account, ingress, &observed.cluster)?;
    plan.require_configuration(state.inspection(), configuration)?;
    require_custody(state.inspection(), &plan)?;
    require(
        !installer_host_fs::file_names(state.inspection().installation_directory(), REFUSED)?
            .contains(&plan.directory()),
    )?;
    state.write_evidence_exclusive(&intent_name(environment), &serde_json::to_vec(&json!({
        "schema":"elevenid.installer-acme-credentials-intent/v1","plan":plan,"plan_sha256":plan.sha256()?,
        "openbao_origin":bao.origin(),"observed_server_time":observed.seconds,
        "initial_setup_only":true,"secret_id_rotation":false,"activation_performed":false
    })).map_err(|_| REFUSED)?)?;
    Ok(plan)
}

/// Library composition seam for direct initial-authority integrations and the
/// isolated OpenBao proof. Rootless Compose uses prepare/provision_resources/
/// admit_for_install instead; bootstrap root never needs to reach the host.
pub fn provision_for_install(
    state: &mut InstallerState,
    installation: &Path,
    configuration: &BoundAcmeConfiguration,
    account: &AccountKeyBinding,
    ingress: &RetainedIngressKey,
    bao: &OpenBaoHttp,
    initial_authority: &str,
) -> Result<CredentialProviders> {
    state.require_live_phase(Phase::Provisioning)?;
    let runtime = runtime()?;
    state.with_maintenance(|state| {
        runtime.block_on(async {
            let plan =
                prepare_initial(state, installation, configuration, account, ingress, bao).await?;
            let identities = provision_resources(&plan, bao, initial_authority).await?;
            admit_initial(state, installation, configuration, bao.clone(), identities).await
        })
    })
}

/// Admit an already transferred installer-owned 0700/0600 folder. The fixed
/// container bridge owns the authenticated transfer; this function never chowns
/// or opens the OpenBao state directory and never consumes bootstrap root.
pub fn admit_for_install(
    state: &mut InstallerState,
    installation: &Path,
    configuration: &BoundAcmeConfiguration,
    bao: &OpenBaoHttp,
    transferred: &Path,
) -> Result<CredentialProviders> {
    state.require_live_phase(Phase::Provisioning)?;
    let runtime = runtime()?;
    state.with_maintenance(|state| {
        let plan = retained_plan(state.inspection(), configuration, bao)?;
        let directory = installer_host_fs::directory(transferred, REFUSED)?;
        require(
            installer_host_fs::file_names(&directory, REFUSED)?
                == BTreeSet::from([
                    "account-identity.json".into(),
                    "csr-identity.json".into(),
                    "plan.json".into(),
                ]),
        )?;
        let saved = installer_host_fs::read_entry(&directory, "plan.json", 0o600, false, REFUSED)?;
        require(CredentialResourcePlan::parse_authenticated(&saved, &plan.sha256()?)? == plan)?;
        let account = store::SecretIdentity::read(
            &directory,
            "account-identity.json",
            &plan,
            Purpose::Account,
        )?;
        let csr =
            store::SecretIdentity::read(&directory, "csr-identity.json", &plan, Purpose::Csr)?;
        runtime.block_on(admit_initial(
            state,
            installation,
            configuration,
            bao.clone(),
            ProvisionedCredentialIdentities { plan, account, csr },
        ))
    })
}
async fn admit_initial(
    state: &mut LockedMaintenance,
    installation: &Path,
    configuration: &BoundAcmeConfiguration,
    bao: OpenBaoHttp,
    identities: ProvisionedCredentialIdentities,
) -> Result<CredentialProviders> {
    let plan = retained_plan(state.inspection(), configuration, &bao)?;
    require(
        identities.plan == plan
            && state
                .read_evidence(&result_name(plan.environment()))?
                .is_none(),
    )?;
    state.inspection().require_path_binding(installation)?;
    let installed = store::install(
        state.inspection(),
        &plan,
        &identities.account,
        &identities.csr,
    )?;
    let providers = CredentialProviders::open(
        state.inspection(),
        installation,
        plan.clone(),
        bao,
        &installed,
    )?;
    let outcome = async {
        providers.account.verified_key().await?;
        providers.csr.retained_key().await?;
        plan.require_configuration(state.inspection(), configuration)?;
        state.write_evidence_exclusive(&result_name(plan.environment()), &serde_json::to_vec(&json!({
            "schema":"elevenid.installer-acme-credentials-result/v1","plan_sha256":plan.sha256()?,"identity_storage":installed,
            "scoped_logins_verified":true,"bootstrap_authority_retained":false,"secret_id_rotation":false,
            "activation_performed":false,"installation_ready":false
        })).map_err(|_| REFUSED)?)?;
        Ok(providers)
    }.await;
    outcome.map_err(|_: String| SETUP_HOLD.to_owned())
}
fn retained_plan(
    state: &LockedInspection,
    configuration: &BoundAcmeConfiguration,
    bao: &OpenBaoHttp,
) -> Result<CredentialResourcePlan> {
    let bytes = state.read_evidence(&intent_name(configuration.parameters().environment()))?;
    let intent = crate::installer_json::decode(&bytes).map_err(|_| REFUSED)?;
    require(
        intent["schema"] == "elevenid.installer-acme-credentials-intent/v1"
            && intent["openbao_origin"] == bao.origin()
            && intent["initial_setup_only"] == true
            && intent["secret_id_rotation"] == false
            && intent["activation_performed"] == false,
    )?;
    let plan = CredentialResourcePlan::parse_authenticated(
        &serde_json::to_vec(&intent["plan"]).map_err(|_| REFUSED)?,
        intent["plan_sha256"].as_str().ok_or(REFUSED)?,
    )?;
    plan.require_configuration(state, configuration)?;
    require_custody(state, &plan)?;
    Ok(plan)
}

/// Read-only local restoration. Live role/policy/key validation happens at each
/// scoped authentication, never by repairing OpenBao resources during restore.
pub fn restore(
    state: &LockedInspection,
    installation: &Path,
    configuration: &BoundAcmeConfiguration,
    bao: OpenBaoHttp,
) -> Result<CredentialProviders> {
    state.require_path_binding(installation)?;
    let plan = retained_plan(state, configuration, &bao)?;
    let bytes = state
        .read_evidence(&result_name(plan.environment()))
        .map_err(|_| SETUP_HOLD)?;
    let result = crate::installer_json::decode(&bytes).map_err(|_| REFUSED)?;
    require(
        result["schema"] == "elevenid.installer-acme-credentials-result/v1"
            && result["plan_sha256"] == plan.sha256()?
            && result["scoped_logins_verified"] == true
            && result["bootstrap_authority_retained"] == false
            && result["secret_id_rotation"] == false
            && result["activation_performed"] == false
            && result["installation_ready"] == false,
    )?;
    let installed: store::InstalledIdentity =
        serde_json::from_value(result["identity_storage"].clone()).map_err(|_| REFUSED)?;
    let providers = CredentialProviders::open(state, installation, plan, bao, &installed)?;
    providers
        .account
        .0
        .storage
        .require_initialized(&providers.account.0.plan, Purpose::Account)?;
    providers
        .csr
        .0
        .storage
        .require_initialized(&providers.csr.0.plan, Purpose::Csr)?;
    Ok(providers)
}

/// Intentionally has no Debug/Serialize: identities and token producers remain
/// inside the installer process. The two authorities cannot be interchanged.
pub struct CredentialProviders {
    account: Arc<AccountCredentials>,
    csr: CsrCredentials,
}
impl CredentialProviders {
    fn open(
        state: &LockedInspection,
        installation: &Path,
        plan: CredentialResourcePlan,
        bao: OpenBaoHttp,
        installed: &store::InstalledIdentity,
    ) -> Result<Self> {
        let account = Identity::open(
            state,
            installation,
            plan.clone(),
            bao.clone(),
            installed,
            Purpose::Account,
        )?;
        let csr = Identity::open(state, installation, plan, bao, installed, Purpose::Csr)?;
        Ok(Self {
            account: Arc::new(AccountCredentials(account)),
            csr: CsrCredentials(csr),
        })
    }
    pub fn account(&self) -> Arc<dyn WorkloadCredentials> {
        self.account.clone()
    }
    pub fn account_credentials(&self) -> &AccountCredentials {
        &self.account
    }
    pub fn csr(&self) -> &CsrCredentials {
        &self.csr
    }
}
pub struct AccountCredentials(Identity);
impl AccountCredentials {
    /// Reconstruct the admitted public binding using scoped authenticated key
    /// metadata. There is no unchecked Deserialize path or host-root dependency.
    pub async fn verified_key(&self) -> Result<AccountKeyBinding> {
        let result = self.0.refresh(false).await?;
        self.0.plan.account(&result.key_metadata)
    }
}
#[async_trait]
impl WorkloadCredentials for AccountCredentials {
    async fn token(&self) -> std::result::Result<HeaderValue, AcmeError> {
        self.0
            .refresh(true)
            .await
            .and_then(|value| value.token.ok_or_else(|| REFUSED.into()))
            .map_err(|_| AcmeError::Str(AUTH_UNAVAILABLE))
    }
}
pub struct CsrCredentials(Identity);
impl CsrCredentials {
    pub async fn retained_key(&self) -> Result<RetainedIngressKey> {
        let result = self.0.refresh(false).await?;
        self.0.plan.ingress(&result.key_metadata)
    }
    /// Call only when the enrolment ledger has no retained CSR. The caller must
    /// preserve the exact admitted bytes before newOrder and reuse them on resume.
    pub async fn signed_csr(&self) -> Result<ValidatedCsr> {
        let result = self.0.refresh(true).await?;
        let token = result.token.ok_or(REFUSED)?;
        let key = self.0.plan.ingress(&result.key_metadata)?;
        let identity = self.0.plan.identity()?;
        tokio::time::timeout(OPERATION_BUDGET, async {
            let authority = header_text(&token)?;
            key.require_metadata(
                &data(
                    &self.0.bao,
                    authority,
                    &format!("transit/keys/{}", key.transit_key_name()),
                )
                .await?,
            )?;
            let signed = request(
                &self.0.bao,
                Method::POST,
                &format!("transit/keys/{}/csr", key.transit_key_name()),
                Some(&key.csr_request(&identity)?),
                Some(authority),
            )
            .await
            .map_err(|_| REFUSED)?;
            let csr = validate_signed_csr(
                signed["data"]["csr"].as_str().ok_or(REFUSED)?.as_bytes(),
                &identity,
                &key,
            )?;
            key.require_metadata(
                &data(
                    &self.0.bao,
                    authority,
                    &format!("transit/keys/{}", key.transit_key_name()),
                )
                .await?,
            )?;
            Ok(csr)
        })
        .await
        .map_err(|_| AUTH_UNAVAILABLE)?
    }
}
struct Identity {
    plan: CredentialResourcePlan,
    purpose: Purpose,
    bao: OpenBaoHttp,
    storage: store::IdentityStorage,
}
struct Refresh {
    token: Option<HeaderValue>,
    key_metadata: Value,
}
impl Identity {
    fn open(
        state: &LockedInspection,
        installation: &Path,
        plan: CredentialResourcePlan,
        bao: OpenBaoHttp,
        installed: &store::InstalledIdentity,
        purpose: Purpose,
    ) -> Result<Self> {
        let storage = store::IdentityStorage::open(state, installation, &plan, installed, purpose)?;
        Ok(Self {
            plan,
            purpose,
            bao,
            storage,
        })
    }
    async fn refresh(&self, mint: bool) -> Result<Refresh> {
        let run = async {
            let mut attempt = self.storage.lock(&self.plan, self.purpose)?;
            let server = server_time(&self.bao).await?;
            require(server.cluster == self.plan.0.server_cluster_id)?;
            attempt.begin(&self.plan, self.purpose, server.seconds, mint)?;
            let result = self.authenticate(&attempt.identity, mint).await;
            match result {
                Ok(value) => {
                    attempt.complete(true)?;
                    Ok(value)
                }
                Err(_) => {
                    attempt.complete(false)?;
                    Err(AUTH_UNAVAILABLE.into())
                }
            }
        };
        // Cancellation leaves a durable pending attempt. The next caller records
        // an unknown-short-lived-token result and honors server-time backoff.
        tokio::time::timeout(REFRESH_BUDGET, run)
            .await
            .map_err(|_| AUTH_UNAVAILABLE.to_owned())?
    }
    async fn authenticate(&self, identity: &store::SecretIdentity, mint: bool) -> Result<Refresh> {
        identity.validate(&self.plan, self.purpose)?;
        let spec = self.plan.spec(self.purpose)?;
        let login = request(
            &self.bao,
            Method::POST,
            &format!("auth/{}/login", spec.mount),
            Some(&identity.login_body()),
            None,
        )
        .await
        .map_err(|_| REFUSED)?;
        let owner = validate_auth(&login["auth"], &spec.owner_policy, OWNER_TTL, false)?;
        let authority = header_text(&owner)?;
        let checked = async {
            let role_path = spec.role_path();
            let token_role_path = format!("auth/token/roles/{}", spec.leaf_role);
            let owner_policy_path = format!("sys/policies/acl/{}", spec.owner_policy);
            let leaf_policy_path = format!("sys/policies/acl/{}", spec.leaf_policy);
            let key_path = format!("transit/keys/{}", spec.key_name);
            let role_id_path = format!("{role_path}/role-id");
            let (role, token_role, policy, leaf_policy, key, lookup, role_id) = tokio::try_join!(
                data(&self.bao, authority, &role_path),
                data(&self.bao, authority, &token_role_path),
                data(&self.bao, authority, &owner_policy_path),
                data(&self.bao, authority, &leaf_policy_path),
                data(&self.bao, authority, &key_path),
                data(&self.bao, authority, "auth/token/lookup-self"),
                data(&self.bao, authority, &role_id_path),
            )?;
            spec.require_owner_role(&role)?;
            spec.require_leaf_role(&token_role)?;
            require(
                policy["policy"] == spec.owner_policy()
                    && leaf_policy["policy"] == self.plan.leaf_policy(self.purpose, &key)?
                    && role_id["role_id"].as_str() == Some(identity.role_id()),
            )?;
            validate_lookup(
                &lookup,
                &spec.owner_policy,
                OWNER_TTL,
                &format!("auth/{}/login", spec.mount),
                None,
                false,
            )?;
            let token = if mint {
                let minted = request(
                    &self.bao,
                    Method::POST,
                    &format!("auth/token/create/{}", spec.leaf_role),
                    Some(&spec.mint_body()),
                    Some(authority),
                )
                .await
                .map_err(|_| REFUSED)?;
                let token = validate_auth(&minted["auth"], &spec.leaf_policy, LEAF_TTL, true)?;
                let lookup = request(
                    &self.bao,
                    Method::POST,
                    "auth/token/lookup",
                    Some(&json!({"token":header_text(&token)?})),
                    Some(authority),
                )
                .await
                .map_err(|_| REFUSED)?;
                validate_lookup(
                    &lookup["data"],
                    &spec.leaf_policy,
                    LEAF_TTL,
                    &format!("auth/token/create/{}", spec.leaf_role),
                    Some(&spec.leaf_role),
                    true,
                )?;
                Some(token)
            } else {
                None
            };
            Ok(Refresh {
                token,
                key_metadata: key,
            })
        }
        .await;
        // Orphan leaves survive revocation of this short owner login. Revocation
        // failure is recorded as uncertainty; no owner token reaches the caller.
        let revoked = request(
            &self.bao,
            Method::POST,
            "auth/token/revoke-self",
            Some(&json!({})),
            Some(authority),
        )
        .await
        .map_err(|_| REFUSED);
        revoked?;
        checked
    }
}
fn validate_auth(auth: &Value, policy: &str, ttl: u64, leaf: bool) -> Result<HeaderValue> {
    let lease = auth["lease_duration"].as_u64().ok_or(REFUSED)?;
    require(
        (1..=ttl).contains(&lease)
            && auth["policies"] == json!([policy])
            && auth["token_policies"] == json!([policy])
            && empty(&auth["identity_policies"])
            && auth["token_type"] == "service"
            && auth["orphan"] == true
            && (!leaf || auth["renewable"] == false),
    )?;
    sensitive(auth["client_token"].as_str().ok_or(REFUSED)?)
}
fn validate_lookup(
    data: &Value,
    policy: &str,
    ttl: u64,
    path: &str,
    role: Option<&str>,
    leaf: bool,
) -> Result<()> {
    let remaining = data["ttl"].as_u64().ok_or(REFUSED)?;
    let created = data["creation_ttl"].as_u64().ok_or(REFUSED)?;
    require(
        (1..=ttl).contains(&remaining)
            && (1..=ttl).contains(&created)
            && data["explicit_max_ttl"] == ttl
            && data["policies"] == json!([policy])
            && empty(&data["identity_policies"])
            && data["type"] == "service"
            && data["orphan"] == true
            && data["num_uses"] == 0
            && data["path"] == path
            && (!leaf || data["renewable"] == false)
            && (data["period"].is_null() || data["period"] == 0)
            && role.is_none_or(|role| data["role"] == role),
    )
}

#[cfg(test)]
#[path = "installer_acme_credentials_tests.rs"]
mod tests;
