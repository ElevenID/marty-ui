//! Read-only public trust material and historical startup evidence. Never changes
//! host trust, contacts Docker/OpenBao, resumes provisioning, or grants Ready.
#![cfg(target_os = "linux")]
use crate::{
    installer_application_graph as graph, installer_generation_binding as generation,
    installer_ingress_outputs::IngressMetadata,
    installer_ingress_provision as ingress,
    installer_state::{CleanupState, LockedInspection, Phase},
};
use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    Deserializer,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use spki::der::{Encode, EncodePem};
use std::fmt;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
type Result<T> = std::result::Result<T, String>;
const REFUSED: &str = "Trust information unavailable or inconsistent; preserve installation evidence. No host trust or readiness was granted";
fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn identifier(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = Unique;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("unambiguous JSON")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Unique, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| Unique(Value::Number(n)))
                    .ok_or_else(|| E::custom("nonfinite number"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut values = Vec::new();
                while let Some(Unique(v)) = seq.next_element()? {
                    values.push(v);
                }
                Ok(Unique(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(de::Error::custom("duplicate JSON field"));
                    }
                    let Unique(value) = map.next_value()?;
                    values.insert(key, value);
                }
                Ok(Unique(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(UniqueVisitor)
    }
}

fn decode(bytes: &[u8]) -> Result<Value> {
    serde_json::from_slice::<Unique>(bytes)
        .map(|v| v.0)
        .map_err(|_| REFUSED.into())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Startup {
    schema: String,
    installation_id: String,
    project: String,
    engine_id: String,
    network_id: String,
    containers: BTreeMap<String, String>,
    redis_volume: String,
    completed_initializers: Vec<String>,
    healthy_services: Vec<String>,
    running_workers: Vec<String>,
    installation_ready: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Created {
    containers: BTreeMap<String, String>,
    redis_volume: String,
    network_id: String,
}
#[derive(Serialize)]
pub struct TrustInfo {
    pub schema: &'static str,
    pub installation_id: String,
    pub origin: String,
    pub ca_certificate_pem: String,
    pub ca_der_sha256: String,
    pub certificate_der_sha256: String,
    pub ca_expires_at: u64,
    pub certificate_expires_at: u64,
    pub recorded_token_expires_at: u64,
    pub evidence_sha256: BTreeMap<String, String>,
    pub recorded_startup_containers: usize,
    pub runtime_observed: bool,
    pub host_trust_observed: bool,
    pub host_trust_modified: bool,
    pub installation_ready: bool,
    pub pending: Vec<&'static str>,
}
fn origin(model: &Value) -> Result<String> {
    let value = model["services"]["installer-ingress"]["environment"]["OIDF_EDGE_PUBLIC_ORIGIN"]
        .as_str()
        .ok_or(REFUSED)?;
    let port = value.strip_prefix("https://localhost:").ok_or(REFUSED)?;
    let number = port.parse::<u16>().map_err(|_| REFUSED)?;
    require(number >= 1024 && port == number.to_string())?;
    Ok(value.to_owned())
}
fn startup(
    record: &Startup,
    created: &Created,
    model: &Value,
    selected: &[String],
    identity: (&str, &str, &str, &str),
) -> Result<()> {
    let (id, project, engine, network) = identity;
    require(
        record.schema == "elevenid.installer-application-start/v1"
            && record.installation_id == id
            && record.project == project
            && record.engine_id == engine
            && record.network_id == network
            && !record.installation_ready
            && created.network_id == network
            && record.containers == created.containers
            && record.redis_volume == created.redis_volume
            && record.redis_volume == format!("{project}_redis-socket"),
    )?;
    let roles = graph::startup_order(model, selected)?;
    require(
        record.containers.keys().cloned().collect::<BTreeSet<_>>()
            == roles.iter().cloned().collect()
            && record.containers.values().all(|v| identifier(v))
            && record.containers.values().collect::<BTreeSet<_>>().len() == roles.len(),
    )?;
    for (values, kind) in [
        (
            &record.completed_initializers,
            graph::Completion::ExitedZero,
        ),
        (&record.healthy_services, graph::Completion::Healthy),
        (&record.running_workers, graph::Completion::Running),
    ] {
        let expected = roles
            .iter()
            .filter_map(|role| match graph::completion(model, role) {
                Ok(actual) if actual == kind => Some(role.clone()),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        require(
            values.len() == expected.len()
                && values.iter().cloned().collect::<BTreeSet<_>>() == expected,
        )?;
    }
    Ok(())
}
fn public_pem(bytes: &[u8]) -> Result<String> {
    let text = std::str::from_utf8(bytes).map_err(|_| REFUSED)?;
    require(
        regex::Regex::new(
            r"\A-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\s*\z",
        )
        .unwrap()
        .is_match(text),
    )?;
    ingress::certificate(text)?;
    Ok(text.to_owned())
}
fn certificates(
    metadata: &[u8],
    ca: &[u8],
    leaf: &[u8],
    id: &str,
    now: u64,
) -> Result<(IngressMetadata, String, u64)> {
    let m: IngressMetadata = serde_json::from_slice(metadata).map_err(|_| REFUSED)?;
    let name = ingress::resource_name(id)?;
    let expires = m
        .token_observed_at
        .checked_add(m.token_ttl_seconds)
        .ok_or(REFUSED)?;
    require(
        m.schema == "elevenid.installer-ingress/v1"
            && m.installation_id == id
            && m.key_name == name
            && m.pki_mount == name
            && m.key_version == 1
            && m.dns_names == ["localhost"]
            && m.ip_addresses == ["127.0.0.1"]
            && !m.trust_installed
            && !m.installation_ready
            && (3600..=28800).contains(&m.token_ttl_seconds)
            && m.token_observed_at <= now
            && expires > now,
    )?;
    let ca_text = public_pem(ca)?;
    let leaf_text = public_pem(leaf)?;
    let ca_cert = ingress::certificate(&ca_text)?;
    let leaf_cert = ingress::certificate(&leaf_text)?;
    require(
        m.ca_pem_sha256 == hash(ca)
            && m.certificate_pem_sha256 == hash(leaf)
            && m.ca_der_sha256 == hash(&ca_cert.to_der().map_err(|_| REFUSED)?)
            && m.certificate_der_sha256 == hash(&leaf_cert.to_der().map_err(|_| REFUSED)?),
    )?;
    let public = leaf_cert
        .tbs_certificate
        .subject_public_key_info
        .to_pem(spki::der::pem::LineEnding::LF)
        .map_err(|_| REFUSED)?;
    require(
        ingress::check_certificates(&ca_text, &leaf_text, &public, &name, now)?
            == (m.ca_expires_at, m.certificate_expires_at),
    )?;
    Ok((m, ca_text, expires))
}
/// Output is public certificate material, not a request to trust an arbitrary CA.
/// The caller may explicitly import this certificate into a chosen browser trust
/// store after checking its fingerprint. This command does not observe that store.
pub fn inspect(path: &Path) -> Result<TrustInfo> {
    let state = LockedInspection::open(path)?;
    inspect_locked(path, &state)
}

pub(crate) fn inspect_locked(path: &Path, state: &LockedInspection) -> Result<TrustInfo> {
    state.require_path_binding(path)?;
    require(
        state.cleanup_status()?.state == CleanupState::NotStarted
            && matches!(
                state.journal().phase(),
                Phase::Provisioning | Phase::Provisioned
            ),
    )?;
    let id = state.journal().installation_id().to_string();
    let engine = &state.journal().runtime().ok_or(REFUSED)?.engine_id;
    let binding = generation::load_verified(path, &id, engine)?.ok_or(REFUSED)?;
    let names = [
        "installer-ingress.json",
        "application-plan.json",
        "application-created-resources.json",
        "application-start-result.json",
        "application-generation-selection.json",
    ];
    let records = names
        .iter()
        .map(|name| Ok((*name, state.read_evidence(name)?)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    for bytes in records.values() {
        decode(bytes)?;
    }
    let plan = decode(&records["application-plan.json"])?;
    let selected: Vec<String> =
        serde_json::from_value(plan["selected_services"].clone()).map_err(|_| REFUSED)?;
    let receipt: Startup =
        serde_json::from_slice(&records["application-start-result.json"]).map_err(|_| REFUSED)?;
    let created: Created = serde_json::from_slice(&records["application-created-resources.json"])
        .map_err(|_| REFUSED)?;
    startup(
        &receipt,
        &created,
        &plan["model"],
        &selected,
        (
            &id,
            &state.journal().compose_project(),
            engine,
            &binding.network_id,
        ),
    )?;
    let origin = origin(&plan["model"])?;
    let ca = state.read_secret("installer_ingress_ca_cert")?;
    let leaf = state.read_secret("installer_ingress_tls_cert")?;
    require(
        binding.read(path, "installer_ingress_ca_cert")? == ca
            && binding.read(path, "installer_ingress_tls_cert")? == leaf,
    )?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| REFUSED)?
        .as_secs();
    let (m, pem, expires) = certificates(&records["installer-ingress.json"], &ca, &leaf, &id, now)?;
    for (name, bytes) in &records {
        require(state.read_evidence(name)? == *bytes)?;
    }
    require(
        generation::load_verified(path, &id, engine)?.as_ref() == Some(&binding)
            && state.read_secret("installer_ingress_ca_cert")? == ca
            && state.read_secret("installer_ingress_tls_cert")? == leaf,
    )?;
    state.require_path_binding(path)?;
    Ok(TrustInfo {
        schema: "elevenid.installer-trust-info/v2",
        installation_id: id,
        origin,
        ca_certificate_pem: pem,
        ca_der_sha256: m.ca_der_sha256,
        certificate_der_sha256: m.certificate_der_sha256,
        ca_expires_at: m.ca_expires_at,
        certificate_expires_at: m.certificate_expires_at,
        recorded_token_expires_at: expires,
        evidence_sha256: records
            .iter()
            .map(|(name, bytes)| (name.to_string(), hash(bytes)))
            .collect(),
        recorded_startup_containers: receipt.containers.len(),
        runtime_observed: false,
        host_trust_observed: false,
        host_trust_modified: false,
        installation_ready: false,
        pending: vec![
            "Explicit browser CA trust and TLS login",
            "Installed issue/present/verify/revoke/deny journey",
            "Live custody, renewal, root retirement and recovery qualification",
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn public_export_rejects_private_material_and_extra_pem() {
        let ca = include_bytes!("../tests/fixtures/installer-log-public-ca.txt");
        assert!(public_pem(ca).is_ok());
        let mut private = ca.to_vec();
        private.extend_from_slice(
            b"\n-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n",
        );
        assert!(public_pem(&private).is_err());
        assert!(public_pem(&[ca.as_slice(), ca.as_slice()].concat()).is_err());
        assert!(public_pem(b"credential-value").is_err());
    }
    #[test]
    fn origin_is_fixed_loopback_https_and_unprivileged() {
        for value in [
            "http://localhost:8443",
            "https://foreign:8443",
            "https://localhost:443",
            "https://localhost:08443",
            "https://localhost:8443/path",
        ] {
            assert!(origin(&json!({"services":{"installer-ingress":{"environment":{"OIDF_EDGE_PUBLIC_ORIGIN":value}}}})).is_err());
        }
        assert_eq!(origin(&json!({"services":{"installer-ingress":{"environment":{"OIDF_EDGE_PUBLIC_ORIGIN":"https://localhost:18443"}}}})).unwrap(),"https://localhost:18443");
    }
    #[test]
    fn startup_identity_and_unknown_fields_are_refused() {
        let raw = json!({"schema":"elevenid.installer-application-start/v1","installation_id":"wrong","project":"p","engine_id":"e","network_id":"n","containers":{},"redis_volume":"p_redis-socket","completed_initializers":[],"healthy_services":[],"running_workers":[],"installation_ready":false});
        let receipt: Startup = serde_json::from_value(raw.clone()).unwrap();
        let created = Created {
            containers: BTreeMap::new(),
            redis_volume: "p_redis-socket".into(),
            network_id: "n".into(),
        };
        assert!(startup(
            &receipt,
            &created,
            &json!({}),
            &[],
            ("expected", "p", "e", "n")
        )
        .is_err());
        let mut extra = raw;
        extra["trust_installed"] = json!(true);
        assert!(serde_json::from_value::<Startup>(extra).is_err());
    }
    #[test]
    fn nested_duplicate_receipt_fields_are_refused() {
        assert!(decode(br#"{"containers":{"edge":"first","edge":"second"}}"#).is_err());
        assert!(decode(
            br#"{"model":{"services":{"edge":{"environment":{"A":"first","A":"second"}}}}}"#
        )
        .is_err());
        assert!(decode(br#"{"installation_ready":false,"installation_ready":true}"#).is_err());
    }
    #[test]
    fn recorded_startup_must_cover_exact_graph_ids_and_completion_classes() {
        let mut services = serde_json::Map::new();
        for role in [
            "gateway",
            "postgres",
            "redis",
            "revocation-profile-migrate",
            "db-migrate",
            "kms-initialize",
            "keycloak-configurator",
            "issuance-migrations",
        ] {
            services.insert(
                role.into(),
                json!({"restart":"no","healthcheck":{"test":["CMD","true"]}}),
            );
        }
        for i in 0..22 {
            services.insert(
                format!("synthetic-{i}"),
                json!({"healthcheck":{"test":["CMD","true"]}}),
            );
        }
        services["kms-initialize"]["depends_on"] = json!({"postgres":{"condition":"service_healthy"},"redis":{"condition":"service_healthy"},"db-migrate":{"condition":"service_completed_successfully"},"revocation-profile-migrate":{"condition":"service_completed_successfully"}});
        let selected = services
            .keys()
            .filter(|name| name.as_str() != "kms-initialize")
            .cloned()
            .collect::<Vec<_>>();
        let model = json!({"services":services});
        let roles = graph::startup_order(&model, &selected).unwrap();
        let containers = roles
            .iter()
            .enumerate()
            .map(|(i, role)| (role.clone(), format!("{i:064x}")))
            .collect::<BTreeMap<_, _>>();
        let initializers = roles
            .iter()
            .filter(|role| {
                graph::completion(&model, role).unwrap() == graph::Completion::ExitedZero
            })
            .cloned()
            .collect::<Vec<_>>();
        let healthy = roles
            .iter()
            .filter(|role| graph::completion(&model, role).unwrap() == graph::Completion::Healthy)
            .cloned()
            .collect::<Vec<_>>();
        let raw = json!({"schema":"elevenid.installer-application-start/v1","installation_id":"id","project":"p","engine_id":"e","network_id":"n","containers":containers,"redis_volume":"p_redis-socket","completed_initializers":initializers,"healthy_services":healthy,"running_workers":[],"installation_ready":false});
        let created = Created {
            containers,
            redis_volume: "p_redis-socket".into(),
            network_id: "n".into(),
        };
        let validate = |value: Value| {
            startup(
                &serde_json::from_value::<Startup>(value).unwrap(),
                &created,
                &model,
                &selected,
                ("id", "p", "e", "n"),
            )
        };
        validate(raw.clone()).unwrap();
        for field in [
            "installation_id",
            "project",
            "engine_id",
            "network_id",
            "redis_volume",
        ] {
            let mut bad = raw.clone();
            bad[field] = json!("foreign");
            assert!(validate(bad).is_err());
        }
        let mut bad = raw.clone();
        bad["containers"]["gateway"] = json!("f".repeat(64));
        assert!(validate(bad).is_err());
        let mut bad = raw.clone();
        bad["healthy_services"].as_array_mut().unwrap().pop();
        assert!(validate(bad).is_err());
        let mut bad = raw;
        bad["installation_ready"] = json!(true);
        assert!(validate(bad).is_err());
    }
    #[test]
    fn trust_information_never_adopts_active_or_incomplete_installation() {
        use crate::installer_state::{Identity, InstallerState};
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("installation");
        let state = InstallerState::create(
            &path,
            Identity {
                source_sha: "a".repeat(40),
                release_tag: "v1.2.3".into(),
                inventory_sha256: format!("sha256:{}", "b".repeat(64)),
            },
        )
        .unwrap();
        let journal = std::fs::read(path.join("installation.json")).unwrap();
        assert!(inspect(&path).is_err());
        drop(state);
        assert!(inspect(&path).is_err());
        assert_eq!(
            std::fs::read(path.join("installation.json")).unwrap(),
            journal
        );
        assert!(!path.join("evidence").exists());
        let inspection = LockedInspection::open(&path).unwrap();
        inspection.require_path_binding(&path).unwrap();
        std::fs::rename(&path, root.path().join("retained-installation")).unwrap();
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(inspection.require_path_binding(&path).is_err());
    }
}
