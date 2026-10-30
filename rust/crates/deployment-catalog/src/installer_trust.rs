//! Read-only public trust material and historical startup evidence. Never changes
//! host trust, contacts Docker/OpenBao, resumes provisioning, or grants Ready.
#![cfg(target_os = "linux")]
use crate::{
    installer_doctor, installer_generation_binding as generation,
    installer_ingress_outputs::IngressMetadata,
    installer_ingress_provision as ingress,
    installer_state::{LockedInspection, Phase},
};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use spki::der::{Encode, EncodePem};
use std::{
    collections::BTreeMap,
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
    require(matches!(
        state.journal().phase(),
        Phase::Provisioning | Phase::Provisioned
    ))?;
    // A started stop/removal may have an uncertain daemon-side result. Historical
    // startup evidence is not a live trust/readiness assertion in that state.
    let maintenance = crate::installer_uninstall::status(state)?;
    require(
        maintenance["operations"]["down"] == "not_started"
            && maintenance["operations"]
                .as_object()
                .ok_or(REFUSED)?
                .values()
                .all(|value| value != "uncertain"),
    )?;
    let saved = installer_doctor::load_session(state, path)?;
    let resources = saved.receipt.resources.as_ref().ok_or(REFUSED)?;
    require(
        installer_doctor::summarize(resources, &saved.receipt.status)?
            ["all_expected_states_observed"]
            == true,
    )?;
    let id = state.journal().installation_id().to_string();
    let engine = &state.journal().runtime().ok_or(REFUSED)?.engine_id;
    let binding = generation::load_verified(path, &id, engine)?.ok_or(REFUSED)?;
    let names = [
        "installer-ingress.json",
        installer_doctor::SESSION_RECORD,
        "application-generation-selection.json",
    ];
    let records = names
        .iter()
        .map(|name| Ok((*name, state.read_evidence(name)?)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    for bytes in records.values() {
        crate::installer_json::decode(bytes).map_err(|_| REFUSED)?;
    }
    let origin = origin(&saved.model)?;
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
            && state.read_secret("installer_ingress_tls_cert")? == leaf
            && serde_json::to_value(&saved).map_err(|_| REFUSED)?
                == serde_json::to_value(installer_doctor::load_session(state, path)?)
                    .map_err(|_| REFUSED)?,
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
        recorded_startup_containers: resources.containers.len(),
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
