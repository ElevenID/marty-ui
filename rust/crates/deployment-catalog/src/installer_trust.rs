//! Read-only public trust material and historical startup evidence. Never changes
//! host trust, contacts Docker/OpenBao, resumes provisioning, or grants Ready.
#![cfg(target_os = "linux")]
use crate::{
    installer_doctor, installer_generation_binding as generation,
    installer_ingress_outputs::IngressMetadata,
    installer_ingress_provision as ingress,
    installer_state::{LockedInspection, Phase},
    operator_certificates::{check_chain_at, check_lifetime_at},
};
use marty_selfhost_identity::origin::PublicOrigin;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use spki::der::{Encode, EncodePem};
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrustSource {
    ConfiguredCa,
    MozillaPublicRoots,
}

#[derive(Clone, Serialize)]
pub struct TrustInfo {
    pub schema: &'static str,
    pub installation_id: String,
    pub origin: String,
    /// Local transport target; HTTP authority and TLS identity remain `origin`.
    pub local_probe_address: SocketAddr,
    pub certificate_scope: &'static str,
    pub public_endpoint_observed: bool,
    pub trust_source: TrustSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca_certificate_pem: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca_der_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca_der_sha256s: Option<Vec<String>>,
    pub certificate_der_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca_expires_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_certificate_admission: Option<Value>,
    pub certificate_expires_at: u64,
    pub recorded_token_expires_at: Option<u64>,
    pub evidence_sha256: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_generation: Option<BTreeMap<String, String>>,
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
    Ok(PublicOrigin::parse(value)
        .map_err(|_| REFUSED)?
        .as_str()
        .to_owned())
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
    identity: &ingress::IngressIdentity,
) -> Result<(IngressMetadata, String, u64)> {
    require(metadata.len() <= 8192)?;
    let recorded: IngressMetadata = serde_json::from_slice(metadata).map_err(|_| REFUSED)?;
    // A selected generation retains its original admission time. The fresh
    // producer's age and lifetime margins do not shorten a serving chain's
    // actual validity or move the fixed credential renewal clock.
    let m = crate::installer_ingress_outputs::metadata_for_identity(
        metadata,
        id,
        recorded.token_observed_at,
        identity,
    )?;
    let name = ingress::resource_name(id)?;
    let expires = m
        .token_observed_at
        .checked_add(m.token_ttl_seconds)
        .ok_or(REFUSED)?;
    require(
        m.installation_id == id
            && m.key_name == name
            && m.pki_mount == name
            && m.key_version == 1
            && m.dns_names == identity.dns_names()
            && m.ip_addresses == identity.ip_addresses()
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
        ingress::check_certificates_for(
            &ca_text,
            &leaf_text,
            &public,
            &name,
            m.token_observed_at,
            identity,
        )? == (m.ca_expires_at, m.certificate_expires_at)
            && now < m.ca_expires_at
            && now < m.certificate_expires_at
            && check_lifetime_at(ca, 0, Duration::from_secs(now)).map_err(|_| REFUSED)?
            && check_lifetime_at(leaf, 0, Duration::from_secs(now)).map_err(|_| REFUSED)?,
    )?;
    check_chain_at(leaf, ca, Duration::from_secs(now)).map_err(|_| REFUSED)?;
    Ok((m, ca_text, expires))
}

struct ImportedCertificates {
    pem: String,
    ca_hashes: Vec<String>,
    leaf_hash: String,
    ca_expiry: u64,
    leaf_expiry: u64,
}

fn public_chain(bytes: &[u8]) -> Result<Vec<x509_cert::Certificate>> {
    let text = std::str::from_utf8(bytes).map_err(|_| REFUSED)?;
    require(bytes.len() <= 65536 && regex::Regex::new(
        r"\A\s*(?:-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\s*)+\z"
    ).unwrap().is_match(text))?;
    let certificates = x509_cert::Certificate::load_pem_chain(bytes).map_err(|_| REFUSED)?;
    require(!certificates.is_empty() && certificates.len() <= 16)?;
    Ok(certificates)
}

fn imported_certificates(
    ca: &[u8],
    leaf: &[u8],
    now: u64,
    origin: &PublicOrigin,
) -> Result<ImportedCertificates> {
    let roots = public_chain(ca)?;
    let chain = public_chain(leaf)?;
    let chain_der = chain
        .iter()
        .map(|cert| {
            cert.to_der()
                .map(rustls::pki_types::CertificateDer::from)
                .map_err(|_| REFUSED.into())
        })
        .collect::<Result<Vec<_>>>()?;
    crate::operator_certificates::check_chain(leaf, ca).map_err(|_| REFUSED)?;
    crate::installer_transport::validate_server_chain_for_origin(
        ca,
        &chain_der,
        rustls::pki_types::UnixTime::since_unix_epoch(std::time::Duration::from_secs(now)),
        origin,
    )?;
    let mut ca_hashes = Vec::new();
    let mut ca_expiry = u64::MAX;
    for root in &roots {
        let validity = &root.tbs_certificate.validity;
        let expires = validity.not_after.to_unix_duration().as_secs();
        require(validity.not_before.to_unix_duration().as_secs() <= now && expires > now)?;
        ca_expiry = ca_expiry.min(expires);
        ca_hashes.push(hash(&root.to_der().map_err(|_| REFUSED)?));
    }
    Ok(ImportedCertificates {
        pem: std::str::from_utf8(ca).map_err(|_| REFUSED)?.into(),
        ca_hashes,
        leaf_hash: hash(chain_der[0].as_ref()),
        ca_expiry,
        leaf_expiry: chain[0]
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs(),
    })
}

pub(crate) fn validate_imported_ingress_for_origin(
    ca: &[u8],
    leaf: &[u8],
    origin: &PublicOrigin,
) -> Result<()> {
    imported_certificates(
        ca,
        leaf,
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| REFUSED)?
            .as_secs(),
        origin,
    )
    .map(|_| ())
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
    let imported = binding.imported_foundation();
    let public_metadata = binding.public_ingress_metadata(path)?;
    let public = public_metadata.is_some();
    let mut names = vec![
        installer_doctor::SESSION_RECORD,
        "application-generation-selection.json",
    ];
    if imported {
        names.push(crate::installer_foundation::RECORD);
    } else if !public {
        names.push("installer-ingress.json");
    }
    if !imported {
        names.push("generation-observation.json");
    }
    if state.journal().hosting_selection_sha256().is_some() {
        names.extend([
            crate::installer_hosting::RECORD,
            crate::installer_hosting::SOURCE,
        ]);
    }
    let records = names
        .iter()
        .map(|name| Ok((*name, state.read_evidence(name)?)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    for bytes in records.values() {
        crate::installer_json::decode(bytes).map_err(|_| REFUSED)?;
    }
    let origin = origin(&saved.model)?;
    let public_origin = PublicOrigin::parse(&origin)?;
    let hosting = crate::installer_hosting::resolve(state)?;
    require(
        public
            == (hosting.certificate_source() == crate::installer_hosting::CertificateSource::Acme),
    )?;
    let listener = crate::installer_compose::bound_ingress_listener(&saved.model, &saved.inputs)?;
    require(hosting.resolve_origin(listener.port)? == public_origin)?;
    let identity = ingress::IngressIdentity::new(
        hosting.certificate_dns_name(),
        hosting.certificate_ip_address(),
    )?;
    let probe_ip = match listener.bind_address {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    let ca = if public {
        None
    } else {
        Some(binding.read(path, "installer_ingress_ca_cert")?)
    };
    let leaf = binding.read(path, "installer_ingress_tls_cert")?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| REFUSED)?
        .as_secs();
    let (pem, ca_hash, ca_hashes, leaf_hash, ca_expiry, leaf_expiry, token_expiry) =
        if let Some(metadata) = &public_metadata {
            require(
                metadata.installation_id == id
                    && metadata.dns_names == identity.dns_names()
                    && metadata.ip_addresses == identity.ip_addresses()
                    && metadata.token_observed_at <= now,
            )?;
            let token_expiry = metadata
                .token_observed_at
                .checked_add(metadata.token_ttl_seconds)
                .ok_or(REFUSED)?;
            require(token_expiry > now)?;
            let certificate = metadata.validate_selected_at(&leaf, now)?;
            let admission = certificate.metadata();
            require(
                admission["trust_class"] == "production_public"
                    && admission["public_chain_validated"] == true,
            )?;
            (
                None,
                None,
                None,
                admission["leaf_der_sha256"]
                    .as_str()
                    .ok_or(REFUSED)?
                    .to_owned(),
                None,
                admission["not_after"].as_u64().ok_or(REFUSED)?,
                Some(token_expiry),
            )
        } else if imported {
            let selection = crate::installer_foundation::load(state)?.ok_or(REFUSED)?;
            require(selection.configuration.public_origin == origin)?;
            let c =
                imported_certificates(ca.as_deref().ok_or(REFUSED)?, &leaf, now, &public_origin)?;
            (
                Some(c.pem),
                Some(c.ca_hashes[0].clone()),
                Some(c.ca_hashes),
                c.leaf_hash,
                Some(c.ca_expiry),
                c.leaf_expiry,
                None,
            )
        } else {
            let selected_metadata = binding.ingress_metadata(path)?;
            let metadata_bytes = match selected_metadata {
                Some(metadata) => serde_json::to_vec(&metadata).map_err(|_| REFUSED)?,
                None => {
                    require(
                        Some(state.read_secret("installer_ingress_ca_cert")?) == ca
                            && state.read_secret("installer_ingress_tls_cert")? == leaf,
                    )?;
                    records["installer-ingress.json"].clone()
                }
            };
            let (m, pem, expires) = certificates(
                &metadata_bytes,
                ca.as_deref().ok_or(REFUSED)?,
                &leaf,
                &id,
                now,
                &identity,
            )?;
            (
                Some(pem),
                Some(m.ca_der_sha256),
                None,
                m.certificate_der_sha256,
                Some(m.ca_expires_at),
                m.certificate_expires_at,
                Some(expires),
            )
        };
    for (name, bytes) in &records {
        require(state.read_evidence(name)? == *bytes)?;
    }
    require(
        generation::load_verified(path, &id, engine)?.as_ref() == Some(&binding)
            && (public || Some(binding.read(path, "installer_ingress_ca_cert")?) == ca)
            && binding.read(path, "installer_ingress_tls_cert")? == leaf
            && serde_json::to_value(&saved).map_err(|_| REFUSED)?
                == serde_json::to_value(installer_doctor::load_session(state, path)?)
                    .map_err(|_| REFUSED)?,
    )?;
    state.require_path_binding(path)?;
    Ok(TrustInfo {
        schema: "elevenid.installer-trust-info/v5",
        installation_id: id,
        origin,
        local_probe_address: SocketAddr::new(probe_ip, listener.port),
        certificate_scope: if hosting.external_tls_owned() {
            "backend"
        } else {
            "public-ingress"
        },
        public_endpoint_observed: false,
        trust_source: if public {
            TrustSource::MozillaPublicRoots
        } else {
            TrustSource::ConfiguredCa
        },
        ca_certificate_pem: pem,
        ca_der_sha256: ca_hash,
        ca_der_sha256s: ca_hashes,
        certificate_der_sha256: leaf_hash,
        ca_expires_at: ca_expiry,
        public_certificate_admission: public_metadata
            .map(|metadata| metadata.certificate_admission),
        certificate_expires_at: leaf_expiry,
        recorded_token_expires_at: token_expiry,
        evidence_sha256: records
            .iter()
            .map(|(name, bytes)| (name.to_string(), hash(bytes)))
            .collect(),
        selected_generation: {
            let evidence = binding.selected_evidence(path)?;
            (!evidence.is_empty()).then_some(evidence)
        },
        recorded_startup_containers: resources.containers.len(),
        runtime_observed: false,
        host_trust_observed: false,
        host_trust_modified: false,
        installation_ready: false,
        pending: if hosting.external_tls_owned() {
            vec![
                "External proxy routing, public certificate and backend TLS verification",
                "Browser OIDC login and installed issue/present/verify/revoke/deny journey",
                "Live custody, renewal and recovery qualification",
            ]
        } else if public {
            vec![
                "Trusted public browser entry at the configured DNS origin and IP alias",
                "Browser OIDC login and installed issue/present/verify/revoke/deny journey",
                "Live renewal, root retirement, restore and reboot recovery qualification",
            ]
        } else if imported {
            vec![
            "Explicit browser CA trust and external OIDC login",
            "Installed issue/present/verify/revoke/deny journey",
            "Live IAM and network isolation, external identity/certificate refresh and recovery qualification",
        ]
        } else {
            vec![
                "Explicit browser CA trust and TLS login",
                "Installed issue/present/verify/revoke/deny journey",
                "Live custody, renewal, root retirement and recovery qualification",
            ]
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn retained_private_trust_outlives_the_initial_admission_window() {
        use crate::installer_managed_renewal::tests::{Fixture, OWNER, REPLACED};
        let fixture = Fixture::new();
        let metadata = serde_json::to_vec(&fixture.next_metadata).unwrap();
        let identity = ingress::IngressIdentity::from_metadata(
            &fixture.next_metadata.dns_names,
            &fixture.next_metadata.ip_addresses,
        )
        .unwrap();
        let ca = &fixture.next[ingress::OUTPUTS[0]];
        let leaf = &fixture.next[ingress::OUTPUTS[1]];
        for at in [REPLACED + 1801, REPLACED + 28_799] {
            let (selected, _, expiry) =
                certificates(&metadata, ca, leaf, OWNER, at, &identity).unwrap();
            assert_eq!(selected, fixture.next_metadata);
            assert_eq!(expiry, REPLACED + 28_800);
            // Initial candidate admission still requires fresh metadata.
            assert!(crate::installer_ingress_outputs::metadata_for_identity(
                &metadata, OWNER, at, &identity
            )
            .is_err());
        }
    }

    #[test]
    fn retained_private_trust_refuses_expired_tokens_chains_and_clock_rollback() {
        use crate::installer_managed_renewal::tests::{Fixture, OWNER, REPLACED};
        let fixture = Fixture::new();
        let identity = ingress::IngressIdentity::from_metadata(
            &fixture.next_metadata.dns_names,
            &fixture.next_metadata.ip_addresses,
        )
        .unwrap();
        let ca = &fixture.next[ingress::OUTPUTS[0]];
        let leaf = &fixture.next[ingress::OUTPUTS[1]];
        let metadata = serde_json::to_vec(&fixture.next_metadata).unwrap();
        assert!(certificates(&metadata, ca, leaf, OWNER, REPLACED - 1, &identity).is_err());

        let mut expired_token = fixture.next_metadata.clone();
        expired_token.token_ttl_seconds = 3600;
        assert!(certificates(
            &serde_json::to_vec(&expired_token).unwrap(),
            ca,
            leaf,
            OWNER,
            REPLACED + 3600,
            &identity,
        )
        .is_err());

        // The token remains live for a minute beyond this leaf. An unexpired
        // token cannot turn the chain's exact expiry into serving validity.
        let mut expired_chain = fixture.next_metadata.clone();
        expired_chain.token_observed_at += 60;
        assert!(certificates(
            &serde_json::to_vec(&expired_chain).unwrap(),
            ca,
            leaf,
            OWNER,
            expired_chain.certificate_expires_at,
            &identity,
        )
        .is_err());
    }

    #[test]
    fn retained_private_trust_rechecks_identity_and_certificate_bytes() {
        use crate::installer_managed_renewal::tests::{Fixture, OWNER, REPLACED};
        let fixture = Fixture::new();
        let metadata = serde_json::to_vec(&fixture.next_metadata).unwrap();
        let identity = ingress::IngressIdentity::from_metadata(
            &fixture.next_metadata.dns_names,
            &fixture.next_metadata.ip_addresses,
        )
        .unwrap();
        let ca = &fixture.next[ingress::OUTPUTS[0]];
        let leaf = &fixture.next[ingress::OUTPUTS[1]];
        let mut changed = leaf.clone();
        changed.push(b'\n');
        assert!(certificates(&metadata, ca, &changed, OWNER, REPLACED + 1801, &identity).is_err());
        let other = ingress::IngressIdentity::new(Some("other.example.com"), None).unwrap();
        assert!(certificates(&metadata, ca, leaf, OWNER, REPLACED + 1801, &other).is_err());
    }

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
    fn origin_requires_a_canonical_https_authority() {
        for value in [
            "http://localhost:8443",
            "https://localhost:443",
            "https://localhost:08443",
            "https://localhost:8443/path",
        ] {
            assert!(origin(&json!({"services":{"installer-ingress":{"environment":{"OIDF_EDGE_PUBLIC_ORIGIN":value}}}})).is_err());
        }
        assert_eq!(origin(&json!({"services":{"installer-ingress":{"environment":{"OIDF_EDGE_PUBLIC_ORIGIN":"https://localhost:18443"}}}})).unwrap(),"https://localhost:18443");
        assert_eq!(origin(&json!({"services":{"installer-ingress":{"environment":{"OIDF_EDGE_PUBLIC_ORIGIN":"https://marty.example.com"}}}})).unwrap(),"https://marty.example.com");
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
