use super::*;
use crate::installer_state::{Identity, InstallerState, Phase};
use serde_json::{json, Value};
use std::{fs, os::unix::fs::PermissionsExt, path::Path};

fn parameters() -> Value {
    json!({"environment":"staging", "directory_url":AcmeEnvironment::Staging.directory_url(),
        "profile":"shortlived", "terms_url":"https://letsencrypt.org/documents/LE-SA-v1.6-August-18-2025.pdf",
        "terms_agreed":true})
}
fn parsed(value: &Value) -> Result<AcmeParameters> {
    AcmeParameters::parse(&serde_json::to_vec(value).unwrap())
}
fn hosting() -> Value {
    json!({"schema":"elevenid.installation-hosting/v1", "mode":"direct",
        "public_origin":"https://login.example.com:9443", "public_entry_origin":"https://[2001:db8::7]:18443",
        "listener":{"bind_address":"0.0.0.0","port":8443},
        "tls":{"termination":"marty-keyless","certificate_source":"managed-ca"}})
}
fn write(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
fn fixture(configuration: Option<Value>) -> (tempfile::TempDir, InstallerState) {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let mut state = InstallerState::create(
        &root.path().join("installation"),
        Identity {
            source_sha: "a".repeat(40),
            release_tag: "v1.2.3".into(),
            inventory_sha256: format!("sha256:{}", "b".repeat(64)),
        },
    )
    .unwrap();
    state.create_private_directory("evidence").unwrap();
    state.advance(Phase::Verified).unwrap();
    if let Some(configuration) = configuration {
        let input = root.path().join("hosting.json");
        write(&input, &serde_json::to_vec(&configuration).unwrap());
        installer_hosting::select(
            installer_hosting::prepare(Some(&input), None).unwrap(),
            &mut state,
        )
        .unwrap();
    }
    (root, state)
}

#[test]
fn requires_explicit_directory_profile_and_same_agreed_terms() {
    let input = parameters();
    let good = parsed(&input).unwrap();
    assert_eq!(good.environment(), AcmeEnvironment::Staging);
    assert_eq!(good.profile(), "shortlived");
    assert!(good.contact().is_none());
    good.require_directory_terms(Some(good.terms_url()))
        .unwrap();
    assert!(good.require_directory_terms(None).is_err());
    assert!(good
        .require_directory_terms(Some("https://letsencrypt.org/documents/changed.pdf"))
        .is_err());
    for (field, invalid) in [
        ("environment", json!("production")),
        (
            "directory_url",
            json!("http://acme-staging-v02.api.letsencrypt.org/directory"),
        ),
        ("profile", json!("classic")),
        ("terms_agreed", json!(false)),
        ("terms_url", json!("https://foreign.example/terms.pdf")),
        (
            "terms_url",
            json!("https://user@letsencrypt.org/documents/terms.pdf"),
        ),
        (
            "terms_url",
            json!("https://letsencrypt.org/documents/terms.pdf?different=1"),
        ),
    ] {
        let mut bad = input.clone();
        bad[field] = invalid;
        assert!(parsed(&bad).is_err(), "{field}");
    }
    for field in [
        "environment",
        "directory_url",
        "profile",
        "terms_url",
        "terms_agreed",
    ] {
        let mut bad = input.clone();
        bad.as_object_mut().unwrap().remove(field);
        assert!(parsed(&bad).is_err(), "missing {field}");
    }
    let mut production = input.clone();
    production["environment"] = json!("production");
    production["directory_url"] = json!(AcmeEnvironment::Production.directory_url());
    assert_eq!(
        parsed(&production).unwrap().environment(),
        AcmeEnvironment::Production
    );
    let encoded = serde_json::to_string(&input).unwrap();
    let duplicate = format!(
        "{},\"environment\":\"staging\"}}",
        encoded.trim_end_matches('}')
    );
    assert!(AcmeParameters::parse(duplicate.as_bytes()).is_err());
    let mut unknown = input;
    unknown["accept_all_terms"] = json!(true);
    assert!(parsed(&unknown).is_err());
}

#[test]
fn contact_is_absent_by_default_and_requires_an_explicit_plain_mailbox() {
    let mut value = parameters();
    assert!(parsed(&value).unwrap().contact().is_none());
    value["contact"] = json!("mailto:Owner+Marty@example.com");
    assert_eq!(
        parsed(&value).unwrap().contact(),
        Some("mailto:Owner+Marty@example.com")
    );
    for contact in [
        "",
        "owner@example.com",
        "mailto:owner@localhost",
        "mailto:one@example.com,two@example.com",
        "mailto:owner@example.com?subject=subscribe",
        "mailto:owner@example.com\n",
        "mailto:owner@EXAMPLE.com",
        "mailto:a..b@example.com",
        "mailto:.owner@example.com",
        "mailto:owner@198.51.100.1",
    ] {
        value["contact"] = json!(contact);
        assert!(parsed(&value).is_err(), "{contact:?}");
    }
}

#[test]
fn bound_configuration_pins_actual_installation_and_exact_dns_ip_origins() {
    let (_root, state) = fixture(Some(hosting()));
    let config = state
        .with_inspection(|view| BoundAcmeConfiguration::bind(view, parsed(&parameters())?))
        .unwrap();
    assert_eq!(config.installation_id(), state.journal().installation_id());
    assert_eq!(
        config.hosting_selection_sha256(),
        state.journal().hosting_selection_sha256().unwrap()
    );
    assert_eq!(config.canonical_origin(), "https://login.example.com:9443");
    assert_eq!(
        config.public_entry_origin(),
        Some("https://[2001:db8::7]:18443")
    );
    let identity = config.certificate_identity().unwrap();
    assert_eq!(identity.dns_name(), "login.example.com");
    assert_eq!(identity.ip_address(), Some("2001:db8::7".parse().unwrap()));
    let repeated = state
        .with_inspection(|view| BoundAcmeConfiguration::bind(view, parsed(&parameters())?))
        .unwrap();
    assert_eq!(
        serde_json::to_vec(&config).unwrap(),
        serde_json::to_vec(&repeated).unwrap()
    );
    let mut production = parameters();
    production["environment"] = json!("production");
    production["directory_url"] = json!(AcmeEnvironment::Production.directory_url());
    let different = state
        .with_inspection(|view| BoundAcmeConfiguration::bind(view, parsed(&production)?))
        .unwrap();
    assert_ne!(config, different);
}

#[test]
fn changed_hosting_and_unrecorded_local_or_external_proxy_configs_are_refused() {
    let (root, state) = fixture(Some(hosting()));
    let record = root
        .path()
        .join("installation/evidence/hosting-selection.json");
    let before = fs::read(&record).unwrap();
    write(&record, b"{}");
    assert!(state
        .with_inspection(|view| BoundAcmeConfiguration::bind(view, parsed(&parameters())?))
        .is_err());
    write(&record, &before);
    assert!(state
        .with_inspection(|view| BoundAcmeConfiguration::bind(view, parsed(&parameters())?))
        .is_ok());
    let (_root, unrecorded) = fixture(None);
    assert!(unrecorded
        .with_inspection(|view| BoundAcmeConfiguration::bind(view, parsed(&parameters())?))
        .is_err());
    let mut proxy = hosting();
    proxy["mode"] = json!("external-proxy");
    proxy.as_object_mut().unwrap().remove("public_entry_origin");
    let (_root, proxy) = fixture(Some(proxy));
    assert!(proxy
        .with_inspection(|view| BoundAcmeConfiguration::bind(view, parsed(&parameters())?))
        .is_err());
}
