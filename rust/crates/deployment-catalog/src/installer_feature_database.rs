//! Fixed credentials for the fresh, native-managed feature database profile.
//! No database operation occurs here. The installation owner writes these
//! bytes once under its dedicated feature-profile-secrets custody, never the
//! broadly mounted legacy secrets directory. SQL setup is a separate admitted
//! one-shot operation; runtime services receive only their individual URLs.
#![cfg(target_os = "linux")]

use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read,
};

type Result<T> = std::result::Result<T, String>;
const REFUSED: &str = "feature database credential inventory is absent, changed or invalid";
const PASSWORD_SCHEMA: &str = "elevenid.feature-database-passwords/v1";
pub(crate) const PASSWORD_INVENTORY: &str = "feature_database_passwords";
pub(crate) const CA_MOUNT: &str = "/run/feature-profile/feature_postgres_ca";
pub(crate) const MIGRATION_ROLES: &[&str] = &["delegation_owner", "credential_owner"];
pub(crate) const RUNTIME_ROLES: &[&str] = &[
    "approval_runtime",
    "approval_consent",
    "approval_authority",
    "approval_organization",
    "command_writer",
    "command_runtime",
    "command_organization",
    "use_writer",
    "use_runtime_reader",
    "use_organization_authority",
    "use_registry_source",
    "use_access_source",
    "use_machine_policy_source",
    "use_machine_policy_evidence",
    "use_delegation_policy_source",
    "use_machine_audit",
    "use_flow_reader",
    "use_flow_ingress",
    "use_credential_trust",
    "use_credential_status",
    "use_credential_evidence",
    "issuance_runtime",
    "observation",
    "association",
];

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PasswordInventory {
    schema: String,
    roles: BTreeMap<String, String>,
}

fn roles() -> impl Iterator<Item = &'static str> {
    MIGRATION_ROLES.iter().chain(RUNTIME_ROLES).copied()
}

pub(crate) fn credential_names() -> BTreeSet<String> {
    roles()
        .map(|role| format!("feature_{role}_database_url"))
        .chain([PASSWORD_INVENTORY.into()])
        .collect()
}

fn database_url(role: &str, password: &str) -> Vec<u8> {
    format!(
        "postgresql://feature_{role}:{password}@postgres:5432/marty?sslmode=verify-full&sslrootcert={CA_MOUNT}"
    ).into_bytes()
}

/// Generates each password independently from OS entropy. A repeated password
/// or partial entropy read refuses the entire in-memory result. The caller
/// retains its existing exclusive file writes and uncertainty handling.
pub(crate) fn generate_credentials() -> Result<BTreeMap<String, Vec<u8>>> {
    let mut random = File::open("/dev/urandom").map_err(|_| REFUSED)?;
    generate_with(|bytes| random.read_exact(bytes).map_err(|_| REFUSED.to_owned()))
}

fn generate_with(
    mut fill: impl FnMut(&mut [u8]) -> Result<()>,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut passwords = BTreeMap::new();
    let mut credentials = BTreeMap::new();
    let mut seen = BTreeSet::new();
    for role in roles() {
        let mut entropy = [0u8; 32];
        fill(&mut entropy)?;
        let password: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
        if entropy == [0; 32] || !seen.insert(password.clone()) {
            return Err(REFUSED.into());
        }
        credentials.insert(
            format!("feature_{role}_database_url"),
            database_url(role, &password),
        );
        passwords.insert(format!("feature_{role}"), password);
    }
    credentials.insert(
        PASSWORD_INVENTORY.into(),
        serde_json::to_vec(&PasswordInventory {
            schema: PASSWORD_SCHEMA.into(),
            roles: passwords,
        })
        .map_err(|_| REFUSED)?,
    );
    validate_credentials(&credentials)?;
    Ok(credentials)
}

/// Validates the original retained bytes without normalizing or rewriting any
/// credential. The one-shot password inventory must agree with every role URL.
pub(crate) fn validate_credentials(credentials: &BTreeMap<String, Vec<u8>>) -> Result<()> {
    if credentials.keys().cloned().collect::<BTreeSet<_>>() != credential_names() {
        return Err(REFUSED.into());
    }
    let raw = credentials.get(PASSWORD_INVENTORY).ok_or(REFUSED)?;
    if raw.len() > 8192 {
        return Err(REFUSED.into());
    }
    let inventory: PasswordInventory =
        serde_json::from_value(crate::installer_json::decode(raw).map_err(|_| REFUSED)?)
            .map_err(|_| REFUSED)?;
    let expected: BTreeSet<_> = roles().map(|role| format!("feature_{role}")).collect();
    if inventory.schema != PASSWORD_SCHEMA
        || inventory.roles.keys().cloned().collect::<BTreeSet<_>>() != expected
    {
        return Err(REFUSED.into());
    }
    let mut seen = BTreeSet::new();
    for role in roles() {
        let password = inventory
            .roles
            .get(&format!("feature_{role}"))
            .ok_or(REFUSED)?;
        if password.len() != 64
            || !password
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || password.bytes().all(|byte| byte == b'0')
            || !seen.insert(password)
            || credentials.get(&format!("feature_{role}_database_url"))
                != Some(&database_url(role, password))
        {
            return Err(REFUSED.into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> BTreeMap<String, Vec<u8>> {
        let mut sequence = 0u8;
        generate_with(|bytes| {
            sequence += 1;
            bytes.fill(sequence);
            Ok(())
        })
        .unwrap()
    }

    #[test]
    fn fixed_roles_have_distinct_passwords_verified_transport_and_no_key_material() {
        let credentials = fixture();
        assert_eq!(MIGRATION_ROLES.len(), 2);
        assert_eq!(RUNTIME_ROLES.len(), 24);
        assert_eq!(credentials.len(), 27);
        validate_credentials(&credentials).unwrap();
        for role in roles() {
            let value =
                std::str::from_utf8(&credentials[&format!("feature_{role}_database_url")]).unwrap();
            assert!(value.starts_with(&format!("postgresql://feature_{role}:")));
            assert!(value.ends_with(&format!(
                "@postgres:5432/marty?sslmode=verify-full&sslrootcert={CA_MOUNT}"
            )));
            assert!(!value.contains("PRIVATE KEY"));
        }
        let before = credentials.clone();
        validate_credentials(&credentials).unwrap();
        assert_eq!(credentials, before);
    }

    #[test]
    fn refuses_aliases_plaintext_extra_roles_changed_inventory_and_bad_entropy() {
        let original = fixture();
        let name = "feature_approval_runtime_database_url";
        for replacement in [
            original["feature_approval_consent_database_url"].clone(),
            String::from_utf8(original[name].clone())
                .unwrap()
                .replace("verify-full", "disable")
                .into_bytes(),
            String::from_utf8(original[name].clone())
                .unwrap()
                .replace("@postgres:", "@elsewhere:")
                .into_bytes(),
        ] {
            let mut changed = original.clone();
            changed.insert(name.into(), replacement);
            assert_eq!(validate_credentials(&changed), Err(REFUSED.into()));
        }
        let mut changed = original.clone();
        changed.insert(
            "feature_unknown_database_url".into(),
            b"not admitted".to_vec(),
        );
        assert!(validate_credentials(&changed).is_err());
        let mut changed = original;
        let mut inventory: serde_json::Value =
            serde_json::from_slice(&changed[PASSWORD_INVENTORY]).unwrap();
        inventory["roles"]["feature_approval_runtime"] = "ab".repeat(32).into();
        changed.insert(
            PASSWORD_INVENTORY.into(),
            serde_json::to_vec(&inventory).unwrap(),
        );
        assert!(validate_credentials(&changed).is_err());
        assert!(generate_with(|bytes| {
            bytes.fill(1);
            Ok(())
        })
        .is_err());
        assert!(generate_with(|_| Ok(())).is_err());
        assert!(generate_with(|_| Err(REFUSED.into())).is_err());
    }
}
