//! Immutable credential generations. Never activates a generation.
use crate::{
    operator::{Result, REFUSAL},
    operator_files::{finish_generation, generation_file, generation_output, private_directory},
};
use marty_selfhost_identity::SELFHOST_ROLES;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};
const CA: &str = "workload_identity_ca_cert";
const METADATA: &str = "selfhost-tls-kms-roles.json";
const FILE_MODES: &[u32] = &[0o400, 0o440, 0o444, 0o600, 0o640, 0o644];
type Files = BTreeMap<String, PathBuf>;
type Payloads = BTreeMap<String, (Vec<u8>, u32)>;

fn inventories() -> (BTreeSet<String>, BTreeSet<String>, BTreeSet<String>) {
    let mut tls = BTreeSet::from([CA.to_owned()]);
    let mut tokens = BTreeSet::new();
    for role in SELFHOST_ROLES {
        tls.insert(role.cert_file.into());
        tls.insert(role.token_file.into());
        tokens.insert(role.token_file.into());
    }
    let mut keycloak = BTreeSet::from(["keycloak_signing_kms_token".into()]);
    tokens.insert("keycloak_signing_kms_token".into());
    for realm in crate::keycloak::REALMS {
        keycloak.insert(format!("keycloak_{realm}_rs256_cert"));
        for purpose in crate::keycloak::PURPOSES {
            let name = format!("keycloak_{realm}_{purpose}_token");
            keycloak.insert(name.clone());
            tokens.insert(name);
        }
    }
    (tls, keycloak, tokens)
}
pub fn entries(root: &Path) -> Result<Files> {
    let mut found = Files::new();
    for entry in fs::read_dir(root).map_err(|_| "secret generation directory is absent")? {
        let entry = entry.map_err(|_| REFUSAL)?;
        let info = entry.file_type().map_err(|_| REFUSAL)?;
        if !info.is_file() || info.is_symlink() {
            return Err("secret generation contains a non-regular entry");
        }
        found.insert(
            entry.file_name().into_string().map_err(|_| REFUSAL)?,
            entry.path(),
        );
    }
    Ok(found)
}
fn single_pem(value: &[u8]) -> bool {
    let value = value.strip_suffix(b"\n").unwrap_or(value);
    let Some(value) = value
        .strip_prefix(b"-----BEGIN CERTIFICATE-----\n")
        .and_then(|v| v.strip_suffix(b"\n-----END CERTIFICATE-----"))
    else {
        return false;
    };
    !value.is_empty()
        && value.split(|c| *c == b'\n').all(|line| {
            !line.is_empty()
                && line
                    .iter()
                    .all(|c| c.is_ascii_alphanumeric() || b"+/=".contains(c))
        })
}
pub fn overlap(old: &[u8], new: &[u8]) -> Result<Vec<u8>> {
    if !single_pem(old)
        || !single_pem(new)
        || old.strip_suffix(b"\n").unwrap_or(old) == new.strip_suffix(b"\n").unwrap_or(new)
    {
        return Err("CA overlap requires two distinct single public certificates");
    }
    let mut result = old.strip_suffix(b"\n").unwrap_or(old).to_vec();
    result.push(b'\n');
    result.extend_from_slice(new.strip_suffix(b"\n").unwrap_or(new));
    result.push(b'\n');
    Ok(result)
}
pub fn retire(bundle: &[u8]) -> Result<Vec<u8>> {
    let refusal = "CA retirement requires an exact two-issuer public bundle";
    let marker = b"-----BEGIN CERTIFICATE-----\n";
    let split = bundle
        .windows(marker.len())
        .enumerate()
        .skip(marker.len())
        .find(|(_, s)| *s == marker)
        .map(|(i, _)| i)
        .ok_or(refusal)?;
    let (old, new) = bundle.split_at(split);
    if overlap(old, new).map_err(|_| refusal)? != bundle {
        return Err(refusal);
    }
    Ok(new.to_vec())
}
fn directory(path: &Path, empty: bool) -> Result<PathBuf> {
    let path = private_directory(path)
        .map_err(|_| "secret generation requires an existing POSIX private directory")?;
    if empty && fs::read_dir(&path).map_err(|_| REFUSAL)?.next().is_some() {
        return Err("new secret generation directory must be empty");
    }
    Ok(path)
}
fn owner(path: &Path) -> Result<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(fs::metadata(path).map_err(|_| REFUSAL)?.uid())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(REFUSAL)
    }
}
fn own_uid() -> Result<u32> {
    #[cfg(unix)]
    {
        Ok(unsafe { libc::getuid() })
    }
    #[cfg(not(unix))]
    {
        Err(REFUSAL)
    }
}
fn read(path: &Path, empty: bool) -> Result<(Vec<u8>, u32)> {
    generation_file(path, empty)
        .map_err(|_| "secret generation contains private or invalid material")
}
fn payloads(files: &Files, renewable: &BTreeSet<String>) -> Result<Payloads> {
    files
        .iter()
        .map(|(name, path)| Ok((name.clone(), read(path, !renewable.contains(name))?)))
        .collect()
}
fn tokens_distinct(values: &Payloads, tokens: &BTreeSet<String>) -> Result<()> {
    let mut found = BTreeSet::new();
    for name in tokens {
        if !found.insert(&values.get(name).ok_or(REFUSAL)?.0) {
            return Err("renewed scopes share a token");
        }
    }
    Ok(())
}
pub fn verify(
    current: &Path,
    candidate: &Path,
    ca_overlap: bool,
    ca_retire: bool,
) -> Result<(usize, usize)> {
    if ca_overlap && ca_retire {
        return Err("CA overlap and trust retirement are separate ceremonies");
    }
    let current = directory(current, false)?;
    let candidate = directory(candidate, false)?;
    if current == candidate {
        return Err("secret generations must be distinct");
    }
    let old = entries(&current)?;
    let new = entries(&candidate)?;
    let (tls, keycloak, tokens) = inventories();
    let renewable = tls.union(&keycloak).cloned().collect::<BTreeSet<_>>();
    if old.keys().ne(new.keys()) || !renewable.iter().all(|n| old.contains_key(n)) {
        return Err("secret generation file inventory changed");
    }
    let old = payloads(&old, &renewable)?;
    let new = payloads(&new, &renewable)?;
    let mut changed = 0;
    for (name, (before, mode)) in &old {
        let (after, new_mode) = new.get(name).ok_or(REFUSAL)?;
        if mode != new_mode {
            return Err("secret generation file mode changed");
        }
        let change = if ca_retire {
            name == CA
        } else {
            renewable.contains(name) && (name != CA || ca_overlap)
        };
        if (before != after) != change {
            return Err("secret generation changed the wrong input");
        }
        if name == CA && ca_overlap {
            let prefix = [before.strip_suffix(b"\n").unwrap_or(before), b"\n"].concat();
            if !after.starts_with(&prefix)
                || overlap(before, &after[prefix.len()..])
                    .map_err(|_| "CA overlap bundle is not the exact old and new public issuers")?
                    != *after
            {
                return Err("CA overlap bundle is not the exact old and new public issuers");
            }
        }
        if name == CA && ca_retire && *after != retire(before)? {
            return Err("CA retirement did not remove only the old public issuer");
        }
        changed += usize::from(change);
    }
    tokens_distinct(&new, &tokens)?;
    Ok((old.len(), changed))
}
fn write(
    values: &Payloads,
    current: &Path,
    output: &Path,
    ca_overlap: bool,
    ca_retire: bool,
) -> Result<usize> {
    write_verified(values, output, || {
        verify(current, output, ca_overlap, ca_retire).map(|_| ())
    })
}

/// Both generation profiles share exclusive writes and cleanup of only their own files.
fn write_verified(
    values: &Payloads,
    output: &Path,
    verify_output: impl FnOnce() -> Result<()>,
) -> Result<usize> {
    let mut created = Vec::new();
    let result = (|| {
        for (name, (value, mode)) in values {
            if !FILE_MODES.contains(mode) {
                return Err("active secret file has unsupported mode");
            }
            let destination = output.join(name);
            let mut file = generation_output(&destination)?;
            created.push(destination);
            finish_generation(&mut file, value, *mode)?;
        }
        verify_output()?;
        Ok(values.len())
    })();
    if result.is_err() {
        let mut failed = false;
        for path in created.iter().rev() {
            if fs::remove_file(path).is_err() {
                failed = true;
            }
        }
        if failed {
            return Err("secret generation rollback requires operator recovery");
        }
    }
    result
}

fn application_inventory() -> (BTreeSet<String>, BTreeSet<String>, BTreeSet<String>) {
    let ordinary = crate::application_tokens::specifications()
        .into_iter()
        .map(|spec| spec.file)
        .collect::<BTreeSet<_>>();
    let runtime = crate::application_tokens::runtime_specs()
        .into_iter()
        .map(|spec| spec.file)
        .collect::<BTreeSet<_>>();
    let (tls, keycloak, mut tokens) = inventories();
    let mut required = tls.union(&keycloak).cloned().collect::<BTreeSet<_>>();
    required.extend(ordinary.iter().cloned());
    tokens.extend(ordinary);
    (required, runtime, tokens)
}

/// Existing writers may add one line ending; it cannot make an old token new.
fn normalized_token(value: &[u8]) -> Result<&[u8]> {
    let value = value.strip_suffix(b"\n").unwrap_or(value);
    if !(20..=1024).contains(&value.len()) || !value.iter().all(u8::is_ascii_graphic) {
        return Err("application generation contains an invalid token");
    }
    Ok(value)
}

fn application_current_tokens<'a>(
    current: &'a Payloads,
    tokens: &BTreeSet<String>,
) -> Result<BTreeSet<&'a [u8]>> {
    if current.values().any(|(_, mode)| !FILE_MODES.contains(mode)) {
        return Err("application generation file mode changed or is unsupported");
    }
    tokens
        .iter()
        .map(|name| normalized_token(&current.get(name).ok_or(REFUSAL)?.0))
        .collect()
}

fn application_payloads(
    current: &Payloads,
    candidate: &Payloads,
    runtime: &BTreeSet<String>,
    tokens: &BTreeSet<String>,
) -> Result<()> {
    if current.keys().ne(candidate.keys()) {
        return Err("application generation file inventory changed");
    }
    let previous_tokens = application_current_tokens(current, tokens)?;
    let mut replacements = BTreeSet::new();
    for (name, (before, mode)) in current {
        let (after, new_mode) = candidate.get(name).ok_or(REFUSAL)?;
        if mode != new_mode {
            return Err("application generation file mode changed or is unsupported");
        }
        if runtime.contains(name) {
            let token = normalized_token(after)?;
            if previous_tokens.contains(token) || !replacements.insert(token) {
                return Err("application generation reuses a token");
            }
        } else if before != after {
            return Err("application generation changed a preserved input");
        }
    }
    Ok(())
}

fn application_current_payloads(
    files: &Files,
    required: &BTreeSet<String>,
    tokens: &BTreeSet<String>,
) -> Result<Payloads> {
    if !required.iter().all(|name| files.contains_key(name)) {
        return Err("active generation lacks a required credential input");
    }
    let values = payloads(files, required)?;
    application_current_tokens(&values, tokens)?;
    Ok(values)
}

/// Read-only full-generation preflight before replacement authority is exercised.
pub fn check_application(current: &Path) -> Result<usize> {
    let current = directory(current, false)?;
    let (required, _, tokens) = application_inventory();
    let values = application_current_payloads(&entries(&current)?, &required, &tokens)?;
    Ok(values.len())
}

/// Verify a complete application-token candidate without touching the active generation.
/// Authorization of the minted tokens and live activation remain separate operations.
pub fn verify_application(current: &Path, candidate: &Path) -> Result<(usize, usize)> {
    let current = directory(current, false)?;
    let candidate = directory(candidate, false)?;
    if current == candidate || owner(&candidate)? != own_uid()? {
        return Err("application generation directories are invalid");
    }
    let old = entries(&current)?;
    let new = entries(&candidate)?;
    let (required, runtime, tokens) = application_inventory();
    if old.keys().ne(new.keys()) {
        return Err("application generation file inventory changed");
    }
    let old = application_current_payloads(&old, &required, &tokens)?;
    let new = payloads(&new, &required)?;
    application_payloads(&old, &new, &runtime, &tokens)?;
    Ok((old.len(), runtime.len()))
}

fn verify_application_snapshot(
    current: &Path,
    candidate: &Path,
    before: &Payloads,
    required: &BTreeSet<String>,
) -> Result<()> {
    verify_application(current, candidate)?;
    if payloads(&entries(current)?, required)? != *before {
        return Err("active generation changed during application staging");
    }
    Ok(())
}

/// Overlay only the closed application-token inventory, retaining minted inputs on failure.
pub fn stage_application(current: &Path, replacements: &Path, output: &Path) -> Result<usize> {
    let roots = [
        directory(current, false)?,
        directory(replacements, false)?,
        directory(output, true)?,
    ];
    if roots.iter().collect::<BTreeSet<_>>().len() != 3 {
        return Err("application generation directories must be distinct");
    }
    let [current, replacements, output] = &roots;
    let uid = own_uid()?;
    if owner(output)? != uid || ![uid, owner(current)?].contains(&owner(replacements)?) {
        return Err("application generation directory has an unexpected owner");
    }
    let active = entries(current)?;
    let replacement_files = entries(replacements)?;
    let (required, runtime, tokens) = application_inventory();
    if replacement_files.keys().cloned().collect::<BTreeSet<_>>() != runtime {
        return Err("application replacement inventory differs from fixed runtime tokens");
    }
    let before = application_current_payloads(&active, &required, &tokens)?;
    let mut values = before.clone();
    for (name, path) in &replacement_files {
        let (value, mode) = read(path, false)?;
        if ![0o400, 0o600].contains(&mode) {
            return Err("application replacement token must be owner-private");
        }
        let active_mode = values.get(name).ok_or(REFUSAL)?.1;
        values.insert(name.clone(), (value, active_mode));
    }
    application_payloads(&before, &values, &runtime, &tokens)?;
    write_verified(&values, output, || {
        verify_application_snapshot(current, output, &before, &required)
    })
}
fn metadata(path: &Path) -> Result<()> {
    // Deserialize duplicate fields as errors rather than silently taking the last.
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Metadata {
        schema: String,
        roles: Vec<Role>,
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Role {
        role: String,
        key_name: String,
        version: u64,
    }
    let bytes = read(path, false)?.0;
    if bytes.len() > 8192 || !bytes.is_ascii() {
        return Err("disposable TLS key metadata is oversized");
    }
    let value: Metadata = serde_json::from_slice(&bytes)
        .map_err(|_| "disposable TLS key metadata has invalid shape")?;
    let mut found = BTreeSet::new();
    if value.schema != "marty.selfhost-disposable-tls-keys/v1"
        || value.roles.len() != SELFHOST_ROLES.len()
    {
        return Err("disposable TLS key metadata has invalid shape");
    }
    for role in value.roles {
        if role.version != 1
            || !SELFHOST_ROLES
                .iter()
                .any(|r| r.name == role.role && r.key_name == role.key_name)
            || !found.insert(role.role)
        {
            return Err("disposable TLS key metadata differs from fixed roles");
        }
    }
    Ok(())
}
pub fn stage(
    current: &Path,
    tls: &Path,
    keycloak: &Path,
    output: &Path,
    ca_overlap: bool,
) -> Result<usize> {
    let roots = [
        directory(current, false)?,
        directory(tls, false)?,
        directory(keycloak, false)?,
        directory(output, true)?,
    ];
    if roots.iter().collect::<BTreeSet<_>>().len() != 4 {
        return Err("secret generation directories must be distinct");
    }
    let [current, tls, keycloak, output] = &roots;
    let uid = own_uid()?;
    let active_owner = owner(current)?;
    if owner(output)? != uid
        || [tls, keycloak]
            .into_iter()
            .any(|p| owner(p).map_or(true, |o| o != uid && o != active_owner))
    {
        return Err("secret generation directory has an unexpected owner");
    }
    let active = entries(current)?;
    let tls_files = entries(tls)?;
    let keycloak_files = entries(keycloak)?;
    let (tls_names, keycloak_names, tokens) = inventories();
    let renewable = tls_names
        .union(&keycloak_names)
        .cloned()
        .collect::<BTreeSet<_>>();
    if !renewable.iter().all(|n| active.contains_key(n)) {
        return Err("active generation lacks a renewable input");
    }
    let mut expected = tls_names;
    expected.insert(METADATA.into());
    if tls_files.keys().cloned().collect::<BTreeSet<_>>() != expected {
        return Err("workload TLS candidate is incomplete");
    }
    if keycloak_files.keys().cloned().collect::<BTreeSet<_>>() != keycloak_names {
        return Err("Keycloak candidate is incomplete");
    }
    metadata(&tls.join(METADATA))?;
    let mut values = payloads(&active, &renewable)?;
    for (name, path) in tls_files.iter().chain(&keycloak_files) {
        if name == METADATA {
            continue;
        }
        let mut value = read(path, false)?.0;
        let (before, mode) = values.get(name).ok_or(REFUSAL)?;
        if name == CA {
            if ca_overlap {
                value = overlap(before, &value)?;
            } else if value != *before {
                return Err("CA rollover needs a separate trust-overlap ceremony");
            }
        } else if value == *before {
            return Err("renewed input did not change");
        }
        values.insert(name.clone(), (value, *mode));
    }
    tokens_distinct(&values, &tokens)?;
    write(&values, current, output, ca_overlap, false)
}
pub fn stage_retired(current: &Path, output: &Path) -> Result<usize> {
    let current = directory(current, false)?;
    let output = directory(output, true)?;
    if current == output || owner(&output)? != own_uid()? {
        return Err("CA retirement generation directories are invalid");
    }
    let active = entries(&current)?;
    let (tls, keycloak, _) = inventories();
    let renewable = tls.union(&keycloak).cloned().collect::<BTreeSet<_>>();
    if !renewable.iter().all(|n| active.contains_key(n)) {
        return Err("active generation lacks a renewable input");
    }
    let mut values = payloads(&active, &renewable)?;
    let (ca, mode) = values.get(CA).ok_or(REFUSAL)?;
    values.insert(CA.into(), (retire(ca)?, *mode));
    write(&values, &current, &output, false, true)
}
/// Fixed commands, JSON errors allow the compatibility adapter to retain ValueError.
pub fn operation(context: &Value) -> Result<Value> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let path = |name: &str| context[name].as_str().map(Path::new).ok_or(REFUSAL);
    let flag = |name: &str| context[name].as_bool().ok_or(REFUSAL);
    match context["operation"].as_str().ok_or(REFUSAL)? {
        "application-check" => Ok(json!(check_application(path("current")?)?)),
        "application-verify" => Ok(json!(verify_application(
            path("current")?,
            path("candidate")?
        )?)),
        "application-stage" => Ok(json!(stage_application(
            path("current")?,
            path("replacements")?,
            path("output")?
        )?)),
        "verify" => Ok(json!(verify(
            path("current")?,
            path("candidate")?,
            flag("ca_overlap")?,
            flag("ca_retire")?
        )?)),
        "stage" => Ok(json!(stage(
            path("current")?,
            path("tls")?,
            path("keycloak")?,
            path("output")?,
            flag("ca_overlap")?
        )?)),
        "retire" => Ok(json!(stage_retired(path("current")?, path("output")?)?)),
        "entries" => Ok(json!(entries(path("root")?)?.keys().collect::<Vec<_>>())),
        "read" => Ok(json!(
            STANDARD.encode(read(path("path")?, flag("allow_empty")?)?.0)
        )),
        "overlap" => Ok(json!(STANDARD.encode(overlap(
            &STANDARD
                .decode(context["old"].as_str().ok_or(REFUSAL)?)
                .map_err(|_| REFUSAL)?,
            &STANDARD
                .decode(context["new"].as_str().ok_or(REFUSAL)?)
                .map_err(|_| REFUSAL)?
        )?))),
        "retired-trust" => Ok(json!(STANDARD.encode(retire(
            &STANDARD
                .decode(context["bundle"].as_str().ok_or(REFUSAL)?)
                .map_err(|_| REFUSAL)?
        )?))),
        _ => Err(REFUSAL),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn partial_generations_rollback_each_position_and_preserve_existing_data() {
        let root = tempfile::tempdir().unwrap();
        let output = root.path().join("output");
        fs::create_dir(&output).unwrap();
        let keep = output.join("operator-note");
        fs::write(&keep, b"keep").unwrap();
        for fail in 0..7 {
            let values: Payloads = (0..7)
                .map(|n| {
                    (
                        format!("{n:02}"),
                        (
                            b"public-bytes\n".to_vec(),
                            if n == fail { 0o777 } else { 0o644 },
                        ),
                    )
                })
                .collect();
            assert!(write(&values, root.path(), &output, false, false).is_err());
            assert_eq!(fs::read(&keep).unwrap(), b"keep");
            assert_eq!(fs::read_dir(&output).unwrap().count(), 1);
        }
        let collision = output.join("01");
        fs::write(&collision, b"untouched").unwrap();
        let values: Payloads = (0..3)
            .map(|n| (format!("{n:02}"), (b"replacement".to_vec(), 0o644)))
            .collect();
        assert!(write(&values, root.path(), &output, false, false).is_err());
        assert!(!output.join("00").exists());
        assert!(!output.join("02").exists());
        assert_eq!(fs::read(&collision).unwrap(), b"untouched");
    }

    #[test]
    fn bounded_files_reject_links_fifos_private_and_oversized_data() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("value");
        for value in [
            vec![],
            b"PRIVATE KEY".to_vec(),
            b"public\0data".to_vec(),
            vec![b'a'; 65537],
        ] {
            fs::write(&file, value).unwrap();
            assert!(read(&file, false).is_err());
        }
        fs::write(&file, b"public\ncertificate\n").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o444)).unwrap();
        let (bytes, mode) = read(&file, false).unwrap();
        assert_eq!(bytes, b"public\ncertificate\n");
        assert_eq!(mode, 0o444);
        let link = root.path().join("link");
        symlink(&file, &link).unwrap();
        assert!(read(&link, false).is_err());
        assert!(entries(root.path()).is_err());
        let fifo = root.path().join("fifo");
        let name = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(read(&fifo, false).is_err());
    }

    struct ApplicationFixture {
        root: tempfile::TempDir,
        current: PathBuf,
        replacements: PathBuf,
        output: PathBuf,
    }

    fn private_test_directory(parent: &Path, name: &str) -> PathBuf {
        let path = parent.join(name);
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    fn put(root: &Path, name: &str, value: &[u8], mode: u32) {
        let path = root.join(name);
        if let Ok(info) = fs::symlink_metadata(&path) {
            assert!(info.file_type().is_file());
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        fs::write(&path, value).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn snapshot(root: &Path) -> Payloads {
        payloads(&entries(root).unwrap(), &BTreeSet::new()).unwrap()
    }

    fn application_fixture() -> ApplicationFixture {
        let root = tempfile::tempdir().unwrap();
        let current = private_test_directory(root.path(), "current");
        let replacements = private_test_directory(root.path(), "inputs");
        let output = private_test_directory(root.path(), "candidate");
        let (required, runtime, tokens) = application_inventory();
        assert_eq!(required.len(), 53);
        assert_eq!(runtime.len(), 11);
        assert_eq!(tokens.len(), 34);
        for (index, name) in required.iter().enumerate() {
            let (value, mode) = if tokens.contains(name) {
                (format!("synthetic-active-token-{name}"), 0o600)
            } else {
                (
                    format!("synthetic-public-certificate-{name}\n"),
                    FILE_MODES[index % FILE_MODES.len()],
                )
            };
            put(&current, name, value.as_bytes(), mode);
        }
        let first = runtime.first().unwrap();
        fs::set_permissions(current.join(first), fs::Permissions::from_mode(0o400)).unwrap();
        put(
            &current,
            "postgres_password",
            b"synthetic-fixed-database-password",
            0o600,
        );
        put(&current, "optional_static", b"", 0o640);
        for (index, name) in runtime.iter().enumerate() {
            let ending = if index % 2 == 0 { "\n" } else { "" };
            let value = format!("synthetic-new-token-{name}{ending}");
            let mode = if index % 2 == 0 { 0o600 } else { 0o400 };
            put(&replacements, name, value.as_bytes(), mode);
        }
        ApplicationFixture {
            root,
            current,
            replacements,
            output,
        }
    }

    fn assert_no_candidate(fixture: &ApplicationFixture) {
        let error = stage_application(&fixture.current, &fixture.replacements, &fixture.output)
            .unwrap_err();
        assert!(!error.contains("synthetic"));
        assert_eq!(fs::read_dir(&fixture.output).unwrap().count(), 0);
    }

    #[test]
    fn application_check_refuses_invalid_current_without_mutating_inputs() {
        let fixture = application_fixture();
        let before = snapshot(&fixture.current);
        let minted = snapshot(&fixture.replacements);
        let (required, _, tokens) = application_inventory();
        assert_eq!(
            operation(&json!({
                "operation": "application-check",
                "current": fixture.current.to_str().unwrap(),
            }))
            .unwrap(),
            json!(before.len())
        );
        for name in &required {
            fs::remove_file(fixture.current.join(name)).unwrap();
            assert!(check_application(&fixture.current).is_err());
            put(&fixture.current, name, &before[name].0, before[name].1);
        }
        for name in &tokens {
            put(&fixture.current, name, b"invalid-old-token", before[name].1);
            let invalid = snapshot(&fixture.current);
            assert!(check_application(&fixture.current).is_err());
            assert_eq!(snapshot(&fixture.current), invalid);
            put(&fixture.current, name, &before[name].0, before[name].1);
        }
        let first = tokens.first().unwrap();
        fs::set_permissions(
            fixture.current.join(first),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        assert!(check_application(&fixture.current).is_err());
        assert_eq!(
            fs::metadata(fixture.current.join(first))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o700,
        );
        fs::set_permissions(
            fixture.current.join(first),
            fs::Permissions::from_mode(before[first].1),
        )
        .unwrap();
        put(
            &fixture.current,
            "unexpected_private_key",
            b"-----BEGIN PRIVATE KEY-----",
            0o600,
        );
        assert!(check_application(&fixture.current).is_err());
        assert_eq!(
            fs::read(fixture.current.join("unexpected_private_key")).unwrap(),
            b"-----BEGIN PRIVATE KEY-----",
        );
        fs::remove_file(fixture.current.join("unexpected_private_key")).unwrap();
        assert_eq!(check_application(&fixture.current).unwrap(), before.len());
        assert_eq!(snapshot(&fixture.current), before);
        assert_eq!(snapshot(&fixture.replacements), minted);
        assert_eq!(fs::read_dir(&fixture.output).unwrap().count(), 0);
    }

    #[test]
    fn application_stage_preserves_every_other_input_and_exposes_fixed_operations() {
        let fixture = application_fixture();
        let before = snapshot(&fixture.current);
        let minted = snapshot(&fixture.replacements);
        let (_, runtime, _) = application_inventory();
        assert_eq!(
            operation(&json!({
                "operation": "application-stage",
                "current": fixture.current.to_str().unwrap(),
                "replacements": fixture.replacements.to_str().unwrap(),
                "output": fixture.output.to_str().unwrap(),
            }))
            .unwrap(),
            json!(before.len())
        );
        let candidate = snapshot(&fixture.output);
        assert!(before.keys().eq(candidate.keys()));
        for (name, (value, mode)) in &candidate {
            assert_eq!(*mode, before[name].1);
            if runtime.contains(name) {
                assert_eq!(value, &minted[name].0);
                assert_ne!(normalized_token(value), normalized_token(&before[name].0));
            } else {
                assert_eq!(value, &before[name].0);
            }
        }
        assert_eq!(
            operation(&json!({
                "operation": "application-verify",
                "current": fixture.current.to_str().unwrap(),
                "candidate": fixture.output.to_str().unwrap(),
            }))
            .unwrap(),
            json!([before.len(), 11])
        );
        assert!(verify(&fixture.current, &fixture.output, false, false).is_err());
        assert!(
            stage_application(&fixture.current, &fixture.replacements, &fixture.output,).is_err()
        );
        assert_eq!(snapshot(&fixture.current), before);
        assert_eq!(snapshot(&fixture.replacements), minted);
        assert_eq!(snapshot(&fixture.output), candidate);
    }

    #[test]
    fn application_stage_rejects_each_missing_required_file_and_extra_minted_inputs() {
        let fixture = application_fixture();
        let before = snapshot(&fixture.current);
        let minted = snapshot(&fixture.replacements);
        let (required, runtime, _) = application_inventory();
        for name in &required {
            fs::remove_file(fixture.current.join(name)).unwrap();
            assert_no_candidate(&fixture);
            let (value, mode) = &before[name];
            put(&fixture.current, name, value, *mode);
        }
        for name in &runtime {
            fs::remove_file(fixture.replacements.join(name)).unwrap();
            assert_no_candidate(&fixture);
            let (value, mode) = &minted[name];
            put(&fixture.replacements, name, value, *mode);
        }
        for name in [
            "unexpected_token",
            "openbao_bootstrap_token",
            "openbao_service_token",
        ] {
            put(
                &fixture.replacements,
                name,
                b"synthetic-unexpected-token",
                0o600,
            );
            assert_no_candidate(&fixture);
            assert_eq!(
                fs::read(fixture.replacements.join(name)).unwrap(),
                b"synthetic-unexpected-token",
            );
            fs::remove_file(fixture.replacements.join(name)).unwrap();
        }
        assert_eq!(snapshot(&fixture.current), before);
        assert_eq!(snapshot(&fixture.replacements), minted);
    }

    #[test]
    fn application_verify_refuses_inventory_mode_and_preserved_file_drift() {
        let fixture = application_fixture();
        let before = snapshot(&fixture.current);
        stage_application(&fixture.current, &fixture.replacements, &fixture.output).unwrap();
        let candidate = snapshot(&fixture.output);
        let (_, runtime, _) = application_inventory();
        for (name, (value, mode)) in &candidate {
            fs::remove_file(fixture.output.join(name)).unwrap();
            assert!(verify_application(&fixture.current, &fixture.output).is_err());
            put(&fixture.output, name, value, *mode);
            let changed_mode = if *mode == 0o400 { 0o600 } else { 0o400 };
            fs::set_permissions(
                fixture.output.join(name),
                fs::Permissions::from_mode(changed_mode),
            )
            .unwrap();
            assert!(verify_application(&fixture.current, &fixture.output).is_err());
            fs::set_permissions(fixture.output.join(name), fs::Permissions::from_mode(*mode))
                .unwrap();
            if !runtime.contains(name) {
                let mut changed = value.clone();
                changed.push(b'x');
                put(&fixture.output, name, &changed, *mode);
                assert!(verify_application(&fixture.current, &fixture.output).is_err());
                put(&fixture.output, name, value, *mode);
            }
        }
        put(&fixture.output, "unexpected_file", b"operator-note", 0o600);
        assert!(verify_application(&fixture.current, &fixture.output).is_err());
        fs::remove_file(fixture.output.join("unexpected_file")).unwrap();
        assert_eq!(
            verify_application(&fixture.current, &fixture.output).unwrap(),
            (before.len(), 11),
        );
        assert_eq!(snapshot(&fixture.current), before);
        assert_eq!(snapshot(&fixture.output), candidate);
    }

    #[test]
    fn application_stage_rejects_shared_old_and_malformed_tokens_without_writes() {
        let fixture = application_fixture();
        let before = snapshot(&fixture.current);
        let minted = snapshot(&fixture.replacements);
        let (_, runtime, tokens) = application_inventory();
        let first = runtime.first().unwrap();
        for name in &tokens {
            let mut reused = normalized_token(&before[name].0).unwrap().to_vec();
            reused.push(b'\n');
            put(&fixture.replacements, first, &reused, 0o600);
            assert_no_candidate(&fixture);
            assert_eq!(fs::read(fixture.replacements.join(first)).unwrap(), reused);
        }
        put(
            &fixture.replacements,
            first,
            &minted[first].0,
            minted[first].1,
        );
        for name in &runtime {
            let mut unchanged = normalized_token(&before[name].0).unwrap().to_vec();
            unchanged.push(b'\n');
            put(&fixture.replacements, name, &unchanged, 0o600);
            assert_no_candidate(&fixture);
            put(&fixture.replacements, name, &minted[name].0, minted[name].1);
        }
        let second = runtime.iter().nth(1).unwrap();
        put(
            &fixture.replacements,
            second,
            normalized_token(&minted[first].0).unwrap(),
            0o600,
        );
        assert_no_candidate(&fixture);
        put(
            &fixture.replacements,
            second,
            &minted[second].0,
            minted[second].1,
        );
        for invalid in [
            vec![],
            vec![b'a'; 19],
            vec![b'a'; 1025],
            vec![b'a'; 65537],
            b"synthetic-token with-space".to_vec(),
            b"synthetic-token\twith-tab".to_vec(),
            b"synthetic-token\nwith-line".to_vec(),
            b"synthetic-token-ending\r\n".to_vec(),
            b"synthetic-token-ending\n\n".to_vec(),
            b"synthetic-token-with-\0nul".to_vec(),
            b"synthetic-token-with-\xffbyte".to_vec(),
            b"synthetic PRIVATE KEY value".to_vec(),
        ] {
            put(&fixture.replacements, first, &invalid, 0o600);
            assert_no_candidate(&fixture);
            assert_eq!(fs::read(fixture.replacements.join(first)).unwrap(), invalid);
        }
        put(
            &fixture.replacements,
            first,
            &minted[first].0,
            minted[first].1,
        );
        assert_eq!(snapshot(&fixture.current), before);
        assert_eq!(snapshot(&fixture.replacements), minted);
    }

    #[test]
    fn application_stage_refuses_nonprivate_or_aliased_directories_and_token_files() {
        let fixture = application_fixture();
        let before = snapshot(&fixture.current);
        let minted = snapshot(&fixture.replacements);
        let (_, runtime, _) = application_inventory();
        let first = runtime.first().unwrap();
        for mode in [0o444, 0o640, 0o644, 0o700] {
            fs::set_permissions(
                fixture.replacements.join(first),
                fs::Permissions::from_mode(mode),
            )
            .unwrap();
            assert_no_candidate(&fixture);
        }
        fs::set_permissions(
            fixture.replacements.join(first),
            fs::Permissions::from_mode(minted[first].1),
        )
        .unwrap();
        fs::set_permissions(
            fixture.current.join(first),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        assert_no_candidate(&fixture);
        fs::set_permissions(
            fixture.current.join(first),
            fs::Permissions::from_mode(before[first].1),
        )
        .unwrap();
        for root in [&fixture.current, &fixture.replacements, &fixture.output] {
            fs::set_permissions(root, fs::Permissions::from_mode(0o755)).unwrap();
            assert_no_candidate(&fixture);
            fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        assert!(stage_application(&fixture.current, &fixture.current, &fixture.output).is_err());
        assert!(
            stage_application(&fixture.current, &fixture.replacements, &fixture.current,).is_err()
        );
        assert!(stage_application(
            &fixture.current,
            &fixture.replacements,
            &fixture.replacements,
        )
        .is_err());
        assert!(stage_application(
            Path::new("relative-generation"),
            &fixture.replacements,
            &fixture.output,
        )
        .is_err());
        let alias = fixture.root.path().join("inputs-alias");
        symlink(&fixture.replacements, &alias).unwrap();
        assert!(stage_application(&fixture.current, &alias, &fixture.output).is_err());
        put(&fixture.output, "operator-note", b"keep-existing", 0o600);
        assert!(
            stage_application(&fixture.current, &fixture.replacements, &fixture.output,).is_err()
        );
        assert_eq!(snapshot(&fixture.output).len(), 1);
        assert_eq!(
            fs::read(fixture.output.join("operator-note")).unwrap(),
            b"keep-existing",
        );
        assert_eq!(snapshot(&fixture.current), before);
        assert_eq!(snapshot(&fixture.replacements), minted);
    }

    #[test]
    fn application_stage_and_verify_refuse_symlinks_and_nonregular_entries() {
        let fixture = application_fixture();
        let before = snapshot(&fixture.current);
        let minted = snapshot(&fixture.replacements);
        let (_, runtime, _) = application_inventory();
        let first = runtime.first().unwrap();
        let input = fixture.replacements.join(first);
        let active = fixture.current.join(first);
        fs::remove_file(&input).unwrap();
        symlink(&active, &input).unwrap();
        assert_no_candidate(&fixture);
        assert!(fs::symlink_metadata(&input)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read(&active).unwrap(), before[first].0);
        fs::remove_file(&input).unwrap();
        let name = std::ffi::CString::new(input.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert_no_candidate(&fixture);
        fs::remove_file(&input).unwrap();
        fs::create_dir(&input).unwrap();
        assert_no_candidate(&fixture);
        fs::remove_dir(&input).unwrap();
        put(
            &fixture.replacements,
            first,
            &minted[first].0,
            minted[first].1,
        );
        fs::remove_file(&active).unwrap();
        symlink(&input, &active).unwrap();
        assert_no_candidate(&fixture);
        fs::remove_file(&active).unwrap();
        put(&fixture.current, first, &before[first].0, before[first].1);
        stage_application(&fixture.current, &fixture.replacements, &fixture.output).unwrap();
        let candidate_file = fixture.output.join(first);
        fs::remove_file(&candidate_file).unwrap();
        symlink(&active, &candidate_file).unwrap();
        assert!(verify_application(&fixture.current, &fixture.output).is_err());
        assert!(fs::symlink_metadata(&candidate_file)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(snapshot(&fixture.current), before);
        assert_eq!(snapshot(&fixture.replacements), minted);
    }

    #[test]
    fn application_candidate_write_failures_clean_only_created_files() {
        let fixture = application_fixture();
        let before = snapshot(&fixture.current);
        let minted = snapshot(&fixture.replacements);
        stage_application(&fixture.current, &fixture.replacements, &fixture.output).unwrap();
        let values = snapshot(&fixture.output);
        let failure_output = private_test_directory(fixture.root.path(), "write-failure");
        put(&failure_output, "operator-note", b"keep-existing", 0o600);
        let collision = values.keys().nth(values.len() / 2).unwrap();
        put(&failure_output, collision, b"keep-collision", 0o600);
        let preexisting = snapshot(&failure_output);
        assert!(write_verified(&values, &failure_output, || {
            verify_application(&fixture.current, &failure_output).map(|_| ())
        })
        .is_err());
        assert_eq!(snapshot(&failure_output), preexisting);
        fs::remove_file(failure_output.join(collision)).unwrap();
        let preexisting = snapshot(&failure_output);
        assert!(write_verified(&values, &failure_output, || {
            verify_application(&fixture.current, &failure_output).map(|_| ())
        })
        .is_err());
        assert_eq!(snapshot(&failure_output), preexisting);
        assert_eq!(snapshot(&fixture.current), before);
        assert_eq!(snapshot(&fixture.replacements), minted);
        assert_eq!(snapshot(&fixture.output), values);
    }

    #[test]
    fn application_candidate_validation_detects_source_drift_after_snapshot() {
        let fixture = application_fixture();
        let before = snapshot(&fixture.current);
        let minted = snapshot(&fixture.replacements);
        let (required, runtime, _) = application_inventory();
        stage_application(&fixture.current, &fixture.replacements, &fixture.output).unwrap();
        let values = snapshot(&fixture.output);
        let first = runtime.first().unwrap();
        put(
            &fixture.current,
            first,
            b"synthetic-concurrently-changed-active-token",
            before[first].1,
        );
        assert!(verify_application(&fixture.current, &fixture.output).is_ok());
        assert!(
            verify_application_snapshot(&fixture.current, &fixture.output, &before, &required,)
                .is_err()
        );
        let failure_output = private_test_directory(fixture.root.path(), "source-drift");
        assert!(write_verified(&values, &failure_output, || {
            verify_application_snapshot(&fixture.current, &failure_output, &before, &required)
        })
        .is_err());
        assert_eq!(fs::read_dir(&failure_output).unwrap().count(), 0);
        assert_eq!(snapshot(&fixture.replacements), minted);
        assert_eq!(snapshot(&fixture.output), values);
        put(&fixture.current, first, &before[first].0, before[first].1);
        assert_eq!(
            verify_application(&fixture.current, &fixture.output).unwrap(),
            (before.len(), 11),
        );
        assert_eq!(snapshot(&fixture.current), before);
    }
}
