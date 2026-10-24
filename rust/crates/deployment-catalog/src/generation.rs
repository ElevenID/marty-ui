//! Immutable KMS-only secret generations. Never activates a generation.
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
    let mut created = Vec::new();
    let result = (|| {
        for (name, (value, mode)) in values {
            if ![0o400, 0o440, 0o444, 0o600, 0o640, 0o644].contains(mode) {
                return Err("active secret file has unsupported mode");
            }
            let destination = output.join(name);
            let mut file = generation_output(&destination)?;
            created.push(destination);
            finish_generation(&mut file, value, *mode)?;
        }
        verify(current, output, ca_overlap, ca_retire)?;
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
}
