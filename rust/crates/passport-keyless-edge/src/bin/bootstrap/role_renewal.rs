//! Pins for renewing the one existing trust-role key, never creating a key or CA.
use super::{checked_existing_role, checked_transit_key_metadata, data, value, Profile, Role};
use marty_crypto::{certificate, serialization};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    error::Error,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

pub(super) const INPUTS: [&str; 7] = [
    "MARTY_TLS_RENEW_PREVIOUS_CERT_FILE",
    "MARTY_TLS_RENEW_PREVIOUS_CERT_SHA256",
    "MARTY_TLS_RENEW_CA_SHA256",
    "MARTY_TLS_RENEW_ROLE_SHA256",
    "MARTY_TLS_RENEW_RESTORE_OWNED_POLICY",
    "MARTY_TLS_RENEW_CYCLE_ID",
    "MARTY_TLS_RENEW_RECOVERY_DIR",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ExistingTrustRole {
    previous_certificate: PathBuf,
    previous_certificate_sha256: String,
    ca_sha256: String,
    role_sha256: String,
    allow_owned_policy_restore: bool,
    cycle_id: String,
    recovery: PathBuf,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum SignerPolicy {
    Reuse,
    Restore,
}

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn hash_value(value: Option<&str>) -> Result<String, Box<dyn Error>> {
    value
        .filter(|v| {
            v.len() == 64
                && v.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        .map(str::to_owned)
        .ok_or_else(|| "existing-key renewal requires an exact SHA256 pin".into())
}

fn public_file(path: &Path, digest: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if !path.is_absolute()
        || !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > 65536
    {
        return Err("existing-key renewal public input is invalid".into());
    }
    let mut bytes = Vec::new();
    fs::File::open(path)?.take(65537).read_to_end(&mut bytes)?;
    if bytes.is_empty()
        || bytes.len() > 65536
        || !bytes.is_ascii()
        || hash(&bytes) != digest
        || bytes.windows(11).any(|b| b == b"PRIVATE KEY")
    {
        return Err("existing-key renewal public input changed".into());
    }
    Ok(bytes)
}

fn cert_der(pem: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(certificate::load_certificate_pem(std::str::from_utf8(
        pem,
    )?)?)
}

// Match the existing provider receipt's recursively sorted compact JSON, without
// depending on serde_json's optional map insertion-order feature.
fn sorted_value(value: &Value) -> Value {
    match value {
        Value::Object(fields) => Value::Object(
            fields
                .iter()
                .map(|(k, v)| (k.clone(), sorted_value(v)))
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.iter().map(sorted_value).collect()),
        _ => value.clone(),
    }
}

impl ExistingTrustRole {
    pub(super) fn from_values<'a>(
        active: bool,
        get: impl Fn(&str) -> Option<&'a str>,
    ) -> Result<Option<Self>, Box<dyn Error>> {
        if !active {
            if INPUTS.iter().any(|name| get(name).is_some()) {
                return Err("existing-key renewal inputs require their explicit profile".into());
            }
            return Ok(None);
        }
        let file = get(INPUTS[0])
            .filter(|v| !v.contains(['\r', '\n']))
            .ok_or("existing-key renewal previous certificate is required")?;
        if !Path::new(file).is_absolute() {
            return Err("existing-key renewal previous certificate must be absolute".into());
        }
        let allow_owned_policy_restore = match get(INPUTS[4]) {
            Some("0") => false,
            Some("1") => true,
            _ => return Err("existing-key renewal policy restoration must be explicit".into()),
        };
        let cycle_id = get(INPUTS[5])
            .filter(|v| {
                v.len() == 32
                    && v.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
            .ok_or("existing-key renewal requires a closed cycle ID")?;
        let recovery = get(INPUTS[6])
            .filter(|v| Path::new(v).is_absolute() && !v.contains(['\r', '\n']))
            .ok_or("existing-key renewal requires an absolute recovery directory")?;
        Ok(Some(Self {
            previous_certificate: file.into(),
            previous_certificate_sha256: hash_value(get(INPUTS[1]))?,
            ca_sha256: hash_value(get(INPUTS[2]))?,
            role_sha256: hash_value(get(INPUTS[3]))?,
            allow_owned_policy_restore,
            cycle_id: cycle_id.into(),
            recovery: recovery.into(),
        }))
    }

    pub(super) fn cycle_id(&self) -> &str {
        &self.cycle_id
    }

    pub(super) fn prepare_recovery(
        &self,
        output: &Path,
        project: &str,
        key: &str,
        mount: &str,
        restore: bool,
    ) -> Result<(), Box<dyn Error>> {
        let parent = output.parent().ok_or("renewal output parent is absent")?;
        let expected_parent = format!("renewal-{}", self.cycle_id);
        if parent.file_name().and_then(|v| v.to_str()) != Some(expected_parent.as_str())
            || self.recovery != parent.join("recovery")
        {
            return Err("renewal recovery must share its fresh cycle namespace".into());
        }
        let metadata = fs::symlink_metadata(&self.recovery)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || fs::read_dir(&self.recovery)?.next().is_some()
        {
            return Err("renewal recovery directory is not fresh".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let out = fs::symlink_metadata(output)?;
            if metadata.permissions().mode() & 0o777 != 0o700
                || metadata.uid() != out.uid()
                || metadata.gid() != out.gid()
                || fs::canonicalize(&self.recovery)? != self.recovery
                || fs::canonicalize(output)? != output
            {
                return Err("renewal recovery custody changed".into());
            }
        }
        #[cfg(unix)]
        {
            self.note("operation-intent.safe.json", &serde_json::json!({"schema":"marty.trust-role-renewal-operation/v1","cycleId":self.cycle_id,"project":project,"keyName":key,"role":"trust-profile-server","pkiMount":mount,"previousCertificateSha256":self.previous_certificate_sha256,"caSha256":self.ca_sha256,"roleDataSha256":self.role_sha256,"ownedPolicyRestore":restore,"tokenMaxSeconds":3600,"automaticRetry":false,"keyRoleIssuerCreation":false}))
        }
        #[cfg(not(unix))]
        {
            let _ = (project, key, mount, restore);
            Err("native renewal recovery requires Unix custody".into())
        }
    }

    pub(super) fn note(&self, name: &str, value: &Value) -> Result<(), Box<dyn Error>> {
        if name.contains(['/', '\\']) || name == ".." {
            return Err("invalid renewal recovery receipt name".into());
        }
        super::write_new(&self.recovery.join(name), &serde_json::to_string(value)?)?;
        #[cfg(unix)]
        fs::File::open(&self.recovery)?.sync_all()?;
        Ok(())
    }

    pub(super) fn capture_token(
        &self,
        token: &super::token_recovery::NewToken,
        response: &Value,
    ) -> Result<(), Box<dyn Error>> {
        super::write_new(&self.recovery.join("new-token.private"), token.value())?;
        #[cfg(unix)]
        fs::File::open(&self.recovery)?.sync_all()?;
        if let Some(accessor) = response
            .get("auth")
            .and_then(|a| a.get("accessor"))
            .and_then(Value::as_str)
        {
            if !(16..=4096).contains(&accessor.len())
                || !accessor.is_ascii()
                || accessor.bytes().any(|b| !b.is_ascii_graphic())
            {
                return Err("new renewal accessor capture is invalid".into());
            }
            super::write_new(&self.recovery.join("new-token-accessor.private"), accessor)?;
            #[cfg(unix)]
            fs::File::open(&self.recovery)?.sync_all()?;
        }
        self.note("new-token-captured.safe.json",&serde_json::json!({"cycleId":self.cycle_id,"newTokenSha256":hash(token.value().as_bytes()),"credentialValuesIncluded":false}))
    }

    pub(super) fn failed(
        &self,
        phase: &str,
        error: &dyn Error,
        containment: Option<&super::token_recovery::Containment>,
    ) -> Box<dyn Error> {
        let error_hash = hash(error.to_string().as_bytes());
        let note = serde_json::json!({"schema":"marty.trust-role-renewal-failure/v1","cycleId":self.cycle_id,"phase":phase,"originalErrorSha256":error_hash,"knownNewTokenContainment":containment,"automaticRetry":false,"credentialValuesIncluded":false});
        let saved = self.note("failure.safe.json", &note).is_ok();
        let confirmed = containment.is_some_and(|c| c.confirmed);
        format!("existing-key renewal failed; phase={phase}; original_error_sha256={error_hash}; exact_new_token_containment_confirmed={confirmed}; recovery_receipt_saved={saved}; preserve operation, no retry").into()
    }

    pub(super) fn previous_spki(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        // An expired previous leaf is historical key identity only, never a
        // renewed lease or a certificate-validity qualification.
        let pem = public_file(
            &self.previous_certificate,
            &self.previous_certificate_sha256,
        )?;
        let spki = certificate::get_certificate_public_key(&cert_der(&pem)?)?;
        if serialization::detect_public_key_type(&spki)? != "EC_P256" {
            return Err("existing-key renewal previous key is not P256".into());
        }
        Ok(spki)
    }

    pub(super) fn issuer(
        &self,
        pinned_path: &Path,
        actual_pem: &str,
    ) -> Result<(), Box<dyn Error>> {
        let expected = cert_der(&public_file(pinned_path, &self.ca_sha256)?)?;
        let actual = cert_der(actual_pem.as_bytes())?;
        if expected != actual
            || certificate::get_certificate_public_key(&expected)?
                != certificate::get_certificate_public_key(&actual)?
        {
            return Err("existing-key renewal issuer DER or SPKI changed".into());
        }
        Ok(())
    }

    pub(super) fn key(&self, metadata: &Value, previous_spki: &[u8]) -> Result<(), Box<dyn Error>> {
        checked_transit_key_metadata(metadata, Profile::Selfhost)?;
        let public = data(metadata, "keys")?
            .get("1")
            .and_then(|v| v.get("public_key"))
            .and_then(Value::as_str)
            .ok_or("existing-key renewal public key is absent")?;
        let actual = serialization::load_public_key_pem(public)?;
        if data(metadata, "deletion_allowed")? != false
            || actual != previous_spki
            || serialization::detect_public_key_type(&actual)? != "EC_P256"
        {
            return Err("existing-key renewal custody or retained SPKI changed".into());
        }
        Ok(())
    }

    pub(super) fn role(&self, metadata: &Value, role: &Role) -> Result<(), Box<dyn Error>> {
        checked_existing_role(metadata, role)?;
        let canonical = serde_json::to_vec(&sorted_value(
            metadata.get("data").ok_or("existing role data is absent")?,
        ))?;
        if hash(&canonical) != self.role_sha256 {
            return Err("existing-key renewal exact role pin changed".into());
        }
        Ok(())
    }

    pub(super) fn policy(
        &self,
        status: u16,
        metadata: &Value,
        expected: &str,
    ) -> Result<SignerPolicy, Box<dyn Error>> {
        if status == 200 && value(metadata, "policy")? == expected {
            return Ok(SignerPolicy::Reuse);
        }
        if status == 404 && self.allow_owned_policy_restore {
            return Ok(SignerPolicy::Restore);
        }
        Err("existing-key renewal signer policy differs or restoration is not authorized".into())
    }

    pub(super) fn signer_cycle(
        &self,
        lookup: &Value,
        project: &str,
        role: &str,
    ) -> Result<(), Box<dyn Error>> {
        if data(lookup, "meta")?
            != &serde_json::json!({"marty_tls_role_renewal_cycle":self.cycle_id,"project":project,"role":role})
        {
            return Err("existing-key renewal token belongs to a different cycle".into());
        }
        Ok(())
    }

    pub(super) fn leaf(
        &self,
        certificate: &str,
        previous_spki: &[u8],
    ) -> Result<(), Box<dyn Error>> {
        let der = cert_der(certificate.as_bytes())?;
        let parsed = certificate::load_certificate_der(&der)?;
        checked_leaf_window(
            parsed.tbs_certificate.validity.not_before.to_system_time(),
            parsed.tbs_certificate.validity.not_after.to_system_time(),
            std::time::SystemTime::now(),
        )?;
        if certificate::get_certificate_public_key(&der)? != previous_spki {
            return Err("existing-key renewal leaf SPKI changed".into());
        }
        Ok(())
    }
}

fn checked_leaf_window(
    before: std::time::SystemTime,
    after: std::time::SystemTime,
    now: std::time::SystemTime,
) -> Result<(), Box<dyn Error>> {
    if before > now
        || !after.duration_since(now).is_ok_and(|remaining| {
            (std::time::Duration::from_secs(1800)..=std::time::Duration::from_secs(3600))
                .contains(&remaining)
        })
    {
        return Err("existing-key renewal leaf is outside the one-hour window".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    const CERT: &str = include_str!("../../../tests/fixtures/existing-key-public.pem");
    #[test]
    fn existing_key_renew_leaf_window_cannot_extend_one_hour_or_admit_expired_material() {
        use std::time::{Duration, SystemTime};
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10000);
        for seconds in [1800, 3599, 3600] {
            assert!(checked_leaf_window(now, now + Duration::from_secs(seconds), now).is_ok());
        }
        for seconds in [0, 1799, 3601, 28800] {
            assert!(checked_leaf_window(now, now + Duration::from_secs(seconds), now).is_err());
        }
        assert!(checked_leaf_window(
            now + Duration::from_secs(1),
            now + Duration::from_secs(3600),
            now
        )
        .is_err());
    }
    #[test]
    fn existing_key_renew_fault_receipt_preserves_unknown_without_credential_output() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = config(false);
        c.recovery = dir.path().to_owned();
        let error: Box<dyn Error> = "synthetic-secret-error".into();
        let result = c
            .failed("MINT_OUTCOME_UNKNOWN", error.as_ref(), None)
            .to_string();
        let receipt = fs::read_to_string(dir.path().join("failure.safe.json")).unwrap();
        assert!(!result.contains("synthetic-secret-error"));
        assert!(!receipt.contains("synthetic-secret-error"));
        let value: Value = serde_json::from_str(&receipt).unwrap();
        assert_eq!(value["automaticRetry"], false);
        assert!(value["knownNewTokenContainment"].is_null());
        assert_eq!(
            value["originalErrorSha256"],
            hash(b"synthetic-secret-error")
        );
    }
    #[cfg(unix)]
    #[test]
    fn existing_key_renew_recovery_requires_fresh_private_same_cycle_and_preserves_intent() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join(format!("renewal-{}", "a".repeat(32)));
        fs::create_dir(&parent).unwrap();
        let output = parent.join("generation");
        let recovery = parent.join("recovery");
        fs::create_dir(&output).unwrap();
        fs::create_dir(&recovery).unwrap();
        fs::set_permissions(&recovery, fs::Permissions::from_mode(0o700)).unwrap();
        let mut c = config(true);
        c.recovery = recovery.clone();
        assert!(c
            .prepare_recovery(&output, "project", "key", "workload-pki", true)
            .is_ok());
        let intent = fs::read(recovery.join("operation-intent.safe.json")).unwrap();
        assert!(c
            .prepare_recovery(&output, "project", "key", "workload-pki", true)
            .is_err());
        assert_eq!(
            fs::read(recovery.join("operation-intent.safe.json")).unwrap(),
            intent
        );
        let v: Value = serde_json::from_slice(&intent).unwrap();
        assert_eq!(v["automaticRetry"], false);
        assert_eq!(v["tokenMaxSeconds"], 3600);
    }
    #[test]
    fn existing_key_renew_token_metadata_binds_exact_cycle_project_and_role() {
        let c = config(false);
        let metadata = serde_json::json!({"data":{"meta":{"marty_tls_role_renewal_cycle":"a".repeat(32),"project":"project","role":"trust-profile-server"}}});
        assert!(c
            .signer_cycle(&metadata, "project", "trust-profile-server")
            .is_ok());
        for field in ["marty_tls_role_renewal_cycle", "project", "role"] {
            let mut changed = metadata.clone();
            changed["data"]["meta"][field] = serde_json::json!("different");
            assert!(c
                .signer_cycle(&changed, "project", "trust-profile-server")
                .is_err());
        }
        assert!(c
            .signer_cycle(
                &serde_json::json!({"data":{}}),
                "project",
                "trust-profile-server"
            )
            .is_err());
    }
    fn config(restore: bool) -> ExistingTrustRole {
        ExistingTrustRole {
            previous_certificate: PathBuf::from("/unused"),
            previous_certificate_sha256: hash(CERT.as_bytes()),
            ca_sha256: hash(CERT.as_bytes()),
            role_sha256: "0".repeat(64),
            allow_owned_policy_restore: restore,
            cycle_id: "a".repeat(32),
            recovery: PathBuf::from("/unused/recovery"),
        }
    }
    fn spki() -> Vec<u8> {
        certificate::get_certificate_public_key(&cert_der(CERT.as_bytes()).unwrap()).unwrap()
    }
    fn key() -> Value {
        json!({"data":{"type":"ecdsa-p256","exportable":false,"allow_plaintext_backup":false,"latest_version":1,"deletion_allowed":false,"keys":{"1":{"public_key":serialization::save_public_key_pem(&spki()).unwrap()}}}})
    }
    #[test]
    fn existing_key_renew_checks_public_leaf_pin_and_same_key_without_expiry_claim() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("old-public.pem");
        fs::write(&file, CERT).unwrap();
        let mut c = config(false);
        c.previous_certificate = file.clone();
        assert_eq!(c.previous_spki().unwrap(), spki());
        assert!(c.issuer(&file, CERT).is_ok());
        assert!(c.key(&key(), &spki()).is_ok());
        // Historical public fixture is not a fresh one-hour lease.
        assert!(c.leaf(CERT, &spki()).is_err());
        c.previous_certificate_sha256 = "1".repeat(64);
        assert!(c.previous_spki().is_err());
        assert!(config(false).key(&key(), &[0; 91]).is_err());
        assert!(config(false).leaf(CERT, &[0; 91]).is_err());
        for (field, value) in [
            ("latest_version", json!(2)),
            ("exportable", json!(true)),
            ("allow_plaintext_backup", json!(true)),
            ("deletion_allowed", json!(true)),
        ] {
            let mut k = key();
            k["data"][field] = value;
            assert!(config(false).key(&k, &spki()).is_err());
        }
    }
    #[test]
    fn existing_key_renew_policy_never_overwrites_a_present_mismatch() {
        let expected = "exact sign-only scope";
        let actual = json!({"data":{"policy":expected}});
        assert_eq!(
            config(false).policy(200, &actual, expected).unwrap(),
            SignerPolicy::Reuse
        );
        assert_eq!(
            config(true).policy(404, &json!({}), expected).unwrap(),
            SignerPolicy::Restore
        );
        assert!(config(false).policy(404, &json!({}), expected).is_err());
        for status in [200, 403, 500] {
            assert!(config(true)
                .policy(status, &json!({"data":{"policy":"broader"}}), expected)
                .is_err());
        }
    }
    #[test]
    fn existing_key_renew_inputs_are_closed_and_cannot_enter_other_profiles() {
        let file = std::env::temp_dir().join("old-public.pem");
        let file = file.to_str().unwrap();
        let h = "a".repeat(64);
        let values = BTreeMap::from([
            (INPUTS[0], file),
            (INPUTS[1], h.as_str()),
            (INPUTS[2], h.as_str()),
            (INPUTS[3], h.as_str()),
            (INPUTS[4], "0"),
            (INPUTS[5], "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            (INPUTS[6], file),
        ]);
        assert!(ExistingTrustRole::from_values(true, |n| values.get(n).copied()).is_ok());
        assert!(ExistingTrustRole::from_values(false, |n| values.get(n).copied()).is_err());
        for name in INPUTS {
            let mut v = values.clone();
            v.remove(name);
            assert!(ExistingTrustRole::from_values(true, |n| v.get(n).copied()).is_err());
        }
    }
    #[test]
    fn existing_key_renew_pins_complete_role_data_and_only_selects_trust() {
        let roles = super::super::selected_roles(Profile::PassportRoleRenew).collect::<Vec<_>>();
        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].name, "trust-profile-server");
        let role = roles[0];
        let mut metadata = json!({"data":{"allow_any_name":true,"allow_localhost":true,"allow_ip_sans":true,"allowed_uri_sans":role.uri_sans.split(',').filter(|v|!v.is_empty()).collect::<Vec<_>>(),"server_flag":role.server,"client_flag":role.client,"key_type":"ec","key_bits":256,"max_ttl":86400,"use_csr_common_name":false,"use_csr_sans":false,"other_provider_field":false}});
        let mut c = config(false);
        c.role_sha256 = hash(&serde_json::to_vec(&sorted_value(&metadata["data"])).unwrap());
        assert!(c.role(&metadata, role).is_ok());
        metadata["data"]["other_provider_field"] = json!(true);
        assert!(c.role(&metadata, role).is_err());
    }
    #[test]
    fn existing_key_renew_keeps_one_hour_nonrenewable_orphan_bounds() {
        let token = json!({"data":{"policies":["owned"],"ttl":3590,"creation_ttl":3600,"explicit_max_ttl":3600,"renewable":false,"orphan":true,"type":"service","path":"auth/token/create-orphan"}});
        assert!(super::super::checked_selective_signer(&token, "owned", true).is_ok());
        for (name, value) in [
            ("ttl", json!(1799)),
            ("creation_ttl", json!(28800)),
            ("explicit_max_ttl", json!(28800)),
            ("renewable", json!(true)),
            ("orphan", json!(false)),
            ("type", json!("batch")),
            ("policies", json!(["other"])),
        ] {
            let mut t = token.clone();
            t["data"][name] = value;
            assert!(super::super::checked_selective_signer(&t, "owned", true).is_err());
        }
    }
}
