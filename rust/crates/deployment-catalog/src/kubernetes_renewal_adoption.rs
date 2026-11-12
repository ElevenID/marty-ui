//! Verify a pair of existing renewal enrollments against one live generation.
//! Enrollment and policy issuance remain owned by application_authority and
//! kubernetes_renewal. This command never retries enrollment or publishes state.
use crate::{
    application_authority::{self, Binding},
    kubernetes_application::{owned_directory, read_owned_file, snapshot, Snapshot},
    kubernetes_renewal,
    operator::{Result, REFUSAL},
    operator_files::write_private,
};
use marty_openbao_http::OpenBaoHttp;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    os::unix::fs::{DirBuilderExt, MetadataExt},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const SCHEMA: &str = "marty.kubernetes-renewal-adoption-verification/v1";
const BUDGET: u64 = 900;
const MINIMUM_TTL: u64 = 3600;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Context {
    binding: Binding,
    bootstrap_id: String,
    adoption_id: String,
    operator_identity: String,
    candidate: PathBuf,
    application_identity: PathBuf,
    renewal_identity: PathBuf,
    renewal_binding: PathBuf,
}

fn require(condition: bool) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(REFUSAL)
    }
}

fn uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn hashes(values: &Snapshot) -> BTreeMap<String, Value> {
    values
        .iter()
        .map(|(name, (bytes, mode))| (name.clone(), json!({"sha256":digest(bytes),"mode":mode})))
        .collect()
}

fn directory(path: &Path) -> Result<(u64, u64, u32, u32, u32)> {
    owned_directory(path)?;
    let value = fs::symlink_metadata(path).map_err(|_| REFUSAL)?;
    Ok((
        value.dev(),
        value.ino(),
        value.uid(),
        value.gid(),
        value.mode(),
    ))
}

fn persist(path: &Path, value: &Value) -> Result<()> {
    write_private(
        path,
        &serde_json::to_string(value).map_err(|_| REFUSAL)?,
        262144,
    )?;
    File::open(path.parent().ok_or(REFUSAL)?)
        .map_err(|_| REFUSAL)?
        .sync_all()
        .map_err(|_| REFUSAL)
}

/// Bind native evidence to the exact compiled operator as well as both identities.
/// A fresh output directory is required for every verification/reconciliation.
pub async fn verify(
    endpoint: &str,
    ca: &Path,
    output: &Path,
    context: &Value,
    build_identity: &str,
) -> Result<Value> {
    let context: Context = serde_json::from_value(context.clone()).map_err(|_| REFUSAL)?;
    context.binding.validate()?;
    require(
        uuid(&context.bootstrap_id)
            && context.adoption_id.len() == 32
            && context
                .adoption_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            && context.operator_identity == build_identity,
    )?;
    let paths = [
        &context.candidate,
        &context.application_identity,
        &context.renewal_identity,
        output,
    ];
    for (index, left) in paths.iter().enumerate() {
        for right in paths.iter().skip(index + 1) {
            require(!left.starts_with(right) && !right.starts_with(left))?;
        }
    }
    let held = paths
        .iter()
        .map(|path| directory(path))
        .collect::<Result<Vec<_>>>()?;
    require(fs::read_dir(output).map_err(|_| REFUSAL)?.next().is_none())?;
    let before = snapshot(&context.candidate)?;
    let application = snapshot(&context.application_identity)?;
    let renewal = snapshot(&context.renewal_identity)?;
    let bound = read_owned_file(&context.renewal_binding, 4096, &[0o400, 0o600])?.0;
    let ca_bytes = read_owned_file(ca, 65536, &[0o400, 0o600])?.0;
    require(
        before
            .get("openbao_tls_ca_cert")
            .is_some_and(|entry| entry.0 == ca_bytes),
    )?;
    let started = Instant::now();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| REFUSAL)?
        .as_secs();
    let deadline = now.checked_add(BUDGET).ok_or(REFUSAL)?;
    let evidence = json!({
        "schema":SCHEMA,"binding":context.binding,"bootstrapId":context.bootstrap_id,
        "adoptionId":context.adoption_id,"operatorIdentity":build_identity,
        "candidateInputs":hashes(&before),"applicationIdentity":hashes(&application),
        "renewalIdentity":hashes(&renewal),"renewalBindingSha256":digest(&bound),
        "verificationStartedAtUnixSeconds":now,"validBeforeUnixSeconds":deadline,
        "minimumTtlSeconds":MINIMUM_TTL,"applicationRoles":11,"scopedLeafTokens":21,
        "enrollmentReplayed":false,"credentialsIssued":false,"activated":false,
    });
    persist(&output.join("attempt.json"), &evidence)?;
    for name in ["application", "renewal"] {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(output.join(name))
            .map_err(|_| REFUSAL)?;
    }
    let bao =
        OpenBaoHttp::connect(endpoint, Some(ca), Duration::from_secs(10)).map_err(|_| REFUSAL)?;
    // The full budget is added to the lifetime floor, so time spent verifying,
    // reading back delivery and publishing cannot silently consume that floor.
    application_authority::verify_enrollment(
        &bao,
        &context.application_identity,
        &context.candidate,
        &output.join("application"),
        &context.binding,
        MINIMUM_TTL + BUDGET,
    )
    .await?;
    require(started.elapsed() < Duration::from_secs(BUDGET))?;
    kubernetes_renewal::verify_enrollment(
        endpoint,
        ca,
        &context.renewal_identity,
        &json!({
            "current":context.candidate,"output":output.join("renewal"),
            "binding_file":context.renewal_binding,"binding":context.binding,
            "minimum_ttl":MINIMUM_TTL + BUDGET,
        }),
    )
    .await?;
    for (path, expected) in paths.iter().zip(held) {
        require(directory(path)? == expected)?;
    }
    require(
        snapshot(&context.candidate)? == before
            && snapshot(&context.application_identity)? == application
            && snapshot(&context.renewal_identity)? == renewal
            && read_owned_file(&context.renewal_binding, 4096, &[0o400, 0o600])?.0 == bound
            && read_owned_file(ca, 65536, &[0o400, 0o600])?.0 == ca_bytes
            && started.elapsed() < Duration::from_secs(BUDGET),
    )?;
    persist(
        &output.join("verified.json"),
        &json!({
            "verification":evidence,"ready":true,"transientSessionsRevoked":true,
        }),
    )?;
    require(started.elapsed() < Duration::from_secs(BUDGET))?;
    Ok(
        json!({"ready":true,"applicationRoles":11,"scopedLeafTokens":21,
        "minimumTtlSeconds":MINIMUM_TTL,"validBeforeUnixSeconds":deadline}),
    )
}
