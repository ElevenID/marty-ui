//! Append-only renewal for the PostgreSQL infrastructure owner. Retains the
//! issuer, server key and mounted directory; only the public leaf is replaced.
use super::*;

const PREFIX: &str = "feature-postgres-renewal-";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    schema: String,
    installation_id: uuid::Uuid,
    engine_id: String,
    sequence: u32,
    ca_sha256: String,
    server_spki_sha256: String,
    previous_certificate_sha256: String,
    certificate_pem: String,
    certificate_sha256: String,
    observed_at: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Completed {
    schema: String,
    installation_id: uuid::Uuid,
    sequence: u32,
    intent_sha256: String,
    certificate_der_sha256: String,
    postgres_reloaded: bool,
    fresh_tls_verified: bool,
}

fn filename(sequence: u32, kind: &str) -> String {
    format!("{PREFIX}{sequence:06}-{kind}.json")
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_json::from_value(crate::installer_json::decode(bytes).map_err(|_| REFUSED)?)
        .map_err(|_| REFUSED.into())
}

pub(super) fn current_leaf(evidence: &File, initial: &Receipt) -> Result<(Vec<u8>, u32)> {
    let names: BTreeSet<_> = fs::file_names(evidence, REFUSED)?
        .into_iter()
        .filter(|n| n.starts_with(PREFIX))
        .collect();
    require(names.len() <= 8192 && names.len().is_multiple_of(2))?;
    let sequence = u32::try_from(names.len() / 2).map_err(|_| REFUSED)?;
    let expected: BTreeSet<_> = (1..=sequence)
        .flat_map(|i| [filename(i, "intent"), filename(i, "result")])
        .collect();
    require(names == expected)?;
    let mut leaf = initial.server_certificate_pem.as_bytes().to_vec();
    require(digest(&leaf) == initial.server_certificate_sha256)?;
    for step in 1..=sequence {
        let bytes = fs::read_entry(evidence, &filename(step, "intent"), 0o600, false, REFUSED)?;
        let intent: Intent = decode(&bytes)?;
        let result: Completed = decode(&fs::read_entry(
            evidence,
            &filename(step, "result"),
            0o600,
            false,
            REFUSED,
        )?)?;
        require(
            intent.schema == "elevenid.installer-feature-postgres-renewal-intent/v1"
                && intent.installation_id == initial.installation_id
                && intent.engine_id == initial.engine_id
                && intent.sequence == step
                && intent.ca_sha256 == initial.ca_sha256
                && intent.server_spki_sha256 == initial.server_spki_sha256
                && intent.previous_certificate_sha256 == digest(&leaf)
                && intent.certificate_sha256 == digest(intent.certificate_pem.as_bytes())
                && result.schema == "elevenid.installer-feature-postgres-renewal-result/v1"
                && result.installation_id == initial.installation_id
                && result.sequence == step
                && result.intent_sha256 == digest(&bytes)
                && result.postgres_reloaded
                && result.fresh_tls_verified
                && result.certificate_der_sha256
                    == digest(
                        &certificate(intent.certificate_pem.as_bytes())?
                            .to_der()
                            .map_err(|_| REFUSED)?,
                    ),
        )?;
        leaf = intent.certificate_pem.into_bytes();
    }
    Ok((leaf, sequence))
}

/// The native caller must first authenticate the selected PostgreSQL container,
/// its exact installation/project/image/mounts, and its current running intent.
/// `reload` signals only that container. `probe` makes a NEW verify-full TLS
/// connection to DNS postgres with the retained CA and must additionally match
/// the supplied DER leaf fingerprint. A successful command exit by itself is
/// not sufficient proof. Pending/failed attempts remain a recovery boundary.
pub(crate) fn renew(
    lock: &mut LockedMaintenance,
    installation: &Path,
    reload: impl FnOnce() -> Result<()>,
    probe: impl FnOnce(&str) -> Result<()>,
) -> Result<bool> {
    renew_at(lock, installation, now()?, reload, probe)
}

pub(super) fn renew_at(
    lock: &mut LockedMaintenance,
    installation: &Path,
    observed: u64,
    reload: impl FnOnce() -> Result<()>,
    probe: impl FnOnce(&str) -> Result<()>,
) -> Result<bool> {
    lock.require_unchanged()?;
    let owner = open_owner(lock.inspection(), installation, observed, true)?;
    if owner.leaf_not_after > observed + RENEW_BEFORE {
        return Ok(false);
    }
    let sequence = owner
        .sequence
        .checked_add(1)
        .filter(|v| *v <= 4096)
        .ok_or(REFUSED)?;
    let params = ca_params(
        owner.receipt.installation_id,
        owner.receipt.ca_not_before,
        owner.receipt.ca_not_after,
    )?;
    let next = leaf_pem(
        &owner.server_key,
        &Issuer::from_params(&params, &owner.ca_key),
        observed,
    )?;
    verify_leaf(
        &owner.ca_pem,
        &next,
        &owner.receipt.server_spki_sha256,
        observed,
        false,
    )?;
    require(next != owner.leaf_pem)?;
    let leaf_fingerprint = digest(&certificate(&next)?.to_der().map_err(|_| REFUSED)?);
    let intent = Intent {
        schema: "elevenid.installer-feature-postgres-renewal-intent/v1".into(),
        installation_id: owner.receipt.installation_id,
        engine_id: owner.receipt.engine_id.clone(),
        sequence,
        ca_sha256: owner.receipt.ca_sha256.clone(),
        server_spki_sha256: owner.receipt.server_spki_sha256.clone(),
        previous_certificate_sha256: digest(&owner.leaf_pem),
        certificate_sha256: digest(&next),
        certificate_pem: String::from_utf8(next.clone()).map_err(|_| REFUSED)?,
        observed_at: observed,
    };
    let intent_bytes = serde_json::to_vec(&intent).map_err(|_| REFUSED)?;
    lock.write_evidence_exclusive(&filename(sequence, "intent"), &intent_bytes)?;
    owner.require_current()?;
    require(fs::read_entry(&owner.server, "server.crt", 0o444, false, REFUSED)? == owner.leaf_pem)?;
    let candidate = format!("renewal-candidate-{sequence:06}.crt");
    create_file(&owner.directory, &candidate, &next, 0o444)?;
    owner.require_current()?;
    // The PostgreSQL mount is a DIRECTORY, so a new leaf inode is visible after
    // atomic replacement. An individual file bind would retain the old inode.
    fs::rename_at(
        &owner.directory,
        &CString::new(candidate).map_err(|_| REFUSED)?,
        &owner.server,
        &CString::new("server.crt").unwrap(),
        fs::RenameMode::Replace,
    )
    .map_err(|_| REFUSED)?;
    owner
        .server
        .sync_all()
        .and_then(|_| owner.directory.sync_all())
        .map_err(|_| REFUSED)?;
    owner.require_current()?;
    require(fs::read_entry(&owner.server, "server.crt", 0o444, false, REFUSED)? == next)?;
    reload()?;
    probe(&leaf_fingerprint)?;
    owner.require_current()?;
    require(fs::read_entry(&owner.server, "server.crt", 0o444, false, REFUSED)? == next)?;
    let completed = Completed {
        schema: "elevenid.installer-feature-postgres-renewal-result/v1".into(),
        installation_id: owner.receipt.installation_id,
        sequence,
        intent_sha256: digest(&intent_bytes),
        certificate_der_sha256: leaf_fingerprint,
        postgres_reloaded: true,
        fresh_tls_verified: true,
    };
    lock.write_evidence_exclusive(
        &filename(sequence, "result"),
        &serde_json::to_vec(&completed).map_err(|_| REFUSED)?,
    )?;
    open_owner(lock.inspection(), installation, observed, false)?;
    Ok(true)
}
