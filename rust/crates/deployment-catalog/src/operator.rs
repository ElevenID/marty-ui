//! Read-only KMS operator validation. Never loads a private key or extracts an archive.
use sha2::{Digest, Sha256};
use spki::der::{DecodePem, Encode};
use std::io::{Read, Seek};

pub const REFUSAL: &str = "KMS operator input refused";
pub type Result<T> = std::result::Result<T, &'static str>;

/// Convert a bounded public PEM or certificate to canonical public SPKI DER.
/// Trust-chain/issuer validation remains the caller's separate responsibility.
pub fn public_spki(pem: &[u8], certificate: bool) -> Result<Vec<u8>> {
    if pem.len() > 64 * 1024 || !pem.is_ascii() || pem.windows(11).any(|s| s == b"PRIVATE KEY") {
        return Err(REFUSAL);
    }
    let key = if certificate {
        x509_cert::Certificate::from_pem(pem)
            .map_err(|_| REFUSAL)?
            .tbs_certificate
            .subject_public_key_info
    } else {
        spki::SubjectPublicKeyInfoOwned::from_pem(pem).map_err(|_| REFUSAL)?
    };
    let der = key.to_der().map_err(|_| REFUSAL)?;
    // Validate supported key material, not only the ASN.1 envelope.
    marty_crypto::jwk::public_key_der_to_jwk(&der).map_err(|_| REFUSAL)?;
    Ok(der)
}

/// Independently validate the existing v2 recovery archive without extraction.
/// The snapshot is streamed, so large encrypted Raft state is never buffered.
pub fn check_snapshot(source: impl Read + Seek) -> Result<()> {
    let mut archive = zip::ZipArchive::new(source).map_err(|_| REFUSAL)?;
    let expected = ["raft.snap", "openbao-selfhost.hcl", "manifest.json"];
    if archive.len() != expected.len() {
        return Err(REFUSAL);
    }
    let mut seen = std::collections::BTreeSet::new();
    for i in 0..archive.len() {
        let entry = archive.by_index(i).map_err(|_| REFUSAL)?;
        let name = entry.name().map_err(|_| REFUSAL)?;
        if !expected.contains(&name.as_ref()) || !seen.insert(name.into_owned()) || entry.is_dir() {
            return Err(REFUSAL);
        }
    }
    let mut manifest = Vec::new();
    let entry = archive.by_name("manifest.json").map_err(|_| REFUSAL)?;
    if entry.size() > 64 * 1024 {
        return Err(REFUSAL);
    }
    entry
        .take(64 * 1024 + 1)
        .read_to_end(&mut manifest)
        .map_err(|_| REFUSAL)?;
    if manifest.len() > 64 * 1024 {
        return Err(REFUSAL);
    }
    let manifest: serde_json::Value = serde_json::from_slice(&manifest).map_err(|_| REFUSAL)?;
    if manifest["format"] != "marty-openbao-raft-snapshot-v2" {
        return Err(REFUSAL);
    }
    let mut snapshot = archive.by_name("raft.snap").map_err(|_| REFUSAL)?;
    if snapshot.size() == 0 {
        return Err(REFUSAL);
    }
    let mut digest = Sha256::new();
    let mut bytes = [0u8; 64 * 1024];
    let mut size = 0u64;
    loop {
        let count = snapshot.read(&mut bytes).map_err(|_| REFUSAL)?;
        if count == 0 {
            break;
        }
        size += count as u64;
        digest.update(&bytes[..count]);
    }
    if size == 0
        || size != snapshot.size()
        || manifest["snapshot_sha256"] != format!("{:x}", digest.finalize())
    {
        return Err(REFUSAL);
    }
    Ok(())
}
