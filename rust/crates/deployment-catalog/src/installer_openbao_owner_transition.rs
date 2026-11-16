//! Local historical observation of the OpenBao TLS initializer's ownership change.
//! This is not deletion authority. A future purge must separately solve access to
//! the now image-owned 0700 directory without changing its permissions here.
#![cfg(target_os = "linux")]

use crate::{installer_creation_identity::ObservedDirectory, installer_purge_host::Kind};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const REFUSED: &str = "OpenBao owner transition could not be recorded";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InitialReceipt {
    schema: String,
    installation_id: uuid::Uuid,
    source_sha: String,
    root: ObservedDirectory,
    evidence: ObservedDirectory,
    downloads: ObservedDirectory,
    local_historical_evidence: bool,
    deletion_authorized: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StateReceipt {
    schema: String,
    installation_id: uuid::Uuid,
    source_sha: String,
    openbao_state: ObservedDirectory,
    local_historical_evidence: bool,
    deletion_authorized: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Completion {
    role: String,
    container_id: String,
    exit_code: i32,
}

pub(crate) struct Evidence<'a> {
    pub initial_bytes: &'a [u8],
    pub state_bytes: &'a [u8],
    pub completion_bytes: &'a [u8],
    pub installation_id: uuid::Uuid,
    pub source_sha: &'a str,
    pub engine_id: &'a str,
    pub image: &'a str,
    pub image_id: &'a str,
    pub container_id: &'a str,
    pub root: &'a ObservedDirectory,
    pub evidence: &'a ObservedDirectory,
    pub state: &'a ObservedDirectory,
}

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn valid_directory(value: &ObservedDirectory) -> bool {
    value.mount_id != 0
        && value.identity.dev != 0
        && value.identity.ino != 0
        && value.identity.mode == 0o700
        && value.identity.kind == Kind::Directory
}

pub(crate) fn receipt_bytes(input: &Evidence<'_>) -> Result<Vec<u8>, String> {
    let initial: InitialReceipt =
        serde_json::from_slice(input.initial_bytes).map_err(|_| REFUSED)?;
    let created: StateReceipt = serde_json::from_slice(input.state_bytes).map_err(|_| REFUSED)?;
    let completed: Completion =
        serde_json::from_slice(input.completion_bytes).map_err(|_| REFUSED)?;
    let prior = &created.openbao_state;
    let current = input.state;
    if initial.schema != "elevenid.installer-created-identity/v1"
        || created.schema != "elevenid.installer-created-openbao-state/v1"
        || initial.installation_id != input.installation_id
        || created.installation_id != input.installation_id
        || initial.source_sha != input.source_sha
        || created.source_sha != input.source_sha
        || !initial.local_historical_evidence
        || !created.local_historical_evidence
        || initial.deletion_authorized
        || created.deletion_authorized
        || !valid_directory(&initial.root)
        || !valid_directory(&initial.evidence)
        || !valid_directory(&initial.downloads)
        || !valid_directory(prior)
        || initial.root != *input.root
        || initial.evidence != *input.evidence
        || initial.downloads.mount_id != input.root.mount_id
        || initial.downloads.identity.dev != input.root.identity.dev
        || prior.mount_id != input.root.mount_id
        || prior.mount_id != current.mount_id
        || prior.identity.dev != current.identity.dev
        || prior.identity.ino != current.identity.ino
        || prior.identity.mode != current.identity.mode
        || prior.identity.kind != current.identity.kind
        || completed.role != "openbao-tls-init"
        || completed.exit_code != 0
        || completed.container_id != input.container_id
        || !hex64(input.container_id)
        || !input.image_id.strip_prefix("sha256:").is_some_and(hex64)
        || !input
            .image
            .strip_prefix("ghcr.io/elevenid/marty-ui-oss/openbao-didcomm@sha256:")
            .is_some_and(hex64)
        || input.engine_id.is_empty()
    {
        return Err(REFUSED.into());
    }
    #[derive(Serialize)]
    struct Receipt<'a> {
        schema: &'static str,
        installation_id: uuid::Uuid,
        source_sha: &'a str,
        engine_id: &'a str,
        image: &'a str,
        image_id: &'a str,
        tls_init_container_id: &'a str,
        initial_receipt_sha256: String,
        state_creation_receipt_sha256: String,
        tls_init_completion_sha256: String,
        root: &'a ObservedDirectory,
        evidence: &'a ObservedDirectory,
        openbao_state_before: &'a ObservedDirectory,
        openbao_state_after: &'a ObservedDirectory,
        local_historical_evidence: bool,
        deletion_authorized: bool,
    }
    serde_json::to_vec(&Receipt {
        schema: "elevenid.installer-openbao-state-owner-transition/v1",
        installation_id: input.installation_id,
        source_sha: input.source_sha,
        engine_id: input.engine_id,
        image: input.image,
        image_id: input.image_id,
        tls_init_container_id: input.container_id,
        initial_receipt_sha256: sha(input.initial_bytes),
        state_creation_receipt_sha256: sha(input.state_bytes),
        tls_init_completion_sha256: sha(input.completion_bytes),
        root: input.root,
        evidence: input.evidence,
        openbao_state_before: prior,
        openbao_state_after: current,
        local_historical_evidence: true,
        deletion_authorized: false,
    })
    .map_err(|_| REFUSED.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::installer_purge_host::{HostIdentity, Kind};
    use serde_json::json;

    fn observed(ino: u64, uid: u32, gid: u32) -> ObservedDirectory {
        ObservedDirectory {
            identity: HostIdentity {
                dev: 11,
                ino,
                uid,
                gid,
                mode: 0o700,
                kind: Kind::Directory,
            },
            mount_id: 22,
        }
    }

    #[test]
    fn records_mapped_owner_without_assuming_image_numeric_ids() {
        let id = uuid::Uuid::new_v4();
        let root = observed(1, 1000, 1000);
        let evidence = observed(2, 1000, 1000);
        let before = observed(3, 1000, 1000);
        let mut after = observed(3, 231072, 231072);
        let initial = serde_json::to_vec(&json!({"schema":"elevenid.installer-created-identity/v1","installation_id":id,"source_sha":"a".repeat(40),"root":root,"evidence":evidence,"downloads":observed(4,1000,1000),"local_historical_evidence":true,"deletion_authorized":false})).unwrap();
        let created = serde_json::to_vec(&json!({"schema":"elevenid.installer-created-openbao-state/v1","installation_id":id,"source_sha":"a".repeat(40),"openbao_state":before,"local_historical_evidence":true,"deletion_authorized":false})).unwrap();
        let container = "c".repeat(64);
        let completion = serde_json::to_vec(
            &json!({"role":"openbao-tls-init","container_id":container,"exit_code":0}),
        )
        .unwrap();
        let source = "a".repeat(40);
        let image = format!(
            "ghcr.io/elevenid/marty-ui-oss/openbao-didcomm@sha256:{}",
            "b".repeat(64)
        );
        let image_id = format!("sha256:{}", "d".repeat(64));
        let check = |initial: &[u8],
                     created: &[u8],
                     completion: &[u8],
                     after: &ObservedDirectory,
                     engine: &str,
                     container: &str| {
            receipt_bytes(&Evidence {
                initial_bytes: initial,
                state_bytes: created,
                completion_bytes: completion,
                installation_id: id,
                source_sha: &source,
                engine_id: engine,
                image: &image,
                image_id: &image_id,
                container_id: container,
                root: &root,
                evidence: &evidence,
                state: after,
            })
        };
        let bytes = check(
            &initial,
            &created,
            &completion,
            &after,
            "bound-engine",
            &container,
        )
        .unwrap();
        let receipt: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(receipt["openbao_state_after"]["identity"]["uid"], 231072);
        assert_eq!(receipt["deletion_authorized"], false);
        assert!(check(
            b"{}",
            &created,
            &completion,
            &after,
            "bound-engine",
            &container
        )
        .is_err());
        assert!(check(
            &initial,
            b"{}",
            &completion,
            &after,
            "bound-engine",
            &container
        )
        .is_err());
        assert!(check(&initial, &created, &completion, &after, "", &container).is_err());
        assert!(check(
            &initial,
            &created,
            &completion,
            &after,
            "bound-engine",
            &"e".repeat(64)
        )
        .is_err());
        let failed = serde_json::to_vec(
            &json!({"role":"openbao-tls-init","container_id":container,"exit_code":1}),
        )
        .unwrap();
        assert!(check(
            &initial,
            &created,
            &failed,
            &after,
            "bound-engine",
            &container
        )
        .is_err());
        after.identity.ino += 1;
        assert!(check(
            &initial,
            &created,
            &completion,
            &after,
            "bound-engine",
            &container
        )
        .is_err());
        after.identity.ino -= 1;
        after.identity.mode = 0o755;
        assert!(check(
            &initial,
            &created,
            &completion,
            &after,
            "bound-engine",
            &container
        )
        .is_err());
    }
}
