//! Retired historical Kubernetes credential recovery boundary.
//!
//! The old source-bound cohort includes retired connector authority. Current
//! source cannot reinterpret or qualify that cohort. Keep commands fail-closed
//! before parsing credentials, opening paths, creating runtimes or using a network.
use crate::operator::Result;
use serde_json::{json, Value};
use std::path::Path;

pub const SCHEMA: &str = "marty.kubernetes-legacy-recovery-inspection/v1";
pub const LEGACY_RUNTIME: &str = "3ff1328d163f2dca38e369f17bda77b6334808eb";
const HISTORICAL_INITIALIZER_SHA256: &str =
    "57adbf26ef7b6f22a47c1ec85b9de75b807e394a2d7de48f6550b374cc8ebe1f";
pub const RECOVERY: &str =
    "Legacy Kubernetes credential recovery is retired; preserve source-bound recovery evidence";

pub fn contract() -> Value {
    json!({"schema":SCHEMA,"legacyRuntimeSourceSha":LEGACY_RUNTIME,
        "historicalInitializerSha256":HISTORICAL_INITIALIZER_SHA256,
        "available":false,"mutationAvailable":false,"credentialAccess":false,
        "networkAccess":false,"historicalStateReinterpreted":false})
}

pub fn stage_contract() -> Value {
    let mut value = contract();
    value["schema"] = json!("marty.kubernetes-legacy-recovery-stage/v1");
    value
}

pub async fn target(_ca: &Path, _expected_cluster: &str) -> Result<Value> {
    Err(RECOVERY)
}

pub async fn inspect_to_file(_request: &[u8], _output: &Path) -> Result<Value> {
    Err(RECOVERY)
}

pub fn secret_targets(_request: &[u8]) -> Result<Value> {
    Err(RECOVERY)
}

pub fn inspect_predecessors(_request: &[u8]) -> Result<Value> {
    Err(RECOVERY)
}

pub async fn stage_candidate(_request: &[u8]) -> Result<Value> {
    Err(RECOVERY)
}

pub async fn qualify_candidate(_request: &[u8]) -> Result<Value> {
    Err(RECOVERY)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn historical_contract_is_unavailable_without_rebinding_its_source() {
        for value in [contract(), stage_contract()] {
            assert_eq!(value["available"], false);
            assert_eq!(value["mutationAvailable"], false);
            assert_eq!(value["credentialAccess"], false);
            assert_eq!(value["networkAccess"], false);
            assert_eq!(value["historicalStateReinterpreted"], false);
            assert_eq!(
                value["historicalInitializerSha256"],
                HISTORICAL_INITIALIZER_SHA256
            );
        }
    }

    #[tokio::test]
    async fn every_retired_entrypoint_refuses_without_touching_inputs_or_outputs() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("preserved.json");
        std::fs::write(&output, b"original-owner-evidence").unwrap();
        for request in [
            b"".as_slice(),
            b"{invalid",
            br#"{"token":"synthetic-never-read"}"#,
        ] {
            assert_eq!(secret_targets(request), Err(RECOVERY));
            assert_eq!(inspect_predecessors(request), Err(RECOVERY));
            assert_eq!(stage_candidate(request).await, Err(RECOVERY));
            assert_eq!(qualify_candidate(request).await, Err(RECOVERY));
            assert_eq!(inspect_to_file(request, &output).await, Err(RECOVERY));
            assert_eq!(std::fs::read(&output).unwrap(), b"original-owner-evidence");
        }
        assert_eq!(
            target(&directory.path().join("absent-ca"), "untrusted").await,
            Err(RECOVERY)
        );
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }
}
