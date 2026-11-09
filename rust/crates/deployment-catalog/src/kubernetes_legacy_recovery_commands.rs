//! Closed native command boundary for the legacy recovery mutation increment.
//! The commands accept bounded private context on stdin, never credentials or
//! arbitrary OpenBao endpoints in command-line arguments.

use super::*;
use serde::de::DeserializeOwned;

const MAX_REQUEST: usize = 512 * 1024;

fn decode<T: DeserializeOwned>(request: &[u8]) -> Result<T> {
    if request.is_empty() || request.len() > MAX_REQUEST {
        return Err(REFUSAL);
    }
    let value = crate::installer_json::decode(request).map_err(|_| REFUSAL)?;
    serde_json::from_value(value).map_err(|_| REFUSAL)
}

pub fn contract() -> Value {
    json!({"schema":staging::STAGE_SCHEMA,"legacyRuntimeSourceSha":LEGACY_RUNTIME,
        "certificateReplacements":18,"tokenReplacements":33,"replacementFiles":51,
        "existingSecretTargets":34,"maximumReplacementTtlSeconds":TTL,
        "migrationTokenReplacement":false,"scopeMutation":false,"activationPerformed":false,
        "qualificationSchema":qualification::SCHEMA,"planLifetimeSeconds":qualification::PLAN_SECONDS})
}

pub fn targets(request: &[u8]) -> Result<Value> {
    let context: Context = decode(request)?;
    let binding = binding(&context)?;
    Ok(
        json!({"schema":"marty.kubernetes-legacy-recovery-targets/v1",
        "namespace":binding.namespace,"names":activation::target_names(&binding)?,"replacementCount":51}),
    )
}

fn connect(context: &Context) -> Result<OpenBaoHttp> {
    binding(context)?;
    generation(&context.current)?;
    OpenBaoHttp::connect(
        "https://openbao:8200",
        Some(&context.current.join("openbao_tls_ca_cert")),
        Duration::from_secs(10),
    )
    .map_err(|_| REFUSAL)
}

pub async fn stage(request: &[u8]) -> Result<Value> {
    let stage: staging::Staging = decode(request)?;
    let bao = connect(&stage.context)?;
    tokio::time::timeout(
        Duration::from_secs(600),
        staging::stage_with(&Http(&bao), &stage),
    )
    .await
    .map_err(|_| staging::RECOVERY)?
}

pub async fn qualify(request: &[u8]) -> Result<Value> {
    let request: qualification::Qualification = decode(request)?;
    let bao = connect(&request.context)?;
    tokio::time::timeout(
        Duration::from_secs(300),
        qualification::qualify_with(&Http(&bao), &request),
    )
    .await
    .map_err(|_| staging::RECOVERY)?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_contract_has_closed_mutation_scope() {
        let value = contract();
        assert_eq!(value["replacementFiles"], 51);
        assert_eq!(value["existingSecretTargets"], 34);
        assert_eq!(value["migrationTokenReplacement"], false);
        assert_eq!(value["scopeMutation"], false);
        assert_eq!(value["activationPerformed"], false);
        assert_eq!(value["planLifetimeSeconds"], 300);
    }

    #[tokio::test]
    async fn command_boundary_rejects_duplicate_nested_json_and_unknown_fields() {
        let duplicate =
            br#"{"schema":"x","context":{"bootstrap":{"namespace":"a","namespace":"b"}}}"#;
        assert!(stage(duplicate).await.is_err());
        assert!(qualify(duplicate).await.is_err());
        assert!(targets(br#"{"schema":"x","extra":true}"#).is_err());
        let too_large = vec![b' '; MAX_REQUEST + 1];
        assert!(stage(&too_large).await.is_err());
    }
}
