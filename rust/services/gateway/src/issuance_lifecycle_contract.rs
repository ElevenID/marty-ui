use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub struct IssuanceLifecycleContractError;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LifecycleRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

pub fn canonicalize_request(
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<Option<Vec<u8>>, IssuanceLifecycleContractError> {
    if method != "POST" || lifecycle_action(path).is_none() {
        return Ok(None);
    }
    let request: LifecycleRequest =
        serde_json::from_slice(body).map_err(|_| IssuanceLifecycleContractError)?;
    if request
        .reason
        .as_ref()
        .is_some_and(|value| value.len() > 2000)
    {
        return Err(IssuanceLifecycleContractError);
    }
    serde_json::to_vec(&request)
        .map(Some)
        .map_err(|_| IssuanceLifecycleContractError)
}

fn lifecycle_action(path: &str) -> Option<&str> {
    match path
        .trim_matches('/')
        .split('/')
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["v1", "issued-credentials", id, action]
            if !id.is_empty() && matches!(*action, "revoke" | "suspend" | "reinstate") =>
        {
            Some(action)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;
    use serde_json::Value;

    use super::*;

    #[derive(Deserialize)]
    struct Contract {
        schema_version: u32,
        request_input: Value,
        expected_request: Value,
        invalid_requests: Vec<Value>,
    }

    #[test]
    fn language_neutral_lifecycle_request_contract() {
        let contract: Contract = serde_json::from_str(include_str!(
            "../../../../contracts/gateway-issued-credential-lifecycle-behavior.json"
        ))
        .expect("lifecycle contract");
        assert_eq!(contract.schema_version, 1);
        let body = canonicalize_request(
            "POST",
            "/v1/issued-credentials/credential-1/revoke",
            &serde_json::to_vec(&contract.request_input).unwrap(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            contract.expected_request
        );
        for invalid in contract.invalid_requests {
            assert!(canonicalize_request(
                "POST",
                "/v1/issued-credentials/credential-1/suspend",
                &serde_json::to_vec(&invalid).unwrap(),
            )
            .is_err());
        }
    }
}
